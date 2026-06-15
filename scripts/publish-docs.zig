const std = @import("std");
const zat = @import("zat");

const Allocator = std.mem.Allocator;

const DocEntry = struct { path: []const u8, file: []const u8 };

/// docs to publish as site.standard.document records
const docs = [_]DocEntry{
    .{ .path = "/", .file = "README.md" },
    .{ .path = "/roadmap", .file = "docs/roadmap.md" },
    .{ .path = "/changelog", .file = "CHANGELOG.md" },
};

/// resolve the PDS service endpoint for a handle via its DID document.
fn resolvePds(allocator: Allocator, io: std.Io, handle_str: []const u8) ![]const u8 {
    const handle = zat.Handle.parse(handle_str) orelse return error.InvalidHandle;

    var handle_resolver = zat.HandleResolver.init(io, allocator);
    defer handle_resolver.deinit();
    const did_str = try handle_resolver.resolve(handle);
    defer allocator.free(did_str);

    const did = zat.Did.parse(did_str) orelse return error.InvalidDid;

    var did_resolver = zat.DidResolver.init(io, allocator);
    defer did_resolver.deinit();
    var doc = try did_resolver.resolve(did);
    defer doc.deinit();

    const pds = doc.pdsEndpoint() orelse return error.NoPdsEndpoint;
    return try allocator.dupe(u8, pds);
}

/// discover devlog entries from the `devlog/` dir so the published document
/// records stay in sync with the site builder (which also discovers them) — a
/// hard-coded list silently drifts every time a new entry lands.
fn discoverDevlog(allocator: Allocator, io: std.Io) ![]DocEntry {
    var dir = try std.Io.Dir.cwd().openDir(io, "devlog", .{ .iterate = true });
    defer dir.close(io);

    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
        if (entry.name.len == 0 or !std.ascii.isDigit(entry.name[0])) continue;
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }

    // sort by filename so the `NNN-` numeric prefix orders chronologically
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    var entries: std.ArrayList(DocEntry) = .empty;
    for (names.items) |name| {
        const dash = std.mem.indexOfScalar(u8, name, '-') orelse continue;
        entries.append(allocator, .{
            .path = try std.fmt.allocPrint(allocator, "/devlog/{s}", .{name[0..dash]}),
            .file = try std.fmt.allocPrint(allocator, "devlog/{s}", .{name}),
        }) catch unreachable;
    }
    return entries.toOwnedSlice(allocator);
}

pub fn main() !void {
    // use page_allocator for CLI tool - OS reclaims on exit
    const allocator = std.heap.page_allocator;

    const handle = "zat.dev";

    const password = if (std.c.getenv("ATPROTO_PASSWORD")) |p| std.mem.span(p) else {
        std.debug.print("error: ATPROTO_PASSWORD not set\n", .{});
        return error.MissingEnv;
    };

    // resolve the account's current PDS from its DID document so a future PDS
    // migration can't silently point this at a stale host (the old default,
    // bsky.social, is where the account is now deactivated). ATPROTO_PDS still
    // overrides for local/testing.
    const pds = if (std.c.getenv("ATPROTO_PDS")) |p|
        try allocator.dupe(u8, std.mem.span(p))
    else
        try resolvePds(allocator, std.Options.debug_io, handle);
    defer allocator.free(pds);
    std.debug.print("publishing to pds {s}\n", .{pds});

    var client = zat.XrpcClient.init(std.Options.debug_io, allocator, pds);
    defer client.deinit();

    const session = try createSession(&client, allocator, handle, password);
    defer {
        allocator.free(session.did);
        allocator.free(session.access_token);
    }

    std.debug.print("authenticated as {s}\n", .{session.did});
    client.setAuth(session.access_token);

    // generate TID for publication (fixed timestamp for deterministic rkey)
    // using 2024-01-01 00:00:00 UTC as base timestamp (1704067200 seconds = 1704067200000000 microseconds)
    const pub_tid = zat.Tid.fromTimestamp(1704067200000000, 0);
    const pub_record = Publication{
        .url = "https://zat.dev",
        .name = "zat",
        .description = "AT Protocol building blocks for zig",
    };

    try putRecord(&client, allocator, session.did, "site.standard.publication", pub_tid.str(), pub_record);
    std.debug.print("created publication: at://{s}/site.standard.publication/{s}\n", .{ session.did, pub_tid.str() });

    var pub_uri_buf: std.ArrayList(u8) = .empty;
    defer pub_uri_buf.deinit(allocator);
    try pub_uri_buf.print(allocator, "at://{s}/site.standard.publication/{s}", .{ session.did, pub_tid.str() });
    const pub_uri = pub_uri_buf.items;

    // publish each doc with deterministic TIDs (same base timestamp, incrementing clock_id)
    const now = timestamp();

    try publishEntries(&client, allocator, session.did, &docs, pub_uri, 1, &now);

    // devlog publication (clock_id 100 to separate from docs)
    const devlog_tid = zat.Tid.fromTimestamp(1704067200000000, 100);
    const devlog_pub = Publication{
        .url = "https://zat.dev/#devlog/index",
        .name = "zat devlog",
        .description = "building zat in public",
    };

    try putRecord(&client, allocator, session.did, "site.standard.publication", devlog_tid.str(), devlog_pub);
    std.debug.print("created publication: at://{s}/site.standard.publication/{s}\n", .{ session.did, devlog_tid.str() });

    var devlog_uri_buf: std.ArrayList(u8) = .empty;
    defer devlog_uri_buf.deinit(allocator);
    try devlog_uri_buf.print(allocator, "at://{s}/site.standard.publication/{s}", .{ session.did, devlog_tid.str() });
    const devlog_uri = devlog_uri_buf.items;

    const devlog = try discoverDevlog(allocator, std.Options.debug_io);
    try publishEntries(&client, allocator, session.did, devlog, devlog_uri, 101, &now);

    std.debug.print("done\n", .{});
}

const Publication = struct {
    @"$type": []const u8 = "site.standard.publication",
    url: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
};

const Document = struct {
    @"$type": []const u8 = "site.standard.document",
    site: []const u8,
    title: []const u8,
    path: ?[]const u8 = null,
    textContent: ?[]const u8 = null,
    publishedAt: []const u8,
};

const Session = struct {
    did: []const u8,
    access_token: []const u8,
};

fn createSession(client: *zat.XrpcClient, allocator: Allocator, handle: []const u8, password: []const u8) !Session {
    const CreateSessionInput = struct {
        identifier: []const u8,
        password: []const u8,
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.print(allocator, "{f}", .{std.json.fmt(CreateSessionInput{
        .identifier = handle,
        .password = password,
    }, .{})});

    const nsid = zat.Nsid.parse("com.atproto.server.createSession").?;
    var response = try client.procedure(nsid, buf.items);
    defer response.deinit();

    if (!response.ok()) {
        std.debug.print("createSession failed: {s}\n", .{response.body});
        return error.AuthFailed;
    }

    var parsed = try response.json();
    defer parsed.deinit();

    const did = zat.json.getString(parsed.value, "did") orelse return error.MissingDid;
    const token = zat.json.getString(parsed.value, "accessJwt") orelse return error.MissingToken;

    return .{
        .did = try allocator.dupe(u8, did),
        .access_token = try allocator.dupe(u8, token),
    };
}

fn putRecord(client: *zat.XrpcClient, allocator: Allocator, repo: []const u8, collection: []const u8, rkey: []const u8, record: anytype) !void {
    const PutRecordInput = struct {
        repo: []const u8,
        collection: []const u8,
        rkey: []const u8,
        record: @TypeOf(record),
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.print(allocator, "{f}", .{std.json.fmt(PutRecordInput{
        .repo = repo,
        .collection = collection,
        .rkey = rkey,
        .record = record,
    }, .{})});

    const nsid = zat.Nsid.parse("com.atproto.repo.putRecord").?;
    var response = try client.procedure(nsid, buf.items);
    defer response.deinit();

    if (!response.ok()) {
        std.debug.print("putRecord failed: {s}\n", .{response.body});
        return error.PutFailed;
    }
}

fn extractTitle(content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 2 and trimmed[0] == '#' and trimmed[1] == ' ') {
            var title = trimmed[2..];
            // strip markdown link: [text](url) -> text
            if (std.mem.indexOf(u8, title, "](")) |bracket| {
                if (title[0] == '[') {
                    title = title[1..bracket];
                }
            }
            return title;
        }
    }
    return null;
}

fn publishEntries(
    client: *zat.XrpcClient,
    allocator: Allocator,
    did: []const u8,
    entries: []const DocEntry,
    site_uri: []const u8,
    clock_id_base: usize,
    now: *const [20]u8,
) !void {
    for (entries, 0..) |entry, i| {
        const content = std.Io.Dir.readFileAlloc(.cwd(), std.Options.debug_io, entry.file, allocator, .limited(1024 * 1024)) catch |err| {
            std.debug.print("warning: could not read {s}: {}\n", .{ entry.file, err });
            continue;
        };
        defer allocator.free(content);

        const title = extractTitle(content) orelse entry.file;
        const tid = zat.Tid.fromTimestamp(1704067200000000, @intCast(clock_id_base + i));

        const record = Document{
            .site = site_uri,
            .title = title,
            .path = entry.path,
            .textContent = content,
            .publishedAt = now,
        };

        try putRecord(client, allocator, did, "site.standard.document", tid.str(), record);
        std.debug.print("published: {s} -> at://{s}/site.standard.document/{s}\n", .{ entry.file, did, tid.str() });
    }
}

fn timestamp() [20]u8 {
    const ns = std.Io.Timestamp.now(std.Options.debug_io, .real).nanoseconds;
    const secs: u64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    var buf: [20]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @as(u32, md.month.numeric()),
        @as(u32, md.day_index) + 1,
        @as(u32, ds.getHoursIntoDay()),
        @as(u32, ds.getMinutesIntoHour()),
        @as(u32, ds.getSecondsIntoMinute()),
    }) catch unreachable;
    return buf;
}
