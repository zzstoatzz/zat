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

/// devlog entries
const devlog = [_]DocEntry{
    .{ .path = "/devlog/001", .file = "devlog/001-self-publishing-docs.md" },
    .{ .path = "/devlog/002", .file = "devlog/002-firehose-and-benchmarks.md" },
    .{ .path = "/devlog/003", .file = "devlog/003-trust-chain.md" },
    .{ .path = "/devlog/004", .file = "devlog/004-sig-verify.md" },
    .{ .path = "/devlog/005", .file = "devlog/005-three-way-verify.md" },
    .{ .path = "/devlog/006", .file = "devlog/006-building-a-relay.md" },
    .{ .path = "/devlog/007", .file = "devlog/007-up-and-to-the-right.md" },
    .{ .path = "/devlog/008", .file = "devlog/008-the-io-migration.md" },
    .{ .path = "/devlog/009", .file = "devlog/009-back-to-threads.md" },
    .{ .path = "/devlog/010", .file = "devlog/010-the-network-is-input.md" },
    .{ .path = "/devlog/011", .file = "devlog/011-building-a-pds.md" },
    .{ .path = "/devlog/012", .file = "devlog/012-mst-bench-notes.md" },
};

pub fn main() !void {
    // use page_allocator for CLI tool - OS reclaims on exit
    const allocator = std.heap.page_allocator;

    const handle = "zat.dev";

    const password = if (std.c.getenv("ATPROTO_PASSWORD")) |p| std.mem.span(p) else {
        std.debug.print("error: ATPROTO_PASSWORD not set\n", .{});
        return error.MissingEnv;
    };

    const pds = if (std.c.getenv("ATPROTO_PDS")) |p| std.mem.span(p) else "https://bsky.social";

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
        .url = "https://zat.dev",
        .name = "zat devlog",
        .description = "building zat in public",
    };

    try putRecord(&client, allocator, session.did, "site.standard.publication", devlog_tid.str(), devlog_pub);
    std.debug.print("created publication: at://{s}/site.standard.publication/{s}\n", .{ session.did, devlog_tid.str() });

    var devlog_uri_buf: std.ArrayList(u8) = .empty;
    defer devlog_uri_buf.deinit(allocator);
    try devlog_uri_buf.print(allocator, "at://{s}/site.standard.publication/{s}", .{ session.did, devlog_tid.str() });
    const devlog_uri = devlog_uri_buf.items;

    try publishEntries(&client, allocator, session.did, &devlog, devlog_uri, 101, &now);

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
