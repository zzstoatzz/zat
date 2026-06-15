//! publish zat's docs to its ATProto repo as `site.standard` records.
//!
//! a small but complete showcase of the library: resolve the account's PDS
//! from its DID document, authenticate, upsert the current document set with
//! stable record keys, and prune anything left over — all through zat's checked
//! XRPC API, so protocol errors arrive as typed `XrpcError`s, not opaque bodies.

const std = @import("std");
const zat = @import("zat");

const Allocator = std.mem.Allocator;

const handle = "zat.dev";
const publication_collection = "site.standard.publication";
const document_collection = "site.standard.document";

/// a document to publish: its record key, site path, and source file.
const DocEntry = struct { rkey: []const u8, path: []const u8, file: []const u8 };

/// top-level docs, with stable record keys derived from their site path.
const docs = [_]DocEntry{
    .{ .rkey = "home", .path = "/", .file = "README.md" },
    .{ .rkey = "roadmap", .path = "/roadmap", .file = "docs/roadmap.md" },
    .{ .rkey = "changelog", .path = "/changelog", .file = "CHANGELOG.md" },
};

const Publication = struct {
    @"$type": []const u8 = publication_collection,
    url: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
};

const Document = struct {
    @"$type": []const u8 = document_collection,
    site: []const u8,
    title: []const u8,
    path: ?[]const u8 = null,
    textContent: ?[]const u8 = null,
    publishedAt: []const u8,
};

pub fn main() !void {
    // short-lived CLI: an arena frees everything at exit, so the body can focus
    // on the protocol rather than on lifetimes.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.Options.debug_io;

    const password = std.mem.span(std.c.getenv("ATPROTO_PASSWORD") orelse {
        std.debug.print("error: ATPROTO_PASSWORD not set\n", .{});
        return error.MissingEnv;
    });

    // resolve the account's current PDS from its DID document so a future PDS
    // migration can't point this at a stale host. ATPROTO_PDS overrides.
    const pds = if (std.c.getenv("ATPROTO_PDS")) |p|
        std.mem.span(p)
    else
        try resolvePds(allocator, io, handle);
    std.debug.print("publishing to pds {s}\n", .{pds});

    var client = zat.XrpcClient.init(io, allocator, pds);
    defer client.deinit();

    const did = try login(&client, allocator, handle, password);
    std.debug.print("authenticated as {s}\n", .{did});

    // the two publications documents are grouped under, with stable rkeys.
    const site_uri = try std.fmt.allocPrint(allocator, "at://{s}/{s}/site", .{ did, publication_collection });
    const devlog_uri = try std.fmt.allocPrint(allocator, "at://{s}/{s}/devlog", .{ did, publication_collection });

    const published_at = try nowIso8601(allocator, io);

    // upsert publications, then every document, tracking the keys we write so
    // we can prune anything stale afterward. putRecord is an upsert, so re-runs
    // are idempotent and writing-before-pruning never leaves the repo empty.
    try putRecord(&client, allocator, did, publication_collection, "site", Publication{
        .url = "https://zat.dev",
        .name = "zat",
        .description = "AT Protocol building blocks for zig",
    });
    try putRecord(&client, allocator, did, publication_collection, "devlog", Publication{
        .url = "https://zat.dev/#devlog/index",
        .name = "zat devlog",
        .description = "building zat in public",
    });

    var doc_keys: std.ArrayList([]const u8) = .empty;
    for (&docs) |entry| {
        if (try publishDocument(&client, allocator, io, did, entry, site_uri, published_at))
            try doc_keys.append(allocator, entry.rkey);
    }
    for (try discoverDevlog(allocator, io)) |entry| {
        if (try publishDocument(&client, allocator, io, did, entry, devlog_uri, published_at))
            try doc_keys.append(allocator, entry.rkey);
    }
    std.debug.print("published {d} document(s)\n", .{doc_keys.items.len});

    // remove records we no longer publish — including any under an older key
    // scheme — so the repo matches exactly what we just wrote.
    try pruneStale(&client, allocator, did, publication_collection, &.{ "site", "devlog" });
    try pruneStale(&client, allocator, did, document_collection, doc_keys.items);
}

/// resolve the PDS service endpoint for a handle via its DID document.
fn resolvePds(allocator: Allocator, io: std.Io, handle_str: []const u8) ![]const u8 {
    const parsed_handle = zat.Handle.parse(handle_str) orelse return error.InvalidHandle;

    var handle_resolver = zat.HandleResolver.init(io, allocator);
    defer handle_resolver.deinit();
    const did_str = try handle_resolver.resolve(parsed_handle);

    const did = zat.Did.parse(did_str) orelse return error.InvalidDid;

    var did_resolver = zat.DidResolver.init(io, allocator);
    defer did_resolver.deinit();
    var doc = try did_resolver.resolve(did);
    defer doc.deinit();

    const pds = doc.pdsEndpoint() orelse return error.NoPdsEndpoint;
    return allocator.dupe(u8, pds);
}

/// authenticate with an app password; returns the account DID and sets auth.
fn login(client: *zat.XrpcClient, allocator: Allocator, identifier: []const u8, password: []const u8) ![]const u8 {
    const body = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(.{
        .identifier = identifier,
        .password = password,
    }, .{})});

    const nsid = zat.Nsid.parse("com.atproto.server.createSession").?;
    var result = try client.procedureChecked(nsid, body, .{});
    defer result.deinit();

    switch (result) {
        .err => |e| return reportXrpcError("createSession", e),
        .ok => |resp| {
            var parsed = try resp.json();
            defer parsed.deinit();
            const did = zat.json.getString(parsed.value, "did") orelse return error.MissingDid;
            const token = zat.json.getString(parsed.value, "accessJwt") orelse return error.MissingToken;
            client.setAuth(try allocator.dupe(u8, token));
            return allocator.dupe(u8, did);
        },
    }
}

/// read a document's source, extract its title, and upsert it. returns false
/// (and warns) if the source can't be read, so a missing file isn't fatal.
fn publishDocument(
    client: *zat.XrpcClient,
    allocator: Allocator,
    io: std.Io,
    did: []const u8,
    entry: DocEntry,
    site_uri: []const u8,
    published_at: []const u8,
) !bool {
    const content = std.Io.Dir.cwd().readFileAlloc(io, entry.file, allocator, .limited(1024 * 1024)) catch |err| {
        std.debug.print("warning: could not read {s}: {}\n", .{ entry.file, err });
        return false;
    };
    try putRecord(client, allocator, did, document_collection, entry.rkey, Document{
        .site = site_uri,
        .title = extractTitle(content) orelse entry.file,
        .path = entry.path,
        .textContent = content,
        .publishedAt = published_at,
    });
    return true;
}

/// discover devlog entries from the `devlog/` dir so the published records stay
/// in sync with the site builder — a hard-coded list silently drifts.
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
        const num = name[0..dash];
        try entries.append(allocator, .{
            .rkey = try std.fmt.allocPrint(allocator, "devlog-{s}", .{num}),
            .path = try std.fmt.allocPrint(allocator, "/devlog/{s}", .{num}),
            .file = try std.fmt.allocPrint(allocator, "devlog/{s}", .{name}),
        });
    }
    return entries.toOwnedSlice(allocator);
}

/// create-or-replace a record. omits null optionals so records carry absent
/// fields, not explicit nulls, which ATProto lexicon validation distinguishes.
fn putRecord(client: *zat.XrpcClient, allocator: Allocator, repo: []const u8, collection: []const u8, rkey: []const u8, value: anytype) !void {
    const record = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{ .emit_null_optional_fields = false })});
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"repo\":\"{s}\",\"collection\":\"{s}\",\"rkey\":\"{s}\",\"record\":{s}}}",
        .{ repo, collection, rkey, record },
    );

    const nsid = zat.Nsid.parse("com.atproto.repo.putRecord").?;
    var result = try client.procedureChecked(nsid, body, .{});
    defer result.deinit();
    switch (result) {
        .ok => {},
        .err => |e| return reportXrpcError("putRecord", e),
    }
}

/// delete every record in `collection` whose rkey is not in `keep`.
fn pruneStale(client: *zat.XrpcClient, allocator: Allocator, repo: []const u8, collection: []const u8, keep: []const []const u8) !void {
    var params = std.StringHashMap([]const u8).init(allocator);
    defer params.deinit();
    try params.put("repo", repo);
    try params.put("collection", collection);
    try params.put("limit", "100");

    const list_nsid = zat.Nsid.parse("com.atproto.repo.listRecords").?;
    var result = try client.queryChecked(list_nsid, params, .{});
    defer result.deinit();

    const resp = switch (result) {
        .err => |e| return reportXrpcError("listRecords", e),
        .ok => |r| r,
    };
    var parsed = try resp.json();
    defer parsed.deinit();

    const records = zat.json.getArray(parsed.value, "records") orelse return;
    for (records) |record| {
        const uri = zat.json.getString(record, "uri") orelse continue;
        const rkey = (zat.AtUri.parse(uri) orelse continue).rkey() orelse continue;
        if (contains(keep, rkey)) continue;
        try deleteRecord(client, allocator, repo, collection, rkey);
        std.debug.print("pruned stale {s}/{s}\n", .{ collection, rkey });
    }
}

fn deleteRecord(client: *zat.XrpcClient, allocator: Allocator, repo: []const u8, collection: []const u8, rkey: []const u8) !void {
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"repo\":\"{s}\",\"collection\":\"{s}\",\"rkey\":\"{s}\"}}",
        .{ repo, collection, rkey },
    );
    const nsid = zat.Nsid.parse("com.atproto.repo.deleteRecord").?;
    var result = try client.procedureChecked(nsid, body, .{});
    defer result.deinit();
    switch (result) {
        .ok => {},
        .err => |e| return reportXrpcError("deleteRecord", e),
    }
}

fn contains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |s| if (std.mem.eql(u8, s, needle)) return true;
    return false;
}

/// log a typed XRPC error and surface it as a Zig error.
fn reportXrpcError(op: []const u8, e: zat.XrpcClient.XrpcError) error{XrpcCallFailed} {
    std.debug.print("{s} failed: {d} {s}: {s}\n", .{
        op,
        @intFromEnum(e.status),
        e.error_name orelse "(no error code)",
        e.message orelse e.body,
    });
    return error.XrpcCallFailed;
}

fn extractTitle(content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 2 and trimmed[0] == '#' and trimmed[1] == ' ') {
            var title = trimmed[2..];
            // strip markdown link: [text](url) -> text
            if (std.mem.indexOf(u8, title, "](")) |bracket| {
                if (title[0] == '[') title = title[1..bracket];
            }
            return title;
        }
    }
    return null;
}

/// current time as an RFC-3339 / ISO-8601 UTC timestamp for `publishedAt`.
fn nowIso8601(allocator: Allocator, io: std.Io) ![]const u8 {
    const ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const secs: u64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @as(u32, md.month.numeric()),
        @as(u32, md.day_index) + 1,
        @as(u32, ds.getHoursIntoDay()),
        @as(u32, ds.getMinutesIntoHour()),
        @as(u32, ds.getSecondsIntoMinute()),
    });
}
