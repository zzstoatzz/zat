//! jetstream client - AT Protocol event stream via WebSocket
//!
//! typed, reconnecting client for the Bluesky Jetstream service.
//! parses commit, identity, and account events into typed structs.
//!
//! see: https://github.com/bluesky-social/jetstream

const std = @import("std");
const websocket = @import("websocket");
const json_helpers = @import("json.zig");
const sync = @import("sync.zig");

const mem = std.mem;
const json = std.json;
const posix = std.posix;
const Allocator = mem.Allocator;
const log = std.log.scoped(.zat);

pub const CommitAction = sync.CommitAction;
pub const AccountStatus = sync.AccountStatus;

pub const Options = struct {
    host: []const u8 = "jetstream2.us-east.bsky.network",
    wanted_collections: []const []const u8 = &.{},
    wanted_dids: []const []const u8 = &.{},
    cursor: ?i64 = null,
    max_message_size: usize = 1024 * 1024,
};

pub const Event = union(enum) {
    commit: CommitEvent,
    identity: IdentityEvent,
    account: AccountEvent,
};

pub const CommitEvent = struct {
    did: []const u8,
    time_us: i64,
    rev: ?[]const u8 = null,
    operation: CommitAction,
    collection: []const u8,
    rkey: []const u8,
    record: ?json.Value = null,
    cid: ?[]const u8 = null,
};

pub const IdentityEvent = struct {
    did: []const u8,
    time_us: i64,
    handle: ?[]const u8 = null,
    seq: ?i64 = null,
    time: ?[]const u8 = null,
};

pub const AccountEvent = struct {
    did: []const u8,
    time_us: i64,
    active: bool,
    status: ?AccountStatus = null,
    seq: ?i64 = null,
    time: ?[]const u8 = null,
};

pub const JetstreamClient = struct {
    allocator: Allocator,
    options: Options,
    last_time_us: ?i64 = null,

    pub fn init(allocator: Allocator, options: Options) JetstreamClient {
        return .{
            .allocator = allocator,
            .options = options,
            .last_time_us = options.cursor,
        };
    }

    pub fn deinit(_: *JetstreamClient) void {}

    /// subscribe with a user-provided handler.
    /// handler must implement: fn onEvent(*@TypeOf(handler), Event) void
    /// optional: fn onError(*@TypeOf(handler), anyerror) void
    /// blocks until deinit — reconnects with exponential backoff on disconnect.
    pub fn subscribe(self: *JetstreamClient, handler: anytype) void {
        var backoff: u64 = 1;
        const max_backoff: u64 = 60;

        while (true) {
            self.connectAndRead(handler) catch |err| {
                if (comptime hasOnError(@TypeOf(handler.*))) {
                    handler.onError(err);
                } else {
                    log.err("jetstream error: {s}, reconnecting in {d}s...", .{ @errorName(err), backoff });
                }
            };
            posix.nanosleep(backoff, 0);
            backoff = @min(backoff * 2, max_backoff);
        }
    }

    fn connectAndRead(self: *JetstreamClient, handler: anytype) !void {
        var path_buf: [2048]u8 = undefined;
        const path = try self.buildSubscribePath(&path_buf);

        log.info("connecting to wss://{s}{s}", .{ self.options.host, path });

        var client = try websocket.Client.init(self.allocator, .{
            .host = self.options.host,
            .port = 443,
            .tls = true,
            .max_size = self.options.max_message_size,
        });
        defer client.deinit();

        var host_header_buf: [256]u8 = undefined;
        const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{self.options.host}) catch self.options.host;

        try client.handshake(path, .{ .headers = host_header });

        log.info("jetstream connected", .{});

        var ws_handler = WsHandler(@TypeOf(handler.*)){
            .allocator = self.allocator,
            .handler = handler,
            .client_state = self,
        };
        try client.readLoop(&ws_handler);
    }

    fn buildSubscribePath(self: *JetstreamClient, buf: *[2048]u8) ![]const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        try writer.writeAll("/subscribe");

        var has_param = false;

        for (self.options.wanted_collections) |col| {
            try writer.writeByte(if (!has_param) '?' else '&');
            try writer.writeAll("wantedCollections=");
            try writer.writeAll(col);
            has_param = true;
        }

        for (self.options.wanted_dids) |did| {
            try writer.writeByte(if (!has_param) '?' else '&');
            try writer.writeAll("wantedDids=");
            try writer.writeAll(did);
            has_param = true;
        }

        if (self.last_time_us) |cursor| {
            try writer.writeByte(if (!has_param) '?' else '&');
            try writer.print("cursor={d}", .{cursor});
        }

        return stream.getWritten();
    }

    fn hasOnError(comptime T: type) bool {
        return @hasDecl(T, "onError");
    }
};

fn WsHandler(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handler: *H,
        client_state: *JetstreamClient,

        const Self = @This();

        pub fn serverMessage(self: *Self, data: []const u8) !void {
            self.processMessage(data) catch |err| {
                log.debug("message parse error: {s}", .{@errorName(err)});
            };
        }

        pub fn close(_: *Self) void {
            log.info("jetstream connection closed", .{});
        }

        fn processMessage(self: *Self, payload: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            const parsed = try json.parseFromSlice(json.Value, alloc, payload, .{});
            const root = parsed.value;

            const kind_str = json_helpers.getString(root, "kind") orelse return;
            const did = json_helpers.getString(root, "did") orelse return;
            const time_us = json_helpers.getInt(root, "time_us") orelse return;

            // track cursor
            self.client_state.last_time_us = time_us;

            if (mem.eql(u8, kind_str, "commit")) {
                const commit = switch (root) {
                    .object => |obj| obj.get("commit") orelse return,
                    else => return,
                };
                const commit_obj = switch (commit) {
                    .object => |obj| obj,
                    else => return,
                };

                const operation_str = switch (commit_obj.get("operation") orelse return) {
                    .string => |s| s,
                    else => return,
                };
                const operation = CommitAction.parse(operation_str) orelse return;

                const collection = switch (commit_obj.get("collection") orelse return) {
                    .string => |s| s,
                    else => return,
                };
                const rkey = switch (commit_obj.get("rkey") orelse return) {
                    .string => |s| s,
                    else => return,
                };

                const rev = blk: {
                    const v = commit_obj.get("rev") orelse break :blk null;
                    break :blk switch (v) {
                        .string => |s| @as(?[]const u8, s),
                        else => null,
                    };
                };

                const cid = blk: {
                    const v = commit_obj.get("cid") orelse break :blk null;
                    break :blk switch (v) {
                        .string => |s| @as(?[]const u8, s),
                        else => null,
                    };
                };

                const record = commit_obj.get("record");

                self.handler.onEvent(.{ .commit = .{
                    .did = did,
                    .time_us = time_us,
                    .rev = rev,
                    .operation = operation,
                    .collection = collection,
                    .rkey = rkey,
                    .record = record,
                    .cid = cid,
                } });
            } else if (mem.eql(u8, kind_str, "identity")) {
                const identity = switch (root) {
                    .object => |obj| obj.get("identity"),
                    else => null,
                };
                const identity_obj = if (identity) |id| switch (id) {
                    .object => |obj| obj,
                    else => null,
                } else null;

                const handle = if (identity_obj) |obj| switch (obj.get("handle") orelse json.Value{ .null = {} }) {
                    .string => |s| @as(?[]const u8, s),
                    else => null,
                } else null;

                const seq = if (identity_obj) |obj| switch (obj.get("seq") orelse json.Value{ .null = {} }) {
                    .integer => |i| @as(?i64, i),
                    else => null,
                } else null;

                const time_val = if (identity_obj) |obj| switch (obj.get("time") orelse json.Value{ .null = {} }) {
                    .string => |s| @as(?[]const u8, s),
                    else => null,
                } else null;

                self.handler.onEvent(.{ .identity = .{
                    .did = did,
                    .time_us = time_us,
                    .handle = handle,
                    .seq = seq,
                    .time = time_val,
                } });
            } else if (mem.eql(u8, kind_str, "account")) {
                const account = switch (root) {
                    .object => |obj| obj.get("account"),
                    else => null,
                };
                const account_obj = if (account) |a| switch (a) {
                    .object => |obj| obj,
                    else => null,
                } else null;

                const active = if (account_obj) |obj| switch (obj.get("active") orelse json.Value{ .null = {} }) {
                    .bool => |b| b,
                    else => true,
                } else true;

                const status_val = if (account_obj) |obj| blk: {
                    const v = obj.get("status") orelse break :blk null;
                    break :blk switch (v) {
                        .string => |s| AccountStatus.parse(s),
                        else => null,
                    };
                } else null;

                const seq = if (account_obj) |obj| switch (obj.get("seq") orelse json.Value{ .null = {} }) {
                    .integer => |i| @as(?i64, i),
                    else => null,
                } else null;

                const time_val = if (account_obj) |obj| switch (obj.get("time") orelse json.Value{ .null = {} }) {
                    .string => |s| @as(?[]const u8, s),
                    else => null,
                } else null;

                self.handler.onEvent(.{ .account = .{
                    .did = did,
                    .time_us = time_us,
                    .active = active,
                    .status = status_val,
                    .seq = seq,
                    .time = time_val,
                } });
            }
            // unknown kinds are silently ignored
        }
    };
}

// === parsing helpers (used by tests and internal parsing) ===

/// parse a raw JSON message into an Event
pub fn parseEvent(allocator: Allocator, payload: []const u8) !Event {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = try json.parseFromSlice(json.Value, alloc, payload, .{});
    const root = parsed.value;

    const kind_str = json_helpers.getString(root, "kind") orelse return error.MissingKind;
    const did = json_helpers.getString(root, "did") orelse return error.MissingDid;
    const time_us = json_helpers.getInt(root, "time_us") orelse return error.MissingTimeUs;

    if (mem.eql(u8, kind_str, "commit")) {
        const commit = switch (root) {
            .object => |obj| obj.get("commit") orelse return error.MissingCommit,
            else => return error.InvalidRoot,
        };
        const commit_obj = switch (commit) {
            .object => |obj| obj,
            else => return error.InvalidCommit,
        };

        const operation_str = switch (commit_obj.get("operation") orelse return error.MissingOperation) {
            .string => |s| s,
            else => return error.InvalidOperation,
        };
        const operation = CommitAction.parse(operation_str) orelse return error.UnknownOperation;

        const collection = switch (commit_obj.get("collection") orelse return error.MissingCollection) {
            .string => |s| s,
            else => return error.InvalidCollection,
        };
        const rkey = switch (commit_obj.get("rkey") orelse return error.MissingRkey) {
            .string => |s| s,
            else => return error.InvalidRkey,
        };

        const rev = blk: {
            const v = commit_obj.get("rev") orelse break :blk null;
            break :blk switch (v) {
                .string => |s| @as(?[]const u8, s),
                else => null,
            };
        };

        const cid = blk: {
            const v = commit_obj.get("cid") orelse break :blk null;
            break :blk switch (v) {
                .string => |s| @as(?[]const u8, s),
                else => null,
            };
        };

        return .{ .commit = .{
            .did = did,
            .time_us = time_us,
            .rev = rev,
            .operation = operation,
            .collection = collection,
            .rkey = rkey,
            .record = commit_obj.get("record"),
            .cid = cid,
        } };
    } else if (mem.eql(u8, kind_str, "identity")) {
        const identity = switch (root) {
            .object => |obj| obj.get("identity"),
            else => null,
        };
        const identity_obj = if (identity) |id| switch (id) {
            .object => |obj| obj,
            else => null,
        } else null;

        const handle = if (identity_obj) |obj| switch (obj.get("handle") orelse json.Value{ .null = {} }) {
            .string => |s| @as(?[]const u8, s),
            else => null,
        } else null;

        const seq = if (identity_obj) |obj| switch (obj.get("seq") orelse json.Value{ .null = {} }) {
            .integer => |i| @as(?i64, i),
            else => null,
        } else null;

        const time_val = if (identity_obj) |obj| switch (obj.get("time") orelse json.Value{ .null = {} }) {
            .string => |s| @as(?[]const u8, s),
            else => null,
        } else null;

        return .{ .identity = .{
            .did = did,
            .time_us = time_us,
            .handle = handle,
            .seq = seq,
            .time = time_val,
        } };
    } else if (mem.eql(u8, kind_str, "account")) {
        const account = switch (root) {
            .object => |obj| obj.get("account"),
            else => null,
        };
        const account_obj = if (account) |a| switch (a) {
            .object => |obj| obj,
            else => null,
        } else null;

        const active = if (account_obj) |obj| switch (obj.get("active") orelse json.Value{ .null = {} }) {
            .bool => |b| b,
            else => true,
        } else true;

        const status_val = if (account_obj) |obj| blk: {
            const v = obj.get("status") orelse break :blk null;
            break :blk switch (v) {
                .string => |s| AccountStatus.parse(s),
                else => null,
            };
        } else null;

        const seq = if (account_obj) |obj| switch (obj.get("seq") orelse json.Value{ .null = {} }) {
            .integer => |i| @as(?i64, i),
            else => null,
        } else null;

        const time_val = if (account_obj) |obj| switch (obj.get("time") orelse json.Value{ .null = {} }) {
            .string => |s| @as(?[]const u8, s),
            else => null,
        } else null;

        return .{ .account = .{
            .did = did,
            .time_us = time_us,
            .active = active,
            .status = status_val,
            .seq = seq,
            .time = time_val,
        } };
    }

    return error.UnknownKind;
}

// === tests ===

test "parse commit event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "rev": "3mbspmpaidl2a",
        \\    "operation": "create",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789",
        \\    "cid": "bafyreitest",
        \\    "record": {
        \\      "text": "hello world",
        \\      "$type": "app.bsky.feed.post"
        \\    }
        \\  }
        \\}
    ;

    const event = try parseEvent(std.testing.allocator, payload);
    const commit = event.commit;

    try std.testing.expectEqualStrings("did:plc:abc123", commit.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), commit.time_us);
    try std.testing.expectEqualStrings("3mbspmpaidl2a", commit.rev.?);
    try std.testing.expectEqual(CommitAction.create, commit.operation);
    try std.testing.expectEqualStrings("app.bsky.feed.post", commit.collection);
    try std.testing.expectEqualStrings("xyz789", commit.rkey);
    try std.testing.expectEqualStrings("bafyreitest", commit.cid.?);
    try std.testing.expect(commit.record != null);

    // verify record contents via json helpers
    const text = json_helpers.getString(commit.record.?, "text");
    try std.testing.expectEqualStrings("hello world", text.?);
}

test "parse identity event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "identity",
        \\  "identity": {
        \\    "handle": "alice.bsky.social",
        \\    "seq": 42,
        \\    "time": "2024-01-01T00:00:00Z"
        \\  }
        \\}
    ;

    const event = try parseEvent(std.testing.allocator, payload);
    const identity = event.identity;

    try std.testing.expectEqualStrings("did:plc:abc123", identity.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), identity.time_us);
    try std.testing.expectEqualStrings("alice.bsky.social", identity.handle.?);
    try std.testing.expectEqual(@as(i64, 42), identity.seq.?);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", identity.time.?);
}

test "parse account event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "account",
        \\  "account": {
        \\    "active": false,
        \\    "status": "suspended",
        \\    "seq": 99,
        \\    "time": "2024-01-01T00:00:00Z"
        \\  }
        \\}
    ;

    const event = try parseEvent(std.testing.allocator, payload);
    const account = event.account;

    try std.testing.expectEqualStrings("did:plc:abc123", account.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), account.time_us);
    try std.testing.expectEqual(false, account.active);
    try std.testing.expectEqual(AccountStatus.suspended, account.status.?);
    try std.testing.expectEqual(@as(i64, 99), account.seq.?);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", account.time.?);
}

test "parse unknown kind returns error" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "unknown_kind"
        \\}
    ;

    const result = parseEvent(std.testing.allocator, payload);
    try std.testing.expectError(error.UnknownKind, result);
}

test "parse commit with unknown operation returns error" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "operation": "archive",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789"
        \\  }
        \\}
    ;

    const result = parseEvent(std.testing.allocator, payload);
    try std.testing.expectError(error.UnknownOperation, result);
}

test "cursor tracking via time_us" {
    // verify that parseEvent extracts time_us correctly for cursor resumption
    const payloads = [_][]const u8{
        \\{"did":"did:plc:a","time_us":100,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"1"}}
        ,
        \\{"did":"did:plc:b","time_us":200,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"2"}}
        ,
    };

    for (payloads) |payload| {
        const event = try parseEvent(std.testing.allocator, payload);
        switch (event) {
            .commit => |c| try std.testing.expect(c.time_us > 0),
            else => unreachable,
        }
    }

    // verify second event has higher time_us
    const e1 = try parseEvent(std.testing.allocator, payloads[0]);
    const e2 = try parseEvent(std.testing.allocator, payloads[1]);
    try std.testing.expect(e2.commit.time_us > e1.commit.time_us);
}

test "build subscribe path" {
    var client = JetstreamClient.init(std.testing.allocator, .{
        .wanted_collections = &.{"app.bsky.feed.post"},
    });

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings("/subscribe?wantedCollections=app.bsky.feed.post", path);
}

test "build subscribe path with multiple params" {
    var client = JetstreamClient.init(std.testing.allocator, .{
        .wanted_collections = &.{ "app.bsky.feed.post", "app.bsky.feed.like" },
        .wanted_dids = &.{"did:plc:abc123"},
        .cursor = 1700000000000,
    });

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings(
        "/subscribe?wantedCollections=app.bsky.feed.post&wantedCollections=app.bsky.feed.like&wantedDids=did:plc:abc123&cursor=1700000000000",
        path,
    );
}

test "build subscribe path no params" {
    var client = JetstreamClient.init(std.testing.allocator, .{});

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings("/subscribe", path);
}

test "parse commit event with delete operation" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "operation": "delete",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789"
        \\  }
        \\}
    ;

    const event = try parseEvent(std.testing.allocator, payload);
    const commit = event.commit;

    try std.testing.expectEqual(CommitAction.delete, commit.operation);
    try std.testing.expect(commit.record == null);
    try std.testing.expect(commit.rev == null);
    try std.testing.expect(commit.cid == null);
}

test "parse identity event with minimal fields" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "identity",
        \\  "identity": {}
        \\}
    ;

    const event = try parseEvent(std.testing.allocator, payload);
    const identity = event.identity;

    try std.testing.expectEqualStrings("did:plc:abc123", identity.did);
    try std.testing.expect(identity.handle == null);
    try std.testing.expect(identity.seq == null);
    try std.testing.expect(identity.time == null);
}

test "parse missing did returns error" {
    const payload =
        \\{
        \\  "time_us": 1700000000000,
        \\  "kind": "commit"
        \\}
    ;

    const result = parseEvent(std.testing.allocator, payload);
    try std.testing.expectError(error.MissingDid, result);
}
