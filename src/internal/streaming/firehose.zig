//! firehose codec - com.atproto.sync.subscribeRepos
//!
//! encode and decode AT Protocol firehose events over WebSocket. messages are
//! DAG-CBOR encoded (unlike jetstream, which is JSON). includes frame encoding/
//! decoding, CAR block packing, and CID creation for records.
//!
//! wire format per frame:
//!   [DAG-CBOR header: {op, t}] [DAG-CBOR payload: {seq, repo, ops, blocks, ...}]
//!
//! see: https://atproto.com/specs/event-stream

const std = @import("std");
const websocket = @import("websocket");
const cbor = @import("../repo/cbor.zig");
const car = @import("../repo/car.zig");
const mst = @import("../repo/mst.zig");
const sync = @import("sync.zig");
const Nsid = @import("../syntax/nsid.zig").Nsid;
const Rkey = @import("../syntax/rkey.zig").Rkey;

const mem = std.mem;
const Allocator = mem.Allocator;
const posix = std.posix;
const Io = std.Io;
const log = std.log.scoped(.zat);

pub const CommitAction = sync.CommitAction;
pub const AccountStatus = sync.AccountStatus;

pub const default_hosts = [_][]const u8{
    "bsky.network",
    "northamerica.firehose.network",
    "europe.firehose.network",
    "asia.firehose.network",
};

pub const Options = struct {
    hosts: []const []const u8 = &default_hosts,
    cursor: ?i64 = null,
    max_message_size: usize = 5 * 1024 * 1024, // 5MB — firehose frames can be large
};

/// decoded firehose event
pub const Event = union(enum) {
    commit: CommitEvent,
    sync: SyncEvent,
    identity: IdentityEvent,
    account: AccountEvent,
    info: InfoEvent,

    pub fn seq(self: Event) ?i64 {
        return switch (self) {
            .commit => |c| c.seq,
            .sync => |s| s.seq,
            .identity => |i| i.seq,
            .account => |a| a.seq,
            .info => null,
        };
    }
};

pub const CommitEvent = struct {
    seq: i64,
    repo: []const u8, // DID
    rev: []const u8, // TID — revision of the commit
    time: []const u8, // datetime — when event was received
    since: ?[]const u8 = null, // TID — rev of preceding commit (null = full repo export)
    commit: ?cbor.Cid = null, // CID of the commit object
    blocks: []const u8 = &.{}, // raw CAR diff bytes
    ops: []const RepoOp,
    prev_data: ?cbor.Cid = null, // MST root CID of the previous revision
    blobs: []const cbor.Cid = &.{}, // new blobs referenced by records in this commit
    too_big: bool = false,

    pub fn toMstOperations(self: CommitEvent, allocator: Allocator) Allocator.Error![]mst.Operation {
        var ops: std.ArrayList(mst.Operation) = .empty;
        errdefer ops.deinit(allocator);
        for (self.ops) |op| {
            const path = if (op.path.len != 0)
                try allocator.dupe(u8, op.path)
            else
                try std.fmt.allocPrint(allocator, "{s}/{s}", .{ op.collection, op.rkey });
            try ops.append(allocator, .{
                .path = path,
                .value = if (op.cid) |cid| cid.raw else null,
                .prev = if (op.prev) |prev| prev.raw else null,
            });
        }
        return ops.toOwnedSlice(allocator);
    }
};

pub const RepoOp = struct {
    action: CommitAction,
    path: []const u8 = "",
    collection: []const u8,
    rkey: []const u8,
    cid: ?cbor.Cid = null, // CID of the record (null for deletes)
    prev: ?cbor.Cid = null, // CID of the previous record for updates/deletes
    record: ?cbor.Value = null, // decoded DAG-CBOR record from CAR block
};

pub const SyncEvent = struct {
    seq: i64,
    did: []const u8,
    rev: []const u8,
    time: []const u8,
    blocks: []const u8, // raw CAR bytes containing the current commit object
};

pub const IdentityEvent = struct {
    seq: i64,
    did: []const u8,
    time: []const u8, // datetime — when event was received
    handle: ?[]const u8 = null,
};

pub const AccountEvent = struct {
    seq: i64,
    did: []const u8,
    time: []const u8, // datetime — when event was received
    active: bool = true,
    status: ?AccountStatus = null,
};

pub const InfoEvent = struct {
    name: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

/// frame header from the wire
const FrameHeader = struct {
    op: i64,
    t: ?[]const u8 = null,
};

pub const FrameOp = enum(i64) {
    message = 1,
    err = -1,
};

pub const DecodeError = error{
    InvalidFrame,
    InvalidHeader,
    UnexpectedEof,
    MissingField,
    InvalidRepoPath,
    UnknownOp,
    UnknownEventType,
} || cbor.DecodeError || car.CarError;

/// decode a raw WebSocket binary frame into a firehose Event
pub fn decodeFrame(allocator: Allocator, data: []const u8) DecodeError!Event {
    // frame = [CBOR header] [CBOR payload] concatenated
    const header_result = try cbor.decode(allocator, data);
    const header_val = header_result.value;
    const payload_data = data[header_result.consumed..];

    // parse header
    const op = header_val.getInt("op") orelse return error.InvalidHeader;
    if (op == -1) return error.UnknownOp; // error frame

    const t = header_val.getString("t") orelse return error.InvalidHeader;

    // decode payload
    const payload = try cbor.decodeAll(allocator, payload_data);

    if (mem.eql(u8, t, "#commit")) {
        return try decodeCommit(allocator, payload);
    } else if (mem.eql(u8, t, "#sync")) {
        return decodeSync(payload);
    } else if (mem.eql(u8, t, "#identity")) {
        return decodeIdentity(payload);
    } else if (mem.eql(u8, t, "#account")) {
        return decodeAccount(payload);
    } else if (mem.eql(u8, t, "#info")) {
        return .{ .info = .{
            .name = payload.getString("name"),
            .message = payload.getString("message"),
        } };
    }

    return error.UnknownEventType;
}

fn decodeCommit(allocator: Allocator, payload: cbor.Value) DecodeError!Event {
    const seq_val = payload.getInt("seq") orelse return error.MissingField;
    const repo = payload.getString("repo") orelse return error.MissingField;
    const rev = payload.getString("rev") orelse return error.MissingField;
    const time = payload.getString("time") orelse return error.MissingField;

    const commit_cid = payload.getCid("commit") orelse return error.MissingField;
    const blocks_bytes = payload.getBytes("blocks") orelse return error.MissingField;
    const prev_data = try optionalCid(payload, "prevData");

    // parse blobs array (array of CID links)
    var blobs: std.ArrayList(cbor.Cid) = .empty;
    if (payload.getArray("blobs")) |blob_values| {
        for (blob_values) |blob_val| {
            switch (blob_val) {
                .cid => |c| try blobs.append(allocator, c),
                else => {},
            }
        }
    }

    // parse CAR blocks for record hydration. CAR verification failure should not
    // hide the wire event; consumers can reject by verifying `blocks` explicitly.
    const parsed_car: ?car.Car = car.read(allocator, blocks_bytes) catch null;

    // parse ops
    const ops_array = payload.getArray("ops");
    var ops: std.ArrayList(RepoOp) = .empty;

    if (ops_array) |op_values| {
        for (op_values) |op_val| {
            const action_str = op_val.getString("action") orelse continue;
            const action = CommitAction.parse(action_str) orelse continue;
            const path = op_val.getString("path") orelse continue;

            const repo_path = try parseRepoPath(path);

            // extract CID from op and look up record from CAR blocks
            var op_cid: ?cbor.Cid = null;
            var op_prev: ?cbor.Cid = null;
            var record: ?cbor.Value = null;
            if (op_val.get("cid")) |cid_val| {
                switch (cid_val) {
                    .cid => |cid| {
                        op_cid = cid;
                        if (parsed_car) |c| {
                            if (car.findBlock(c, cid.raw)) |block_data| {
                                record = cbor.decodeAll(allocator, block_data) catch null;
                            }
                        }
                    },
                    else => {},
                }
            }
            if (op_val.get("prev")) |prev_val| {
                switch (prev_val) {
                    .cid => |cid| op_prev = cid,
                    else => {},
                }
            }

            try ops.append(allocator, .{
                .action = action,
                .path = path,
                .collection = repo_path.collection,
                .rkey = repo_path.rkey,
                .cid = op_cid,
                .prev = op_prev,
                .record = record,
            });
        }
    }

    return .{ .commit = .{
        .seq = seq_val,
        .repo = repo,
        .rev = rev,
        .time = time,
        .since = payload.getString("since"),
        .commit = commit_cid,
        .blocks = blocks_bytes,
        .ops = try ops.toOwnedSlice(allocator),
        .prev_data = prev_data,
        .blobs = try blobs.toOwnedSlice(allocator),
        .too_big = payload.getBool("tooBig") orelse false,
    } };
}

const RepoPath = struct {
    collection: []const u8,
    rkey: []const u8,
};

fn parseRepoPath(path: []const u8) DecodeError!RepoPath {
    const slash = mem.indexOfScalar(u8, path, '/') orelse return error.InvalidRepoPath;
    if (mem.indexOfScalarPos(u8, path, slash + 1, '/') != null) return error.InvalidRepoPath;

    const collection = path[0..slash];
    const rkey = path[slash + 1 ..];
    if (Nsid.parse(collection) == null) return error.InvalidRepoPath;
    if (Rkey.parse(rkey) == null) return error.InvalidRepoPath;

    return .{ .collection = collection, .rkey = rkey };
}

fn optionalCid(value: cbor.Value, key: []const u8) DecodeError!?cbor.Cid {
    const found = value.get(key) orelse return error.MissingField;
    return switch (found) {
        .cid => |cid| cid,
        .null => null,
        else => error.MissingField,
    };
}

fn decodeSync(payload: cbor.Value) DecodeError!Event {
    return .{ .sync = .{
        .seq = payload.getInt("seq") orelse return error.MissingField,
        .did = payload.getString("did") orelse return error.MissingField,
        .rev = payload.getString("rev") orelse return error.MissingField,
        .time = payload.getString("time") orelse return error.MissingField,
        .blocks = payload.getBytes("blocks") orelse return error.MissingField,
    } };
}

fn decodeIdentity(payload: cbor.Value) DecodeError!Event {
    return .{ .identity = .{
        .seq = payload.getInt("seq") orelse return error.MissingField,
        .did = payload.getString("did") orelse return error.MissingField,
        .time = payload.getString("time") orelse return error.MissingField,
        .handle = payload.getString("handle"),
    } };
}

fn decodeAccount(payload: cbor.Value) DecodeError!Event {
    const status_str = payload.getString("status");
    return .{ .account = .{
        .seq = payload.getInt("seq") orelse return error.MissingField,
        .did = payload.getString("did") orelse return error.MissingField,
        .time = payload.getString("time") orelse return error.MissingField,
        .active = payload.getBool("active") orelse true,
        .status = if (status_str) |s| AccountStatus.parse(s) else null,
    } };
}

// === encoder ===

/// encode a firehose Event into a wire frame: [DAG-CBOR header] [DAG-CBOR payload]
pub fn encodeFrame(allocator: Allocator, event: Event) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    const tag = switch (event) {
        .commit => "#commit",
        .sync => "#sync",
        .identity => "#identity",
        .account => "#account",
        .info => "#info",
    };

    // encode header: {op: 1, t: "#..."}
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "op", .value = .{ .unsigned = 1 } },
        .{ .key = "t", .value = .{ .text = tag } },
    } };
    try cbor.encode(allocator, &aw.writer, header);

    // encode payload based on event type
    switch (event) {
        .commit => |commit| try encodeCommitPayload(allocator, &aw.writer, commit),
        .sync => |sync_event| try encodeSyncPayload(allocator, &aw.writer, sync_event),
        .identity => |id| try encodeIdentityPayload(allocator, &aw.writer, id),
        .account => |acct| try encodeAccountPayload(allocator, &aw.writer, acct),
        .info => |inf| try encodeInfoPayload(allocator, &aw.writer, inf),
    }

    return try aw.toOwnedSlice();
}

fn encodeCommitPayload(allocator: Allocator, writer: anytype, commit: CommitEvent) !void {
    // build ops array and CAR blocks simultaneously
    var op_values: std.ArrayList(cbor.Value) = .empty;
    defer op_values.deinit(allocator);
    var car_blocks: std.ArrayList(car.Block) = .empty;
    defer car_blocks.deinit(allocator);
    var root_cids: std.ArrayList(cbor.Cid) = .empty;
    defer root_cids.deinit(allocator);

    for (commit.ops) |op| {
        const action_str: []const u8 = @tagName(op.action);
        const path = if (op.path.len != 0)
            op.path
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ op.collection, op.rkey });
        _ = try parseRepoPath(path);

        if (op.record) |record| {
            // encode record, create CID, add to CAR blocks
            const record_bytes = try cbor.encodeAlloc(allocator, record);
            const cid = try cbor.Cid.forDagCbor(allocator, record_bytes);

            try car_blocks.append(allocator, .{
                .cid_raw = cid.raw,
                .data = record_bytes,
            });

            if (root_cids.items.len == 0) {
                try root_cids.append(allocator, cid);
            }

            var op_entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
            defer op_entries.deinit(allocator);
            try op_entries.append(allocator, .{ .key = "action", .value = .{ .text = action_str } });
            try op_entries.append(allocator, .{ .key = "cid", .value = .{ .cid = cid } });
            try op_entries.append(allocator, .{ .key = "path", .value = .{ .text = path } });
            if (op.prev) |prev| {
                try op_entries.append(allocator, .{ .key = "prev", .value = .{ .cid = prev } });
            }
            try op_values.append(allocator, .{ .map = try op_entries.toOwnedSlice(allocator) });
        } else {
            var op_entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
            defer op_entries.deinit(allocator);
            try op_entries.append(allocator, .{ .key = "action", .value = .{ .text = action_str } });
            try op_entries.append(allocator, .{ .key = "cid", .value = .null });
            try op_entries.append(allocator, .{ .key = "path", .value = .{ .text = path } });
            if (op.prev) |prev| {
                try op_entries.append(allocator, .{ .key = "prev", .value = .{ .cid = prev } });
            }
            try op_values.append(allocator, .{ .map = try op_entries.toOwnedSlice(allocator) });
        }
    }

    const blocks_bytes = if (commit.blocks.len != 0) commit.blocks else blk: {
        const car_data = car.Car{
            .roots = root_cids.items,
            .blocks = car_blocks.items,
        };
        break :blk try car.writeAlloc(allocator, car_data);
    };

    // build blobs array
    var blob_values: std.ArrayList(cbor.Value) = .empty;
    defer blob_values.deinit(allocator);
    for (commit.blobs) |blob| {
        try blob_values.append(allocator, .{ .cid = blob });
    }

    // build payload entries
    var entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
    defer entries.deinit(allocator);

    try entries.append(allocator, .{ .key = "blocks", .value = .{ .bytes = blocks_bytes } });
    if (commit.commit) |commit_cid| {
        try entries.append(allocator, .{ .key = "commit", .value = .{ .cid = commit_cid } });
    }
    try entries.append(allocator, .{ .key = "blobs", .value = .{ .array = blob_values.items } });
    try entries.append(allocator, .{ .key = "ops", .value = .{ .array = op_values.items } });
    try entries.append(allocator, .{ .key = "prevData", .value = if (commit.prev_data) |prev_data| .{ .cid = prev_data } else .null });
    try entries.append(allocator, .{ .key = "repo", .value = .{ .text = commit.repo } });
    try entries.append(allocator, .{ .key = "rev", .value = .{ .text = commit.rev } });
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(commit.seq) } });
    if (commit.since) |s| {
        try entries.append(allocator, .{ .key = "since", .value = .{ .text = s } });
    }
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = commit.time } });
    if (commit.too_big) {
        try entries.append(allocator, .{ .key = "tooBig", .value = .{ .boolean = true } });
    }

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeSyncPayload(allocator: Allocator, writer: anytype, sync_event: SyncEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
    defer entries.deinit(allocator);

    try entries.append(allocator, .{ .key = "blocks", .value = .{ .bytes = sync_event.blocks } });
    try entries.append(allocator, .{ .key = "did", .value = .{ .text = sync_event.did } });
    try entries.append(allocator, .{ .key = "rev", .value = .{ .text = sync_event.rev } });
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(sync_event.seq) } });
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = sync_event.time } });

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeIdentityPayload(allocator: Allocator, writer: anytype, identity: IdentityEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
    defer entries.deinit(allocator);

    try entries.append(allocator, .{ .key = "did", .value = .{ .text = identity.did } });
    if (identity.handle) |h| {
        try entries.append(allocator, .{ .key = "handle", .value = .{ .text = h } });
    }
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(identity.seq) } });
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = identity.time } });

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeAccountPayload(allocator: Allocator, writer: anytype, account: AccountEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
    defer entries.deinit(allocator);

    if (!account.active) {
        try entries.append(allocator, .{ .key = "active", .value = .{ .boolean = false } });
    }
    try entries.append(allocator, .{ .key = "did", .value = .{ .text = account.did } });
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(account.seq) } });
    if (account.status) |s| {
        try entries.append(allocator, .{ .key = "status", .value = .{ .text = @tagName(s) } });
    }
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = account.time } });

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeInfoPayload(allocator: Allocator, writer: anytype, info: InfoEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .empty;
    defer entries.deinit(allocator);

    if (info.message) |m| {
        try entries.append(allocator, .{ .key = "message", .value = .{ .text = m } });
    }
    if (info.name) |n| {
        try entries.append(allocator, .{ .key = "name", .value = .{ .text = n } });
    }

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

pub const FirehoseClient = struct {
    io: Io,
    allocator: Allocator,
    options: Options,
    last_seq: ?i64 = null,

    pub fn init(io: Io, allocator: Allocator, options: Options) FirehoseClient {
        return .{
            .io = io,
            .allocator = allocator,
            .options = options,
            .last_seq = if (options.cursor) |c| c else null,
        };
    }

    pub fn deinit(_: *FirehoseClient) void {}

    /// subscribe with a user-provided handler.
    /// handler must implement: fn onEvent(*@TypeOf(handler), Event) void
    /// optional: fn onError(*@TypeOf(handler), anyerror) void
    /// blocks forever — reconnects with exponential backoff on disconnect.
    /// rotates through hosts on each reconnect attempt.
    pub fn subscribe(self: *FirehoseClient, handler: anytype) Io.Cancelable!void {
        var backoff: u64 = 1;
        var host_index: usize = 0;
        const max_backoff: u64 = 60;
        var prev_host_index: usize = 0;

        while (true) {
            const host = self.options.hosts[host_index % self.options.hosts.len];
            const effective_index = host_index % self.options.hosts.len;

            // reset backoff on host switch (fresh host deserves a fresh chance)
            if (host_index > 0 and effective_index != prev_host_index) {
                backoff = 1;
            }

            log.info("connecting to host {d}/{d}: {s}", .{ effective_index + 1, self.options.hosts.len, host });

            self.connectAndRead(host, handler) catch |err| {
                if (comptime @hasDecl(@TypeOf(handler.*), "onError")) {
                    handler.onError(err);
                } else {
                    log.err("firehose error: {s}, reconnecting in {d}s...", .{ @errorName(err), backoff });
                }
            };

            prev_host_index = effective_index;
            host_index += 1;
            try self.io.sleep(Io.Duration.fromSeconds(@intCast(backoff)), .awake);
            backoff = @min(backoff * 2, max_backoff);
        }
    }

    fn connectAndRead(self: *FirehoseClient, host: []const u8, handler: anytype) !void {
        var path_buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&path_buf);

        try w.writeAll("/xrpc/com.atproto.sync.subscribeRepos");
        if (self.last_seq) |cursor| {
            try w.print("?cursor={d}", .{cursor});
        }
        const path = w.buffered();

        log.info("connecting to wss://{s}{s}", .{ host, path });

        var client = try websocket.Client.init(self.io, self.allocator, .{
            .host = host,
            .port = 443,
            .tls = true,
            .max_size = self.options.max_message_size,
        });
        defer client.deinit();

        var host_header_buf: [256]u8 = undefined;
        const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{host}) catch host;

        try client.handshake(path, .{ .headers = host_header });
        configureKeepalive(&client);

        log.info("firehose connected to {s}", .{host});

        var ws_handler = WsHandler(@TypeOf(handler.*)){
            .allocator = self.allocator,
            .handler = handler,
            .client_state = self,
        };
        try client.readLoop(&ws_handler);
    }
};

fn WsHandler(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handler: *H,
        client_state: *FirehoseClient,

        const Self = @This();

        pub fn serverMessage(self: *Self, data: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            const event = decodeFrame(arena.allocator(), data) catch |err| {
                log.debug("frame decode error: {s}", .{@errorName(err)});
                return;
            };

            if (event.seq()) |s| {
                self.client_state.last_seq = s;
            }

            self.handler.onEvent(event);
        }

        pub fn close(_: *Self) void {
            log.info("firehose connection closed", .{});
        }
    };
}

/// enable TCP keepalive so reads don't block forever when a peer
/// disappears without FIN/RST (network partition, crash, power loss).
/// detection time: 10s idle + 5s × 2 probes = 20s.
fn configureKeepalive(client: *websocket.Client) void {
    const fd = client.stream.stream.socket.handle;
    const builtin = @import("builtin");
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(i32, 1))) catch return;
    const tcp: i32 = @intCast(posix.IPPROTO.TCP);
    if (builtin.os.tag == .linux) {
        posix.setsockopt(fd, tcp, posix.TCP.KEEPIDLE, &std.mem.toBytes(@as(i32, 10))) catch return;
    } else if (builtin.os.tag == .macos) {
        posix.setsockopt(fd, tcp, posix.TCP.KEEPALIVE, &std.mem.toBytes(@as(i32, 10))) catch return;
    }
    posix.setsockopt(fd, tcp, posix.TCP.KEEPINTVL, &std.mem.toBytes(@as(i32, 5))) catch return;
    posix.setsockopt(fd, tcp, posix.TCP.KEEPCNT, &std.mem.toBytes(@as(i32, 2))) catch return;
}

// === tests ===

test "decode frame header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // simulate a frame: header {op: 1, t: "#info"} + payload {name: "OutdatedCursor"}
    const header_bytes = [_]u8{
        0xa2, // map(2)
        0x61, 't', 0x65, '#', 'i', 'n', 'f', 'o', // "t": "#info"
        0x62, 'o', 'p', 0x01, // "op": 1
    };
    const payload_bytes = [_]u8{
        0xa1, // map(1)
        0x64, 'n', 'a', 'm', 'e', // "name"
        0x6e, 'O', 'u', 't', 'd', 'a', 't', 'e', 'd', 'C', 'u', 'r', 's', 'o', 'r', // "OutdatedCursor"
    };

    var frame: [header_bytes.len + payload_bytes.len]u8 = undefined;
    @memcpy(frame[0..header_bytes.len], &header_bytes);
    @memcpy(frame[header_bytes.len..], &payload_bytes);

    const event = try decodeFrame(alloc, &frame);
    const info = event.info;
    try std.testing.expectEqualStrings("OutdatedCursor", info.name.?);
}

test "decode identity frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build frame via encoder for cleaner test
    const original = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test",
        .time = "2024-01-15T10:30:00Z",
    } };
    const frame = try encodeFrame(alloc, original);

    const event = try decodeFrame(alloc, frame);
    const identity = event.identity;
    try std.testing.expectEqual(@as(i64, 42), identity.seq);
    try std.testing.expectEqualStrings("did:plc:test", identity.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", identity.time);
}

test "Event.seq works" {
    const info_event = Event{ .info = .{ .name = "test" } };
    try std.testing.expect(info_event.seq() == null);

    const identity_event = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test",
        .time = "2024-01-15T10:30:00Z",
    } };
    try std.testing.expectEqual(@as(i64, 42), identity_event.seq().?);
}

// === encoder tests ===

test "encode → decode info frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .info = .{
        .name = "OutdatedCursor",
        .message = "cursor is behind",
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqualStrings("OutdatedCursor", decoded.info.name.?);
    try std.testing.expectEqualStrings("cursor is behind", decoded.info.message.?);
}

test "encode → decode identity frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test123",
        .time = "2024-01-15T10:30:00Z",
        .handle = "alice.bsky.social",
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const id = decoded.identity;
    try std.testing.expectEqual(@as(i64, 42), id.seq);
    try std.testing.expectEqualStrings("did:plc:test123", id.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", id.time);
    try std.testing.expectEqualStrings("alice.bsky.social", id.handle.?);
}

test "encode → decode account frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .account = .{
        .seq = 100,
        .did = "did:plc:suspended",
        .time = "2024-01-15T10:30:00Z",
        .active = false,
        .status = .suspended,
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const acct = decoded.account;
    try std.testing.expectEqual(@as(i64, 100), acct.seq);
    try std.testing.expectEqualStrings("did:plc:suspended", acct.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", acct.time);
    try std.testing.expectEqual(false, acct.active);
    try std.testing.expectEqual(AccountStatus.suspended, acct.status.?);
}

test "encode → decode commit frame with record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const record: cbor.Value = .{ .map = &.{
        .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "text", .value = .{ .text = "hello firehose" } },
    } };
    const commit_cid = try cbor.Cid.forDagCbor(alloc, "commit");
    const prev_data = try cbor.Cid.forDagCbor(alloc, "prev-data");

    const original = Event{ .commit = .{
        .seq = 999,
        .repo = "did:plc:poster",
        .rev = "3k2abc000000",
        .time = "2024-01-15T10:30:00Z",
        .since = "3k2abd000000",
        .commit = commit_cid,
        .prev_data = prev_data,
        .ops = &.{.{
            .action = .create,
            .collection = "app.bsky.feed.post",
            .rkey = "3k2abc",
            .record = record,
        }},
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const commit = decoded.commit;
    try std.testing.expectEqual(@as(i64, 999), commit.seq);
    try std.testing.expectEqualStrings("did:plc:poster", commit.repo);
    try std.testing.expectEqualStrings("3k2abc000000", commit.rev);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", commit.time);
    try std.testing.expectEqualStrings("3k2abd000000", commit.since.?);
    try std.testing.expectEqualSlices(u8, commit_cid.raw, commit.commit.?.raw);
    try std.testing.expect(commit.blocks.len > 0);
    try std.testing.expectEqualSlices(u8, prev_data.raw, commit.prev_data.?.raw);
    try std.testing.expectEqual(@as(usize, 0), commit.blobs.len);
    try std.testing.expectEqual(@as(usize, 1), commit.ops.len);

    const op = commit.ops[0];
    try std.testing.expectEqual(CommitAction.create, op.action);
    try std.testing.expectEqualStrings("app.bsky.feed.post/3k2abc", op.path);
    try std.testing.expectEqualStrings("app.bsky.feed.post", op.collection);
    try std.testing.expectEqualStrings("3k2abc", op.rkey);
    try std.testing.expect(op.cid != null);

    // record should be decoded from the CAR blocks
    const rec = op.record.?;
    try std.testing.expectEqualStrings("hello firehose", rec.getString("text").?);
    try std.testing.expectEqualStrings("app.bsky.feed.post", rec.getString("$type").?);

    const mst_ops = try commit.toMstOperations(alloc);
    try std.testing.expectEqual(@as(usize, 1), mst_ops.len);
    try std.testing.expectEqualStrings("app.bsky.feed.post/3k2abc", mst_ops[0].path);
    try std.testing.expectEqualSlices(u8, op.cid.?.raw, mst_ops[0].value.?);
    try std.testing.expect(mst_ops[0].prev == null);
}

test "encode → decode commit with delete (no record)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const commit_cid = try cbor.Cid.forDagCbor(alloc, "commit");
    const prev_data = try cbor.Cid.forDagCbor(alloc, "prev-data");
    const prev_record = try cbor.Cid.forDagCbor(alloc, "prev-record");

    const original = Event{ .commit = .{
        .seq = 500,
        .repo = "did:plc:deleter",
        .rev = "3k2xyz000000",
        .time = "2024-01-15T10:30:00Z",
        .commit = commit_cid,
        .prev_data = prev_data,
        .ops = &.{.{
            .action = .delete,
            .collection = "app.bsky.feed.post",
            .rkey = "abc123",
            .prev = prev_record,
            .record = null,
        }},
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqual(@as(i64, 500), decoded.commit.seq);
    try std.testing.expectEqualStrings("3k2xyz000000", decoded.commit.rev);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", decoded.commit.time);
    try std.testing.expectEqual(@as(usize, 1), decoded.commit.ops.len);
    try std.testing.expectEqual(CommitAction.delete, decoded.commit.ops[0].action);
    try std.testing.expect(decoded.commit.ops[0].cid == null);
    try std.testing.expectEqualSlices(u8, prev_record.raw, decoded.commit.ops[0].prev.?.raw);
    try std.testing.expect(decoded.commit.ops[0].record == null);
}

test "encode → decode commit with null prevData" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const commit_cid = try cbor.Cid.forDagCbor(alloc, "commit");

    const original = Event{ .commit = .{
        .seq = 501,
        .repo = "did:plc:initial",
        .rev = "3k2xyz000001",
        .time = "2024-01-15T10:30:00Z",
        .since = null,
        .commit = commit_cid,
        .blocks = "car bytes",
        .prev_data = null,
        .ops = &.{},
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqual(@as(i64, 501), decoded.commit.seq);
    try std.testing.expectEqualStrings("did:plc:initial", decoded.commit.repo);
    try std.testing.expectEqualStrings("3k2xyz000001", decoded.commit.rev);
    try std.testing.expect(decoded.commit.since == null);
    try std.testing.expect(decoded.commit.prev_data == null);
    try std.testing.expectEqualStrings("car bytes", decoded.commit.blocks);
}

test "commit op paths are validated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const commit_cid = try cbor.Cid.forDagCbor(alloc, "commit");

    const event = Event{ .commit = .{
        .seq = 502,
        .repo = "did:plc:badpath",
        .rev = "3k2xyz000002",
        .time = "2024-01-15T10:30:00Z",
        .commit = commit_cid,
        .blocks = "car bytes",
        .prev_data = null,
        .ops = &.{.{
            .action = .create,
            .path = "app.bsky.feed.post/not/one/rkey",
            .collection = "app.bsky.feed.post",
            .rkey = "unused",
        }},
    } };

    try std.testing.expectError(error.InvalidRepoPath, encodeFrame(alloc, event));
}

test "encode → decode sync frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .sync = .{
        .seq = 777,
        .did = "did:plc:sync",
        .rev = "3k2sync00000",
        .time = "2024-01-15T10:30:00Z",
        .blocks = "car bytes",
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqual(@as(i64, 777), decoded.sync.seq);
    try std.testing.expectEqualStrings("did:plc:sync", decoded.sync.did);
    try std.testing.expectEqualStrings("3k2sync00000", decoded.sync.rev);
    try std.testing.expectEqualStrings("car bytes", decoded.sync.blocks);
}
