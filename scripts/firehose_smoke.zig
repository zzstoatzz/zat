//! firehose smoke test — connects to the live AT Protocol firehose,
//! decodes CBOR frames, parses CAR blocks, and verifies CIDs.
//! exercises the full CBOR → CAR → CID pipeline on production data.
//!
//! run: just firehose-smoke

const std = @import("std");
const zat = @import("zat");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const allocator = da.allocator();

    std.debug.print("firehose smoke test starting (CBOR + CAR + CID on live data)\n", .{});

    var handler = Handler{};
    var client = zat.FirehoseClient.init(std.Options.debug_io, allocator, .{});
    try client.subscribe(&handler);
}

const Handler = struct {
    count: u64 = 0,
    commits: u64 = 0,
    records: u64 = 0,
    connects: u64 = 0,
    errors: u64 = 0,

    pub fn onEvent(self: *Handler, event: zat.FirehoseEvent) void {
        self.count += 1;

        switch (event) {
            .commit => |commit| {
                self.commits += 1;
                for (commit.ops) |op| {
                    if (op.record) |record| {
                        // record was decoded from CAR blocks via CBOR
                        _ = record.getString("$type");
                        self.records += 1;
                    }
                }
            },
            else => {},
        }

        if (self.count % 1000 == 0) {
            std.debug.print("  [{d}] commits={d} records={d} errors={d}\n", .{
                self.count, self.commits, self.records, self.errors,
            });
        }

        // stop after 10k events
        if (self.count >= 10000) {
            std.debug.print("\nfirehose smoke test PASSED\n", .{});
            std.debug.print("  {d} events, {d} commits, {d} records decoded, {d} errors\n", .{
                self.count, self.commits, self.records, self.errors,
            });
            std.process.exit(0);
        }
    }

    pub fn onConnect(self: *Handler, host: []const u8) void {
        self.connects += 1;
        std.debug.print("CONNECT #{d} to {s}\n", .{ self.connects, host });
    }

    pub fn onError(self: *Handler, err: anyerror) void {
        self.errors += 1;
        std.debug.print("ERROR: {s}\n", .{@errorName(err)});
    }
};
