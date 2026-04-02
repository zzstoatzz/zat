const std = @import("std");
const zat = @import("zat");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const allocator = da.allocator();

    std.debug.print("smoke test starting\n", .{});

    var handler = Handler{};
    var client = zat.JetstreamClient.init(std.Options.debug_io, allocator, .{
        .hosts = &.{"jetstream2.us-east.bsky.network"},
        .wanted_collections = &.{"app.bsky.feed.post"},
    });
    try client.subscribe(&handler);
}

const Handler = struct {
    count: u64 = 0,
    connects: u64 = 0,

    pub fn onEvent(self: *Handler, event: zat.JetstreamEvent) void {
        self.count += 1;
        if (self.count % 1000 == 0) {
            std.debug.print("  [{d}] time_us={d}\n", .{ self.count, event.timeUs() });
        }
    }

    pub fn onConnect(self: *Handler, host: []const u8) void {
        self.connects += 1;
        std.debug.print("CONNECT #{d} to {s} (total events so far: {d})\n", .{ self.connects, host, self.count });
    }

    pub fn onError(_: *Handler, err: anyerror) void {
        std.debug.print("ERROR: {s}\n", .{@errorName(err)});
    }
};
