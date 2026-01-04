//! Handle Resolver - resolve handles to DIDs
//!
//! resolves AT Protocol handles via HTTP:
//! https://{handle}/.well-known/atproto-did
//!
//! note: DNS TXT resolution (_atproto.{handle}) not yet implemented
//! as zig std doesn't provide TXT record lookup.
//!
//! see: https://atproto.com/specs/handle

const std = @import("std");
const Handle = @import("handle.zig").Handle;
const Did = @import("did.zig").Did;

pub const HandleResolver = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator) HandleResolver {
        return .{
            .allocator = allocator,
            .http_client = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *HandleResolver) void {
        self.http_client.deinit();
    }

    /// resolve a handle to a DID via HTTP well-known
    pub fn resolve(self: *HandleResolver, handle: Handle) ![]const u8 {
        return try self.resolveHttp(handle);
    }

    /// resolve via HTTP at https://{handle}/.well-known/atproto-did
    fn resolveHttp(self: *HandleResolver, handle: Handle) ![]const u8 {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "https://{s}/.well-known/atproto-did",
            .{handle.str()},
        );
        defer self.allocator.free(url);

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = self.http_client.fetch(.{
            .location = .{ .url = url },
            .response_writer = &aw.writer,
        }) catch return error.HttpResolutionFailed;

        if (result.status != .ok) {
            return error.HttpResolutionFailed;
        }

        // response body should be the DID as plain text
        const did_str = std.mem.trim(u8, aw.toArrayList().items, &std.ascii.whitespace);

        // validate it's a proper DID
        if (Did.parse(did_str) == null) {
            return error.InvalidDidInResponse;
        }

        return try self.allocator.dupe(u8, did_str);
    }
};

// === integration tests ===
// these actually hit the network - run with: zig test src/internal/handle_resolver.zig

test "resolve handle - integration" {
    // use arena for http client internals that may leak
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(arena.allocator());
    defer resolver.deinit();

    // resolve a known handle that has .well-known/atproto-did
    const handle = Handle.parse("jay.bsky.social") orelse return error.InvalidHandle;
    const did = resolver.resolve(handle) catch |err| {
        // network errors are ok in CI without network access
        std.debug.print("network error (expected in some CI): {}\n", .{err});
        return;
    };

    // should be a valid did:plc
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:plc:"));
}
