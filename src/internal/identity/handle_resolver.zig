//! Handle Resolver - resolve handles to DIDs
//!
//! resolves AT Protocol handles via HTTP:
//! https://{handle}/.well-known/atproto-did
//!
//! DNS TXT resolution uses DNS-over-HTTPS because Zig stdlib does not expose
//! direct TXT lookup.
//!
//! see: https://atproto.com/specs/handle

const std = @import("std");
const Handle = @import("../syntax/handle.zig").Handle;
const Did = @import("../syntax/did.zig").Did;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;
const network_safety = @import("network_safety.zig");

const max_handle_response_size = 8 * 1024;
const max_dns_txt_response_size = 1 * 1024 * 1024;

pub const HandleResolver = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,
    doh_endpoint: []const u8,

    pub fn init(io: std.Io, allocator: std.mem.Allocator) HandleResolver {
        return .{
            .allocator = allocator,
            .transport = HttpTransport.init(io, allocator),
            .doh_endpoint = "https://cloudflare-dns.com/dns-query",
        };
    }

    pub fn deinit(self: *HandleResolver) void {
        self.transport.deinit();
    }

    /// resolve a handle to a DID via HTTP well-known
    pub fn resolve(self: *HandleResolver, handle: Handle) ![]const u8 {
        if (self.resolveHttp(handle)) |did| {
            return did;
        } else |err| switch (err) {
            error.UnsafeIdentityHost => return err,
            else => return try self.resolveDns(handle),
        }
    }

    /// resolve via HTTP at https://{handle}/.well-known/atproto-did
    fn resolveHttp(self: *HandleResolver, handle: Handle) ![]const u8 {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "https://{s}/.well-known/atproto-did",
            .{handle.str()},
        );
        defer self.allocator.free(url);

        var checked_url = network_safety.resolveIdentityUrl(
            self.allocator,
            &self.transport,
            self.doh_endpoint,
            url,
        ) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.UnsafeIdentityHost => |e| return e,
            else => return error.HttpResolutionFailed,
        };
        defer checked_url.deinit(self.allocator);

        const result = self.transport.fetch(.{
            .url = url,
            .max_response_size = max_handle_response_size,
            .redirect_behavior = .not_allowed,
            .resolved_connection = checked_url.resolvedConnection(),
        }) catch return error.HttpResolutionFailed;
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.HttpResolutionFailed;
        }

        // response body should be the DID as plain text
        const did_str = std.mem.trim(u8, result.body, &std.ascii.whitespace);

        // validate it's a proper DID
        if (Did.parse(did_str) == null) {
            return error.InvalidDidInResponse;
        }

        return try self.allocator.dupe(u8, did_str);
    }

    /// resolve via DoH default: https://cloudflare-dns.com/dns-query
    pub fn resolveDns(self: *HandleResolver, handle: Handle) ![]const u8 {
        const dns_name = try std.fmt.allocPrint(
            self.allocator,
            "_atproto.{s}",
            .{handle.str()},
        );
        defer self.allocator.free(dns_name);

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}?name={s}&type=TXT",
            .{ self.doh_endpoint, dns_name },
        );
        defer self.allocator.free(url);

        const result = self.transport.fetch(.{
            .url = url,
            .accept = "application/dns-json",
            .max_response_size = max_dns_txt_response_size,
            .redirect_behavior = .not_allowed,
        }) catch return error.DnsResolutionFailed;
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.DnsResolutionFailed;
        }

        return self.didFromDohBody(result.body);
    }

    /// parse a Cloudflare DoH JSON body and extract exactly one valid `did=` TXT value.
    fn didFromDohBody(self: *HandleResolver, body: []const u8) ![]const u8 {
        // Cloudflare appends an unknown `Comment` field for DNSSEC zones, so the
        // parse must tolerate fields `DnsResponse` doesn't declare.
        const parsed = std.json.parseFromSlice(
            DnsResponse,
            self.allocator,
            body,
            .{ .ignore_unknown_fields = true },
        ) catch return error.InvalidDnsResponse;
        defer parsed.deinit();

        const dns_response = parsed.value;
        if (dns_response.Answer == null or dns_response.Answer.?.len == 0) {
            return error.NoDnsRecordsFound;
        }

        var found: ?[]const u8 = null;
        var found_count: usize = 0;
        for (dns_response.Answer.?) |answer| {
            const data = answer.data orelse continue;
            const did_str = extractDidFromTxt(data) orelse continue;
            found_count += 1;
            found = did_str;
        }

        if (found_count != 1) {
            return error.NoValidDidFound;
        }

        const did_str = found.?;
        if (Did.parse(did_str) == null) {
            return error.NoValidDidFound;
        }

        return try self.allocator.dupe(u8, did_str);
    }
};

fn extractDidFromTxt(txt_data: []const u8) ?[]const u8 {
    var data = txt_data;
    if (data.len >= 2 and data[0] == '"' and data[data.len - 1] == '"') {
        data = data[1 .. data.len - 1];
    }

    const prefix = "did=";
    if (std.mem.startsWith(u8, data, prefix)) {
        return data[prefix.len..];
    }

    return null;
}

const DnsResponse = struct {
    Status: i32,
    TC: bool,
    RD: bool,
    RA: bool,
    AD: bool,
    CD: bool,
    Question: ?[]Question = null,
    Answer: ?[]Answer = null,
};

const Question = struct {
    name: []const u8,
    type: i32,
};

const Answer = struct {
    name: []const u8,
    type: i32,
    TTL: i32,
    data: ?[]const u8 = null,
};

// === integration tests ===
// these actually hit the network - run with: zig test src/internal/handle_resolver.zig

test "didFromDohBody tolerates Cloudflare DNSSEC Comment field" {
    var resolver = HandleResolver.init(std.Options.debug_io, std.testing.allocator);
    defer resolver.deinit();

    // real Cloudflare DoH body for `_atproto.dholms.at`: includes a `Comment`
    // field that `DnsResponse` doesn't declare (regression for strict parse).
    const body =
        \\{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
        \\ "Question":[{"name":"_atproto.dholms.at","type":16}],
        \\ "Answer":[{"name":"_atproto.dholms.at","type":16,"TTL":3600,
        \\            "data":"\"did=did:plc:yk4dd2qkboz2yv6tpubpc6co\""}],
        \\ "Comment":["EDE(10): RRSIGs Missing for DNSKEY at., id = 1253"]}
    ;

    const did = try resolver.didFromDohBody(body);
    defer std.testing.allocator.free(did);

    try std.testing.expectEqualStrings("did:plc:yk4dd2qkboz2yv6tpubpc6co", did);
}

test "didFromDohBody requires exactly one did TXT record" {
    var resolver = HandleResolver.init(std.Options.debug_io, std.testing.allocator);
    defer resolver.deinit();

    const single =
        \\{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
        \\ "Answer":[
        \\   {"name":"_atproto.example.com","type":16,"TTL":300,"data":"\"foo=bar\""},
        \\   {"name":"_atproto.example.com","type":16,"TTL":300,"data":"\"did=did:plc:abc123\""}
        \\ ]}
    ;
    const did = try resolver.didFromDohBody(single);
    defer std.testing.allocator.free(did);
    try std.testing.expectEqualStrings("did:plc:abc123", did);

    const multiple =
        \\{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
        \\ "Answer":[
        \\   {"name":"_atproto.example.com","type":16,"TTL":300,"data":"\"did=did:plc:abc123\""},
        \\   {"name":"_atproto.example.com","type":16,"TTL":300,"data":"\"did=did:plc:def456\""}
        \\ ]}
    ;
    try std.testing.expectError(error.NoValidDidFound, resolver.didFromDohBody(multiple));

    const invalid =
        \\{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
        \\ "Answer":[{"name":"_atproto.example.com","type":16,"TTL":300,"data":"\"did=not-a-did\""}]}
    ;
    try std.testing.expectError(error.NoValidDidFound, resolver.didFromDohBody(invalid));
}

test "resolve handle (http) - integration" {
    // use arena for http client internals that may leak
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(std.Options.debug_io, arena.allocator());
    defer resolver.deinit();

    // resolve a known handle that has .well-known/atproto-did
    const handle = Handle.parse("jay.bsky.social") orelse return error.InvalidHandle;
    const did = resolver.resolveHttp(handle) catch {
        return; // network error, expected in CI
    };

    // should be a valid did:plc
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:plc:"));
}

test "resolve handle (dns over http) - integration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(std.Options.debug_io, arena.allocator());
    defer resolver.deinit();

    const handle = Handle.parse("seiso.moe") orelse return error.InvalidHandle;
    const did = resolver.resolveDns(handle) catch {
        return; // network error, expected in CI
    };

    // should be a valid DID
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:"));
}

test "resolve handle - integration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(std.Options.debug_io, arena.allocator());
    defer resolver.deinit();

    const handle = Handle.parse("jay.bsky.social") orelse return error.InvalidHandle;
    const did = resolver.resolve(handle) catch {
        return; // network error, expected in CI
    };

    // should be a valid DID
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:"));
}
