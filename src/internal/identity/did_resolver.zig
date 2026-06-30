//! DID Resolver - fetches and parses DID documents
//!
//! resolves did:plc via plc.directory and did:web via .well-known/did.json
//!
//! see: https://atproto.com/specs/did

const std = @import("std");
const Did = @import("../syntax/did.zig").Did;
const DidDocument = @import("did_document.zig").DidDocument;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;
const network_safety = @import("network_safety.zig");

const max_did_document_size = 1 * 1024 * 1024;

pub const DidResolver = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,

    /// plc directory url (default: https://plc.directory)
    plc_url: []const u8 = "https://plc.directory",
    /// DoH endpoint for did:web host safety preflight.
    doh_endpoint: []const u8 = "https://cloudflare-dns.com/dns-query",

    pub fn init(io: std.Io, allocator: std.mem.Allocator) DidResolver {
        return initWithOptions(io, allocator, .{});
    }

    pub const Options = struct {
        keep_alive: bool = true,
    };

    pub fn initWithOptions(io: std.Io, allocator: std.mem.Allocator, options: Options) DidResolver {
        var transport = HttpTransport.init(io, allocator);
        transport.keep_alive = options.keep_alive;
        return .{
            .allocator = allocator,
            .transport = transport,
        };
    }

    pub fn deinit(self: *DidResolver) void {
        self.transport.deinit();
    }

    /// resolve a did to its document
    pub fn resolve(self: *DidResolver, did: Did) !DidDocument {
        return switch (did.method()) {
            .plc => try self.resolvePlc(did),
            .web => try self.resolveWeb(did),
            .other => error.UnsupportedDidMethod,
        };
    }

    /// resolve did:plc via plc.directory
    fn resolvePlc(self: *DidResolver, did: Did) !DidDocument {
        // build url: {plc_url}/{did}
        const url = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.plc_url, did.raw });
        defer self.allocator.free(url);

        return try self.fetchDidDocument(url, null);
    }

    /// resolve did:web via .well-known
    fn resolveWeb(self: *DidResolver, did: Did) !DidDocument {
        const url = try buildDidWebDocumentUrl(self.allocator, did);
        defer self.allocator.free(url);

        var checked_url = try network_safety.resolveIdentityUrl(
            self.allocator,
            &self.transport,
            self.doh_endpoint,
            url,
        );
        defer checked_url.deinit(self.allocator);
        return try self.fetchDidDocument(url, checked_url.resolvedConnection());
    }

    /// fetch and parse a did document from url
    fn fetchDidDocument(
        self: *DidResolver,
        url: []const u8,
        resolved_connection: ?HttpTransport.ResolvedConnection,
    ) !DidDocument {
        const result = try self.transport.fetch(.{
            .url = url,
            .max_response_size = max_did_document_size,
            .redirect_behavior = .not_allowed,
            .resolved_connection = resolved_connection,
        });
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.DidResolutionFailed;
        }

        return try DidDocument.parse(self.allocator, result.body);
    }
};

fn buildDidWebDocumentUrl(allocator: std.mem.Allocator, did: Did) ![]u8 {
    const identifier = did.identifier();
    if (identifier.len == 0 or std.mem.indexOfScalar(u8, identifier, ':') != null) {
        return error.UnsupportedDidMethod;
    }

    const authority = try percentDecodeAlloc(allocator, identifier);
    defer allocator.free(authority);

    const scheme: []const u8 = if (std.mem.eql(u8, authority, "localhost") or std.mem.startsWith(u8, authority, "localhost:"))
        "http"
    else
        "https";

    return try std.fmt.allocPrint(allocator, "{s}://{s}/.well-known/did.json", .{ scheme, authority });
}

fn percentDecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != '%') {
            try out.append(allocator, input[i]);
            i += 1;
            continue;
        }

        if (i + 2 >= input.len) return error.InvalidPercentEncoding;
        const byte = std.fmt.parseInt(u8, input[i + 1 .. i + 3], 16) catch return error.InvalidPercentEncoding;
        try out.append(allocator, byte);
        i += 3;
    }

    return try out.toOwnedSlice(allocator);
}

// === tests ===

test "resolve did:plc - integration" {
    // use arena for http client internals that may leak
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = DidResolver.init(std.Options.debug_io, arena.allocator());
    defer resolver.deinit();

    const did = Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?;
    var doc = resolver.resolve(did) catch {
        return; // network error, expected in CI
    };
    defer doc.deinit();

    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", doc.id);
    try std.testing.expect(doc.handle() != null);
}

test "resolve did:plc - leak check (no arena)" {
    // repro for memory leak report: use testing.allocator directly
    // (no arena) to see if std.http.Client leaks on deinit
    var resolver = DidResolver.init(std.Options.debug_io, std.testing.allocator);
    defer resolver.deinit();

    const did = Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?;
    var doc = resolver.resolve(did) catch {
        return; // network error, expected in CI
    };
    defer doc.deinit();

    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", doc.id);
}

test "did:web loopback host is rejected before fetch" {
    var resolver = DidResolver.init(std.Options.debug_io, std.testing.allocator);
    defer resolver.deinit();

    const did = Did.parse("did:web:127.0.0.1") orelse return error.SkipZigTest;
    try std.testing.expectError(error.UnsafeIdentityHost, resolver.resolve(did));
}

test "did:web url construction" {
    const simple = try buildDidWebDocumentUrl(std.testing.allocator, Did.parse("did:web:example.com").?);
    defer std.testing.allocator.free(simple);
    try std.testing.expectEqualStrings("https://example.com/.well-known/did.json", simple);

    const with_port = try buildDidWebDocumentUrl(std.testing.allocator, Did.parse("did:web:example.com%3A3000").?);
    defer std.testing.allocator.free(with_port);
    try std.testing.expectEqualStrings("https://example.com:3000/.well-known/did.json", with_port);

    const localhost = try buildDidWebDocumentUrl(std.testing.allocator, Did.parse("did:web:localhost%3A3000").?);
    defer std.testing.allocator.free(localhost);
    try std.testing.expectEqualStrings("http://localhost:3000/.well-known/did.json", localhost);

    try std.testing.expectError(error.UnsupportedDidMethod, buildDidWebDocumentUrl(std.testing.allocator, Did.parse("did:web:example.com:user:alice").?));
    try std.testing.expectError(error.InvalidPercentEncoding, buildDidWebDocumentUrl(std.testing.allocator, Did.parse("did:web:example.com%xx").?));
}
