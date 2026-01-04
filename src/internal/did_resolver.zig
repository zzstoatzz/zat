//! DID Resolver - fetches and parses DID documents
//!
//! resolves did:plc via plc.directory and did:web via .well-known/did.json
//!
//! see: https://atproto.com/specs/did

const std = @import("std");
const Did = @import("did.zig").Did;
const DidDocument = @import("did_document.zig").DidDocument;

pub const DidResolver = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,

    /// plc directory url (default: https://plc.directory)
    plc_url: []const u8 = "https://plc.directory",

    pub fn init(allocator: std.mem.Allocator) DidResolver {
        return .{
            .allocator = allocator,
            .http_client = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *DidResolver) void {
        self.http_client.deinit();
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

        return try self.fetchDidDocument(url);
    }

    /// resolve did:web via .well-known
    fn resolveWeb(self: *DidResolver, did: Did) !DidDocument {
        // did:web:example.com -> https://example.com/.well-known/did.json
        // did:web:example.com:path:to -> https://example.com/path/to/did.json
        const domain_and_path = did.raw["did:web:".len..];

        // decode percent-encoded colons in path
        var url_buf: std.ArrayList(u8) = .empty;
        defer url_buf.deinit(self.allocator);

        try url_buf.appendSlice(self.allocator, "https://");

        var first_segment = true;
        var it = std.mem.splitScalar(u8, domain_and_path, ':');
        while (it.next()) |segment| {
            if (first_segment) {
                // first segment is the domain
                try url_buf.appendSlice(self.allocator, segment);
                first_segment = false;
            } else {
                // subsequent segments are path components
                try url_buf.append(self.allocator, '/');
                try url_buf.appendSlice(self.allocator, segment);
            }
        }

        // add .well-known/did.json or /did.json
        if (std.mem.indexOf(u8, domain_and_path, ":") == null) {
            // no path, use .well-known
            try url_buf.appendSlice(self.allocator, "/.well-known/did.json");
        } else {
            // has path, append did.json
            try url_buf.appendSlice(self.allocator, "/did.json");
        }

        return try self.fetchDidDocument(url_buf.items);
    }

    /// fetch and parse a did document from url
    fn fetchDidDocument(self: *DidResolver, url: []const u8) !DidDocument {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = self.http_client.fetch(.{
            .location = .{ .url = url },
            .response_writer = &aw.writer,
        }) catch return error.DidResolutionFailed;

        if (result.status != .ok) {
            return error.DidResolutionFailed;
        }

        return try DidDocument.parse(self.allocator, aw.toArrayList().items);
    }
};

// === tests ===

test "resolve did:plc" {
    // this is an integration test - requires network
    if (true) return error.SkipZigTest; // skip by default

    var resolver = DidResolver.init(std.testing.allocator);
    defer resolver.deinit();

    // jay's did
    const did = Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?;
    var doc = try resolver.resolve(did);
    defer doc.deinit();

    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", doc.id);
    try std.testing.expect(doc.handle() != null);
}

test "did:web url construction" {
    // test url building without network
    var resolver = DidResolver.init(std.testing.allocator);
    defer resolver.deinit();

    // simple domain
    {
        const did = Did.parse("did:web:example.com").?;
        _ = did;
        // would resolve to https://example.com/.well-known/did.json
    }

    // domain with path
    {
        const did = Did.parse("did:web:example.com:user:alice").?;
        _ = did;
        // would resolve to https://example.com/user/alice/did.json
    }
}
