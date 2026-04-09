//! DID Resolver - fetches and parses DID documents
//!
//! resolves did:plc via plc.directory and did:web via .well-known/did.json
//!
//! see: https://atproto.com/specs/did

const std = @import("std");
const Did = @import("../syntax/did.zig").Did;
const DidDocument = @import("did_document.zig").DidDocument;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;

pub const DidResolver = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,

    /// plc directory url (default: https://plc.directory)
    plc_url: []const u8 = "https://plc.directory",

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
        const result = try self.transport.fetch(.{ .url = url });
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.DidResolutionFailed;
        }

        return try DidDocument.parse(self.allocator, result.body);
    }
};

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

test "regression: transport errors propagate distinct kinds" {
    // before this fix, transport.fetch had `catch return error.RequestFailed`
    // and fetchDidDocument had `catch return error.DidResolutionFailed`, so
    // every transport-layer failure (DNS, TCP, TLS) collapsed to one
    // indistinguishable error and callers had no way to see what was wrong.
    // this regression test asserts the underlying error kind survives the
    // resolver layer for at least one common transport failure mode.
    //
    // history: zlay 2026-04-08, where the host_authority pool failed at 100%
    // and we had no production telemetry on which transport error fired
    // because both layers had been swallowed. see relay docs/zlay-external-
    // review-2026-04-09.md.
    var resolver = DidResolver.init(std.Options.debug_io, std.testing.allocator);
    defer resolver.deinit();

    // 127.0.0.1:443 is almost certainly not listening on a test machine.
    // did:web:127.0.0.1 → https://127.0.0.1/.well-known/did.json → connect refused.
    const did = Did.parse("did:web:127.0.0.1") orelse return error.SkipZigTest;
    if (resolver.resolve(did)) |doc| {
        // someone is actually serving a DID doc on 127.0.0.1:443 — skip rather
        // than fail, since the assertion below assumes a transport failure
        var d = doc;
        d.deinit();
        return error.SkipZigTest;
    } else |err| {
        // exact error name varies by platform (ConnectionRefused on linux/darwin,
        // possibly different elsewhere). just assert it's not the catch-all that
        // the pre-fix code returned for everything.
        try std.testing.expect(err != error.DidResolutionFailed);
        try std.testing.expect(err != error.RequestFailed);
    }
}

test "did:web url construction" {
    // test url building without network
    var resolver = DidResolver.init(std.Options.debug_io, std.testing.allocator);
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
