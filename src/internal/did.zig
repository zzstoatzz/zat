//! DID - Decentralized Identifier
//!
//! dids are globally unique identifiers in the atproto network.
//! supports did:plc and did:web methods.
//!
//! examples:
//! - did:plc:z72i7hdynmk6r22z27h6tvur
//! - did:web:example.com

const std = @import("std");

pub const Did = struct {
    /// the full did string (borrowed, not owned)
    raw: []const u8,

    /// the method (plc or web)
    method: Method,

    /// offset where method-specific identifier starts
    id_start: usize,

    pub const Method = enum {
        plc,
        web,
    };

    /// parse a did string. returns null if invalid.
    pub fn parse(s: []const u8) ?Did {
        if (!std.mem.startsWith(u8, s, "did:")) return null;

        const after_did = s[4..];

        if (std.mem.startsWith(u8, after_did, "plc:")) {
            const id = after_did[4..];
            if (id.len == 0) return null;
            // plc identifiers should be 24 base32 chars
            if (!isValidPlcId(id)) return null;
            return .{
                .raw = s,
                .method = .plc,
                .id_start = 8,
            };
        }

        if (std.mem.startsWith(u8, after_did, "web:")) {
            const domain = after_did[4..];
            if (domain.len == 0) return null;
            return .{
                .raw = s,
                .method = .web,
                .id_start = 8,
            };
        }

        return null;
    }

    /// the method-specific identifier
    /// for plc: the 24-char base32 id
    /// for web: the domain
    pub fn identifier(self: Did) []const u8 {
        return self.raw[self.id_start..];
    }

    /// check if this is a plc did
    pub fn isPlc(self: Did) bool {
        return self.method == .plc;
    }

    /// check if this is a web did
    pub fn isWeb(self: Did) bool {
        return self.method == .web;
    }

    /// get the full did string
    pub fn str(self: Did) []const u8 {
        return self.raw;
    }

    fn isValidPlcId(id: []const u8) bool {
        // plc ids are base32 encoded (a-z, 2-7)
        for (id) |c| {
            const valid = (c >= 'a' and c <= 'z') or (c >= '2' and c <= '7');
            if (!valid) return false;
        }
        return true;
    }
};

test "parse did:plc" {
    const did = Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur") orelse return error.InvalidDid;
    try std.testing.expect(did.isPlc());
    try std.testing.expect(!did.isWeb());
    try std.testing.expectEqualStrings("z72i7hdynmk6r22z27h6tvur", did.identifier());
}

test "parse did:web" {
    const did = Did.parse("did:web:example.com") orelse return error.InvalidDid;
    try std.testing.expect(did.isWeb());
    try std.testing.expect(!did.isPlc());
    try std.testing.expectEqualStrings("example.com", did.identifier());
}

test "reject invalid dids" {
    // missing prefix
    try std.testing.expect(Did.parse("plc:xyz") == null);

    // unknown method
    try std.testing.expect(Did.parse("did:unknown:xyz") == null);

    // empty identifier
    try std.testing.expect(Did.parse("did:plc:") == null);
    try std.testing.expect(Did.parse("did:web:") == null);

    // invalid plc chars
    try std.testing.expect(Did.parse("did:plc:INVALID") == null);
}
