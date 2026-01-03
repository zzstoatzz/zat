//! AT-URI Parser
//!
//! at-uris identify records in the atproto network.
//! format: at://<did>/<collection>/<rkey>
//!
//! examples:
//! - at://did:plc:xyz/app.bsky.feed.post/abc123
//! - at://did:web:example.com/app.bsky.actor.profile/self

const std = @import("std");

pub const AtUri = struct {
    /// the full uri string (borrowed, not owned)
    raw: []const u8,

    /// offset where did ends (after "at://")
    did_end: usize,

    /// offset where collection ends
    collection_end: usize,

    const prefix = "at://";

    /// parse an at-uri. returns null if invalid.
    pub fn parse(s: []const u8) ?AtUri {
        if (!std.mem.startsWith(u8, s, prefix)) return null;

        const after_prefix = s[prefix.len..];

        // find first slash (end of did)
        const did_end_rel = std.mem.indexOfScalar(u8, after_prefix, '/') orelse return null;
        if (did_end_rel == 0) return null; // empty did

        const after_did = after_prefix[did_end_rel + 1 ..];

        // find second slash (end of collection)
        const collection_end_rel = std.mem.indexOfScalar(u8, after_did, '/') orelse return null;
        if (collection_end_rel == 0) return null; // empty collection

        // check rkey isn't empty
        const rkey_start = prefix.len + did_end_rel + 1 + collection_end_rel + 1;
        if (rkey_start >= s.len) return null;

        return .{
            .raw = s,
            .did_end = prefix.len + did_end_rel,
            .collection_end = prefix.len + did_end_rel + 1 + collection_end_rel,
        };
    }

    /// the did portion (e.g., "did:plc:xyz")
    pub fn did(self: AtUri) []const u8 {
        return self.raw[prefix.len..self.did_end];
    }

    /// the collection portion (e.g., "app.bsky.feed.post")
    pub fn collection(self: AtUri) []const u8 {
        return self.raw[self.did_end + 1 .. self.collection_end];
    }

    /// the rkey portion (e.g., "abc123")
    pub fn rkey(self: AtUri) []const u8 {
        return self.raw[self.collection_end + 1 ..];
    }

    /// format a new at-uri into the provided buffer.
    /// returns the slice of the buffer used, or null if buffer too small.
    pub fn format(
        buf: []u8,
        did_str: []const u8,
        collection_str: []const u8,
        rkey_str: []const u8,
    ) ?[]const u8 {
        const total_len = prefix.len + did_str.len + 1 + collection_str.len + 1 + rkey_str.len;
        if (buf.len < total_len) return null;

        var pos: usize = 0;

        @memcpy(buf[pos..][0..prefix.len], prefix);
        pos += prefix.len;

        @memcpy(buf[pos..][0..did_str.len], did_str);
        pos += did_str.len;

        buf[pos] = '/';
        pos += 1;

        @memcpy(buf[pos..][0..collection_str.len], collection_str);
        pos += collection_str.len;

        buf[pos] = '/';
        pos += 1;

        @memcpy(buf[pos..][0..rkey_str.len], rkey_str);
        pos += rkey_str.len;

        return buf[0..pos];
    }
};

test "parse valid at-uri" {
    const uri = AtUri.parse("at://did:plc:xyz/app.bsky.feed.post/abc123") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:plc:xyz", uri.did());
    try std.testing.expectEqualStrings("app.bsky.feed.post", uri.collection());
    try std.testing.expectEqualStrings("abc123", uri.rkey());
}

test "parse did:web uri" {
    const uri = AtUri.parse("at://did:web:example.com/app.bsky.actor.profile/self") orelse return error.InvalidUri;
    try std.testing.expectEqualStrings("did:web:example.com", uri.did());
    try std.testing.expectEqualStrings("app.bsky.actor.profile", uri.collection());
    try std.testing.expectEqualStrings("self", uri.rkey());
}

test "reject invalid uris" {
    // missing prefix
    try std.testing.expect(AtUri.parse("did:plc:xyz/app.bsky.feed.post/abc") == null);

    // wrong prefix
    try std.testing.expect(AtUri.parse("http://did:plc:xyz/app.bsky.feed.post/abc") == null);

    // missing collection
    try std.testing.expect(AtUri.parse("at://did:plc:xyz") == null);

    // missing rkey
    try std.testing.expect(AtUri.parse("at://did:plc:xyz/app.bsky.feed.post") == null);

    // empty did
    try std.testing.expect(AtUri.parse("at:///app.bsky.feed.post/abc") == null);
}

test "format at-uri" {
    var buf: [256]u8 = undefined;
    const result = AtUri.format(&buf, "did:plc:xyz", "app.bsky.feed.post", "abc123") orelse return error.BufferTooSmall;
    try std.testing.expectEqualStrings("at://did:plc:xyz/app.bsky.feed.post/abc123", result);
}
