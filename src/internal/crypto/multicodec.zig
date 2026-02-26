//! multicodec key parsing
//!
//! parses multicodec-prefixed public keys from DID documents.
//! extracts key type and raw key bytes.
//!
//! see: https://github.com/multiformats/multicodec

const std = @import("std");

/// supported key types for AT Protocol
pub const KeyType = enum {
    secp256k1, // ES256K - used by most AT Protocol accounts
    p256, // ES256 - also supported
};

/// parsed public key with type and raw bytes
pub const PublicKey = struct {
    key_type: KeyType,
    /// raw compressed public key (33 bytes for secp256k1/p256)
    raw: []const u8,
};

/// multicodec prefixes (unsigned varint encoding)
/// secp256k1-pub: 0xe7 = 231, varint encoded as 0xe7 0x01 (2 bytes)
/// p256-pub: 0x1200 = 4608, varint encoded as 0x80 0x24 (2 bytes)
/// parse a multicodec-prefixed public key
/// returns the key type and a slice pointing to the raw key bytes
pub fn parsePublicKey(data: []const u8) !PublicKey {
    if (data.len < 2) return error.TooShort;

    // check for secp256k1-pub (varint 0xe7 = 231 encoded as 0xe7 0x01)
    if (data.len >= 2 and data[0] == 0xe7 and data[1] == 0x01) {
        const raw = data[2..];
        if (raw.len != 33) return error.InvalidKeyLength;
        return .{
            .key_type = .secp256k1,
            .raw = raw,
        };
    }

    // check for p256-pub (varint 0x1200 = 4608 encoded as 0x80 0x24)
    if (data.len >= 2 and data[0] == 0x80 and data[1] == 0x24) {
        const raw = data[2..];
        if (raw.len != 33) return error.InvalidKeyLength;
        return .{
            .key_type = .p256,
            .raw = raw,
        };
    }

    return error.UnsupportedKeyType;
}

/// encode a raw public key with multicodec prefix
pub fn encodePublicKey(allocator: std.mem.Allocator, key_type: KeyType, raw: []const u8) ![]u8 {
    if (raw.len != 33) return error.InvalidKeyLength;

    const result = try allocator.alloc(u8, 2 + raw.len);
    switch (key_type) {
        .secp256k1 => {
            result[0] = 0xe7;
            result[1] = 0x01;
        },
        .p256 => {
            result[0] = 0x80;
            result[1] = 0x24;
        },
    }
    @memcpy(result[2..], raw);
    return result;
}

/// format a raw public key as a did:key string
pub fn formatDidKey(allocator: std.mem.Allocator, key_type: KeyType, raw: []const u8) ![]u8 {
    const multibase = @import("multibase.zig");

    const mc_bytes = try encodePublicKey(allocator, key_type, raw);
    defer allocator.free(mc_bytes);

    const multibase_str = try multibase.encode(allocator, .base58btc, mc_bytes);
    defer allocator.free(multibase_str);

    // "did:key:" + multibase string (which already has 'z' prefix)
    const prefix = "did:key:";
    const result = try allocator.alloc(u8, prefix.len + multibase_str.len);
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..], multibase_str);
    return result;
}

// === tests ===

test "parse secp256k1 key" {
    // 0xe7 0x01 prefix (varint) + 33-byte compressed key
    var data: [35]u8 = undefined;
    data[0] = 0xe7;
    data[1] = 0x01;
    data[2] = 0x02; // compressed point prefix
    @memset(data[3..], 0xaa);

    const key = try parsePublicKey(&data);
    try std.testing.expectEqual(KeyType.secp256k1, key.key_type);
    try std.testing.expectEqual(@as(usize, 33), key.raw.len);
}

test "parse p256 key" {
    // 0x80 0x24 prefix + 33-byte compressed key
    var data: [35]u8 = undefined;
    data[0] = 0x80;
    data[1] = 0x24;
    data[2] = 0x03; // compressed point prefix
    @memset(data[3..], 0xbb);

    const key = try parsePublicKey(&data);
    try std.testing.expectEqual(KeyType.p256, key.key_type);
    try std.testing.expectEqual(@as(usize, 33), key.raw.len);
}

test "reject unsupported key type" {
    const data = [_]u8{ 0xff, 0x02, 0x00 };
    try std.testing.expectError(error.UnsupportedKeyType, parsePublicKey(&data));
}

test "reject too short" {
    const data = [_]u8{0xe7};
    try std.testing.expectError(error.TooShort, parsePublicKey(&data));
}

test "encode-decode round-trip secp256k1" {
    const alloc = std.testing.allocator;
    var raw: [33]u8 = undefined;
    raw[0] = 0x02;
    @memset(raw[1..], 0xaa);

    const encoded = try encodePublicKey(alloc, .secp256k1, &raw);
    defer alloc.free(encoded);

    const parsed = try parsePublicKey(encoded);
    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "did:key round-trip secp256k1" {
    const alloc = std.testing.allocator;
    const multibase = @import("multibase.zig");

    var raw: [33]u8 = undefined;
    raw[0] = 0x02;
    @memset(raw[1..], 0xcc);

    const did_key_str = try formatDidKey(alloc, .secp256k1, &raw);
    defer alloc.free(did_key_str);

    // should start with "did:key:z"
    try std.testing.expect(std.mem.startsWith(u8, did_key_str, "did:key:z"));

    // parse back: strip "did:key:" prefix, decode multibase, parse multicodec
    const multibase_str = did_key_str["did:key:".len..];
    const mc_bytes = try multibase.decode(alloc, multibase_str);
    defer alloc.free(mc_bytes);

    const parsed = try parsePublicKey(mc_bytes);
    try std.testing.expectEqual(KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}

test "did:key round-trip p256" {
    const alloc = std.testing.allocator;
    const multibase = @import("multibase.zig");

    var raw: [33]u8 = undefined;
    raw[0] = 0x03;
    @memset(raw[1..], 0xdd);

    const did_key_str = try formatDidKey(alloc, .p256, &raw);
    defer alloc.free(did_key_str);

    const multibase_str = did_key_str["did:key:".len..];
    const mc_bytes = try multibase.decode(alloc, multibase_str);
    defer alloc.free(mc_bytes);

    const parsed = try parsePublicKey(mc_bytes);
    try std.testing.expectEqual(KeyType.p256, parsed.key_type);
    try std.testing.expectEqualSlices(u8, &raw, parsed.raw);
}
