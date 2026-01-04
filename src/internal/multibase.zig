//! multibase decoder
//!
//! decodes multibase-encoded strings (prefix + encoded data).
//! currently supports base58btc (z prefix) for DID document public keys.
//!
//! see: https://github.com/multiformats/multibase

const std = @import("std");

/// multibase encoding types
pub const Encoding = enum {
    base58btc, // z prefix

    pub fn fromPrefix(prefix: u8) ?Encoding {
        return switch (prefix) {
            'z' => .base58btc,
            else => null,
        };
    }
};

/// decode a multibase string, returning the raw bytes
/// the first character is the encoding prefix
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return error.EmptyInput;

    const encoding = Encoding.fromPrefix(input[0]) orelse return error.UnsupportedEncoding;

    return switch (encoding) {
        .base58btc => try base58btc.decode(allocator, input[1..]),
    };
}

/// base58btc decoder (bitcoin alphabet)
pub const base58btc = struct {
    /// bitcoin base58 alphabet
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// reverse lookup table
    const decode_table: [256]i8 = blk: {
        var table: [256]i8 = .{-1} ** 256;
        for (alphabet, 0..) |c, i| {
            table[c] = @intCast(i);
        }
        break :blk table;
    };

    /// decode base58btc string to bytes
    pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) return allocator.alloc(u8, 0);

        // count leading zeros (1s in base58)
        var leading_zeros: usize = 0;
        for (input) |c| {
            if (c != '1') break;
            leading_zeros += 1;
        }

        // estimate output size: each base58 char represents ~5.86 bits
        // use a simple overestimate: input.len bytes is more than enough
        const max_output = input.len;
        const result = try allocator.alloc(u8, max_output);
        errdefer allocator.free(result);

        // decode using big integer arithmetic
        // accumulator = accumulator * 58 + digit
        var acc = try std.math.big.int.Managed.init(allocator);
        defer acc.deinit();

        var multiplier = try std.math.big.int.Managed.initSet(allocator, @as(u64, 58));
        defer multiplier.deinit();

        var temp = try std.math.big.int.Managed.init(allocator);
        defer temp.deinit();

        for (input) |c| {
            const digit = decode_table[c];
            if (digit < 0) {
                allocator.free(result);
                return error.InvalidCharacter;
            }

            // acc = acc * 58 + digit
            try temp.mul(&acc, &multiplier);
            try acc.copy(temp.toConst());
            try acc.addScalar(&acc, @as(u8, @intCast(digit)));
        }

        // convert big int to bytes (big-endian for base58)
        const limbs = acc.toConst().limbs;
        const limb_count = acc.len();

        // calculate byte size from limbs
        var byte_count: usize = 0;
        if (limb_count > 0 and !acc.toConst().eqlZero()) {
            const bit_count = acc.toConst().bitCountAbs();
            byte_count = (bit_count + 7) / 8;
        }

        // write bytes in big-endian order
        var output_bytes = try allocator.alloc(u8, leading_zeros + byte_count);
        errdefer allocator.free(output_bytes);

        // leading zeros
        @memset(output_bytes[0..leading_zeros], 0);

        // convert limbs to big-endian bytes
        if (byte_count > 0) {
            const output_slice = output_bytes[leading_zeros..];

            // limbs are in little-endian order, we need big-endian output
            var pos: usize = byte_count;
            for (limbs[0..limb_count]) |limb| {
                const limb_bytes = @sizeOf(@TypeOf(limb));
                var i: usize = 0;
                while (i < limb_bytes and pos > 0) : (i += 1) {
                    pos -= 1;
                    output_slice[pos] = @truncate(limb >> @intCast(i * 8));
                }
            }
        }

        allocator.free(result);
        return output_bytes;
    }
};

// === tests ===

test "base58btc decode" {
    const alloc = std.testing.allocator;

    // "abc" in base58btc
    // "abc" = 0x616263 = 6382179
    // expected base58btc: "ZiCa" (verify with external tool)
    {
        const decoded = try base58btc.decode(alloc, "ZiCa");
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, "abc", decoded);
    }
}

test "base58btc decode with leading zeros" {
    const alloc = std.testing.allocator;

    // leading 1s map to leading zero bytes
    {
        const decoded = try base58btc.decode(alloc, "111");
        defer alloc.free(decoded);
        try std.testing.expectEqual(@as(usize, 3), decoded.len);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, decoded);
    }
}

test "multibase decode base58btc" {
    const alloc = std.testing.allocator;

    // z prefix = base58btc
    {
        const decoded = try decode(alloc, "zZiCa");
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, "abc", decoded);
    }
}

test "base58btc decode real multibase key - secp256k1" {
    const alloc = std.testing.allocator;
    const multicodec = @import("multicodec.zig");

    // from a real DID document: zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF
    // this is a compressed secp256k1 public key with multicodec prefix
    const key = "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF";
    const decoded = try decode(alloc, key);
    defer alloc.free(decoded);

    // should decode to 35 bytes: 2-byte multicodec prefix (0xe7 0x01 varint) + 33-byte compressed key
    try std.testing.expectEqual(@as(usize, 35), decoded.len);

    // first two bytes should be secp256k1-pub multicodec prefix (0xe7 0x01 varint for 231)
    try std.testing.expectEqual(@as(u8, 0xe7), decoded[0]);
    try std.testing.expectEqual(@as(u8, 0x01), decoded[1]);

    // parse with multicodec
    const parsed = try multicodec.parsePublicKey(decoded);
    try std.testing.expectEqual(multicodec.KeyType.secp256k1, parsed.key_type);
    try std.testing.expectEqual(@as(usize, 33), parsed.raw.len);

    // compressed point prefix should be 0x02 or 0x03
    try std.testing.expect(parsed.raw[0] == 0x02 or parsed.raw[0] == 0x03);
}
