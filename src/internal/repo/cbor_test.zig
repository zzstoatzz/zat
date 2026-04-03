//! additional DAG-CBOR codec tests ported from atmos (Go implementation).
//!
//! focuses on spec compliance, edge cases, and error paths not covered
//! by the inline tests in cbor.zig.

const std = @import("std");
const cbor = @import("cbor.zig");
const Value = cbor.Value;
const Cid = cbor.Cid;

// === non-minimal encoding rejection ===
//
// DAG-CBOR requires shortest-form encoding. values that fit in a smaller
// representation must not be encoded with a larger one.

test "reject non-minimal unsigned: 0 encoded as 1-byte" {
    // 0x18 0x00 = unsigned(0) with 1-byte additional, but 0 fits in additional field directly
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x18, 0x00 }));
}

test "reject non-minimal unsigned: 23 encoded as 1-byte" {
    // 0x18 0x17 = unsigned(23) with 1-byte additional, but 23 fits in additional field
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x18, 0x17 }));
}

test "reject non-minimal unsigned: 255 encoded as 2-byte" {
    // 0x19 0x00 0xff = unsigned(255) with 2-byte additional, but fits in 1-byte
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x19, 0x00, 0xff }));
}

test "reject non-minimal unsigned: 256 encoded as 4-byte" {
    // 0x1a 0x00 0x00 0x01 0x00 = unsigned(256) with 4-byte additional, but fits in 2-byte
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x1a, 0x00, 0x00, 0x01, 0x00 }));
}

test "reject non-minimal unsigned: 65535 encoded as 4-byte" {
    // 0x1a 0x00 0x00 0xff 0xff = unsigned(65535) with 4-byte, but fits in 2-byte
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x1a, 0x00, 0x00, 0xff, 0xff }));
}

test "reject non-minimal unsigned: 1 encoded as 8-byte" {
    // 0x1b 0x00..0x01 = unsigned(1) with 8-byte additional
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }));
}

test "reject non-minimal negative: -1 encoded as 1-byte" {
    // 0x38 0x00 = negative(-1) with 1-byte additional, but -1 fits in additional field (0x20)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x38, 0x00 }));
}

test "reject non-minimal negative: -24 encoded as 1-byte" {
    // 0x38 0x17 = negative(-24) with 1-byte additional, but fits in additional field (0x37)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x38, 0x17 }));
}

test "reject non-minimal text string length: empty string as 1-byte length" {
    // 0x78 0x00 = text(0) with 1-byte length, but 0 fits in additional field (0x60)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x78, 0x00 }));
}

test "reject non-minimal byte string length" {
    // 0x58 0x00 = bytes(0) with 1-byte length, but 0 fits in additional field (0x40)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x58, 0x00 }));
}

test "reject non-minimal array length" {
    // 0x98 0x00 = array(0) with 1-byte length, but 0 fits in additional field (0x80)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0x98, 0x00 }));
}

test "reject non-minimal map length" {
    // 0xb8 0x00 = map(0) with 1-byte length, but 0 fits in additional field (0xa0)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.NonMinimalEncoding, cbor.decode(arena.allocator(), &.{ 0xb8, 0x00 }));
}

// === trailing bytes rejection ===

test "decodeAll rejects trailing bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // integer 1 followed by extra byte 0x02
    try std.testing.expectError(error.TrailingBytes, cbor.decodeAll(arena.allocator(), &.{ 0x01, 0x02 }));
}

// === tag restriction ===
//
// DAG-CBOR only allows tag 42 (CID links). all other tags must be rejected.

test "reject tag 0 (date/time)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xc0 0x60 = tag(0) wrapping empty text string
    try std.testing.expectError(error.UnsupportedTag, cbor.decode(arena.allocator(), &.{ 0xc0, 0x60 }));
}

test "reject tag 1 (epoch time)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xc1 0x01 = tag(1) wrapping integer 1
    try std.testing.expectError(error.UnsupportedTag, cbor.decode(arena.allocator(), &.{ 0xc1, 0x01 }));
}

test "reject tag 2 (positive bignum)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xc2 0x41 0x01 = tag(2) wrapping byte string [0x01]
    try std.testing.expectError(error.UnsupportedTag, cbor.decode(arena.allocator(), &.{ 0xc2, 0x41, 0x01 }));
}

test "reject tag 3 (negative bignum)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedTag, cbor.decode(arena.allocator(), &.{ 0xc3, 0x41, 0x01 }));
}

test "reject tag 55799 (self-describe CBOR)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xd9 0xd9 0xf7 0x01 = tag(55799) wrapping integer 1
    try std.testing.expectError(error.UnsupportedTag, cbor.decode(arena.allocator(), &.{ 0xd9, 0xd9, 0xf7, 0x01 }));
}

// === map key ordering validation ===
//
// DAG-CBOR requires map keys sorted by byte length (shorter first),
// then lexicographically.

test "reject unsorted map keys: wrong lexicographic order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // {"b": 1, "a": 2} — same length, wrong lex order
    try std.testing.expectError(error.UnsortedMapKeys, cbor.decode(arena.allocator(), &.{
        0xa2, // map(2)
        0x61, 'b', 0x01, // "b": 1
        0x61, 'a', 0x02, // "a": 2  (should come before "b")
    }));
}

test "reject unsorted map keys: longer key before shorter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // {"bb": 1, "a": 2} — 2-char key before 1-char key
    try std.testing.expectError(error.UnsortedMapKeys, cbor.decode(arena.allocator(), &.{
        0xa2, // map(2)
        0x62, 'b', 'b', 0x01, // "bb": 1
        0x61, 'a', 0x02, // "a": 2  (shorter, should come first)
    }));
}

test "accept correctly sorted map keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // {"a": 1, "b": 2, "cc": 3} — correct order: short first, then lex
    const result = try cbor.decode(arena.allocator(), &.{
        0xa3, // map(3)
        0x61, 'a', 0x01, // "a": 1
        0x61, 'b', 0x02, // "b": 2
        0x62, 'c', 'c', 0x03, // "cc": 3
    });
    try std.testing.expectEqual(@as(u64, 1), result.value.get("a").?.unsigned);
    try std.testing.expectEqual(@as(u64, 2), result.value.get("b").?.unsigned);
    try std.testing.expectEqual(@as(u64, 3), result.value.get("cc").?.unsigned);
}

// === duplicate map key rejection ===

test "reject duplicate map keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // {"a": 1, "a": 2} — duplicate key "a"
    try std.testing.expectError(error.DuplicateMapKey, cbor.decode(arena.allocator(), &.{
        0xa2, // map(2)
        0x61, 'a', 0x01, // "a": 1
        0x61, 'a', 0x02, // "a": 2  (duplicate!)
    }));
}

// === float rejection (all variants) ===

test "reject float16" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedFloat, cbor.decode(arena.allocator(), &.{ 0xf9, 0x00, 0x00 }));
}

test "reject float32" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xfa 0x47 0xc3 0x50 0x00 = float32(100000.0)
    try std.testing.expectError(error.UnsupportedFloat, cbor.decode(arena.allocator(), &.{ 0xfa, 0x47, 0xc3, 0x50, 0x00 }));
}

test "reject float64" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xfb + 8 bytes = float64(1.0)
    try std.testing.expectError(error.UnsupportedFloat, cbor.decode(arena.allocator(), &.{ 0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

// === simple values rejection ===

test "reject undefined (0xf7)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedSimpleValue, cbor.decode(arena.allocator(), &.{0xf7}));
}

test "reject simple value 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xf8 0x00 = simple(0) — only false/true/null allowed
    try std.testing.expectError(error.UnsupportedSimpleValue, cbor.decode(arena.allocator(), &.{ 0xf8, 0x00 }));
}

test "reject simple value 32" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedSimpleValue, cbor.decode(arena.allocator(), &.{ 0xf8, 0x20 }));
}

test "reject simple value 255" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedSimpleValue, cbor.decode(arena.allocator(), &.{ 0xf8, 0xff }));
}

// === indefinite-length rejection (all types) ===

test "reject indefinite-length byte string (0x5f)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.IndefiniteLength, cbor.decode(arena.allocator(), &.{0x5f}));
}

test "reject indefinite-length text string (0x7f)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.IndefiniteLength, cbor.decode(arena.allocator(), &.{0x7f}));
}

test "reject indefinite-length array (0x9f)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.IndefiniteLength, cbor.decode(arena.allocator(), &.{0x9f}));
}

test "reject indefinite-length map (0xbf)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.IndefiniteLength, cbor.decode(arena.allocator(), &.{0xbf}));
}

test "reject break stop code (0xff)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.IndefiniteLength, cbor.decode(arena.allocator(), &.{0xff}));
}

// === reserved additional info (28, 29, 30) for all major types ===

test "reject reserved additional info for unsigned" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // additional 28 = 0x1c, 29 = 0x1d, 30 = 0x1e
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x1c}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x1d}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x1e}));
}

test "reject reserved additional info for negative" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x3c}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x3d}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x3e}));
}

test "reject reserved additional info for byte string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x5c}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x5d}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x5e}));
}

test "reject reserved additional info for text string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x7c}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x7d}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x7e}));
}

test "reject reserved additional info for array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x9c}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x9d}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0x9e}));
}

test "reject reserved additional info for map" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xbc}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xbd}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xbe}));
}

test "reject reserved additional info for tag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xdc}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xdd}));
    try std.testing.expectError(error.ReservedAdditionalInfo, cbor.decode(arena.allocator(), &.{0xde}));
}

// === integer boundary encode/decode ===

test "integer boundary: 255 (max 1-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 0x18 0xff = unsigned(255)
    try std.testing.expectEqual(@as(u64, 255), (try cbor.decode(alloc, &.{ 0x18, 0xff })).value.unsigned);
    // round-trip
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 255 });
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0xff }, encoded);
}

test "integer boundary: 256 (min 2-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 0x19 0x01 0x00 = unsigned(256)
    try std.testing.expectEqual(@as(u64, 256), (try cbor.decode(alloc, &.{ 0x19, 0x01, 0x00 })).value.unsigned);
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 256 });
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x01, 0x00 }, encoded);
}

test "integer boundary: 65535 (max 2-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(@as(u64, 65535), (try cbor.decode(alloc, &.{ 0x19, 0xff, 0xff })).value.unsigned);
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 65535 });
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0xff, 0xff }, encoded);
}

test "integer boundary: 65536 (min 4-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(@as(u64, 65536), (try cbor.decode(alloc, &.{ 0x1a, 0x00, 0x01, 0x00, 0x00 })).value.unsigned);
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 65536 });
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0x00, 0x01, 0x00, 0x00 }, encoded);
}

test "integer boundary: 0xffffffff (max 4-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(@as(u64, 0xffffffff), (try cbor.decode(alloc, &.{ 0x1a, 0xff, 0xff, 0xff, 0xff })).value.unsigned);
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 0xffffffff });
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0xff, 0xff, 0xff, 0xff }, encoded);
}

test "integer boundary: 0x100000000 (min 8-byte)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(@as(u64, 0x100000000), (try cbor.decode(alloc, &.{ 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 })).value.unsigned);
    const encoded = try cbor.encodeAlloc(alloc, .{ .unsigned = 0x100000000 });
    try std.testing.expectEqualSlices(u8, &.{ 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, encoded);
}

test "integer boundary: max u64" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const max_u64: u64 = std.math.maxInt(u64);
    try std.testing.expectEqual(max_u64, (try cbor.decode(alloc, &.{ 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })).value.unsigned);
}

// === negative integer boundary tests ===

test "negative boundary: -24 (max inline)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -24 = major 1, additional 23 → 0x37
    try std.testing.expectEqual(@as(i64, -24), (try cbor.decode(alloc, &.{0x37})).value.negative);
    const encoded = try cbor.encodeAlloc(alloc, .{ .negative = -24 });
    try std.testing.expectEqualSlices(u8, &.{0x37}, encoded);
}

test "negative boundary: -25 (min 1-byte additional)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -25 = major 1, additional 24 → 0x38 0x18
    try std.testing.expectEqual(@as(i64, -25), (try cbor.decode(alloc, &.{ 0x38, 0x18 })).value.negative);
    const encoded = try cbor.encodeAlloc(alloc, .{ .negative = -25 });
    try std.testing.expectEqualSlices(u8, &.{ 0x38, 0x18 }, encoded);
}

test "negative boundary: -256 (max 1-byte additional)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -256 = -1 - 255 → 0x38 0xff
    try std.testing.expectEqual(@as(i64, -256), (try cbor.decode(alloc, &.{ 0x38, 0xff })).value.negative);
    const encoded = try cbor.encodeAlloc(alloc, .{ .negative = -256 });
    try std.testing.expectEqualSlices(u8, &.{ 0x38, 0xff }, encoded);
}

test "negative boundary: -257 (min 2-byte additional)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -257 = -1 - 256 → 0x39 0x01 0x00
    try std.testing.expectEqual(@as(i64, -257), (try cbor.decode(alloc, &.{ 0x39, 0x01, 0x00 })).value.negative);
    const encoded = try cbor.encodeAlloc(alloc, .{ .negative = -257 });
    try std.testing.expectEqualSlices(u8, &.{ 0x39, 0x01, 0x00 }, encoded);
}

test "negative boundary: -65537 (min 4-byte additional)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -65537 = -1 - 65536 → 0x3a 0x00 0x01 0x00 0x00
    try std.testing.expectEqual(@as(i64, -65537), (try cbor.decode(alloc, &.{ 0x3a, 0x00, 0x01, 0x00, 0x00 })).value.negative);
    const encoded = try cbor.encodeAlloc(alloc, .{ .negative = -65537 });
    try std.testing.expectEqualSlices(u8, &.{ 0x3a, 0x00, 0x01, 0x00, 0x00 }, encoded);
}

test "negative boundary: min i64 (-2^63)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const min_i64: i64 = std.math.minInt(i64);
    // -2^63 = -1 - (2^63 - 1) → 0x3b 0x7f 0xff 0xff 0xff 0xff 0xff 0xff 0xff
    try std.testing.expectEqual(min_i64, (try cbor.decode(alloc, &.{ 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })).value.negative);
}

// === negative integer overflow ===

test "reject negative integer overflow: -(2^63 + 1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x3b 0x80 0x00 ... 0x00 = -1 - 2^63 = -(2^63 + 1), overflows i64
    try std.testing.expectError(error.Overflow, cbor.decode(arena.allocator(), &.{ 0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

test "reject negative integer overflow: -(2^64)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x3b 0xff ... 0xff = -1 - (2^64 - 1) = -2^64, overflows i64
    try std.testing.expectError(error.Overflow, cbor.decode(arena.allocator(), &.{ 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }));
}

// === truncated data handling ===

test "reject empty input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{}));
}

test "reject truncated 1-byte unsigned header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x18 needs 1 more byte
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{0x18}));
}

test "reject truncated 2-byte unsigned header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x19 needs 2 more bytes
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{0x19}));
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x19, 0x01 }));
}

test "reject truncated 4-byte unsigned header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{0x1a}));
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x1a, 0x00, 0x00 }));
}

test "reject truncated 8-byte unsigned header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{0x1b}));
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x1b, 0x00, 0x00, 0x00, 0x00 }));
}

test "reject truncated text string payload" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x65 = text(5) but only 3 bytes follow
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x65, 'h', 'e', 'l' }));
}

test "reject truncated byte string payload" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x44 = bytes(4) but only 2 bytes follow
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x44, 0x01, 0x02 }));
}

test "reject truncated array elements" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x83 = array(3) but only 2 elements
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{ 0x83, 0x01, 0x02 }));
}

test "reject truncated map entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0xa2 = map(2) but only 1 entry
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{
        0xa2,
        0x61,
        'a',
        0x01,
    }));
}

// === string/bytes at encoding boundaries ===

test "text string at encoding boundaries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 23-byte string (max inline length)
    const s23 = "12345678901234567890123";
    const encoded23 = try cbor.encodeAlloc(alloc, .{ .text = s23 });
    try std.testing.expectEqual(@as(u8, 0x77), encoded23[0]); // 0x60 + 23
    const decoded23 = try cbor.decodeAll(alloc, encoded23);
    try std.testing.expectEqualStrings(s23, decoded23.text);

    // 24-byte string (first to use 1-byte length)
    const s24 = "123456789012345678901234";
    const encoded24 = try cbor.encodeAlloc(alloc, .{ .text = s24 });
    try std.testing.expectEqual(@as(u8, 0x78), encoded24[0]); // text + 1-byte length
    try std.testing.expectEqual(@as(u8, 24), encoded24[1]);
    const decoded24 = try cbor.decodeAll(alloc, encoded24);
    try std.testing.expectEqualStrings(s24, decoded24.text);
}

test "byte string at encoding boundaries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 23-byte bytes (max inline length)
    const b23 = &[_]u8{0xaa} ** 23;
    const encoded23 = try cbor.encodeAlloc(alloc, .{ .bytes = b23 });
    try std.testing.expectEqual(@as(u8, 0x57), encoded23[0]); // 0x40 + 23
    const decoded23 = try cbor.decodeAll(alloc, encoded23);
    try std.testing.expectEqualSlices(u8, b23, decoded23.bytes);

    // 24-byte bytes (first to use 1-byte length)
    const b24 = &[_]u8{0xbb} ** 24;
    const encoded24 = try cbor.encodeAlloc(alloc, .{ .bytes = b24 });
    try std.testing.expectEqual(@as(u8, 0x58), encoded24[0]); // bytes + 1-byte length
    try std.testing.expectEqual(@as(u8, 24), encoded24[1]);
    const decoded24 = try cbor.decodeAll(alloc, encoded24);
    try std.testing.expectEqualSlices(u8, b24, decoded24.bytes);
}

// === CID edge cases ===

test "reject tag 42 wrapping non-bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // tag(42) + text string "hello" instead of byte string
    try std.testing.expectError(error.InvalidCid, cbor.decode(arena.allocator(), &.{
        0xd8, 0x2a, // tag(42)
        0x65, 'h', 'e', 'l', 'l', 'o', // text "hello" (should be bytes)
    }));
}

test "reject tag 42 with empty bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // tag(42) + empty byte string (missing 0x00 prefix)
    try std.testing.expectError(error.InvalidCid, cbor.decode(arena.allocator(), &.{
        0xd8, 0x2a, // tag(42)
        0x40, // bytes(0) — empty, no 0x00 prefix
    }));
}

test "reject tag 42 with wrong prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // tag(42) + byte string with 0x01 prefix instead of 0x00
    try std.testing.expectError(error.InvalidCid, cbor.decode(arena.allocator(), &.{
        0xd8, 0x2a, // tag(42)
        0x42, 0x01, 0xaa, // bytes [0x01, 0xaa] — wrong prefix
    }));
}

// === complex nested round-trips ===

test "round-trip: mixed array with all types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // [42, -7, "hello", true, false, null, [1, 2], {"k": 0}]
    const original: Value = .{ .array = &.{
        .{ .unsigned = 42 },
        .{ .negative = -7 },
        .{ .text = "hello" },
        .{ .boolean = true },
        .{ .boolean = false },
        .null,
        .{ .array = &.{ .{ .unsigned = 1 }, .{ .unsigned = 2 } } },
        .{ .map = &.{.{ .key = "k", .value = .{ .unsigned = 0 } }} },
    } };

    const encoded = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, encoded);

    const arr = decoded.array;
    try std.testing.expectEqual(@as(usize, 8), arr.len);
    try std.testing.expectEqual(@as(u64, 42), arr[0].unsigned);
    try std.testing.expectEqual(@as(i64, -7), arr[1].negative);
    try std.testing.expectEqualStrings("hello", arr[2].text);
    try std.testing.expectEqual(true, arr[3].boolean);
    try std.testing.expectEqual(false, arr[4].boolean);
    try std.testing.expectEqual(Value.null, arr[5]);
    try std.testing.expectEqual(@as(usize, 2), arr[6].array.len);
    try std.testing.expectEqual(@as(u64, 0), arr[7].get("k").?.unsigned);
}

test "round-trip: deeply nested maps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"a": {"b": {"c": {"d": 42}}}}
    const original: Value = .{ .map = &.{
        .{ .key = "a", .value = .{ .map = &.{
            .{ .key = "b", .value = .{ .map = &.{
                .{ .key = "c", .value = .{ .map = &.{
                    .{ .key = "d", .value = .{ .unsigned = 42 } },
                } } },
            } } },
        } } },
    } };

    const encoded = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, encoded);

    const d = decoded.get("a").?.get("b").?.get("c").?.get("d").?.unsigned;
    try std.testing.expectEqual(@as(u64, 42), d);
}

test "round-trip: unicode text strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cases = [_][]const u8{
        "",
        "a",
        "IETF",
        "\"\\\u{00fc}\u{6c34}",
        "\xc3\xbc", // ü
        "\xe6\xb0\xb4", // 水
        "\xf0\x9f\x98\x80", // 😀
        "\xf0\x9f\x91\xa8\xe2\x80\x8d\xf0\x9f\x91\xa9\xe2\x80\x8d\xf0\x9f\x91\xa7\xe2\x80\x8d\xf0\x9f\x91\xa7", // family ZWJ emoji
    };

    for (cases) |text| {
        const encoded = try cbor.encodeAlloc(alloc, .{ .text = text });
        const decoded = try cbor.decodeAll(alloc, encoded);
        try std.testing.expectEqualStrings(text, decoded.text);
    }
}

test "round-trip: empty containers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // empty array
    const empty_arr = try cbor.encodeAlloc(alloc, .{ .array = &.{} });
    try std.testing.expectEqualSlices(u8, &.{0x80}, empty_arr);
    const decoded_arr = try cbor.decodeAll(alloc, empty_arr);
    try std.testing.expectEqual(@as(usize, 0), decoded_arr.array.len);

    // empty map
    const empty_map = try cbor.encodeAlloc(alloc, .{ .map = &.{} });
    try std.testing.expectEqualSlices(u8, &.{0xa0}, empty_map);
    const decoded_map = try cbor.decodeAll(alloc, empty_map);
    try std.testing.expectEqual(@as(usize, 0), decoded_map.map.len);
}

test "round-trip: map with empty key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original: Value = .{ .map = &.{
        .{ .key = "", .value = .{ .unsigned = 1 } },
        .{ .key = "a", .value = .{ .unsigned = 2 } },
    } };

    const encoded = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, encoded);

    // empty key should sort first (shorter)
    try std.testing.expectEqualStrings("", decoded.map[0].key);
    try std.testing.expectEqualStrings("a", decoded.map[1].key);
    try std.testing.expectEqual(@as(u64, 1), decoded.get("").?.unsigned);
    try std.testing.expectEqual(@as(u64, 2), decoded.get("a").?.unsigned);
}

// === byte-identical re-encoding ===

test "canonical re-encoding: encode then decode then re-encode is identical" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build a non-trivially-ordered map
    const original: Value = .{ .map = &.{
        .{ .key = "z", .value = .{ .unsigned = 26 } },
        .{ .key = "a", .value = .{ .text = "first" } },
        .{ .key = "mm", .value = .{ .array = &.{
            .{ .boolean = true },
            .null,
            .{ .negative = -100 },
        } } },
    } };

    const first_encode = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, first_encode);
    const second_encode = try cbor.encodeAlloc(alloc, decoded);

    try std.testing.expectEqualSlices(u8, first_encode, second_encode);
}

test "deterministic encoding: 10 iterations produce identical bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const value: Value = .{ .map = &.{
        .{ .key = "type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "text", .value = .{ .text = "Hello, world!" } },
        .{ .key = "createdAt", .value = .{ .text = "2024-01-01T00:00:00Z" } },
        .{ .key = "langs", .value = .{ .array = &.{.{ .text = "en" }} } },
    } };

    const first = try cbor.encodeAlloc(alloc, value);
    for (0..10) |_| {
        const again = try cbor.encodeAlloc(alloc, value);
        try std.testing.expectEqualSlices(u8, first, again);
    }
}

// === single-byte exhaustive scan ===
//
// every possible single-byte CBOR input should either decode or return
// a well-defined error — never panic or trigger undefined behavior.

test "single-byte exhaustive: no panics on any byte value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var byte: u16 = 0;
    while (byte <= 255) : (byte += 1) {
        const data = [_]u8{@intCast(byte)};
        _ = cbor.decode(alloc, &data) catch continue;
    }
}

// === non-string map key rejection ===

test "reject integer map key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // map(1) with integer key: {1: 2}
    try std.testing.expectError(error.InvalidMapKey, cbor.decode(arena.allocator(), &.{
        0xa1, // map(1)
        0x01, // key: integer 1 (not text!)
        0x02, // value: 2
    }));
}

test "reject bytes map key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // map(1) with byte string key
    try std.testing.expectError(error.InvalidMapKey, cbor.decode(arena.allocator(), &.{
        0xa1, // map(1)
        0x41, 0x01, // key: bytes [0x01] (not text!)
        0x02, // value: 2
    }));
}

test "reject array map key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidMapKey, cbor.decode(arena.allocator(), &.{
        0xa1, // map(1)
        0x80, // key: empty array (not text!)
        0x02, // value: 2
    }));
}

test "reject boolean map key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidMapKey, cbor.decode(arena.allocator(), &.{
        0xa1, // map(1)
        0xf5, // key: true (not text!)
        0x02, // value: 2
    }));
}

// === map key ordering: comprehensive DAG-CBOR rules ===

test "map key ordering: length takes priority over lexicographic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // "z" (1 byte) must come before "aa" (2 bytes), even though "aa" < "z" lexicographically
    const original: Value = .{ .map = &.{
        .{ .key = "aa", .value = .{ .unsigned = 2 } },
        .{ .key = "z", .value = .{ .unsigned = 1 } },
    } };

    const encoded = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, encoded);

    try std.testing.expectEqualStrings("z", decoded.map[0].key);
    try std.testing.expectEqualStrings("aa", decoded.map[1].key);
}

test "map key ordering: empty key sorts first" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original: Value = .{ .map = &.{
        .{ .key = "a", .value = .{ .unsigned = 2 } },
        .{ .key = "", .value = .{ .unsigned = 1 } },
        .{ .key = "bb", .value = .{ .unsigned = 3 } },
    } };

    const encoded = try cbor.encodeAlloc(alloc, original);
    const decoded = try cbor.decodeAll(alloc, encoded);

    try std.testing.expectEqualStrings("", decoded.map[0].key);
    try std.testing.expectEqualStrings("a", decoded.map[1].key);
    try std.testing.expectEqualStrings("bb", decoded.map[2].key);
}

// === UTF-8 validation ===
//
// CBOR text strings (major type 3) must contain valid UTF-8.
// DAG-CBOR inherits this requirement.

test "reject invalid UTF-8 in text string: 0xff byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text(1) containing 0xff — not valid UTF-8
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{ 0x61, 0xff }));
}

test "reject invalid UTF-8 in text string: truncated multi-byte sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text(1) containing 0xc3 — start of 2-byte sequence but missing continuation
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{ 0x61, 0xc3 }));
}

test "reject invalid UTF-8 in text string: lone continuation byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text(1) containing 0x80 — continuation byte without start
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{ 0x61, 0x80 }));
}

test "reject invalid UTF-8 in text string: surrogate half (U+D800)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text(3) containing ED A0 80 — UTF-8 encoding of U+D800 (surrogate)
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{ 0x63, 0xed, 0xa0, 0x80 }));
}

test "reject invalid UTF-8 in text string: overlong encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text(2) containing C0 80 — overlong encoding of U+0000
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{ 0x62, 0xc0, 0x80 }));
}

test "reject invalid UTF-8 in map key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // map(1) with key containing invalid UTF-8
    try std.testing.expectError(error.InvalidUtf8, cbor.decode(arena.allocator(), &.{
        0xa1, // map(1)
        0x61, 0xff, // key: text(1) with 0xff — invalid UTF-8
        0x01, // value: 1
    }));
}

test "accept valid UTF-8 text: café" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // "café" = 63 61 66 c3 a9 — valid UTF-8
    const result = try cbor.decode(arena.allocator(), &.{ 0x65, 'c', 'a', 'f', 0xc3, 0xa9 });
    try std.testing.expectEqualStrings("caf\xc3\xa9", result.value.text);
}

test "accept valid UTF-8 text: CJK and emoji" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // encode and decode a string with multi-byte characters
    const text = "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xf0\x9f\x98\x80"; // 日本語😀
    const encoded = try cbor.encodeAlloc(alloc, .{ .text = text });
    const decoded = try cbor.decodeAll(alloc, encoded);
    try std.testing.expectEqualStrings(text, decoded.text);
}

// === nesting depth limit ===

test "accept nesting at max_depth - 1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // build array(1) nested max_depth - 1 times, with 0 at the bottom
    var buf: [cbor.max_depth + 1]u8 = undefined;
    for (0..cbor.max_depth - 1) |i| {
        buf[i] = 0x81; // array(1)
    }
    buf[cbor.max_depth - 1] = 0x00; // integer 0 at the bottom

    const result = try cbor.decodeAll(arena.allocator(), buf[0..cbor.max_depth]);
    // verify outermost is an array
    try std.testing.expectEqual(@as(usize, 1), result.array.len);
}

test "reject nesting beyond max_depth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // build array(1) nested max_depth + 1 times
    var buf: [cbor.max_depth + 2]u8 = undefined;
    for (0..cbor.max_depth + 1) |i| {
        buf[i] = 0x81; // array(1)
    }
    buf[cbor.max_depth + 1] = 0x00;

    try std.testing.expectError(error.MaxDepthExceeded, cbor.decodeAll(arena.allocator(), buf[0 .. cbor.max_depth + 2]));
}

// === huge allocation rejection ===
//
// the decoder should reject claims for impossibly large collections
// without attempting to allocate.

test "reject huge array allocation claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x9b + 8 bytes claiming 2^32 elements, but only a few bytes of data follow
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{
        0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // array(2^32)
        0x00, // just one byte of data
    }));
}

test "reject huge map allocation claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // map claiming 2^32 entries with minimal data
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{
        0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // map(2^32)
        0x61, 'a', 0x01, // one entry
    }));
}

test "reject huge byte string claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // bytes claiming 2^32 length with minimal data
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{
        0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // bytes(2^32)
        0x00, // just one byte
    }));
}

test "reject huge text string claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // text claiming 2^32 length with minimal data
    try std.testing.expectError(error.UnexpectedEof, cbor.decode(arena.allocator(), &.{
        0x7b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // text(2^32)
        0x00, // just one byte
    }));
}
