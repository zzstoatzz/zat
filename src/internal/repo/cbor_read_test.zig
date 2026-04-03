const std = @import("std");
const cbor = @import("cbor.zig");
const readArg = cbor.readArg;
const Arg = cbor.Arg;
const readText = cbor.readText;
const readBytes = cbor.readBytes;
const readUint = cbor.readUint;
const readInt = cbor.readInt;
const readBool = cbor.readBool;
const readNull = cbor.readNull;
const readMapHeader = cbor.readMapHeader;
const readArrayHeader = cbor.readArrayHeader;
const readCidLink = cbor.readCidLink;

// ---------------------------------------------------------------------------
// Inline values 0-23 (major type 0 = unsigned)
// ---------------------------------------------------------------------------

test "readArg: inline value 0" {
    const data = [_]u8{0x00}; // major 0, additional 0
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 0), arg.val);
    try std.testing.expectEqual(@as(usize, 1), arg.end);
}

test "readArg: inline value 1" {
    const data = [_]u8{0x01};
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 1), arg.val);
    try std.testing.expectEqual(@as(usize, 1), arg.end);
}

test "readArg: inline value 23" {
    const data = [_]u8{0x17}; // major 0, additional 23
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 23), arg.val);
    try std.testing.expectEqual(@as(usize, 1), arg.end);
}

// ---------------------------------------------------------------------------
// 1-byte value (additional info = 24)
// ---------------------------------------------------------------------------

test "readArg: 1-byte value 24" {
    const data = [_]u8{ 0x18, 24 }; // major 0, additional 24, payload 24
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 24), arg.val);
    try std.testing.expectEqual(@as(usize, 2), arg.end);
}

test "readArg: 1-byte value 255" {
    const data = [_]u8{ 0x18, 0xff }; // major 0, additional 24, payload 255
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 255), arg.val);
    try std.testing.expectEqual(@as(usize, 2), arg.end);
}

// ---------------------------------------------------------------------------
// 2-byte value (additional info = 25)
// ---------------------------------------------------------------------------

test "readArg: 2-byte value 256" {
    const data = [_]u8{ 0x19, 0x01, 0x00 }; // major 0, additional 25, payload 256 big-endian
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 256), arg.val);
    try std.testing.expectEqual(@as(usize, 3), arg.end);
}

// ---------------------------------------------------------------------------
// 4-byte value (additional info = 26)
// ---------------------------------------------------------------------------

test "readArg: 4-byte value 65536" {
    const data = [_]u8{ 0x1a, 0x00, 0x01, 0x00, 0x00 }; // major 0, additional 26, payload 65536
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 65536), arg.val);
    try std.testing.expectEqual(@as(usize, 5), arg.end);
}

// ---------------------------------------------------------------------------
// 8-byte value (additional info = 27)
// ---------------------------------------------------------------------------

test "readArg: 8-byte value 0x100000000" {
    // major 0, additional 27, payload 0x00_00_00_01_00_00_00_00
    const data = [_]u8{ 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const arg = try readArg(&data, 0);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 0x100000000), arg.val);
    try std.testing.expectEqual(@as(usize, 9), arg.end);
}

// ---------------------------------------------------------------------------
// Reject non-minimal encodings
// ---------------------------------------------------------------------------

test "readArg: reject non-minimal 0 encoded as 1-byte" {
    // Value 0 encoded with additional=24 payload=0x00 (should be inline 0)
    const data = [_]u8{ 0x18, 0x00 };
    try std.testing.expectError(error.NonMinimalEncoding, readArg(&data, 0));
}

test "readArg: reject non-minimal 255 encoded as 2-byte" {
    // Value 255 encoded with additional=25 payload=0x00ff (should be 1-byte)
    const data = [_]u8{ 0x19, 0x00, 0xff };
    try std.testing.expectError(error.NonMinimalEncoding, readArg(&data, 0));
}

// ---------------------------------------------------------------------------
// Reject truncated data
// ---------------------------------------------------------------------------

test "readArg: reject truncated 2-byte" {
    // additional=25 needs 2 payload bytes, but only 1 provided
    const data = [_]u8{ 0x19, 0x01 };
    try std.testing.expectError(error.UnexpectedEof, readArg(&data, 0));
}

// ---------------------------------------------------------------------------
// Reject reserved additional info (28-30)
// ---------------------------------------------------------------------------

test "readArg: reject reserved additional info 28" {
    const data = [_]u8{0x1c}; // major 0, additional 28
    try std.testing.expectError(error.ReservedAdditionalInfo, readArg(&data, 0));
}

// ---------------------------------------------------------------------------
// Reject indefinite length (additional info = 31)
// ---------------------------------------------------------------------------

test "readArg: reject indefinite length 31" {
    const data = [_]u8{0x5f}; // major 2 (byte string), additional 31
    try std.testing.expectError(error.IndefiniteLength, readArg(&data, 0));
}

// ---------------------------------------------------------------------------
// Non-zero start position
// ---------------------------------------------------------------------------

test "readArg: non-zero start position" {
    // prefix byte 0xAA, then a valid CBOR unsigned 24 at position 1
    const data = [_]u8{ 0xaa, 0x18, 24 };
    const arg = try readArg(&data, 1);
    try std.testing.expectEqual(@as(u3, 0), arg.major);
    try std.testing.expectEqual(@as(u64, 24), arg.val);
    try std.testing.expectEqual(@as(usize, 3), arg.end);
}

test "readArg: non-zero start position with different major type" {
    // At position 2: 0x63 = major 3 (text string), additional 3 (inline length 3)
    const data = [_]u8{ 0x00, 0x00, 0x63, 0x66, 0x6f, 0x6f };
    const arg = try readArg(&data, 2);
    try std.testing.expectEqual(@as(u3, 3), arg.major);
    try std.testing.expectEqual(@as(u64, 3), arg.val);
    try std.testing.expectEqual(@as(usize, 3), arg.end);
}

// ---------------------------------------------------------------------------
// EOF at start position
// ---------------------------------------------------------------------------

test "readArg: empty data returns UnexpectedEof" {
    const data = [_]u8{};
    try std.testing.expectError(error.UnexpectedEof, readArg(&data, 0));
}

test "readArg: pos beyond data returns UnexpectedEof" {
    const data = [_]u8{0x00};
    try std.testing.expectError(error.UnexpectedEof, readArg(&data, 1));
}

// ===========================================================================
// readText
// ===========================================================================

test "readText: short string 'hello'" {
    // 0x65 = major 3 (text), length 5
    const data = [_]u8{ 0x65, 'h', 'e', 'l', 'l', 'o' };
    const result = try readText(&data, 0);
    try std.testing.expectEqualStrings("hello", result.val);
    try std.testing.expectEqual(@as(usize, 6), result.end);
}

test "readText: empty string" {
    const data = [_]u8{0x60}; // major 3, length 0
    const result = try readText(&data, 0);
    try std.testing.expectEqual(@as(usize, 0), result.val.len);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readText: reject non-text major" {
    const data = [_]u8{ 0x45, 'h', 'e', 'l', 'l', 'o' }; // major 2 (bytes), length 5
    try std.testing.expectError(error.WrongType, readText(&data, 0));
}

test "readText: reject invalid UTF-8" {
    // 0x62 = major 3, length 2; 0xff 0xfe is invalid UTF-8
    const data = [_]u8{ 0x62, 0xff, 0xfe };
    try std.testing.expectError(error.InvalidUtf8, readText(&data, 0));
}

// ===========================================================================
// readBytes
// ===========================================================================

test "readBytes: 3-byte string" {
    const data = [_]u8{ 0x43, 0x01, 0x02, 0x03 }; // major 2, length 3
    const result = try readBytes(&data, 0);
    try std.testing.expectEqual(@as(usize, 3), result.val.len);
    try std.testing.expectEqual(@as(u8, 0x01), result.val[0]);
    try std.testing.expectEqual(@as(u8, 0x02), result.val[1]);
    try std.testing.expectEqual(@as(u8, 0x03), result.val[2]);
    try std.testing.expectEqual(@as(usize, 4), result.end);
}

test "readBytes: empty bytes" {
    const data = [_]u8{0x40}; // major 2, length 0
    const result = try readBytes(&data, 0);
    try std.testing.expectEqual(@as(usize, 0), result.val.len);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

// ===========================================================================
// readUint
// ===========================================================================

test "readUint: value 1000" {
    // 0x19 = major 0, additional 25 (2-byte), 0x03e8 = 1000
    const data = [_]u8{ 0x19, 0x03, 0xe8 };
    const result = try readUint(&data, 0);
    try std.testing.expectEqual(@as(u64, 1000), result.val);
    try std.testing.expectEqual(@as(usize, 3), result.end);
}

test "readUint: reject negative" {
    const data = [_]u8{0x20}; // major 1, value 0 => -1
    try std.testing.expectError(error.WrongType, readUint(&data, 0));
}

// ===========================================================================
// readInt
// ===========================================================================

test "readInt: positive 42" {
    // 0x18 = major 0, additional 24 (1-byte), 42
    const data = [_]u8{ 0x18, 42 };
    const result = try readInt(&data, 0);
    try std.testing.expectEqual(@as(i64, 42), result.val);
    try std.testing.expectEqual(@as(usize, 2), result.end);
}

test "readInt: negative -10" {
    // major 1, value 9 => -1 - 9 = -10
    // 0x29 = 0b001_01001 = major 1, additional 9
    const data = [_]u8{0x29};
    const result = try readInt(&data, 0);
    try std.testing.expectEqual(@as(i64, -10), result.val);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readInt: reject non-integer" {
    const data = [_]u8{0x60}; // major 3 (text), length 0
    try std.testing.expectError(error.WrongType, readInt(&data, 0));
}

// ===========================================================================
// readBool
// ===========================================================================

test "readBool: true" {
    const data = [_]u8{0xf5};
    const result = try readBool(&data, 0);
    try std.testing.expectEqual(true, result.val);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readBool: false" {
    const data = [_]u8{0xf4};
    const result = try readBool(&data, 0);
    try std.testing.expectEqual(false, result.val);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readBool: reject non-bool" {
    const data = [_]u8{0xf6}; // null
    try std.testing.expectError(error.WrongType, readBool(&data, 0));
}

// ===========================================================================
// readNull
// ===========================================================================

test "readNull: null" {
    const data = [_]u8{0xf6};
    const result = try readNull(&data, 0);
    try std.testing.expectEqual(@as(usize, 1), result);
}

test "readNull: reject non-null" {
    const data = [_]u8{0xf5}; // true
    try std.testing.expectError(error.WrongType, readNull(&data, 0));
}

// ===========================================================================
// readMapHeader
// ===========================================================================

test "readMapHeader: count 2" {
    const data = [_]u8{0xa2}; // major 5, length 2
    const result = try readMapHeader(&data, 0);
    try std.testing.expectEqual(@as(u64, 2), result.val);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readMapHeader: reject non-map" {
    const data = [_]u8{0x82}; // major 4 (array), length 2
    try std.testing.expectError(error.WrongType, readMapHeader(&data, 0));
}

// ===========================================================================
// readArrayHeader
// ===========================================================================

test "readArrayHeader: count 3" {
    const data = [_]u8{0x83}; // major 4, length 3
    const result = try readArrayHeader(&data, 0);
    try std.testing.expectEqual(@as(u64, 3), result.val);
    try std.testing.expectEqual(@as(usize, 1), result.end);
}

test "readArrayHeader: reject non-array" {
    const data = [_]u8{0xa3}; // major 5 (map), length 3
    try std.testing.expectError(error.WrongType, readArrayHeader(&data, 0));
}

// ===========================================================================
// readCidLink
// ===========================================================================

test "readCidLink: valid CID (tag(42) + bytes with 0x00 prefix + 36-byte CIDv1)" {
    // tag(42): 0xd8 0x2a
    // bytes(37): 0x58 0x25 (37 = 1 prefix + 36 CID)
    // 0x00 prefix
    // 36-byte CID: 0x01 0x71 0x12 0x20 ++ [0xaa] ** 32
    const cid_raw = [_]u8{ 0x01, 0x71, 0x12, 0x20 } ++ [_]u8{0xaa} ** 32;
    const data = [_]u8{ 0xd8, 0x2a, 0x58, 0x25, 0x00 } ++ cid_raw;
    const result = try readCidLink(&data, 0);
    try std.testing.expectEqual(@as(usize, 36), result.val.len);
    try std.testing.expectEqual(@as(u8, 0x01), result.val[0]);
    try std.testing.expectEqual(@as(u8, 0x71), result.val[1]);
    try std.testing.expectEqual(@as(u8, 0x12), result.val[2]);
    try std.testing.expectEqual(@as(u8, 0x20), result.val[3]);
    try std.testing.expectEqual(@as(u8, 0xaa), result.val[4]);
    try std.testing.expectEqual(@as(usize, 4 + 37), result.end); // 4 header bytes (2 tag + 2 bytes hdr) + 37 payload bytes
}

test "readCidLink: reject non-tag" {
    const data = [_]u8{ 0x43, 0x01, 0x02, 0x03 }; // major 2 (bytes), not a tag
    try std.testing.expectError(error.WrongType, readCidLink(&data, 0));
}
