const std = @import("std");
const cbor = @import("cbor.zig");
const readArg = cbor.readArg;
const Arg = cbor.Arg;

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
