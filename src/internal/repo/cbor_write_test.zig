const std = @import("std");
const cbor = @import("cbor.zig");

const writeArg = cbor.writeArg;
const writeText = cbor.writeText;
const writeBytes = cbor.writeBytes;
const writeUint = cbor.writeUint;
const writeInt = cbor.writeInt;
const writeMapHeader = cbor.writeMapHeader;
const writeArrayHeader = cbor.writeArrayHeader;
const writeBool = cbor.writeBool;
const writeNull = cbor.writeNull;
const writeCidLink = cbor.writeCidLink;

const readArg = cbor.readArg;
const readText = cbor.readText;
const readBytes = cbor.readBytes;
const readUint = cbor.readUint;
const readInt = cbor.readInt;
const readBool = cbor.readBool;
const readNull = cbor.readNull;
const readMapHeader = cbor.readMapHeader;
const readArrayHeader = cbor.readArrayHeader;
const readCidLink = cbor.readCidLink;

const decodeAll = cbor.decodeAll;

// ===========================================================================
// writeArg
// ===========================================================================

test "writeArg: value 0 (1 byte)" {
    var buf: [16]u8 = undefined;
    const end = writeArg(&buf, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
}

test "writeArg: value 23 (1 byte)" {
    var buf: [16]u8 = undefined;
    const end = writeArg(&buf, 0, 0, 23);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0x17), buf[0]);
}

test "writeArg: value 24 (2 bytes)" {
    var buf: [16]u8 = undefined;
    const end = writeArg(&buf, 0, 0, 24);
    try std.testing.expectEqual(@as(usize, 2), end);
    try std.testing.expectEqual(@as(u8, 0x18), buf[0]);
    try std.testing.expectEqual(@as(u8, 24), buf[1]);
}

test "writeArg: value 1000 (3 bytes)" {
    var buf: [16]u8 = undefined;
    const end = writeArg(&buf, 0, 0, 1000);
    try std.testing.expectEqual(@as(usize, 3), end);
    try std.testing.expectEqual(@as(u8, 0x19), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xe8), buf[2]);
}

// ===========================================================================
// writeText round-trip
// ===========================================================================

test "writeText: 'hello' round-trip" {
    var buf: [64]u8 = undefined;
    const end = writeText(&buf, 0, "hello");
    const result = try readText(&buf, 0);
    try std.testing.expectEqualStrings("hello", result.val);
    try std.testing.expectEqual(end, result.end);
}

// ===========================================================================
// writeBytes round-trip
// ===========================================================================

test "writeBytes: [1,2,3] round-trip" {
    var buf: [64]u8 = undefined;
    const input = [_]u8{ 1, 2, 3 };
    const end = writeBytes(&buf, 0, &input);
    const result = try readBytes(&buf, 0);
    try std.testing.expectEqual(@as(usize, 3), result.val.len);
    try std.testing.expectEqual(@as(u8, 1), result.val[0]);
    try std.testing.expectEqual(@as(u8, 2), result.val[1]);
    try std.testing.expectEqual(@as(u8, 3), result.val[2]);
    try std.testing.expectEqual(end, result.end);
}

// ===========================================================================
// writeUint round-trip
// ===========================================================================

test "writeUint: 42 round-trip" {
    var buf: [16]u8 = undefined;
    const end = writeUint(&buf, 0, 42);
    const result = try readUint(&buf, 0);
    try std.testing.expectEqual(@as(u64, 42), result.val);
    try std.testing.expectEqual(end, result.end);
}

// ===========================================================================
// writeInt
// ===========================================================================

test "writeInt: -10 verify bytes" {
    var buf: [16]u8 = undefined;
    const end = writeInt(&buf, 0, -10);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0x29), buf[0]);
}

test "writeInt: positive 42 round-trip" {
    var buf: [16]u8 = undefined;
    const end = writeInt(&buf, 0, 42);
    const result = try readInt(&buf, 0);
    try std.testing.expectEqual(@as(i64, 42), result.val);
    try std.testing.expectEqual(end, result.end);
}

// ===========================================================================
// writeMapHeader
// ===========================================================================

test "writeMapHeader: count 3 verify byte" {
    var buf: [16]u8 = undefined;
    const end = writeMapHeader(&buf, 0, 3);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0xa3), buf[0]);
}

// ===========================================================================
// writeArrayHeader
// ===========================================================================

test "writeArrayHeader: count 2 verify byte" {
    var buf: [16]u8 = undefined;
    const end = writeArrayHeader(&buf, 0, 2);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0x82), buf[0]);
}

// ===========================================================================
// writeBool
// ===========================================================================

test "writeBool: true and false consecutive" {
    var buf: [16]u8 = undefined;
    var p = writeBool(&buf, 0, true);
    p = writeBool(&buf, p, false);
    try std.testing.expectEqual(@as(u8, 0xf5), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xf4), buf[1]);
    try std.testing.expectEqual(@as(usize, 2), p);

    const r1 = try readBool(&buf, 0);
    try std.testing.expectEqual(true, r1.val);
    const r2 = try readBool(&buf, r1.end);
    try std.testing.expectEqual(false, r2.val);
}

// ===========================================================================
// writeNull
// ===========================================================================

test "writeNull: verify byte" {
    var buf: [16]u8 = undefined;
    const end = writeNull(&buf, 0);
    try std.testing.expectEqual(@as(usize, 1), end);
    try std.testing.expectEqual(@as(u8, 0xf6), buf[0]);
    // round-trip
    const read_end = try readNull(&buf, 0);
    try std.testing.expectEqual(end, read_end);
}

// ===========================================================================
// writeCidLink round-trip
// ===========================================================================

test "writeCidLink: round-trip" {
    var buf: [128]u8 = undefined;
    const cid_raw = [_]u8{ 0x01, 0x71, 0x12, 0x20 } ++ [_]u8{0xaa} ** 32;
    const end = writeCidLink(&buf, 0, &cid_raw);
    const result = try readCidLink(&buf, 0);
    try std.testing.expectEqual(@as(usize, 36), result.val.len);
    try std.testing.expectEqualSlices(u8, &cid_raw, result.val);
    try std.testing.expectEqual(end, result.end);
}

// ===========================================================================
// Full record: manually write {"text": "hello", "value": 42} then decodeAll
// ===========================================================================

test "full record: write map then decodeAll" {
    var buf: [128]u8 = undefined;
    // DAG-CBOR sorts keys by length then lex: "text" (4) < "value" (5)
    var p: usize = 0;
    p = writeMapHeader(&buf, p, 2);
    p = writeText(&buf, p, "text");
    p = writeText(&buf, p, "hello");
    p = writeText(&buf, p, "value");
    p = writeUint(&buf, p, 42);

    const encoded = buf[0..p];

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const decoded = try decodeAll(arena.allocator(), encoded);

    try std.testing.expectEqualStrings("hello", decoded.getString("text").?);
    try std.testing.expectEqual(@as(u64, 42), decoded.getUint("value").?);
}
