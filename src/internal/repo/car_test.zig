//! additional CAR v1 codec tests ported from atmos (Go implementation).
//!
//! focuses on error paths, validation, and edge cases not covered
//! by the inline tests in car.zig.

const std = @import("std");
const car = @import("car.zig");
const cbor = @import("cbor.zig");

// === header validation ===

test "reject CAR with version 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build header with version: 0
    const root_cid = try cbor.Cid.forDagCbor(alloc, "data");
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{.{ .cid = root_cid }} } },
        .{ .key = "version", .value = .{ .unsigned = 0 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    try std.testing.expectError(error.InvalidHeader, car.read(alloc, car_aw.written()));
}

test "reject CAR with version 2" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const root_cid = try cbor.Cid.forDagCbor(alloc, "data");
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{.{ .cid = root_cid }} } },
        .{ .key = "version", .value = .{ .unsigned = 2 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    try std.testing.expectError(error.InvalidHeader, car.read(alloc, car_aw.written()));
}

test "reject CAR with missing version field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const root_cid = try cbor.Cid.forDagCbor(alloc, "data");
    // header with roots but no version
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{.{ .cid = root_cid }} } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    try std.testing.expectError(error.InvalidHeader, car.read(alloc, car_aw.written()));
}

test "reject CAR with missing roots field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // header with version but no roots
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "version", .value = .{ .unsigned = 1 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    try std.testing.expectError(error.InvalidHeader, car.read(alloc, car_aw.written()));
}

test "reject CAR with empty roots array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // header with empty roots: []
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{} } },
        .{ .key = "version", .value = .{ .unsigned = 1 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    try std.testing.expectError(error.InvalidHeader, car.read(alloc, car_aw.written()));
}

// === input edge cases ===

test "reject empty input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidVarint, car.read(arena.allocator(), &.{}));
}

test "reject truncated header varint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // 0x80 = continuation byte, needs more data
    try std.testing.expectError(error.InvalidVarint, car.read(arena.allocator(), &.{0x80}));
}

test "reject truncated header data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // header_len = 50 but only 3 bytes of data follow
    try std.testing.expectError(error.UnexpectedEof, car.read(arena.allocator(), &.{ 0x32, 0xaa, 0xbb, 0xcc }));
}

// === block edge cases ===

test "reject block with truncated data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build a valid CAR with one block, then truncate the block data
    const data = try cbor.encodeAlloc(alloc, .{ .map = &.{
        .{ .key = "x", .value = .{ .unsigned = 1 } },
    } });
    const cid = try cbor.Cid.forDagCbor(alloc, data);
    const car_bytes = try car.writeAlloc(alloc, .{
        .roots = &.{cid},
        .blocks = &.{.{ .cid_raw = cid.raw, .data = data }},
    });

    // truncate the last 5 bytes (removing part of block data)
    const truncated = car_bytes[0 .. car_bytes.len - 5];
    try std.testing.expectError(error.UnexpectedEof, car.read(alloc, truncated));
}

// === round-trip determinism ===

test "write then read then write produces identical bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a multi-block CAR
    const data1 = try cbor.encodeAlloc(alloc, .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "first block" } },
    } });
    const data2 = try cbor.encodeAlloc(alloc, .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "second block" } },
    } });
    const cid1 = try cbor.Cid.forDagCbor(alloc, data1);
    const cid2 = try cbor.Cid.forDagCbor(alloc, data2);

    const original = car.Car{
        .roots = &.{cid1},
        .blocks = &.{
            .{ .cid_raw = cid1.raw, .data = data1 },
            .{ .cid_raw = cid2.raw, .data = data2 },
        },
    };

    // write → read → write
    const first_write = try car.writeAlloc(alloc, original);
    const parsed = try car.read(alloc, first_write);
    const second_write = try car.writeAlloc(alloc, parsed);

    try std.testing.expectEqualSlices(u8, first_write, second_write);
}

// === multiple roots ===

test "round-trip with multiple roots" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data1 = "block one";
    const data2 = "block two";
    const cid1 = try cbor.Cid.forDagCbor(alloc, data1);
    const cid2 = try cbor.Cid.forDagCbor(alloc, data2);

    const original = car.Car{
        .roots = &.{ cid1, cid2 },
        .blocks = &.{
            .{ .cid_raw = cid1.raw, .data = data1 },
            .{ .cid_raw = cid2.raw, .data = data2 },
        },
    };

    const car_bytes = try car.writeAlloc(alloc, original);
    const parsed = try car.read(alloc, car_bytes);

    try std.testing.expectEqual(@as(usize, 2), parsed.roots.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.blocks.len);
    try std.testing.expectEqualSlices(u8, cid1.digest().?, parsed.roots[0].digest().?);
    try std.testing.expectEqualSlices(u8, cid2.digest().?, parsed.roots[1].digest().?);
}

// === CID integrity ===

test "reject single-bit corruption in block data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data = try cbor.encodeAlloc(alloc, .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "original data" } },
    } });
    const cid = try cbor.Cid.forDagCbor(alloc, data);

    // write valid CAR, then flip one bit in block content
    const car_bytes = try car.writeAlloc(alloc, .{
        .roots = &.{cid},
        .blocks = &.{.{ .cid_raw = cid.raw, .data = data }},
    });

    // find the block data in the CAR and corrupt it
    var corrupted = try alloc.dupe(u8, car_bytes);
    corrupted[corrupted.len - 1] ^= 0x01; // flip last bit

    try std.testing.expectError(error.BadBlockHash, car.read(alloc, corrupted));
}

// === findBlock ===

test "findBlock via hash index" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data = "test block";
    const cid = try cbor.Cid.forDagCbor(alloc, data);

    const car_bytes = try car.writeAlloc(alloc, .{
        .roots = &.{cid},
        .blocks = &.{.{ .cid_raw = cid.raw, .data = data }},
    });
    const parsed = try car.read(alloc, car_bytes);

    // lookup by CID should return block data
    const found = car.findBlock(parsed, cid.raw).?;
    try std.testing.expectEqualSlices(u8, data, found);

    // lookup with wrong CID should return null
    const other_cid = try cbor.Cid.forDagCbor(alloc, "other");
    try std.testing.expect(car.findBlock(parsed, other_cid.raw) == null);
}

// === size limits ===

test "reject CAR exceeding max size" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // tiny CAR, but set max_size very small
    const data = "x";
    const cid = try cbor.Cid.forDagCbor(alloc, data);
    const car_bytes = try car.writeAlloc(alloc, .{
        .roots = &.{cid},
        .blocks = &.{.{ .cid_raw = cid.raw, .data = data }},
    });

    // set max_size smaller than the CAR
    try std.testing.expectError(error.BlocksTooLarge, car.readWithOptions(alloc, car_bytes, .{
        .max_size = 10,
    }));
}

// === varint edge cases (via CAR reader) ===

test "readUvarint rejects varint longer than 10 bytes" {
    // 10 continuation bytes + 1 terminator = 11 bytes total
    const data = [_]u8{0x80} ** 10 ++ [_]u8{0x00};
    var pos: usize = 0;
    try std.testing.expect(cbor.readUvarint(&data, &pos) == null);
}

test "readUvarint accepts 10-byte varint" {
    // max valid: 9 continuation bytes + 1 terminator with bit 0 set
    const data = [_]u8{0x80} ** 9 ++ [_]u8{0x01};
    var pos: usize = 0;
    const val = cbor.readUvarint(&data, &pos);
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(usize, 10), pos);
}

// === header-only CAR (roots, no blocks) ===

test "CAR with roots but no blocks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const root_cid = try cbor.Cid.forDagCbor(alloc, "root");
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "roots", .value = .{ .array = &.{.{ .cid = root_cid }} } },
        .{ .key = "version", .value = .{ .unsigned = 1 } },
    } };
    const header_bytes = try cbor.encodeAlloc(alloc, header);

    var car_aw: std.Io.Writer.Allocating = .init(alloc);
    try cbor.writeUvarint(&car_aw.writer, header_bytes.len);
    try car_aw.writer.writeAll(header_bytes);

    const parsed = try car.read(alloc, car_aw.written());
    try std.testing.expectEqual(@as(usize, 1), parsed.roots.len);
    try std.testing.expectEqual(@as(usize, 0), parsed.blocks.len);
}

// note: checkAllAllocationFailures cannot be used for car.read because
// readWithOptions uses an internal ArenaAllocator for header CBOR parsing,
// which creates non-deterministic page-level allocations from the backing
// allocator. the errdefer cleanup on roots/blocks/block_index in
// readWithOptions ensures no leaks on OOM; the header arena's defer deinit
// ensures the header Value tree is always freed.
