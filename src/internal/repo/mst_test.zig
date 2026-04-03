//! additional MST tests ported from atmos (Go implementation).
//!
//! focuses on edge cases, stress tests, and compliance gaps not covered
//! by the inline tests in mst.zig.

const std = @import("std");
const mst = @import("mst.zig");
const cbor = @import("cbor.zig");
const Mst = mst.Mst;
const Cid = cbor.Cid;

// known empty tree CID from the AT Protocol reference implementations
const empty_tree_cid = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";

fn testCid(a: std.mem.Allocator, data: []const u8) !Cid {
    return Cid.forDagCbor(a, data);
}

// === edge cases ===

test "get from empty tree returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const tree = Mst.init(a);
    try std.testing.expect(tree.get("anything") == null);
    try std.testing.expect(tree.get("app.bsky.feed.post/abc123") == null);
}

test "delete nonexistent key is no-op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid = try testCid(a, "value");
    try tree.put("key1", cid);

    // deleting a key that doesn't exist should not error
    try tree.delete("nonexistent");

    // original key still present
    try std.testing.expect(tree.get("key1") != null);
}

test "remove all keys produces empty tree CID" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid = try testCid(a, "value");

    try tree.put("key1", cid);
    try tree.put("key2", cid);
    try tree.put("key3", cid);

    try tree.delete("key1");
    try tree.delete("key2");
    try tree.delete("key3");

    const root = try tree.rootCid();
    const expected = try mst.parseCidString(a, empty_tree_cid);
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "update existing key changes value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid1 = try testCid(a, "v1");
    const cid2 = try testCid(a, "v2");

    try tree.put("key", cid1);
    try std.testing.expectEqualSlices(u8, cid1.raw, tree.get("key").?.raw);

    try tree.put("key", cid2);
    try std.testing.expectEqualSlices(u8, cid2.raw, tree.get("key").?.raw);
}

// === order independence ===

test "order independence: 50 keys in 3 orderings produce same root CID" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // generate 50 deterministic keys
    const n = 50;
    var keys: [n][]const u8 = undefined;
    var key_bufs: [n][64]u8 = undefined;
    for (0..n) |i| {
        const len = std.fmt.bufPrint(&key_bufs[i], "app.bsky.feed.post/{d:0>12}", .{i}) catch unreachable;
        keys[i] = len;
    }

    const val = try testCid(a, "value");

    // forward order
    var tree1 = Mst.init(a);
    for (keys) |k| try tree1.put(k, val);
    const cid1 = try tree1.rootCid();

    // reverse order
    var tree2 = Mst.init(a);
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        try tree2.put(keys[i], val);
    }
    const cid2 = try tree2.rootCid();

    // interleaved order (even indices first, then odd)
    var tree3 = Mst.init(a);
    for (0..n) |j| {
        if (j % 2 == 0) try tree3.put(keys[j], val);
    }
    for (0..n) |j| {
        if (j % 2 == 1) try tree3.put(keys[j], val);
    }
    const cid3 = try tree3.rootCid();

    try std.testing.expectEqualSlices(u8, cid1.raw, cid2.raw);
    try std.testing.expectEqualSlices(u8, cid1.raw, cid3.raw);
}

// === stress tests ===

test "100 keys: all retrievable after insertion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const n = 100;
    var tree = Mst.init(a);
    var key_bufs: [n][64]u8 = undefined;
    var keys: [n][]const u8 = undefined;
    var cids: [n]Cid = undefined;

    for (0..n) |i| {
        keys[i] = std.fmt.bufPrint(&key_bufs[i], "app.bsky.feed.post/{d:0>12}", .{i}) catch unreachable;
        cids[i] = try testCid(a, keys[i]);
        try tree.put(keys[i], cids[i]);
    }

    // all keys retrievable with correct CIDs
    for (0..n) |i| {
        const got = tree.get(keys[i]) orelse {
            std.debug.print("FAIL: key {s} not found after insert\n", .{keys[i]});
            return error.TestExpectedEqual;
        };
        try std.testing.expectEqualSlices(u8, cids[i].raw, got.raw);
    }
}

test "insert 50 keys then remove every other" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const n = 50;
    var tree = Mst.init(a);
    var key_bufs: [n][64]u8 = undefined;
    var keys: [n][]const u8 = undefined;
    const val = try testCid(a, "value");

    for (0..n) |i| {
        keys[i] = std.fmt.bufPrint(&key_bufs[i], "app.bsky.feed.post/{d:0>12}", .{i}) catch unreachable;
        try tree.put(keys[i], val);
    }

    // remove even-indexed keys
    for (0..n) |i| {
        if (i % 2 == 0) try tree.delete(keys[i]);
    }

    // verify: even keys gone, odd keys present
    for (0..n) |i| {
        const got = tree.get(keys[i]);
        if (i % 2 == 0) {
            try std.testing.expect(got == null);
        } else {
            try std.testing.expect(got != null);
        }
    }
}

// === height edge cases ===

test "keyHeight: empty key has height 0" {
    try std.testing.expectEqual(@as(u32, 0), mst.keyHeight(""));
}

test "keyHeight: deterministic for same input" {
    const h1 = mst.keyHeight("app.bsky.feed.post/3jqfcqzm3fo2j");
    const h2 = mst.keyHeight("app.bsky.feed.post/3jqfcqzm3fo2j");
    try std.testing.expectEqual(h1, h2);
}

test "keyHeight: different keys can have different heights" {
    // "blue" is known to have height 1 from the interop fixtures
    try std.testing.expectEqual(@as(u32, 1), mst.keyHeight("blue"));
    try std.testing.expectEqual(@as(u32, 0), mst.keyHeight("asdf"));
}
