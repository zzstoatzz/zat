//! merkle search tree (MST)
//!
//! the AT Protocol repository data structure. a deterministic search tree
//! where each key's tree layer is derived from the leading zero bits of
//! SHA-256(key). keys are stored sorted within each node, with subtree
//! pointers interleaved between entries.
//!
//! see: https://atproto.com/specs/repository#mst-structure

const std = @import("std");
const cbor = @import("cbor.zig");
const multibase = @import("multibase.zig");
const Allocator = std.mem.Allocator;

/// compute MST tree layer for a key.
/// layer = count leading zero bits in SHA-256(key), divided by 2, rounded down.
pub fn keyHeight(key: []const u8) u32 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
    var leading_zeros: u32 = 0;
    for (digest) |byte| {
        if (byte == 0) {
            leading_zeros += 8;
        } else {
            leading_zeros += @clz(byte);
            break;
        }
    }
    return leading_zeros / 2;
}

/// byte-level common prefix length between two strings
pub fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const min_len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (a[i] != b[i]) break;
    }
    return i;
}

/// parse a CID string (base32lower multibase, e.g. "bafyrei...")
pub fn parseCidString(allocator: Allocator, s: []const u8) !cbor.Cid {
    if (s.len == 0) return error.InvalidCid;
    // strip 'b' multibase prefix and decode base32lower
    if (s[0] != 'b') return error.UnsupportedEncoding;
    const raw = try multibase.base32lower.decode(allocator, s[1..]);
    return .{ .raw = raw };
}

/// MST node. stores a left subtree pointer and a list of entries.
/// each entry has a key, CID value, and optional right subtree.
const Node = struct {
    left: ?*Node,
    entries: std.ArrayList(Entry),

    const Entry = struct {
        key: []const u8,
        value: cbor.Cid,
        right: ?*Node,
    };

    fn init() Node {
        return .{
            .left = null,
            .entries = .{},
        };
    }
};

/// merkle search tree
pub const Mst = struct {
    allocator: Allocator,
    root: ?*Node,
    root_layer: ?u32,

    pub fn init(allocator: Allocator) Mst {
        return .{
            .allocator = allocator,
            .root = null,
            .root_layer = null,
        };
    }

    /// insert or update a key-value pair
    pub fn put(self: *Mst, key: []const u8, value: cbor.Cid) !void {
        const height = keyHeight(key);

        if (self.root == null) {
            // empty tree: create root at key's height
            const node = try self.createNode();
            try node.entries.append(self.allocator, .{
                .key = try self.allocator.dupe(u8, key),
                .value = value,
                .right = null,
            });
            self.root = node;
            self.root_layer = height;
            return;
        }

        const root_layer = self.root_layer.?;

        if (height > root_layer) {
            // key belongs above the current root — lift
            self.root = try self.insertAbove(self.root.?, root_layer, key, value, height);
            self.root_layer = height;
        } else if (height == root_layer) {
            // key belongs at root layer
            self.root = try self.insertAtLayer(self.root.?, key, value, height);
        } else {
            // key belongs below — recurse into subtree
            try self.insertBelow(self.root.?, root_layer, key, value, height);
        }
    }

    /// look up a key, returning its CID value if present
    pub fn get(self: *const Mst, key: []const u8) ?cbor.Cid {
        return findKey(self.root, self.root_layer orelse return null, key, keyHeight(key));
    }

    fn findKey(maybe_node: ?*Node, layer: u32, key: []const u8, height: u32) ?cbor.Cid {
        const node = maybe_node orelse return null;

        if (height == layer) {
            for (node.entries.items) |entry| {
                const cmp = std.mem.order(u8, key, entry.key);
                if (cmp == .eq) return entry.value;
                if (cmp == .lt) return null;
            }
            return null;
        }

        // height < layer: recurse into the subtree gap containing key
        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) == .lt) {
                const subtree = if (i == 0) node.left else node.entries.items[i - 1].right;
                return findKey(subtree, layer - 1, key, height);
            }
        }
        // after all entries
        const last_right = if (node.entries.items.len > 0)
            node.entries.items[node.entries.items.len - 1].right
        else
            node.left;
        return findKey(last_right, layer - 1, key, height);
    }

    /// delete a key from the tree
    pub fn delete(self: *Mst, key: []const u8) !void {
        if (self.root == null) return;
        try self.deleteFromNode(self.root.?, self.root_layer.?, key);
        // trim: if root has no entries and only left subtree, collapse
        while (self.root) |root| {
            if (root.entries.items.len == 0) {
                if (root.left) |left| {
                    self.root = left;
                    if (self.root_layer.? > 0) {
                        self.root_layer = self.root_layer.? - 1;
                    } else {
                        self.root = null;
                        self.root_layer = null;
                        break;
                    }
                } else {
                    self.root = null;
                    self.root_layer = null;
                    break;
                }
            } else break;
        }
    }

    fn deleteFromNode(self: *Mst, node: *Node, layer: u32, key: []const u8) !void {
        const height = keyHeight(key);

        if (height == layer) {
            // find and remove the entry
            for (node.entries.items, 0..) |entry, i| {
                if (std.mem.eql(u8, entry.key, key)) {
                    // merge left and right subtrees around the deleted entry
                    const left_sub = if (i == 0) node.left else node.entries.items[i - 1].right;
                    const right_sub = entry.right;
                    const merged = try self.mergeSubtrees(left_sub, right_sub);

                    if (i == 0) {
                        node.left = merged;
                    } else {
                        node.entries.items[i - 1].right = merged;
                    }

                    self.allocator.free(entry.key);
                    _ = node.entries.orderedRemove(i);
                    return;
                }
            }
            return; // key not found
        }

        // height < layer: recurse into the appropriate gap
        if (node.entries.items.len == 0) {
            if (node.left) |left| {
                try self.deleteFromNode(left, layer - 1, key);
            }
            return;
        }

        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) == .lt) {
                const subtree = if (i == 0) &node.left else &node.entries.items[i - 1].right;
                if (subtree.*) |sub| {
                    try self.deleteFromNode(sub, layer - 1, key);
                }
                return;
            }
        }
        // after all entries
        const last = &node.entries.items[node.entries.items.len - 1].right;
        if (last.*) |sub| {
            try self.deleteFromNode(sub, layer - 1, key);
        }
    }

    /// merge two subtrees that were separated by a deleted entry.
    /// both nodes are at the same layer. concatenate their entries
    /// and recursively merge if the junction creates adjacent children.
    /// follows the Go reference `appendMerge` / `mergeNodes` algorithm.
    fn mergeSubtrees(self: *Mst, left: ?*Node, right: ?*Node) !?*Node {
        if (left == null) return right;
        if (right == null) return left;

        const l = left.?;
        const r = right.?;

        // create merged node: takes left's `left` pointer and all entries from both
        const merged = try self.createNode();
        merged.left = l.left;

        // copy left entries
        for (l.entries.items) |entry| {
            try merged.entries.append(self.allocator, entry);
        }

        // check junction: last entry of left's `right` vs right's `left`
        if (merged.entries.items.len > 0) {
            const last = &merged.entries.items[merged.entries.items.len - 1];
            if (last.right != null and r.left != null) {
                // both sides of the junction are subtrees — recursively merge
                last.right = try self.mergeSubtrees(last.right, r.left);
            } else if (last.right == null and r.left != null) {
                last.right = r.left;
            }
            // if last.right != null and r.left == null, keep last.right as-is
        } else {
            // left has no entries: junction is merged.left vs r.left
            if (merged.left != null and r.left != null) {
                merged.left = try self.mergeSubtrees(merged.left, r.left);
            } else if (merged.left == null) {
                merged.left = r.left;
            }
        }

        // copy right entries
        for (r.entries.items) |entry| {
            try merged.entries.append(self.allocator, entry);
        }

        return merged;
    }

    const MstError = Allocator.Error;

    /// compute the root CID of the tree
    pub fn rootCid(self: *Mst) MstError!cbor.Cid {
        return self.nodeCid(self.root);
    }

    fn nodeCid(self: *Mst, maybe_node: ?*Node) MstError!cbor.Cid {
        const encoded = try self.serializeNode(maybe_node);
        defer self.allocator.free(encoded);
        return cbor.Cid.forDagCbor(self.allocator, encoded);
    }

    fn serializeNode(self: *Mst, maybe_node: ?*Node) MstError![]u8 {
        const node = maybe_node orelse {
            // empty node: { "l": null, "e": [] }
            return cbor.encodeAlloc(self.allocator, .{ .map = &.{
                .{ .key = "e", .value = .{ .array = &.{} } },
                .{ .key = "l", .value = .null },
            } });
        };

        // compute left subtree CID
        const left_value: cbor.Value = if (node.left) |left| blk: {
            const left_cid = try self.nodeCid(left);
            break :blk .{ .cid = left_cid };
        } else .null;

        // build entry array with prefix compression
        var entry_values: std.ArrayList(cbor.Value) = .{};
        defer entry_values.deinit(self.allocator);

        var prev_key: []const u8 = "";
        for (node.entries.items) |entry| {
            const prefix_len = commonPrefixLen(prev_key, entry.key);
            const suffix = entry.key[prefix_len..];

            // right subtree CID
            const tree_val: cbor.Value = if (entry.right) |right| blk: {
                const right_cid = try self.nodeCid(right);
                break :blk .{ .cid = right_cid };
            } else .null;

            // allocate map entries on heap (stack-local &.{...} would alias across iterations)
            const map_entries = try self.allocator.alloc(cbor.Value.MapEntry, 4);
            map_entries[0] = .{ .key = "k", .value = .{ .bytes = suffix } };
            map_entries[1] = .{ .key = "p", .value = .{ .unsigned = prefix_len } };
            map_entries[2] = .{ .key = "t", .value = tree_val };
            map_entries[3] = .{ .key = "v", .value = .{ .cid = entry.value } };

            try entry_values.append(self.allocator, .{ .map = map_entries });

            prev_key = entry.key;
        }

        const entries_slice = try self.allocator.dupe(cbor.Value, entry_values.items);
        defer self.allocator.free(entries_slice);

        return cbor.encodeAlloc(self.allocator, .{ .map = &.{
            .{ .key = "e", .value = .{ .array = entries_slice } },
            .{ .key = "l", .value = left_value },
        } });
    }

    // === internal helpers ===

    fn createNode(self: *Mst) !*Node {
        const node = try self.allocator.create(Node);
        node.* = Node.init();
        return node;
    }

    /// insert a key that belongs above the current root.
    /// splits the tree at its own layer, wraps each half in parent nodes
    /// to bridge the layer gap, then assembles the new root.
    fn insertAbove(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_layer: u32) !*Node {
        // 1. split the tree at its current layer around the key
        const splits = try self.splitNode(node, key);
        var left = splits.left;
        var right = splits.right;

        // 2. wrap each half in parent layers (bridge the gap)
        // "extraLayersToAdd = keyZeros - layer"
        // "intentionally starting at 1, since first layer is taken care of by split"
        const extra_layers = target_layer - node_layer;
        var i: u32 = 1;
        while (i < extra_layers) : (i += 1) {
            if (left) |l| {
                const parent = try self.createNode();
                parent.left = l;
                left = parent;
            }
            if (right) |r| {
                const parent = try self.createNode();
                parent.left = r;
                right = parent;
            }
        }

        // 3. assemble new root: [left_tree, key_leaf, right_tree]
        const new_root = try self.createNode();
        new_root.left = left;
        try new_root.entries.append(self.allocator, .{
            .key = try self.allocator.dupe(u8, key),
            .value = value,
            .right = right,
        });
        return new_root;
    }

    /// insert a key at the same layer as the node
    fn insertAtLayer(self: *Mst, node: *Node, key: []const u8, value: cbor.Cid, layer: u32) !*Node {
        _ = layer;
        // find insertion position
        var insert_idx: usize = node.entries.items.len;
        for (node.entries.items, 0..) |entry, i| {
            const cmp = std.mem.order(u8, key, entry.key);
            if (cmp == .eq) {
                // update existing
                node.entries.items[i].value = value;
                return node;
            }
            if (cmp == .lt) {
                insert_idx = i;
                break;
            }
        }

        // split the subtree that spans the insertion gap
        const gap_subtree = if (insert_idx == 0) node.left else node.entries.items[insert_idx - 1].right;

        var left_split: ?*Node = null;
        var right_split: ?*Node = null;

        if (gap_subtree) |subtree| {
            const splits = try self.splitNode(subtree, key);
            left_split = splits.left;
            right_split = splits.right;
        }

        // update the pointer before the gap
        if (insert_idx == 0) {
            node.left = left_split;
        } else {
            node.entries.items[insert_idx - 1].right = left_split;
        }

        // insert the new entry
        try node.entries.insert(self.allocator, insert_idx, .{
            .key = try self.allocator.dupe(u8, key),
            .value = value,
            .right = right_split,
        });

        return node;
    }

    /// insert a key below the current node's layer
    fn insertBelow(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32) !void {
        // find which gap the key falls into
        for (node.entries.items, 0..) |entry, i| {
            const cmp = std.mem.order(u8, key, entry.key);
            if (cmp == .eq) {
                // update existing
                node.entries.items[i].value = value;
                return;
            }
            if (cmp == .lt) {
                // key goes in the gap before this entry
                const subtree_ptr = if (i == 0) &node.left else &node.entries.items[i - 1].right;
                try self.insertIntoGap(subtree_ptr, node_layer - 1, key, value, target_height);
                return;
            }
        }
        // key goes after all entries
        const last_ptr = if (node.entries.items.len > 0)
            &node.entries.items[node.entries.items.len - 1].right
        else
            &node.left;
        try self.insertIntoGap(last_ptr, node_layer - 1, key, value, target_height);
    }

    fn insertIntoGap(self: *Mst, subtree_ptr: *?*Node, gap_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32) MstError!void {
        if (target_height == gap_layer) {
            // insert at this layer
            if (subtree_ptr.*) |existing| {
                subtree_ptr.* = try self.insertAtLayer(existing, key, value, gap_layer);
            } else {
                const new_node = try self.createNode();
                try new_node.entries.append(self.allocator, .{
                    .key = try self.allocator.dupe(u8, key),
                    .value = value,
                    .right = null,
                });
                subtree_ptr.* = new_node;
            }
        } else if (target_height > gap_layer) {
            // need to lift — split and wrap
            if (subtree_ptr.*) |existing| {
                subtree_ptr.* = try self.insertAbove(existing, gap_layer, key, value, target_height);
            } else {
                const new_node = try self.createNode();
                try new_node.entries.append(self.allocator, .{
                    .key = try self.allocator.dupe(u8, key),
                    .value = value,
                    .right = null,
                });
                subtree_ptr.* = new_node;
            }
        } else {
            // target_height < gap_layer: recurse deeper
            if (subtree_ptr.*) |existing| {
                try self.insertBelow(existing, gap_layer, key, value, target_height);
            } else {
                // create node at gap_layer and recurse
                const new_node = try self.createNode();
                subtree_ptr.* = new_node;
                try self.insertBelow(new_node, gap_layer, key, value, target_height);
            }
        }
    }

    /// split a subtree around a key: everything < key goes left, everything >= key goes right.
    /// follows the Go reference: find split point among leaf entries, then recursively
    /// split the subtree in the gap if needed.
    fn splitNode(self: *Mst, node: *Node, key: []const u8) !struct { left: ?*Node, right: ?*Node } {
        // find the first entry >= key
        var split_idx: usize = node.entries.items.len;
        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) != .gt) {
                split_idx = i;
                break;
            }
        }

        // left gets entries [0..split_idx), right gets entries [split_idx..]
        var left_node = try self.createNode();
        var right_node = try self.createNode();

        // left node takes the original node's left subtree
        left_node.left = node.left;

        // copy entries to left
        for (node.entries.items[0..split_idx]) |entry| {
            try left_node.entries.append(self.allocator, entry);
        }

        // copy entries to right
        for (node.entries.items[split_idx..]) |entry| {
            try right_node.entries.append(self.allocator, entry);
        }

        // the subtree between the last left entry and first right entry may need recursive splitting.
        // in our representation: this is the right pointer of the last left entry (or left's left if no entries)
        // for the right node, its "left" is initially null — we need to set it from the gap.

        // split the gap subtree between the two halves
        if (left_node.entries.items.len > 0) {
            const last_left = &left_node.entries.items[left_node.entries.items.len - 1];
            if (last_left.right) |gap_subtree| {
                const sub_split = try self.splitNode(gap_subtree, key);
                last_left.right = sub_split.left;
                right_node.left = sub_split.right;
            }
        } else if (left_node.left != null and split_idx == 0) {
            // all entries went right — the gap is the original node's left subtree
            const sub_split = try self.splitNode(left_node.left.?, key);
            left_node.left = sub_split.left;
            right_node.left = sub_split.right;
        }

        const left_result: ?*Node = if (left_node.entries.items.len > 0 or left_node.left != null) left_node else null;
        const right_result: ?*Node = if (right_node.entries.items.len > 0 or right_node.left != null) right_node else null;

        return .{ .left = left_result, .right = right_result };
    }
};

// === tests ===

test "keyHeight" {
    // values from interop test fixtures
    try std.testing.expectEqual(@as(u32, 0), keyHeight(""));
    try std.testing.expectEqual(@as(u32, 0), keyHeight("asdf"));
    try std.testing.expectEqual(@as(u32, 1), keyHeight("blue"));
    try std.testing.expectEqual(@as(u32, 0), keyHeight("2653ae71"));
    try std.testing.expectEqual(@as(u32, 2), keyHeight("88bfafc7"));
    try std.testing.expectEqual(@as(u32, 4), keyHeight("2a92d355"));
    try std.testing.expectEqual(@as(u32, 6), keyHeight("884976f5"));
    try std.testing.expectEqual(@as(u32, 4), keyHeight("app.bsky.feed.post/454397e440ec"));
    try std.testing.expectEqual(@as(u32, 8), keyHeight("app.bsky.feed.post/9adeb165882c"));
}

test "commonPrefixLen" {
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("", ""));
    try std.testing.expectEqual(@as(usize, 3), commonPrefixLen("abc", "abc"));
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("", "abc"));
    try std.testing.expectEqual(@as(usize, 2), commonPrefixLen("ab", "abc"));
    try std.testing.expectEqual(@as(usize, 3), commonPrefixLen("abcde", "abc"));
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("abcde", "qbb"));
}

test "put and get" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);

    const cid1 = try cbor.Cid.forDagCbor(a, "value1");
    const cid2 = try cbor.Cid.forDagCbor(a, "value2");

    try tree.put("key1", cid1);
    try tree.put("key2", cid2);

    const got1 = tree.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid1.raw, got1.raw);

    const got2 = tree.get("key2") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid2.raw, got2.raw);

    try std.testing.expect(tree.get("nonexistent") == null);
}

test "put and delete" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid = try cbor.Cid.forDagCbor(a, "value");

    try tree.put("key1", cid);
    try tree.put("key2", cid);

    try std.testing.expect(tree.get("key1") != null);
    try tree.delete("key1");
    try std.testing.expect(tree.get("key1") == null);
    try std.testing.expect(tree.get("key2") != null);
}

test "rootCid is deterministic" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid_val = try cbor.Cid.forDagCbor(a, "leaf");

    // build tree 1
    var tree1 = Mst.init(a);
    try tree1.put("a", cid_val);
    try tree1.put("b", cid_val);
    const root1 = try tree1.rootCid();

    // build tree 2 (same keys, same order)
    var tree2 = Mst.init(a);
    try tree2.put("a", cid_val);
    try tree2.put("b", cid_val);
    const root2 = try tree2.rootCid();

    try std.testing.expectEqualSlices(u8, root1.raw, root2.raw);
}

test "empty tree rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const root = try tree.rootCid();
    try std.testing.expectEqual(@as(u64, 1), root.version().?);

    // known empty tree CID from Go reference implementation
    const expected = try parseCidString(a, "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "single key rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    // use a known CID value (the leaf CID from commit-proof fixtures)
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // single layer-0 key
    try tree.put("com.example.record/3jqfcqzm3fo2j", leaf_cid);

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "single layer-2 key rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // single layer-2 key
    try tree.put("com.example.record/3jqfcqzm3fx2j", leaf_cid);

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "5 key tree matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // 5 keys from Go test (note: last key has 4fc not 3ft)
    const keys = [_][]const u8{
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j",
    };

    for (keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "two deep split fixture" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    var tree = Mst.init(a);
    const initial_keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (initial_keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const expected_before = try parseCidString(a, "bafyreicraprx2xwnico4tuqir3ozsxpz46qkcpox3obf5bagicqwurghpy");
    try std.testing.expectEqualSlices(u8, expected_before.raw, (try tree.rootCid()).raw);

    try tree.put("D2/269196", leaf_cid);

    const expected_after = try parseCidString(a, "bafyreihvay6pazw3dfa47u5d2tn3rd6pa57sr37bo5bqyvjuqc73ib65my");
    try std.testing.expectEqualSlices(u8, expected_after.raw, (try tree.rootCid()).raw);
}

test "complex multi-op commit" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    var tree = Mst.init(a);
    const initial_keys = [_][]const u8{
        "B0/601692", "C2/014073", "D0/952776",
        "E2/819540", "F0/697858", "H0/131238",
    };
    for (initial_keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const expected_before = try parseCidString(a, "bafyreigr3plnts7dax6yokvinbhcqpyicdfgg6npvvyx6okc5jo55slfqi");
    try std.testing.expectEqualSlices(u8, expected_before.raw, (try tree.rootCid()).raw);

    // adds
    try tree.put("A2/827942", leaf_cid);
    try tree.put("G2/611528", leaf_cid);
    // del
    try tree.delete("C2/014073");

    const expected_after = try parseCidString(a, "bafyreiftrcrbhrwmi37u4egedlg56gk3jeh3tvmqvwgowoifuklfysyx54");
    try std.testing.expectEqualSlices(u8, expected_after.raw, (try tree.rootCid()).raw);
}

test "parseCidString" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(@as(u64, 0x71), cid.codec().?);
    try std.testing.expectEqual(@as(u64, 0x12), cid.hashFn().?);
    try std.testing.expectEqual(@as(usize, 32), cid.digest().?.len);
}
