//! merkle search tree (MST)
//!
//! the AT Protocol repository data structure. a deterministic search tree
//! where each key's tree layer is derived from the leading zero bits of
//! SHA-256(key). keys are stored sorted within each node, with subtree
//! pointers interleaved between entries.
//!
//! supports partial and lazy trees for sync 1.1 and repo mutation: nodes not
//! present in memory are represented as stubs (known CID, no block data).
//! when a block reader is attached, operations resolve stubs on demand.
//!
//! see: https://atproto.com/specs/repository#mst-structure

const std = @import("std");
const cbor = @import("cbor.zig");
const car = @import("car.zig");
const multibase = @import("../crypto/multibase.zig");
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

/// Lexicographic byte ordering for MST keys.
///
/// `std.mem.order(u8, ...)` is intentionally generic and scalar. MST lookup is
/// dominated by key comparisons, and ATProto keys often share long prefixes, so
/// compare eight bytes at a time while preserving byte-order semantics.
fn keyOrder(a: []const u8, b: []const u8) std.math.Order {
    if (a.ptr != b.ptr) {
        const min_len = @min(a.len, b.len);
        var i: usize = 0;
        while (i + 8 <= min_len) : (i += 8) {
            const a_word = std.mem.readInt(u64, a[i..][0..8], .big);
            const b_word = std.mem.readInt(u64, b[i..][0..8], .big);
            if (a_word != b_word) return std.math.order(a_word, b_word);
        }
        while (i < min_len) : (i += 1) {
            if (a[i] != b[i]) return std.math.order(a[i], b[i]);
        }
    }
    return std.math.order(a.len, b.len);
}

fn keyEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.ptr == b.ptr) return true;
    var i: usize = 0;
    while (i + 8 <= a.len) : (i += 8) {
        const a_word = std.mem.readInt(u64, a[i..][0..8], .big);
        const b_word = std.mem.readInt(u64, b[i..][0..8], .big);
        if (a_word != b_word) return false;
    }
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

/// parse a CID string (base32lower multibase, e.g. "bafyrei...")
pub fn parseCidString(allocator: Allocator, s: []const u8) !cbor.Cid {
    if (s.len == 0) return error.InvalidCid;
    // strip 'b' multibase prefix and decode base32lower
    if (s[0] != 'b') return error.UnsupportedEncoding;
    const raw = try multibase.base32lower.decode(allocator, s[1..]);
    return .{ .raw = raw };
}

/// content-addressed block reader used by lazy MST loading.
///
/// The returned block bytes only need to live for the duration of the call:
/// MST loading copies all keys and CID bytes it retains.
pub const BlockReader = struct {
    ctx: *anyopaque,
    getFn: *const fn (ctx: *anyopaque, cid_raw: []const u8) anyerror!?[]const u8,

    pub fn get(self: BlockReader, cid_raw: []const u8) anyerror!?[]const u8 {
        return self.getFn(self.ctx, cid_raw);
    }
};

/// MST node. stores a left subtree pointer and a list of entries.
/// each entry has a key, CID value, and optional right subtree.
pub const Node = struct {
    left: ?*Node,
    entries: std.ArrayList(Entry),
    layer: u32,
    dirty: bool,
    cid: ?cbor.Cid,

    pub const Entry = struct {
        key: []const u8,
        right: ?*Node,
        value: cbor.Cid,
    };

    fn init(layer: u32, dirty: bool) Node {
        return .{
            .left = null,
            .entries = .empty,
            .layer = layer,
            .dirty = dirty,
            .cid = null,
        };
    }
};

/// an operation on the MST (create, update, or delete a record)
pub const Operation = struct {
    path: []const u8, // "collection/rkey"
    value: ?[]const u8, // raw CID bytes — non-null for create/update
    prev: ?[]const u8, // raw CID bytes — non-null for update/delete

    fn isCreate(self: Operation) bool {
        return self.value != null and self.prev == null;
    }

    fn isDelete(self: Operation) bool {
        return self.value == null and self.prev != null;
    }

    fn isUpdate(self: Operation) bool {
        return self.value != null and self.prev != null;
    }
};

/// merkle search tree
pub const Mst = struct {
    allocator: Allocator,
    root: ?*Node,
    root_layer: ?u32,
    block_reader: ?BlockReader,

    pub fn init(allocator: Allocator) Mst {
        return .{
            .allocator = allocator,
            .root = null,
            .root_layer = null,
            .block_reader = null,
        };
    }

    /// load an MST lazily from a root CID and block reader.
    ///
    /// This mirrors Atmos's `LoadTree(store, root)`: construction does not
    /// fetch storage. The root block is loaded only when an operation needs it.
    pub fn loadLazy(allocator: Allocator, root_cid_raw: []const u8, block_reader: BlockReader) !Mst {
        return .{
            .allocator = allocator,
            .root = try createStubNode(allocator, root_cid_raw, null),
            .root_layer = null,
            .block_reader = block_reader,
        };
    }

    /// insert or update a key-value pair
    pub fn put(self: *Mst, key: []const u8, value: cbor.Cid) !void {
        _ = try self.putReturn(key, value);
    }

    /// insert or update a key-value pair without copying the key bytes.
    ///
    /// The key must outlive the tree.
    pub fn putBorrowed(self: *Mst, key: []const u8, value: cbor.Cid) !void {
        _ = try self.putReturnInternal(key, value, false);
    }

    /// insert or update a key-value pair, returning the previous value CID if it existed
    pub fn putReturn(self: *Mst, key: []const u8, value: cbor.Cid) !?cbor.Cid {
        return try self.putReturnInternal(key, value, true);
    }

    fn putReturnInternal(self: *Mst, key: []const u8, value: cbor.Cid, copy_key: bool) !?cbor.Cid {
        try self.ensureRootLoaded();
        const height = keyHeight(key);

        if (self.root == null) {
            // empty tree: create root at key's height
            const node = try self.createNode(height);
            try node.entries.append(self.allocator, .{
                .key = try self.storeKey(key, copy_key),
                .value = value,
                .right = null,
            });
            self.root = node;
            self.root_layer = height;
            return null;
        }

        const root_layer = self.root_layer.?;

        if (height > root_layer) {
            // key belongs above the current root — lift (new key, never an update)
            self.root = try self.insertAbove(self.root.?, root_layer, key, value, height, copy_key);
            self.root_layer = height;
            return null;
        } else if (height == root_layer) {
            // key belongs at root layer
            var prev: ?cbor.Cid = null;
            self.root = try self.insertAtLayer(self.root.?, key, value, height, &prev, copy_key);
            return prev;
        } else {
            // key belongs below — recurse into subtree
            return try self.insertBelow(self.root.?, root_layer, key, value, height, copy_key);
        }
    }

    /// look up a key, returning its CID value if present
    pub fn get(self: *const Mst, key: []const u8) ?cbor.Cid {
        return findKey(self.root, self.root_layer orelse return null, key, keyHeight(key));
    }

    /// look up a key when its MST height has already been computed.
    pub fn getWithHeight(self: *const Mst, key: []const u8, height: u32) ?cbor.Cid {
        return findKey(self.root, self.root_layer orelse return null, key, height);
    }

    /// look up a key, resolving lazy stubs on demand.
    pub fn getLazy(self: *Mst, key: []const u8) !?cbor.Cid {
        try self.ensureRootLoaded();
        return try self.findKeyLazy(self.root, self.root_layer orelse return null, key, keyHeight(key));
    }

    fn entryLowerBound(entries: []const Node.Entry, key: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (keyOrder(entries[mid].key, key) == .lt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    fn childAtIndex(node: *Node, idx: usize) *?*Node {
        return if (idx == 0) &node.left else &node.entries.items[idx - 1].right;
    }

    fn childAtIndexConst(node: *const Node, idx: usize) ?*Node {
        return if (idx == 0) node.left else node.entries.items[idx - 1].right;
    }

    fn findKey(maybe_node: ?*Node, layer: u32, key: []const u8, height: u32) ?cbor.Cid {
        const node = maybe_node orelse return null;

        if (height >= layer) {
            for (node.entries.items) |entry| {
                switch (keyOrder(key, entry.key)) {
                    .lt => return null,
                    .eq => return entry.value,
                    .gt => {},
                }
            }
            return null;
        }

        if (layer == 0) return null;
        for (node.entries.items, 0..) |entry, i| {
            switch (keyOrder(key, entry.key)) {
                .lt => {
                    const child = if (i == 0) node.left else node.entries.items[i - 1].right;
                    return findKey(child, layer - 1, key, height);
                },
                .eq => return entry.value,
                .gt => {},
            }
        }

        const child = if (node.entries.items.len > 0)
            node.entries.items[node.entries.items.len - 1].right
        else
            node.left;
        return findKey(child, layer - 1, key, height);
    }

    fn findKeyLazy(self: *Mst, maybe_node: ?*Node, layer: u32, key: []const u8, height: u32) !?cbor.Cid {
        const node = maybe_node orelse return null;

        if (height >= layer) {
            for (node.entries.items) |entry| {
                switch (keyOrder(key, entry.key)) {
                    .lt => return null,
                    .eq => return entry.value,
                    .gt => {},
                }
            }
            return null;
        }

        if (layer == 0) return null;
        for (node.entries.items, 0..) |entry, i| {
            switch (keyOrder(key, entry.key)) {
                .lt => {
                    const child_ref = if (i == 0) &node.left else &node.entries.items[i - 1].right;
                    if (try self.ensureChildNode(child_ref)) |child|
                        return try self.findKeyLazy(child, layer - 1, key, height)
                    else
                        return null;
                },
                .eq => return entry.value,
                .gt => {},
            }
        }

        const child_ref = if (node.entries.items.len > 0)
            &node.entries.items[node.entries.items.len - 1].right
        else
            &node.left;
        if (try self.ensureChildNode(child_ref)) |child|
            return try self.findKeyLazy(child, layer - 1, key, height)
        else
            return null;
    }

    /// delete a key from the tree
    pub fn delete(self: *Mst, key: []const u8) !void {
        _ = try self.deleteReturn(key);
    }

    /// delete a key from the tree, returning the removed value CID if it existed
    pub fn deleteReturn(self: *Mst, key: []const u8) !?cbor.Cid {
        try self.ensureRootLoaded();
        if (self.root == null) return null;
        const prev = try self.deleteFromNode(self.root.?, self.root_layer.?, key);
        // trim: if root has no entries and only left subtree, collapse
        while (self.root) |root| {
            if (root.entries.items.len == 0) {
                if (try self.ensureChildNode(&root.left)) |left| {
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
        return prev;
    }

    fn deleteFromNode(self: *Mst, node: *Node, layer: u32, key: []const u8) !?cbor.Cid {
        const height = keyHeight(key);

        if (height >= layer) {
            // find and remove the entry
            const i = entryLowerBound(node.entries.items, key);
            if (i < node.entries.items.len and keyEql(node.entries.items[i].key, key)) {
                const entry = node.entries.items[i];
                const prev_value = entry.value;
                // merge left and right subtrees around the deleted entry
                const left_sub = if (i == 0) node.left else node.entries.items[i - 1].right;
                const right_sub = entry.right;
                const merged = try self.mergeSubtrees(left_sub, right_sub);

                if (i == 0) {
                    node.left = merged;
                } else {
                    node.entries.items[i - 1].right = merged;
                }

                _ = node.entries.orderedRemove(i);
                node.dirty = true;
                return prev_value;
            }
            return null; // key not found
        }

        // height < layer: recurse into the appropriate gap
        if (layer == 0) return null; // can't go deeper
        if (node.entries.items.len == 0) {
            if (try self.ensureChildNode(&node.left)) |left| {
                const prev = try self.deleteFromNode(left, layer - 1, key);
                if (prev != null) node.dirty = true;
                return prev;
            } else return null;
        }

        const child_ref = childAtIndex(node, entryLowerBound(node.entries.items, key));
        if (try self.ensureChildNode(child_ref)) |sub| {
            const prev = try self.deleteFromNode(sub, layer - 1, key);
            if (prev != null) node.dirty = true;
            return prev;
        } else return null;
    }

    /// merge two subtrees that were separated by a deleted entry.
    /// both nodes are at the same layer. concatenate their entries
    /// and recursively merge if the junction creates adjacent children.
    /// follows the Go reference `appendMerge` / `mergeNodes` algorithm.
    fn mergeSubtrees(self: *Mst, left: ?*Node, right: ?*Node) !?*Node {
        const l = try self.ensureNodeLoaded(left orelse return right);
        const r = try self.ensureNodeLoaded(right orelse return left);

        // create merged node: takes left's `left` pointer and all entries from both
        const merged = try self.createNode(l.layer);
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
            // if last.right is present and r.left is not, keep last.right as-is
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

    pub const MstError = error{ PartialTree, WriteFailed } || Allocator.Error;

    /// compute the root CID of the tree
    pub fn rootCid(self: *Mst) MstError!cbor.Cid {
        if (self.root) |root| {
            return self.nodeCid(root);
        }
        return self.nodeCid(null);
    }

    fn nodeCid(self: *Mst, child: ?*Node) MstError!cbor.Cid {
        const node = child orelse {
            // empty node: { "l": null, "e": [] }
            const encoded = try cbor.encodeAlloc(self.allocator, .{ .map = &.{
                .{ .key = "e", .value = .{ .array = &.{} } },
                .{ .key = "l", .value = .null },
            } });
            defer self.allocator.free(encoded);
            return cbor.Cid.forDagCbor(self.allocator, encoded);
        };

        if (!node.dirty) {
            if (node.cid) |cid| return cid;
        }
        const loaded = self.ensureNodeLoaded(node) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.PartialTree => return error.PartialTree,
            else => return error.PartialTree,
        };
        const encoded = try self.serializeNode(loaded);
        defer self.allocator.free(encoded);
        const cid = try cbor.Cid.forDagCbor(self.allocator, encoded);
        loaded.cid = .{ .raw = try self.allocator.dupe(u8, cid.raw) };
        loaded.dirty = false;
        return cid;
    }

    fn serializeNode(self: *Mst, node: *Node) MstError![]u8 {
        var encoded: std.ArrayList(u8) = .empty;
        errdefer encoded.deinit(self.allocator);
        try encoded.ensureTotalCapacity(self.allocator, 64 + node.entries.items.len * 60);

        try encoded.appendSlice(self.allocator, &.{ 0xa2, 0x61, 0x65 }); // map(2), "e"
        try appendCborArgument(&encoded, self.allocator, 4, @intCast(node.entries.items.len));

        var prev_key: []const u8 = "";
        for (node.entries.items) |entry| {
            const prefix_len = commonPrefixLen(prev_key, entry.key);
            const suffix = entry.key[prefix_len..];

            try encoded.appendSlice(self.allocator, &.{ 0xa4, 0x61, 0x6b }); // map(4), "k"
            try appendCborBytes(&encoded, self.allocator, suffix);
            try encoded.appendSlice(self.allocator, &.{ 0x61, 0x70 }); // "p"
            try appendCborArgument(&encoded, self.allocator, 0, @intCast(prefix_len));
            try encoded.appendSlice(self.allocator, &.{ 0x61, 0x74 }); // "t"
            try self.appendChildCid(&encoded, entry.right);
            try encoded.appendSlice(self.allocator, &.{ 0x61, 0x76 }); // "v"
            try appendCborCid(&encoded, self.allocator, entry.value);

            prev_key = entry.key;
        }

        try encoded.appendSlice(self.allocator, &.{ 0x61, 0x6c }); // "l"
        try self.appendChildCid(&encoded, node.left);

        return try encoded.toOwnedSlice(self.allocator);
    }

    fn appendChildCid(self: *Mst, encoded: *std.ArrayList(u8), child: ?*Node) MstError!void {
        if (child) |node| {
            try appendCborCid(encoded, self.allocator, try self.nodeCid(node));
        } else {
            try encoded.append(self.allocator, 0xf6);
        }
    }

    /// deep copy the tree. loaded nodes stay loaded; stubs stay stubs.
    pub fn copy(self: *Mst) !Mst {
        var new = Mst.init(self.allocator);
        if (self.root) |root| {
            new.root = try self.copyNode(root);
        }
        new.root_layer = self.root_layer;
        new.block_reader = self.block_reader;
        return new;
    }

    fn copyNode(self: *Mst, node: *Node) !*Node {
        const new_node = try self.createNode(node.layer);
        new_node.dirty = node.dirty;
        if (node.cid) |cid| {
            new_node.cid = .{ .raw = try self.allocator.dupe(u8, cid.raw) };
        }
        new_node.left = try self.copyChild(node.left);
        for (node.entries.items) |entry| {
            try new_node.entries.append(self.allocator, .{
                .key = try self.allocator.dupe(u8, entry.key),
                .value = .{ .raw = try self.allocator.dupe(u8, entry.value.raw) },
                .right = try self.copyChild(entry.right),
            });
        }
        return new_node;
    }

    fn copyChild(self: *Mst, child: ?*Node) Allocator.Error!?*Node {
        return if (child) |n| try self.copyNode(n) else null;
    }

    /// load a partial MST from CAR blocks. nodes present in the CAR are
    /// fully loaded; child CIDs not present become stubs.
    pub fn loadFromBlocks(allocator: Allocator, repo_car: car.Car, root_cid_raw: []const u8) !Mst {
        const root_data = car.findBlock(repo_car, root_cid_raw) orelse return error.CommitBlockNotFound;
        const root_node_data = try decodeMstNode(allocator, root_data);

        if (root_node_data.entries.len == 0 and root_node_data.left == null) {
            return Mst.init(allocator);
        }

        const root_node = try loadNodeFromData(allocator, repo_car, root_node_data);
        root_node.cid = .{ .raw = try allocator.dupe(u8, root_cid_raw) };
        root_node.dirty = false;

        var tree = Mst{
            .allocator = allocator,
            .root = root_node,
            .root_layer = null,
            .block_reader = null,
        };
        tree.root_layer = try tree.inferNodeLayer(root_node);
        tree.seedNodeLayers(root_node, tree.root_layer.?);
        return tree;
    }

    fn loadNodeFromData(allocator: Allocator, repo_car: ?car.Car, data: MstNodeData) !*Node {
        const node = try allocator.create(Node);
        node.* = Node.init(0, false);

        // load left child
        node.left = if (data.left) |left_cid_raw|
            try loadChild(allocator, repo_car, left_cid_raw)
        else
            null;

        // load entries, reconstructing full keys from prefix compression
        var prev_key: []const u8 = "";
        for (data.entries) |entry_data| {
            // reconstruct full key
            if (entry_data.prefix_len > prev_key.len) return error.InvalidMstNode;
            const full_key = try allocator.alloc(u8, entry_data.prefix_len + entry_data.key_suffix.len);
            if (entry_data.prefix_len > 0) {
                @memcpy(full_key[0..entry_data.prefix_len], prev_key[0..entry_data.prefix_len]);
            }
            @memcpy(full_key[entry_data.prefix_len..], entry_data.key_suffix);

            const right_child = if (entry_data.tree) |tree_cid_raw|
                try loadChild(allocator, repo_car, tree_cid_raw)
            else
                null;

            try node.entries.append(allocator, .{
                .key = full_key,
                .value = .{ .raw = try allocator.dupe(u8, entry_data.value) },
                .right = right_child,
            });

            prev_key = full_key;
        }

        return node;
    }

    fn loadChild(allocator: Allocator, repo_car: ?car.Car, cid_raw: []const u8) (MstDecodeError || error{CommitBlockNotFound})!*Node {
        if (repo_car) |rc| {
            if (car.findBlock(rc, cid_raw)) |block_data| {
                const child_data = try decodeMstNode(allocator, block_data);
                const child = try loadNodeFromData(allocator, rc, child_data);
                child.cid = .{ .raw = try allocator.dupe(u8, cid_raw) };
                child.dirty = false;
                return child;
            }
        }
        return try createStubNode(allocator, cid_raw, null);
    }

    // === internal helpers ===

    fn ensureRootLoaded(self: *Mst) !void {
        const root = self.root orelse return;
        _ = try self.ensureNodeLoaded(root);
        if (self.root_layer == null) {
            self.root_layer = try self.inferNodeLayer(root);
            self.seedNodeLayers(root, self.root_layer.?);
        }
    }

    fn ensureChildNode(self: *Mst, child: *?*Node) !?*Node {
        const node = child.* orelse return null;
        return try self.ensureNodeLoaded(node);
    }

    fn ensureNodeLoaded(self: *Mst, node: *Node) !*Node {
        if (node.dirty or node.entries.items.len > 0 or node.left != null) return node;
        const cid = node.cid orelse return node;
        const reader = self.block_reader orelse return error.PartialTree;
        const block_data = (try reader.get(cid.raw)) orelse return error.PartialTree;
        const node_data = try decodeMstNode(self.allocator, block_data);
        const loaded = try loadNodeFromData(self.allocator, null, node_data);

        node.left = loaded.left;
        node.entries = loaded.entries;
        node.layer = if (node.layer != 0) node.layer else try self.inferNodeLayer(node);
        node.cid = .{ .raw = try self.allocator.dupe(u8, cid.raw) };
        node.dirty = false;
        self.seedNodeLayers(node, node.layer);
        return node;
    }

    fn inferNodeLayer(self: *Mst, node: *Node) anyerror!u32 {
        if (node.entries.items.len > 0) {
            return keyHeight(node.entries.items[0].key);
        }
        if (try self.ensureChildNode(&node.left)) |left| {
            return (try self.inferNodeLayer(left)) + 1;
        }
        return 0;
    }

    fn seedNodeLayers(self: *Mst, node: *Node, layer: u32) void {
        node.layer = layer;
        if (layer == 0) return;
        self.seedChildLayer(&node.left, layer - 1);
        for (node.entries.items) |*entry| {
            self.seedChildLayer(&entry.right, layer - 1);
        }
    }

    fn seedChildLayer(self: *Mst, child: *?*Node, layer: u32) void {
        if (child.*) |node| self.seedNodeLayers(node, layer);
    }

    fn createNode(self: *Mst, layer: u32) !*Node {
        const node = try self.allocator.create(Node);
        node.* = Node.init(layer, true);
        return node;
    }

    fn createStubNode(allocator: Allocator, cid_raw: []const u8, layer: ?u32) !*Node {
        const node = try allocator.create(Node);
        node.* = Node.init(layer orelse 0, false);
        node.cid = .{ .raw = try allocator.dupe(u8, cid_raw) };
        return node;
    }

    fn storeKey(self: *Mst, key: []const u8, copy_key: bool) Allocator.Error![]const u8 {
        return if (copy_key) try self.allocator.dupe(u8, key) else key;
    }

    /// insert a key that belongs above the current root.
    /// splits the tree at its own layer, wraps each half in parent nodes
    /// to bridge the layer gap, then assembles the new root.
    fn insertAbove(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_layer: u32, copy_key: bool) !*Node {
        // 1. split the tree at its current layer around the key
        const splits = try self.splitNode(node, key);
        var left = splits.left;
        var right = splits.right;

        // 2. wrap each half in parent layers (bridge the gap)
        const extra_layers = target_layer - node_layer;
        var i: u32 = 1;
        while (i < extra_layers) : (i += 1) {
            if (left != null) {
                const parent = try self.createNode(node_layer + i);
                parent.left = left;
                left = parent;
            }
            if (right != null) {
                const parent = try self.createNode(node_layer + i);
                parent.left = right;
                right = parent;
            }
        }

        // 3. assemble new root: [left_tree, key_leaf, right_tree]
        const new_root = try self.createNode(target_layer);
        new_root.left = left;
        try new_root.entries.append(self.allocator, .{
            .key = try self.storeKey(key, copy_key),
            .value = value,
            .right = right,
        });
        return new_root;
    }

    /// insert a key at the same layer as the node
    fn insertAtLayer(self: *Mst, node: *Node, key: []const u8, value: cbor.Cid, layer: u32, prev_out: *?cbor.Cid, copy_key: bool) !*Node {
        _ = layer;
        // find insertion position
        const insert_idx = entryLowerBound(node.entries.items, key);
        if (insert_idx < node.entries.items.len and keyEql(key, node.entries.items[insert_idx].key)) {
            // update existing — return previous value
            prev_out.* = node.entries.items[insert_idx].value;
            node.entries.items[insert_idx].value = value;
            node.dirty = true;
            return node;
        }

        // split the subtree that spans the insertion gap
        const gap_child = if (insert_idx == 0) node.left else node.entries.items[insert_idx - 1].right;

        var left_split: ?*Node = null;
        var right_split: ?*Node = null;

        if (gap_child) |subtree| {
            const splits = try self.splitNode(try self.ensureNodeLoaded(subtree), key);
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
            .key = try self.storeKey(key, copy_key),
            .value = value,
            .right = right_split,
        });
        node.dirty = true;

        return node;
    }

    /// insert a key below the current node's layer
    fn insertBelow(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32, copy_key: bool) anyerror!?cbor.Cid {
        // find which gap the key falls into
        const idx = entryLowerBound(node.entries.items, key);
        if (idx < node.entries.items.len and keyEql(key, node.entries.items[idx].key)) {
            // update existing
            const prev = node.entries.items[idx].value;
            node.entries.items[idx].value = value;
            node.dirty = true;
            return prev;
        }
        const prev = try self.insertIntoGap(childAtIndex(node, idx), node_layer - 1, key, value, target_height, copy_key);
        node.dirty = true;
        return prev;
    }

    fn insertIntoGap(self: *Mst, subtree_ptr: *?*Node, gap_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32, copy_key: bool) anyerror!?cbor.Cid {
        if (target_height == gap_layer) {
            // insert at this layer
            if (subtree_ptr.*) |existing| {
                var prev: ?cbor.Cid = null;
                subtree_ptr.* = try self.insertAtLayer(try self.ensureNodeLoaded(existing), key, value, gap_layer, &prev, copy_key);
                return prev;
            } else {
                const new_node = try self.createNode(gap_layer);
                try new_node.entries.append(self.allocator, .{
                    .key = try self.storeKey(key, copy_key),
                    .value = value,
                    .right = null,
                });
                subtree_ptr.* = new_node;
                return null;
            }
        } else if (target_height > gap_layer) {
            // need to lift — split and wrap
            if (subtree_ptr.*) |existing| {
                subtree_ptr.* = try self.insertAbove(try self.ensureNodeLoaded(existing), gap_layer, key, value, target_height, copy_key);
                return null;
            } else {
                const new_node = try self.createNode(target_height);
                try new_node.entries.append(self.allocator, .{
                    .key = try self.storeKey(key, copy_key),
                    .value = value,
                    .right = null,
                });
                subtree_ptr.* = new_node;
                return null;
            }
        } else {
            // target_height < gap_layer: recurse deeper
            if (subtree_ptr.*) |existing| {
                return try self.insertBelow(try self.ensureNodeLoaded(existing), gap_layer, key, value, target_height, copy_key);
            } else {
                // create node at gap_layer and recurse
                const new_node = try self.createNode(gap_layer);
                subtree_ptr.* = new_node;
                return try self.insertBelow(new_node, gap_layer, key, value, target_height, copy_key);
            }
        }
    }

    /// split a subtree around a key: everything < key goes left, everything >= key goes right.
    fn splitNode(self: *Mst, node: *Node, key: []const u8) !struct { left: ?*Node, right: ?*Node } {
        // find the first entry >= key
        const split_idx = entryLowerBound(node.entries.items, key);

        // left gets entries [0..split_idx), right gets entries [split_idx..]
        var left_node = try self.createNode(node.layer);
        var right_node = try self.createNode(node.layer);

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

        // split the gap subtree between the two halves
        if (left_node.entries.items.len > 0) {
            const last_left = &left_node.entries.items[left_node.entries.items.len - 1];
            if (last_left.right) |gap_subtree| {
                const sub_split = try self.splitNode(try self.ensureNodeLoaded(gap_subtree), key);
                last_left.right = sub_split.left;
                right_node.left = sub_split.right;
            }
        } else if (left_node.left != null and split_idx == 0) {
            // all entries went right — the gap is the original node's left subtree
            if (left_node.left) |gap_subtree| {
                const sub_split = try self.splitNode(try self.ensureNodeLoaded(gap_subtree), key);
                left_node.left = sub_split.left;
                right_node.left = sub_split.right;
            }
        }

        const left_result: ?*Node = if (left_node.entries.items.len > 0 or left_node.left != null)
            left_node
        else
            null;
        const right_result: ?*Node = if (right_node.entries.items.len > 0 or right_node.left != null)
            right_node
        else
            null;

        return .{ .left = left_result, .right = right_result };
    }
};

fn appendCborArgument(out: *std.ArrayList(u8), allocator: Allocator, major: u3, val: u64) Allocator.Error!void {
    const major_byte: u8 = @as(u8, major) << 5;
    if (val < 24) {
        try out.append(allocator, major_byte | @as(u8, @intCast(val)));
    } else if (val <= std.math.maxInt(u8)) {
        try out.appendSlice(allocator, &.{ major_byte | 24, @intCast(val) });
    } else if (val <= std.math.maxInt(u16)) {
        try out.append(allocator, major_byte | 25);
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(val), .big);
        try out.appendSlice(allocator, &bytes);
    } else if (val <= std.math.maxInt(u32)) {
        try out.append(allocator, major_byte | 26);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(val), .big);
        try out.appendSlice(allocator, &bytes);
    } else {
        try out.append(allocator, major_byte | 27);
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, val, .big);
        try out.appendSlice(allocator, &bytes);
    }
}

fn appendCborBytes(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) Allocator.Error!void {
    try appendCborArgument(out, allocator, 2, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn appendCborCid(out: *std.ArrayList(u8), allocator: Allocator, cid: cbor.Cid) Allocator.Error!void {
    try appendCborArgument(out, allocator, 6, 42);
    try appendCborArgument(out, allocator, 2, @intCast(cid.raw.len + 1));
    try out.append(allocator, 0x00);
    try out.appendSlice(allocator, cid.raw);
}

// === inversion primitives ===

/// normalize operations: check for duplicate paths, sort deletions first then by path
pub fn normalizeOps(allocator: Allocator, ops: []const Operation) ![]Operation {
    if (ops.len == 0) return try allocator.alloc(Operation, 0);

    const sorted = try allocator.dupe(Operation, ops);
    errdefer allocator.free(sorted);

    // sort: deletions first, then by path
    std.mem.sort(Operation, sorted, {}, struct {
        fn lessThan(_: void, a: Operation, b: Operation) bool {
            // deletions before creates/updates
            const a_del: u1 = if (a.isDelete()) 0 else 1;
            const b_del: u1 = if (b.isDelete()) 0 else 1;
            if (a_del != b_del) return a_del < b_del;
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lessThan);

    // check for duplicate paths
    var i: usize = 1;
    while (i < sorted.len) : (i += 1) {
        if (std.mem.eql(u8, sorted[i].path, sorted[i - 1].path)) {
            allocator.free(sorted);
            return error.DuplicatePath;
        }
    }

    return sorted;
}

/// invert a single operation against the tree.
/// create → delete, update → reverse update, delete → put back
pub fn invertOp(tree: *Mst, op: Operation) !void {
    if (op.isCreate()) {
        // create → delete: remove the path, verify removed CID matches op.value
        const removed = try tree.deleteReturn(op.path) orelse return error.InversionMismatch;
        if (!std.mem.eql(u8, removed.raw, op.value.?)) return error.InversionMismatch;
    } else if (op.isUpdate()) {
        // update → reverse: put op.prev back, verify displaced CID matches op.value
        const displaced = try tree.putReturn(op.path, .{ .raw = op.prev.? }) orelse return error.InversionMismatch;
        if (!std.mem.eql(u8, displaced.raw, op.value.?)) return error.InversionMismatch;
    } else if (op.isDelete()) {
        // delete → put back: insert op.prev, verify path didn't already exist
        const displaced = try tree.putReturn(op.path, .{ .raw = op.prev.? });
        if (displaced != null) return error.InversionMismatch;
    } else {
        return error.InversionMismatch;
    }
}

// === specialized MST node decoder ===
//
// parses the known MST node CBOR schema directly, avoiding generic Value
// union construction. all byte data is zero-copy (slices into input buffer).
// only allocation: the entries array.
//
// MST node schema:
//   map(2) { "e": array [ map(4) {k,p,t,v}, ... ], "l": CID|null }

pub const MstNodeData = struct {
    left: ?[]const u8, // raw CID bytes, or null
    entries: []const MstEntryData,
};

pub const MstEntryData = struct {
    key_suffix: []const u8,
    prefix_len: usize,
    tree: ?[]const u8, // raw CID bytes, or null
    value: []const u8, // raw CID bytes
};

pub fn decodeMstNode(allocator: Allocator, data: []const u8) !MstNodeData {
    var pos: usize = 0;

    const map_hdr = cbor.readMapHeader(data, pos) catch return error.InvalidMstNode;
    pos = map_hdr.end;
    if (map_hdr.val != 2) return error.InvalidMstNode;

    // "e" key
    const key_e = cbor.readText(data, pos) catch return error.InvalidMstNode;
    pos = key_e.end;
    if (!std.mem.eql(u8, key_e.val, "e")) return error.InvalidMstNode;

    // entries array
    const arr_hdr = cbor.readArrayHeader(data, pos) catch return error.InvalidMstNode;
    pos = arr_hdr.end;
    const entries = try allocator.alloc(MstEntryData, @intCast(arr_hdr.val));
    errdefer allocator.free(entries);
    for (entries) |*entry| {
        const result = readMstEntry(data, pos) catch return error.InvalidMstNode;
        entry.* = result.entry;
        pos = result.end;
    }

    // "l" key
    const key_l = cbor.readText(data, pos) catch return error.InvalidMstNode;
    pos = key_l.end;
    if (!std.mem.eql(u8, key_l.val, "l")) return error.InvalidMstNode;

    // left CID or null
    const left_result = readCidOrNull(data, pos) catch return error.InvalidMstNode;

    return .{ .left = left_result.val, .entries = entries };
}

const MstEntryResult = struct {
    entry: MstEntryData,
    end: usize,
};

fn readMstEntry(data: []const u8, pos: usize) !MstEntryResult {
    var p = pos;

    const map_hdr = cbor.readMapHeader(data, p) catch return error.InvalidMstNode;
    p = map_hdr.end;
    if (map_hdr.val != 4) return error.InvalidMstNode;

    // "k" → key suffix (byte string)
    const key_k = cbor.readText(data, p) catch return error.InvalidMstNode;
    p = key_k.end;
    const key_suffix = cbor.readBytes(data, p) catch return error.InvalidMstNode;
    p = key_suffix.end;

    // "p" → prefix length (unsigned int)
    const key_p = cbor.readText(data, p) catch return error.InvalidMstNode;
    p = key_p.end;
    const prefix_len = cbor.readUint(data, p) catch return error.InvalidMstNode;
    p = prefix_len.end;

    // "t" → right subtree CID or null
    const key_t = cbor.readText(data, p) catch return error.InvalidMstNode;
    p = key_t.end;
    const tree_result = readCidOrNull(data, p) catch return error.InvalidMstNode;
    p = tree_result.end;

    // "v" → value CID
    const key_v = cbor.readText(data, p) catch return error.InvalidMstNode;
    p = key_v.end;
    const value = cbor.readCidLink(data, p) catch return error.InvalidMstNode;
    p = value.end;

    return .{
        .entry = .{
            .key_suffix = key_suffix.val,
            .prefix_len = @intCast(prefix_len.val),
            .tree = tree_result.val,
            .value = value.val,
        },
        .end = p,
    };
}

const CidOrNullResult = struct {
    val: ?[]const u8,
    end: usize,
};

fn readCidOrNull(data: []const u8, pos: usize) !CidOrNullResult {
    if (pos >= data.len) return error.InvalidMstNode;
    if (data[pos] == 0xf6) return .{ .val = null, .end = pos + 1 };
    const cid_result = cbor.readCidLink(data, pos) catch return error.InvalidMstNode;
    return .{ .val = cid_result.val, .end = cid_result.end };
}

pub const MstDecodeError = error{InvalidMstNode} || Allocator.Error;

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

test "putReturn and deleteReturn" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    // first insert returns null (no previous)
    const prev1 = try tree.putReturn("key1", cid1);
    try std.testing.expect(prev1 == null);

    // update returns old value
    const prev2 = try tree.putReturn("key1", cid2);
    try std.testing.expect(prev2 != null);
    try std.testing.expectEqualSlices(u8, cid1.raw, prev2.?.raw);

    // delete returns removed value
    const removed = try tree.deleteReturn("key1");
    try std.testing.expect(removed != null);
    try std.testing.expectEqualSlices(u8, cid2.raw, removed.?.raw);

    // delete nonexistent returns null
    const removed2 = try tree.deleteReturn("key1");
    try std.testing.expect(removed2 == null);
}

test "copy produces independent tree" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    try tree.put("key1", cid1);
    try tree.put("key2", cid1);

    var tree2 = try tree.copy();

    // modify copy
    try tree2.put("key1", cid2);
    try tree2.delete("key2");

    // original unchanged
    const got1 = tree.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid1.raw, got1.raw);
    try std.testing.expect(tree.get("key2") != null);

    // copy has changes
    const got1_copy = tree2.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid2.raw, got1_copy.raw);
    try std.testing.expect(tree2.get("key2") == null);
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

const TestBlockStore = struct {
    blocks: std.StringHashMapUnmanaged([]const u8) = .empty,
    loads: usize = 0,

    fn putNode(self: *TestBlockStore, allocator: Allocator, tree: *Mst, node: *Node) !cbor.Cid {
        if (node.left) |left| _ = try self.putNode(allocator, tree, left);
        for (node.entries.items) |entry| {
            if (entry.right) |right| _ = try self.putNode(allocator, tree, right);
        }

        const data = try tree.serializeNode(node);
        const cid = try cbor.Cid.forDagCbor(allocator, data);
        try self.blocks.put(allocator, cid.raw, data);
        return cid;
    }

    fn reader(self: *TestBlockStore) BlockReader {
        return .{
            .ctx = self,
            .getFn = getBlock,
        };
    }

    fn getBlock(ctx: *anyopaque, cid_raw: []const u8) anyerror!?[]const u8 {
        const self: *TestBlockStore = @ptrCast(@alignCast(ctx));
        self.loads += 1;
        return self.blocks.get(cid_raw);
    }
};

test "loadLazy keeps root as CID stub until first access" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    var eager = Mst.init(a);
    const keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (keys) |key| try eager.put(key, leaf_cid);

    var store = TestBlockStore{};
    const root_cid = try store.putNode(a, &eager, eager.root.?);

    var lazy = try Mst.loadLazy(a, root_cid.raw, store.reader());
    try std.testing.expectEqual(@as(usize, 0), store.loads);
    try std.testing.expect(lazy.root != null);
    try std.testing.expect(lazy.root.?.cid != null);
    try std.testing.expectEqual(@as(usize, 0), lazy.root.?.entries.items.len);

    const lazy_root = try lazy.rootCid();
    try std.testing.expectEqualSlices(u8, root_cid.raw, lazy_root.raw);
    try std.testing.expectEqual(@as(usize, 0), store.loads);
}

test "rootCid caches clean root and put dirties it" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    var tree = Mst.init(a);
    try tree.put("app.bsky.feed.post/0000000000001", leaf_cid);
    try tree.put("app.bsky.feed.post/0000000000002", leaf_cid);

    try std.testing.expect(tree.root.?.dirty);
    const root1 = try tree.rootCid();
    try std.testing.expect(!tree.root.?.dirty);
    try std.testing.expect(tree.root.?.cid != null);

    const root2 = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root1.raw, root2.raw);
    try std.testing.expect(!tree.root.?.dirty);

    try tree.put("app.bsky.feed.post/0000000000003", leaf_cid);
    try std.testing.expect(tree.root.?.dirty);

    const root3 = try tree.rootCid();
    try std.testing.expect(!tree.root.?.dirty);
    try std.testing.expect(!std.mem.eql(u8, root1.raw, root3.raw));
}

test "getLazy resolves root and child stubs on demand" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    var eager = Mst.init(a);
    const keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (keys) |key| try eager.put(key, leaf_cid);

    var store = TestBlockStore{};
    const root_cid = try store.putNode(a, &eager, eager.root.?);

    var child_key: []const u8 = keys[0];
    for (keys) |key| {
        if (keyHeight(key) < eager.root_layer.?) {
            child_key = key;
            break;
        }
    }

    var lazy = try Mst.loadLazy(a, root_cid.raw, store.reader());
    const got = try lazy.getLazy(child_key) orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, leaf_cid.raw, got.raw);
    try std.testing.expect(store.loads > 1);
}

test "putReturn mutates through lazy stubs and matches eager root" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    var eager = Mst.init(a);
    const initial_keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (initial_keys) |key| try eager.put(key, leaf_cid);

    var store = TestBlockStore{};
    const root_cid = try store.putNode(a, &eager, eager.root.?);

    var expected = try eager.copy();
    try expected.put("D2/269196", leaf_cid);
    const expected_root = try expected.rootCid();

    var lazy = try Mst.loadLazy(a, root_cid.raw, store.reader());
    const prev = try lazy.putReturn("D2/269196", leaf_cid);
    try std.testing.expect(prev == null);

    const lazy_root = try lazy.rootCid();
    try std.testing.expectEqualSlices(u8, expected_root.raw, lazy_root.raw);
    try std.testing.expect(store.loads > 1);
}

test "deleteReturn mutates through lazy stubs and matches eager root" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    var eager = Mst.init(a);
    const keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (keys) |key| try eager.put(key, leaf_cid);

    var store = TestBlockStore{};
    const root_cid = try store.putNode(a, &eager, eager.root.?);

    var delete_key: []const u8 = keys[0];
    for (keys) |key| {
        if (keyHeight(key) < eager.root_layer.?) {
            delete_key = key;
            break;
        }
    }

    var expected = try eager.copy();
    const expected_removed = try expected.deleteReturn(delete_key) orelse return error.NotFound;
    const expected_root = try expected.rootCid();

    var lazy = try Mst.loadLazy(a, root_cid.raw, store.reader());
    const removed = try lazy.deleteReturn(delete_key) orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, expected_removed.raw, removed.raw);

    const lazy_root = try lazy.rootCid();
    try std.testing.expectEqualSlices(u8, expected_root.raw, lazy_root.raw);
    try std.testing.expect(store.loads > 1);
}

test "inversion: create then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "record1");

    var tree = Mst.init(a);
    const root_before = try tree.rootCid();

    // apply forward: create
    try tree.put("col/rkey1", cid1);

    // invert: should remove it
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = cid1.raw,
        .prev = null,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: update then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    var tree = Mst.init(a);
    try tree.put("col/rkey1", cid1);
    const root_before = try tree.rootCid();

    // apply forward: update cid1 → cid2
    try tree.put("col/rkey1", cid2);

    // invert
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = cid2.raw,
        .prev = cid1.raw,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: delete then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");

    var tree = Mst.init(a);
    try tree.put("col/rkey1", cid1);
    const root_before = try tree.rootCid();

    // apply forward: delete
    try tree.delete("col/rkey1");

    // invert
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = null,
        .prev = cid1.raw,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: multi-op commit round-trip" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");
    const cid3 = try cbor.Cid.forDagCbor(a, "v3");

    // build initial tree
    var tree = Mst.init(a);
    try tree.put("col/existing", cid1);
    try tree.put("col/to_update", cid1);
    try tree.put("col/to_delete", cid2);
    const root_before = try tree.rootCid();

    // apply forward ops
    try tree.put("col/new_record", cid3); // create
    try tree.put("col/to_update", cid2); // update
    try tree.delete("col/to_delete"); // delete

    // normalize and invert
    const ops = [_]Operation{
        .{ .path = "col/new_record", .value = cid3.raw, .prev = null }, // create
        .{ .path = "col/to_update", .value = cid2.raw, .prev = cid1.raw }, // update
        .{ .path = "col/to_delete", .value = null, .prev = cid2.raw }, // delete
    };
    const sorted = try normalizeOps(a, &ops);

    for (sorted) |op| {
        try invertOp(&tree, op);
    }

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "normalizeOps rejects duplicates" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const ops = [_]Operation{
        .{ .path = "col/same", .value = "cid1", .prev = null },
        .{ .path = "col/same", .value = "cid2", .prev = null },
    };

    try std.testing.expectError(error.DuplicatePath, normalizeOps(a, &ops));
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
