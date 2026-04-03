//! DAG-CBOR codec
//!
//! encode and decode the DAG-CBOR subset used by AT Protocol.
//! handles: integers, byte/text strings, arrays, maps, tag 42 (CID links),
//! booleans, null. no floats, no indefinite lengths.
//!
//! encoding follows DAG-CBOR deterministic rules:
//!   - integers use shortest encoding
//!   - map keys sorted by byte length, then lexicographically
//!   - CIDs encoded as tag 42 with 0x00 identity multibase prefix
//!
//! see: https://ipld.io/specs/codecs/dag-cbor/spec/

const std = @import("std");
const Allocator = std.mem.Allocator;

/// CBOR major types (high 3 bits of initial byte)
const MajorType = enum(u3) {
    unsigned = 0,
    negative = 1,
    byte_string = 2,
    text_string = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

/// decoded CBOR value
pub const Value = union(enum) {
    unsigned: u64,
    negative: i64, // stored as -(1 + raw), so -1 is stored as -1
    bytes: []const u8,
    text: []const u8,
    array: []const Value,
    map: []const MapEntry,
    boolean: bool,
    null,
    cid: Cid,

    pub const MapEntry = struct {
        key: []const u8, // DAG-CBOR: keys are always text strings
        value: Value,
    };

    /// look up a key in a map value
    pub fn get(self: Value, key: []const u8) ?Value {
        return switch (self) {
            .map => |entries| {
                for (entries) |entry| {
                    if (std.mem.eql(u8, entry.key, key)) return entry.value;
                }
                return null;
            },
            else => null,
        };
    }

    /// get a text string from a map by key
    pub fn getString(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .text => |s| s,
            else => null,
        };
    }

    /// get an integer from a map by key
    pub fn getInt(self: Value, key: []const u8) ?i64 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .unsigned => |u| std.math.cast(i64, u),
            .negative => |n| n,
            else => null,
        };
    }

    /// get an unsigned integer from a map by key
    pub fn getUint(self: Value, key: []const u8) ?u64 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .unsigned => |u| u,
            .negative => |n| std.math.cast(u64, n),
            else => null,
        };
    }

    /// get a bool from a map by key
    pub fn getBool(self: Value, key: []const u8) ?bool {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .boolean => |b| b,
            else => null,
        };
    }

    /// get a byte string from a map by key
    pub fn getBytes(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .bytes => |b| b,
            else => null,
        };
    }

    /// get an array from a map by key
    pub fn getArray(self: Value, key: []const u8) ?[]const Value {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .array => |a| a,
            else => null,
        };
    }

    /// get a CID from a map by key
    pub fn getCid(self: Value, key: []const u8) ?Cid {
        const v = self.get(key) orelse return null;
        return switch (v) {
            .cid => |c| c,
            else => null,
        };
    }

    // verify the Value union stayed slim after Cid optimization (was ~64, now 24)
    comptime {
        std.debug.assert(@sizeOf(Value) == 24);
        std.debug.assert(@sizeOf(MapEntry) == 40);
    }
};

/// well-known multicodec values
pub const Codec = struct {
    pub const dag_cbor: u64 = 0x71;
    pub const dag_pb: u64 = 0x70;
    pub const raw: u64 = 0x55;
};

/// well-known multihash function codes
pub const HashFn = struct {
    pub const sha2_256: u64 = 0x12;
    pub const identity: u64 = 0x00;
};

/// CID (Content Identifier) parsed from tag 42.
/// stores only the raw bytes — version/codec/hash_fn/digest are parsed lazily on demand.
/// this keeps the struct at 16 bytes (1 slice) instead of 56 bytes, which shrinks
/// the Value union from ~64 to ~24 bytes.
pub const Cid = struct {
    raw: []const u8,

    /// parse CID version from raw bytes (0 for CIDv0, 1+ for CIDv1)
    pub fn version(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        // CIDv0: starts with 0x12 0x20 (sha2-256 multihash)
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0;
        var pos: usize = 0;
        return readUvarint(self.raw, &pos);
    }

    /// parse codec from raw bytes (implicit dag-pb for CIDv0)
    pub fn codec(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0x70; // dag-pb
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        return readUvarint(self.raw, &pos);
    }

    /// parse hash function code from raw bytes
    pub fn hashFn(self: Cid) ?u64 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) return 0x12; // sha2-256
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        _ = readUvarint(self.raw, &pos) orelse return null; // codec
        return readUvarint(self.raw, &pos);
    }

    /// parse digest bytes from raw CID
    pub fn digest(self: Cid) ?[]const u8 {
        if (self.raw.len < 2) return null;
        if (self.raw[0] == 0x12 and self.raw[1] == 0x20) {
            if (self.raw.len < 34) return null;
            return self.raw[2..34];
        }
        var pos: usize = 0;
        _ = readUvarint(self.raw, &pos) orelse return null; // version
        _ = readUvarint(self.raw, &pos) orelse return null; // codec
        _ = readUvarint(self.raw, &pos) orelse return null; // hash_fn
        const digest_len = readUvarint(self.raw, &pos) orelse return null;
        if (pos + digest_len > self.raw.len) return null;
        return self.raw[pos..][0..digest_len];
    }

    /// create a CIDv1 by hashing DAG-CBOR encoded data with SHA-256.
    /// the returned Cid's raw slice is owned by the allocator.
    pub fn forDagCbor(allocator: Allocator, data: []const u8) !Cid {
        return create(allocator, 1, Codec.dag_cbor, HashFn.sha2_256, data);
    }

    /// create a CIDv1 with the given codec by hashing data with SHA-256.
    pub fn create(allocator: Allocator, ver: u64, cod: u64, hash_fn_code: u64, data: []const u8) !Cid {
        const Sha256 = std.crypto.hash.sha2.Sha256;
        var hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(data, &hash, .{});

        // build CID on the stack then copy to allocator — avoids dynamic writer
        // overhead. max varint size is 10 bytes × 4 fields + 32 byte hash = 72 bytes.
        var buf: [72]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        writeUvarint(&w, ver) catch unreachable;
        writeUvarint(&w, cod) catch unreachable;
        writeUvarint(&w, hash_fn_code) catch unreachable;
        writeUvarint(&w, Sha256.digest_length) catch unreachable;
        w.writeAll(&hash) catch unreachable;

        const raw = try allocator.dupe(u8, w.buffered());
        return .{ .raw = raw };
    }

    /// serialize this CID to raw bytes (version varint + codec varint + multihash)
    pub fn toBytes(self: Cid, allocator: Allocator) ![]u8 {
        return try allocator.dupe(u8, self.raw);
    }
};

pub const DecodeError = error{
    UnexpectedEof,
    IndefiniteLength,
    UnsupportedSimpleValue,
    UnsupportedFloat,
    InvalidMapKey,
    InvalidCid,
    ReservedAdditionalInfo,
    Overflow,
    OutOfMemory,
    NonMinimalEncoding,
    TrailingBytes,
    UnsupportedTag,
    UnsortedMapKeys,
    DuplicateMapKey,
    InvalidUtf8,
    MaxDepthExceeded,
    WrongType,
};

/// maximum nesting depth for arrays/maps to prevent stack overflow
pub const max_depth: usize = 128;

/// decode a single CBOR value from the front of `data`.
/// returns the value and the number of bytes consumed.
pub fn decode(allocator: Allocator, data: []const u8) DecodeError!struct { value: Value, consumed: usize } {
    var pos: usize = 0;
    const value = try decodeAt(allocator, data, &pos, 0);
    return .{ .value = value, .consumed = pos };
}

/// decode all bytes as a single CBOR value, rejecting trailing bytes
pub fn decodeAll(allocator: Allocator, data: []const u8) DecodeError!Value {
    var pos: usize = 0;
    const value = try decodeAt(allocator, data, &pos, 0);
    if (pos != data.len) return error.TrailingBytes;
    return value;
}

fn decodeAt(allocator: Allocator, data: []const u8, pos: *usize, depth: usize) DecodeError!Value {
    if (pos.* >= data.len) return error.UnexpectedEof;
    const initial = data[pos.*];
    const major: u3 = @truncate(initial >> 5);
    const additional: u5 = @truncate(initial);

    // simple values (major 7) are handled without readArg since floats
    // use additional 25/26/27 to mean float16/32/64, not integer arguments
    if (major == 7) {
        pos.* += 1;
        return switch (additional) {
            20 => .{ .boolean = false },
            21 => .{ .boolean = true },
            22 => .null,
            25, 26, 27 => error.UnsupportedFloat, // DAG-CBOR forbids floats in AT Protocol
            31 => error.IndefiniteLength, // break code — DAG-CBOR forbids indefinite lengths
            else => error.UnsupportedSimpleValue,
        };
    }

    const arg = try readArg(data, pos.*);
    pos.* = arg.end;

    return switch (@as(MajorType, @enumFromInt(major))) {
        .unsigned => .{ .unsigned = arg.val },
        .negative => blk: {
            // negative CBOR: value is -1 - val
            if (arg.val > std.math.maxInt(i64)) return error.Overflow;
            break :blk .{ .negative = -1 - @as(i64, @intCast(arg.val)) };
        },
        .byte_string => blk: {
            const len = std.math.cast(usize, arg.val) orelse return error.UnexpectedEof;
            const end = std.math.add(usize, pos.*, len) catch return error.UnexpectedEof;
            if (end > data.len) return error.UnexpectedEof;
            const bytes = data[pos.*..end];
            pos.* = end;
            break :blk .{ .bytes = bytes };
        },
        .text_string => blk: {
            const len = std.math.cast(usize, arg.val) orelse return error.UnexpectedEof;
            const end = std.math.add(usize, pos.*, len) catch return error.UnexpectedEof;
            if (end > data.len) return error.UnexpectedEof;
            const text = data[pos.*..end];
            if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
            pos.* = end;
            break :blk .{ .text = text };
        },
        .array => blk: {
            if (depth >= max_depth) return error.MaxDepthExceeded;
            // sanity check: each element is at least 1 byte
            if (arg.val > data.len - pos.*) return error.UnexpectedEof;
            const items = try allocator.alloc(Value, @intCast(arg.val));
            for (items) |*item| {
                item.* = try decodeAt(allocator, data, pos, depth + 1);
            }
            break :blk .{ .array = items };
        },
        .map => blk: {
            if (depth >= max_depth) return error.MaxDepthExceeded;
            // sanity check: each entry is at least 2 bytes (key + value)
            if (arg.val > (data.len - pos.*) / 2) return error.UnexpectedEof;
            const entries = try allocator.alloc(Value.MapEntry, @intCast(arg.val));
            for (entries, 0..) |*entry, i| {
                // DAG-CBOR: map keys must be text strings — inline read to avoid
                // a full decodeAt + Value union construction per key
                const key_arg = try readArg(data, pos.*);
                pos.* = key_arg.end;
                if (key_arg.major != 3) return error.InvalidMapKey;
                const key_len = std.math.cast(usize, key_arg.val) orelse return error.UnexpectedEof;
                const key_end = std.math.add(usize, pos.*, key_len) catch return error.UnexpectedEof;
                if (key_end > data.len) return error.UnexpectedEof;
                entry.key = data[pos.*..key_end];
                if (!std.unicode.utf8ValidateSlice(entry.key)) return error.InvalidUtf8;
                pos.* = key_end;

                // DAG-CBOR: keys must be sorted (shorter first, then lex) and unique
                if (i > 0) {
                    const prev = entries[i - 1].key;
                    if (prev.len < entry.key.len) {
                        // ok — shorter key first
                    } else if (prev.len == entry.key.len) {
                        switch (std.mem.order(u8, prev, entry.key)) {
                            .lt => {}, // ok — lex order
                            .eq => return error.DuplicateMapKey,
                            .gt => return error.UnsortedMapKeys,
                        }
                    } else {
                        return error.UnsortedMapKeys;
                    }
                }

                entry.value = try decodeAt(allocator, data, pos, depth + 1);
            }
            break :blk .{ .map = entries };
        },
        .tag => blk: {
            if (arg.val != 42) return error.UnsupportedTag; // DAG-CBOR only allows tag 42 (CID)
            // CID link — content is a byte string with 0x00 prefix
            const content = try decodeAt(allocator, data, pos, depth);
            const cid_bytes = switch (content) {
                .bytes => |b| b,
                else => return error.InvalidCid,
            };
            // CID byte string must have 0x00 identity multibase prefix + at least
            // version byte + codec byte (minimum 3 bytes total)
            if (cid_bytes.len < 3 or cid_bytes[0] != 0x00) return error.InvalidCid;
            break :blk .{ .cid = .{ .raw = cid_bytes[1..] } }; // zero-cost: just reference the bytes
        },
        .simple => unreachable, // handled above
    };
}

/// wrap raw CID bytes (after removing the 0x00 multibase prefix) into a Cid.
/// does not validate the CID structure — call version()/codec()/digest() to parse lazily.
pub fn parseCid(raw: []const u8) Cid {
    return .{ .raw = raw };
}

/// read an unsigned varint (LEB128). rejects varints longer than 10 bytes
/// and rejects overflow (10th byte must have value <= 1).
pub fn readUvarint(data: []const u8, pos: *usize) ?u64 {
    var result: u64 = 0;
    var shift: u7 = 0;
    for (0..10) |i| {
        if (pos.* >= data.len) return null;
        const byte = data[pos.*];
        pos.* += 1;
        // 10th byte (i=9, shift=63): only bit 0 can fit in u64
        if (i == 9 and byte > 1) return null;
        result |= @as(u64, byte & 0x7f) << @as(u6, @intCast(shift));
        if (byte & 0x80 == 0) return result;
        shift += 7;
    }
    return null; // varint too long
}

// === encoder ===

pub const EncodeError = error{
    OutOfMemory,
};

/// write the CBOR initial byte + argument using shortest encoding (DAG-CBOR requirement).
/// batches all bytes into a single writeAll call to minimize writer dispatch overhead.
fn writeArgument(writer: anytype, major: u3, val: u64) !void {
    const prefix: u8 = @as(u8, major) << 5;
    if (val < 24) {
        try writer.writeAll(&.{prefix | @as(u8, @intCast(val))});
    } else if (val <= 0xff) {
        try writer.writeAll(&.{ prefix | 24, @as(u8, @intCast(val)) });
    } else if (val <= 0xffff) {
        const v: u16 = @intCast(val);
        try writer.writeAll(&.{ prefix | 25, @truncate(v >> 8), @truncate(v) });
    } else if (val <= 0xffffffff) {
        const v: u32 = @intCast(val);
        try writer.writeAll(&.{
            prefix | 26,
            @truncate(v >> 24),
            @truncate(v >> 16),
            @truncate(v >> 8),
            @truncate(v),
        });
    } else {
        try writer.writeAll(&.{
            prefix | 27,
            @truncate(val >> 56),
            @truncate(val >> 48),
            @truncate(val >> 40),
            @truncate(val >> 32),
            @truncate(val >> 24),
            @truncate(val >> 16),
            @truncate(val >> 8),
            @truncate(val),
        });
    }
}

/// check if map entries are already in DAG-CBOR key order
fn keysAlreadySorted(entries: []const Value.MapEntry) bool {
    if (entries.len <= 1) return true;
    var prev = entries[0].key;
    for (entries[1..]) |entry| {
        if (prev.len > entry.key.len) return false;
        if (prev.len == entry.key.len and std.mem.order(u8, prev, entry.key) != .lt) return false;
        prev = entry.key;
    }
    return true;
}

/// DAG-CBOR map key ordering: shorter keys first, then lexicographic
fn dagCborKeyLessThan(_: void, a: Value.MapEntry, b: Value.MapEntry) bool {
    if (a.key.len != b.key.len) return a.key.len < b.key.len;
    return std.mem.order(u8, a.key, b.key) == .lt;
}

/// write a short text string (< 24 bytes) as a single fused write.
/// this is the hot path for map keys in AT Protocol records, where keys
/// are always short ASCII strings. fusing header+payload into one writeAll
/// halves the writer dispatch count.
fn writeShortText(writer: anytype, text: []const u8) !void {
    if (text.len < 24) {
        var buf: [24]u8 = undefined;
        buf[0] = 0x60 | @as(u8, @intCast(text.len));
        @memcpy(buf[1..][0..text.len], text);
        try writer.writeAll(buf[0 .. 1 + text.len]);
    } else {
        try writeArgument(writer, 3, text.len);
        try writer.writeAll(text);
    }
}

/// encode a Value to the given writer in DAG-CBOR format.
/// allocator is needed for sorting map keys during encoding.
pub fn encode(allocator: Allocator, writer: anytype, value: Value) !void {
    switch (value) {
        .unsigned => |v| try writeArgument(writer, 0, v),
        .negative => |v| {
            // CBOR negative: -1 - n encoded in major type 1
            const raw: u64 = @intCast(-1 - v);
            try writeArgument(writer, 1, raw);
        },
        .bytes => |b| {
            try writeArgument(writer, 2, b.len);
            try writer.writeAll(b);
        },
        .text => |t| try writeShortText(writer, t),
        .array => |items| {
            try writeArgument(writer, 4, items.len);
            for (items) |item| {
                try encode(allocator, writer, item);
            }
        },
        .map => |entries| {
            try writeArgument(writer, 5, entries.len);
            // DAG-CBOR: keys sorted by byte length, then lexicographically.
            // three paths: already sorted (common for decoded data), stack sort
            // for small maps (≤16 entries, covers all AT Protocol records), or
            // heap sort for rare large maps.
            if (keysAlreadySorted(entries)) {
                for (entries) |entry| {
                    try writeShortText(writer, entry.key);
                    try encode(allocator, writer, entry.value);
                }
            } else if (entries.len <= 16) {
                var buf: [16]Value.MapEntry = undefined;
                const sorted = buf[0..entries.len];
                @memcpy(sorted, entries);
                std.mem.sort(Value.MapEntry, sorted, {}, dagCborKeyLessThan);
                for (sorted) |entry| {
                    try writeShortText(writer, entry.key);
                    try encode(allocator, writer, entry.value);
                }
            } else {
                const sorted = try allocator.dupe(Value.MapEntry, entries);
                defer allocator.free(sorted);
                std.mem.sort(Value.MapEntry, sorted, {}, dagCborKeyLessThan);
                for (sorted) |entry| {
                    try writeShortText(writer, entry.key);
                    try encode(allocator, writer, entry.value);
                }
            }
        },
        .boolean => |b| try writer.writeByte(if (b) @as(u8, 0xf5) else @as(u8, 0xf4)),
        .null => try writer.writeByte(0xf6),
        .cid => |c| {
            // tag 42 + byte string with 0x00 identity multibase prefix + raw CID bytes
            try writeArgument(writer, 6, 42);
            try writeArgument(writer, 2, 1 + c.raw.len);
            try writer.writeByte(0x00);
            try writer.writeAll(c.raw);
        },
    }
}

/// encode a Value to a freshly allocated byte slice
pub fn encodeAlloc(allocator: Allocator, value: Value) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try encode(allocator, &aw.writer, value);
    return try aw.toOwnedSlice();
}

/// write an unsigned varint (LEB128) — used for CID and CAR serialization
pub fn writeUvarint(writer: anytype, val: u64) !void {
    var v = val;
    while (v >= 0x80) {
        try writer.writeByte(@as(u8, @truncate(v)) | 0x80);
        v >>= 7;
    }
    try writer.writeByte(@as(u8, @truncate(v)));
}

/// Result of reading a CBOR initial byte and its argument.
pub const Arg = struct {
    major: u3,
    val: u64,
    end: usize,
};

/// Read a CBOR initial byte at `pos`, parse the argument value from
/// additional info + following bytes, and return the major type (high 3 bits),
/// argument value, and position after the header.
///
/// Validates shortest-form encoding (DAG-CBOR requirement).
/// This is the public, value-semantics equivalent of the internal `readArgument`.
pub fn readArg(data: []const u8, pos: usize) DecodeError!Arg {
    if (pos >= data.len) return error.UnexpectedEof;
    const initial = data[pos];
    const major: u3 = @truncate(initial >> 5);
    const additional: u5 = @truncate(initial);
    var cur = pos + 1;
    const val: u64 = switch (additional) {
        0...23 => @as(u64, additional),
        24 => blk: { // 1-byte
            if (cur >= data.len) return error.UnexpectedEof;
            const v = data[cur];
            cur += 1;
            if (v < 24) return error.NonMinimalEncoding;
            break :blk @as(u64, v);
        },
        25 => blk: { // 2-byte big-endian
            if (cur + 2 > data.len) return error.UnexpectedEof;
            const v = std.mem.readInt(u16, data[cur..][0..2], .big);
            cur += 2;
            if (v <= 0xff) return error.NonMinimalEncoding;
            break :blk @as(u64, v);
        },
        26 => blk: { // 4-byte big-endian
            if (cur + 4 > data.len) return error.UnexpectedEof;
            const v = std.mem.readInt(u32, data[cur..][0..4], .big);
            cur += 4;
            if (v <= 0xffff) return error.NonMinimalEncoding;
            break :blk @as(u64, v);
        },
        27 => blk: { // 8-byte big-endian
            if (cur + 8 > data.len) return error.UnexpectedEof;
            const v = std.mem.readInt(u64, data[cur..][0..8], .big);
            cur += 8;
            if (v <= 0xffffffff) return error.NonMinimalEncoding;
            break :blk v;
        },
        28, 29, 30 => return error.ReservedAdditionalInfo,
        31 => return error.IndefiniteLength,
    };
    return .{ .major = major, .val = val, .end = cur };
}

// ---------------------------------------------------------------------------
// Type-specific readers — zero-copy, no allocator needed
// ---------------------------------------------------------------------------

pub const SliceResult = struct { val: []const u8, end: usize };
pub const U64Result = struct { val: u64, end: usize };
pub const I64Result = struct { val: i64, end: usize };
pub const BoolResult = struct { val: bool, end: usize };

/// Read a CBOR text string (major type 3) at `pos`.
/// Validates UTF-8. Returns a zero-copy slice into `data`.
pub fn readText(data: []const u8, pos: usize) DecodeError!SliceResult {
    const arg = try readArg(data, pos);
    if (arg.major != 3) return error.WrongType;
    const len = std.math.cast(usize, arg.val) orelse return error.UnexpectedEof;
    const end = std.math.add(usize, arg.end, len) catch return error.UnexpectedEof;
    if (end > data.len) return error.UnexpectedEof;
    const text = data[arg.end..end];
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
    return .{ .val = text, .end = end };
}

/// Read a CBOR byte string (major type 2) at `pos`.
/// Returns a zero-copy slice into `data`.
pub fn readBytes(data: []const u8, pos: usize) DecodeError!SliceResult {
    const arg = try readArg(data, pos);
    if (arg.major != 2) return error.WrongType;
    const len = std.math.cast(usize, arg.val) orelse return error.UnexpectedEof;
    const end = std.math.add(usize, arg.end, len) catch return error.UnexpectedEof;
    if (end > data.len) return error.UnexpectedEof;
    return .{ .val = data[arg.end..end], .end = end };
}

/// Read a CBOR unsigned integer (major type 0) at `pos`.
pub fn readUint(data: []const u8, pos: usize) DecodeError!U64Result {
    const arg = try readArg(data, pos);
    if (arg.major != 0) return error.WrongType;
    return .{ .val = arg.val, .end = arg.end };
}

/// Read a CBOR integer (major type 0 or 1) at `pos`.
/// Major 0 = positive, major 1 = negative (-1 - val).
/// Returns error.Overflow if a positive value exceeds maxInt(i64).
pub fn readInt(data: []const u8, pos: usize) DecodeError!I64Result {
    const arg = try readArg(data, pos);
    switch (arg.major) {
        0 => {
            if (arg.val > @as(u64, @intCast(std.math.maxInt(i64)))) return error.Overflow;
            return .{ .val = @intCast(arg.val), .end = arg.end };
        },
        1 => {
            // CBOR negative: -1 - val
            // val can be 0..2^64-1, result is -1..-2^64
            // i64 can hold down to -2^63, so max raw val is 2^63 - 1
            if (arg.val > @as(u64, @intCast(std.math.maxInt(i64)))) return error.Overflow;
            return .{ .val = -1 - @as(i64, @intCast(arg.val)), .end = arg.end };
        },
        else => return error.WrongType,
    }
}

/// Read a CBOR boolean at `pos`.
/// 0xf4 = false, 0xf5 = true.
pub fn readBool(data: []const u8, pos: usize) DecodeError!BoolResult {
    if (pos >= data.len) return error.UnexpectedEof;
    return switch (data[pos]) {
        0xf4 => .{ .val = false, .end = pos + 1 },
        0xf5 => .{ .val = true, .end = pos + 1 },
        else => error.WrongType,
    };
}

/// Read a CBOR null at `pos`.
/// 0xf6 = null. Returns position after the null byte.
pub fn readNull(data: []const u8, pos: usize) DecodeError!usize {
    if (pos >= data.len) return error.UnexpectedEof;
    if (data[pos] != 0xf6) return error.WrongType;
    return pos + 1;
}

/// Read a CBOR map header (major type 5) at `pos`.
/// Returns the entry count.
pub fn readMapHeader(data: []const u8, pos: usize) DecodeError!U64Result {
    const arg = try readArg(data, pos);
    if (arg.major != 5) return error.WrongType;
    return .{ .val = arg.val, .end = arg.end };
}

/// Read a CBOR array header (major type 4) at `pos`.
/// Returns the element count.
pub fn readArrayHeader(data: []const u8, pos: usize) DecodeError!U64Result {
    const arg = try readArg(data, pos);
    if (arg.major != 4) return error.WrongType;
    return .{ .val = arg.val, .end = arg.end };
}

/// Read a DAG-CBOR CID link at `pos`.
/// Expects tag(42) followed by a byte string with a 0x00 identity multibase prefix.
/// Returns the raw CID bytes (after the 0x00 prefix) as a zero-copy slice.
pub fn readCidLink(data: []const u8, pos: usize) DecodeError!SliceResult {
    // Read the tag header — must be tag(42)
    const tag_arg = try readArg(data, pos);
    if (tag_arg.major != 6 or tag_arg.val != 42) return error.WrongType;
    // Read the inner byte string
    const bytes_result = try readBytes(data, tag_arg.end);
    const payload = bytes_result.val;
    // Must have 0x00 prefix + at least version byte + codec byte (min 3 bytes)
    if (payload.len < 3 or payload[0] != 0x00) return error.InvalidCid;
    return .{ .val = payload[1..], .end = bytes_result.end };
}

// ---------------------------------------------------------------------------
// Streaming helpers — skip / peek without full decode
// ---------------------------------------------------------------------------

/// Skip one CBOR value at `pos` without decoding it. Returns the position
/// after the skipped value. Iterative (not recursive) using a small stack
/// for nested containers. Zero allocation.
pub fn skipValue(data: []const u8, pos: usize) DecodeError!usize {
    const max_stack = 32;
    var stack: [max_stack]u64 = undefined;
    var depth: usize = 0;
    var cur = pos;

    while (true) {
        const arg = try readArg(data, cur);
        cur = arg.end;

        switch (arg.major) {
            0, 1 => {
                // integers: header only, nothing to skip after readArg
            },
            2, 3 => {
                // byte string / text string: skip `val` bytes of payload
                const len = std.math.cast(usize, arg.val) orelse return error.UnexpectedEof;
                cur = std.math.add(usize, cur, len) catch return error.UnexpectedEof;
                if (cur > data.len) return error.UnexpectedEof;
            },
            4 => {
                // array: push element count
                if (arg.val > 0) {
                    if (depth >= max_stack) return error.MaxDepthExceeded;
                    stack[depth] = arg.val;
                    depth += 1;
                    continue; // don't decrement — we haven't consumed an element yet
                }
            },
            5 => {
                // map: push key+value count (2 per entry)
                if (arg.val > 0) {
                    if (depth >= max_stack) return error.MaxDepthExceeded;
                    stack[depth] = std.math.mul(u64, arg.val, 2) catch return error.Overflow;
                    depth += 1;
                    continue;
                }
            },
            6 => {
                // tag: the tagged value follows immediately — loop to read it
                // don't push anything, don't decrement
                continue;
            },
            7 => {
                // simple/float: header only
            },
        }

        // After consuming a value, unwind the stack
        while (depth > 0) {
            stack[depth - 1] -= 1;
            if (stack[depth - 1] > 0) break;
            depth -= 1;
        }

        if (depth == 0) return cur;
    }
}

/// Peek at the "$type" field in a DAG-CBOR map without full decode.
/// Returns the type string (zero-copy slice) or null if not found.
pub fn peekType(data: []const u8) DecodeError!?[]const u8 {
    return peekTypeAt(data, 0);
}

/// Peek at the "$type" field starting from a given position.
pub fn peekTypeAt(data: []const u8, pos: usize) DecodeError!?[]const u8 {
    const map_header = try readArg(data, pos);
    if (map_header.major != 5) return null;

    var cur = map_header.end;
    const count = map_header.val;

    const safe_count = std.math.cast(usize, count) orelse return null;
    for (0..safe_count) |_| {
        // Read key — DAG-CBOR keys are always text strings
        const key = readText(data, cur) catch return null;
        cur = key.end;

        if (std.mem.eql(u8, key.val, "$type")) {
            // Read the value as text
            const val = readText(data, cur) catch return null;
            return val.val;
        }

        // Skip the value
        cur = try skipValue(data, cur);
    }

    return null;
}

// === low-level write API ===

/// Write CBOR initial byte + argument using shortest encoding.
/// Returns new position after written bytes. Caller must ensure buf is large enough.
pub fn writeArg(buf: []u8, pos: usize, major: u3, val: u64) usize {
    const prefix: u8 = @as(u8, major) << 5;
    if (val < 24) {
        buf[pos] = prefix | @as(u8, @intCast(val));
        return pos + 1;
    } else if (val <= 0xff) {
        buf[pos] = prefix | 24;
        buf[pos + 1] = @intCast(val);
        return pos + 2;
    } else if (val <= 0xffff) {
        buf[pos] = prefix | 25;
        const v: u16 = @intCast(val);
        buf[pos + 1] = @truncate(v >> 8);
        buf[pos + 2] = @truncate(v);
        return pos + 3;
    } else if (val <= 0xffffffff) {
        buf[pos] = prefix | 26;
        const v: u32 = @intCast(val);
        buf[pos + 1] = @truncate(v >> 24);
        buf[pos + 2] = @truncate(v >> 16);
        buf[pos + 3] = @truncate(v >> 8);
        buf[pos + 4] = @truncate(v);
        return pos + 5;
    } else {
        buf[pos] = prefix | 27;
        buf[pos + 1] = @truncate(val >> 56);
        buf[pos + 2] = @truncate(val >> 48);
        buf[pos + 3] = @truncate(val >> 40);
        buf[pos + 4] = @truncate(val >> 32);
        buf[pos + 5] = @truncate(val >> 24);
        buf[pos + 6] = @truncate(val >> 16);
        buf[pos + 7] = @truncate(val >> 8);
        buf[pos + 8] = @truncate(val);
        return pos + 9;
    }
}

/// Write CBOR text string header + payload.
pub fn writeText(buf: []u8, pos: usize, text: []const u8) usize {
    const p = writeArg(buf, pos, 3, text.len);
    @memcpy(buf[p..][0..text.len], text);
    return p + text.len;
}

/// Write CBOR byte string header + payload.
pub fn writeBytes(buf: []u8, pos: usize, bytes: []const u8) usize {
    const p = writeArg(buf, pos, 2, bytes.len);
    @memcpy(buf[p..][0..bytes.len], bytes);
    return p + bytes.len;
}

/// Write unsigned integer (major 0).
pub fn writeUint(buf: []u8, pos: usize, val: u64) usize {
    return writeArg(buf, pos, 0, val);
}

/// Write signed integer. Positive values use major 0, negative values use major 1.
pub fn writeInt(buf: []u8, pos: usize, val: i64) usize {
    if (val >= 0) {
        return writeArg(buf, pos, 0, @intCast(val));
    } else {
        const raw: u64 = @intCast(-1 - val);
        return writeArg(buf, pos, 1, raw);
    }
}

/// Write map header (major 5).
pub fn writeMapHeader(buf: []u8, pos: usize, count: usize) usize {
    return writeArg(buf, pos, 5, count);
}

/// Write array header (major 4).
pub fn writeArrayHeader(buf: []u8, pos: usize, count: usize) usize {
    return writeArg(buf, pos, 4, count);
}

/// Write boolean: 0xf5 (true) or 0xf4 (false).
pub fn writeBool(buf: []u8, pos: usize, val: bool) usize {
    buf[pos] = if (val) 0xf5 else 0xf4;
    return pos + 1;
}

/// Write null: 0xf6.
pub fn writeNull(buf: []u8, pos: usize) usize {
    buf[pos] = 0xf6;
    return pos + 1;
}

/// Write tag(42) + byte string with 0x00 prefix + CID raw bytes.
pub fn writeCidLink(buf: []u8, pos: usize, cid_raw: []const u8) usize {
    var p = writeArg(buf, pos, 6, 42);
    p = writeArg(buf, p, 2, 1 + cid_raw.len);
    buf[p] = 0x00;
    p += 1;
    @memcpy(buf[p..][0..cid_raw.len], cid_raw);
    return p + cid_raw.len;
}

// === tests ===

test "decode unsigned integers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // 0
    try std.testing.expectEqual(@as(u64, 0), (try decode(alloc, &.{0x00})).value.unsigned);
    // 1
    try std.testing.expectEqual(@as(u64, 1), (try decode(alloc, &.{0x01})).value.unsigned);
    // 23
    try std.testing.expectEqual(@as(u64, 23), (try decode(alloc, &.{0x17})).value.unsigned);
    // 24 (1-byte follows)
    try std.testing.expectEqual(@as(u64, 24), (try decode(alloc, &.{ 0x18, 24 })).value.unsigned);
    // 1000 (2-byte follows)
    try std.testing.expectEqual(@as(u64, 1000), (try decode(alloc, &.{ 0x19, 0x03, 0xe8 })).value.unsigned);
}

test "decode negative integers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -1 (major 1, additional 0)
    try std.testing.expectEqual(@as(i64, -1), (try decode(alloc, &.{0x20})).value.negative);
    // -10
    try std.testing.expectEqual(@as(i64, -10), (try decode(alloc, &.{0x29})).value.negative);
}

test "decode text strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // empty string
    try std.testing.expectEqualStrings("", (try decode(alloc, &.{0x60})).value.text);
    // "a"
    try std.testing.expectEqualStrings("a", (try decode(alloc, &.{ 0x61, 'a' })).value.text);
    // "hello"
    try std.testing.expectEqualStrings("hello", (try decode(alloc, &.{ 0x65, 'h', 'e', 'l', 'l', 'o' })).value.text);
}

test "decode byte strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // empty bytes
    try std.testing.expectEqualSlices(u8, &.{}, (try decode(alloc, &.{0x40})).value.bytes);
    // 3 bytes
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try decode(alloc, &.{ 0x43, 1, 2, 3 })).value.bytes);
}

test "decode booleans and null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqual(false, (try decode(alloc, &.{0xf4})).value.boolean);
    try std.testing.expectEqual(true, (try decode(alloc, &.{0xf5})).value.boolean);
    try std.testing.expectEqual(Value.null, (try decode(alloc, &.{0xf6})).value);
}

test "decode array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // [1, 2, 3]
    const result = try decode(alloc, &.{ 0x83, 0x01, 0x02, 0x03 });
    const arr = result.value.array;
    try std.testing.expectEqual(@as(usize, 3), arr.len);
    try std.testing.expectEqual(@as(u64, 1), arr[0].unsigned);
    try std.testing.expectEqual(@as(u64, 2), arr[1].unsigned);
    try std.testing.expectEqual(@as(u64, 3), arr[2].unsigned);
}

test "decode map" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"a": 1, "b": 2}
    const result = try decode(alloc, &.{
        0xa2, // map(2)
        0x61, 'a', 0x01, // "a": 1
        0x61, 'b', 0x02, // "b": 2
    });
    const val = result.value;
    try std.testing.expectEqual(@as(u64, 1), val.get("a").?.unsigned);
    try std.testing.expectEqual(@as(u64, 2), val.get("b").?.unsigned);
}

test "decode nested map" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"t": "#commit", "op": 1} — sorted by key length (1 < 2)
    const result = try decode(alloc, &.{
        0xa2, // map(2)
        0x61, 't', 0x67, '#', 'c', 'o', 'm', 'm', 'i', 't', // "t": "#commit"
        0x62, 'o', 'p', 0x01, // "op": 1
    });
    const val = result.value;
    try std.testing.expectEqual(@as(u64, 1), val.get("op").?.unsigned);
    try std.testing.expectEqualStrings("#commit", val.getString("t").?);
}

test "consumed bytes tracking" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // two concatenated CBOR values: 1, 2
    const data = &[_]u8{ 0x01, 0x02 };
    const first = try decode(alloc, data);
    try std.testing.expectEqual(@as(u64, 1), first.value.unsigned);
    try std.testing.expectEqual(@as(usize, 1), first.consumed);

    const second = try decode(alloc, data[first.consumed..]);
    try std.testing.expectEqual(@as(u64, 2), second.value.unsigned);
}

test "reject floats" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // half-float (f16)
    try std.testing.expectError(error.UnsupportedFloat, decode(alloc, &.{ 0xf9, 0x00, 0x00 }));
}

test "Value helper methods" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const result = try decode(alloc, &.{
        0xa3, // map(3)
        0x63, 'a', 'g', 'e', 0x18, 30, // "age": 30  (3 bytes, shortest)
        0x64, 'n', 'a', 'm', 'e', 0x65, 'a', 'l', 'i', 'c', 'e', // "name": "alice" (4 bytes)
        0x66, 'a', 'c', 't', 'i', 'v', 'e', 0xf5, // "active": true (6 bytes)
    });
    const val = result.value;
    try std.testing.expectEqualStrings("alice", val.getString("name").?);
    try std.testing.expectEqual(@as(i64, 30), val.getInt("age").?);
    try std.testing.expectEqual(true, val.getBool("active").?);
    try std.testing.expect(val.getString("missing") == null);
}

// === encoder tests ===

test "encode unsigned integers" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // 0 → single byte
    try encode(alloc, &w, .{ .unsigned = 0 });
    try std.testing.expectEqualSlices(u8, &.{0x00}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 23 });
    try std.testing.expectEqualSlices(u8, &.{0x17}, w.buffered());

    // 24 → 2 bytes (shortest encoding)
    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 24 });
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 24 }, w.buffered());

    // 1000 → 3 bytes
    w.end = 0;
    try encode(alloc, &w, .{ .unsigned = 1000 });
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x03, 0xe8 }, w.buffered());
}

test "encode negative integers" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // -1 → major 1, additional 0
    try encode(alloc, &w, .{ .negative = -1 });
    try std.testing.expectEqualSlices(u8, &.{0x20}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .negative = -10 });
    try std.testing.expectEqualSlices(u8, &.{0x29}, w.buffered());
}

test "encode text strings" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .text = "" });
    try std.testing.expectEqualSlices(u8, &.{0x60}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .text = "hello" });
    try std.testing.expectEqualSlices(u8, &.{ 0x65, 'h', 'e', 'l', 'l', 'o' }, w.buffered());
}

test "encode byte strings" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .bytes = &.{} });
    try std.testing.expectEqualSlices(u8, &.{0x40}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .bytes = &.{ 1, 2, 3 } });
    try std.testing.expectEqualSlices(u8, &.{ 0x43, 1, 2, 3 }, w.buffered());
}

test "encode booleans and null" {
    var buf: [4]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .boolean = false });
    try std.testing.expectEqualSlices(u8, &.{0xf4}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .{ .boolean = true });
    try std.testing.expectEqualSlices(u8, &.{0xf5}, w.buffered());

    w.end = 0;
    try encode(alloc, &w, .null);
    try std.testing.expectEqualSlices(u8, &.{0xf6}, w.buffered());
}

test "encode array" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // [1, 2, 3]
    try encode(alloc, &w, .{ .array = &.{
        .{ .unsigned = 1 },
        .{ .unsigned = 2 },
        .{ .unsigned = 3 },
    } });
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x01, 0x02, 0x03 }, w.buffered());
}

test "encode map with DAG-CBOR key sorting" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    // keys provided unsorted — encoder must sort by length, then lex
    // "bb" (len 2), "a" (len 1), "cc" (len 2) → sorted: "a", "bb", "cc"
    try encode(alloc, &w, .{ .map = &.{
        .{ .key = "bb", .value = .{ .unsigned = 2 } },
        .{ .key = "a", .value = .{ .unsigned = 1 } },
        .{ .key = "cc", .value = .{ .unsigned = 3 } },
    } });

    const expected = &[_]u8{
        0xa3, // map(3)
        0x61, 'a', 0x01, // "a": 1 (shortest key first)
        0x62, 'b', 'b', 0x02, // "bb": 2 (same length, lex order)
        0x62, 'c', 'c', 0x03, // "cc": 3
    };
    try std.testing.expectEqualSlices(u8, expected, w.buffered());
}

test "round-trip encode → decode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build a complex value: {"active": true, "name": "alice", "seq": 42}
    const original: Value = .{ .map = &.{
        .{ .key = "name", .value = .{ .text = "alice" } },
        .{ .key = "active", .value = .{ .boolean = true } },
        .{ .key = "seq", .value = .{ .unsigned = 42 } },
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    try std.testing.expectEqualStrings("alice", decoded.getString("name").?);
    try std.testing.expectEqual(true, decoded.getBool("active").?);
    try std.testing.expectEqual(@as(i64, 42), decoded.getInt("seq").?);
}

test "round-trip nested structures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // {"ops": [{"action": "create"}], "seq": 1}
    const original: Value = .{ .map = &.{
        .{ .key = "ops", .value = .{ .array = &.{
            .{ .map = &.{
                .{ .key = "action", .value = .{ .text = "create" } },
            } },
        } } },
        .{ .key = "seq", .value = .{ .unsigned = 1 } },
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    const ops = decoded.getArray("ops").?;
    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("create", ops[0].getString("action").?);
    try std.testing.expectEqual(@as(i64, 1), decoded.getInt("seq").?);
}

test "encode CID via tag 42" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a CIDv1 (dag-cbor, sha2-256, 32-byte digest of 0xaa)
    const raw_cid = [_]u8{
        0x01, // version
        0x71, // dag-cbor
        0x12, // sha2-256
        0x20, // 32-byte digest
    } ++ [_]u8{0xaa} ** 32;

    const original: Value = .{ .cid = .{
        .raw = &raw_cid,
    } };

    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    // should decode back as a CID with the same raw bytes
    const cid = decoded.cid;
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(@as(u64, 0x71), cid.codec().?);
    try std.testing.expectEqual(@as(u64, 0x12), cid.hashFn().?);
    try std.testing.expectEqualSlices(u8, &raw_cid, cid.raw);
}

test "writeUvarint round-trip" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);

    const test_values = [_]u64{ 0, 1, 127, 128, 255, 256, 16384, 0xffffffff };
    for (test_values) |val| {
        w.end = 0;
        try writeUvarint(&w, val);
        const written = w.buffered();

        var pos: usize = 0;
        const decoded = readUvarint(written, &pos).?;
        try std.testing.expectEqual(val, decoded);
        try std.testing.expectEqual(written.len, pos);
    }
}

test "DAG-CBOR key sort is stable" {
    // same-length keys must be lexicographically sorted
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const alloc = std.testing.allocator;

    try encode(alloc, &w, .{ .map = &.{
        .{ .key = "op", .value = .{ .unsigned = 1 } },
        .{ .key = "ab", .value = .{ .unsigned = 2 } },
    } });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const decoded = try decodeAll(arena.allocator(), w.buffered());

    // "ab" should come before "op" (lex order, same length)
    const entries = decoded.map;
    try std.testing.expectEqualStrings("ab", entries[0].key);
    try std.testing.expectEqualStrings("op", entries[1].key);
}

// === CID creation tests ===

test "Cid.forDagCbor creates valid CIDv1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // encode some CBOR, then create a CID for it
    const value: Value = .{ .map = &.{
        .{ .key = "text", .value = .{ .text = "hello" } },
    } };
    const encoded = try encodeAlloc(alloc, value);
    const cid = try Cid.forDagCbor(alloc, encoded);

    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(Codec.dag_cbor, cid.codec().?);
    try std.testing.expectEqual(HashFn.sha2_256, cid.hashFn().?);
    try std.testing.expectEqual(@as(usize, 32), cid.digest().?.len);
    // raw should be: version(1) + codec(0x71) + hash_fn(0x12) + digest_len(0x20) + 32 bytes
    try std.testing.expectEqual(@as(usize, 36), cid.raw.len);
}

test "Cid.forDagCbor is deterministic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const data = "identical input";
    const cid1 = try Cid.forDagCbor(alloc, data);
    const cid2 = try Cid.forDagCbor(alloc, data);

    try std.testing.expectEqualSlices(u8, cid1.raw, cid2.raw);
    try std.testing.expectEqualSlices(u8, cid1.digest().?, cid2.digest().?);
}

test "Cid.forDagCbor different data → different CIDs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cid1 = try Cid.forDagCbor(alloc, "data A");
    const cid2 = try Cid.forDagCbor(alloc, "data B");

    try std.testing.expect(!std.mem.eql(u8, cid1.digest().?, cid2.digest().?));
}

test "Cid.toBytes round-trips through parseCid" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const cid = try Cid.forDagCbor(alloc, "test content");
    const bytes = try cid.toBytes(alloc);
    const parsed = parseCid(bytes);

    try std.testing.expectEqual(cid.version().?, parsed.version().?);
    try std.testing.expectEqual(cid.codec().?, parsed.codec().?);
    try std.testing.expectEqual(cid.hashFn().?, parsed.hashFn().?);
    try std.testing.expectEqualSlices(u8, cid.digest().?, parsed.digest().?);
}

test "CID round-trip through CBOR encode/decode" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // create a CID for some content
    const cid = try Cid.forDagCbor(alloc, "block data");

    // embed in a map and round-trip through CBOR
    const original: Value = .{ .map = &.{
        .{ .key = "link", .value = .{ .cid = cid } },
    } };
    const encoded = try encodeAlloc(alloc, original);
    const decoded = try decodeAll(alloc, encoded);

    const got = decoded.get("link").?.cid;
    try std.testing.expectEqual(cid.version().?, got.version().?);
    try std.testing.expectEqual(cid.codec().?, got.codec().?);
    try std.testing.expectEqualSlices(u8, cid.digest().?, got.digest().?);
}

// === verify CIDs against real AT Protocol records ===

test "real record: pfrazee 'First!' post CID matches network" {
    // at://did:plc:ragtjsm2j2vknwkz3zp4oxrd/app.bsky.feed.post/3jhnzcfawac27
    // CID: bafyreiaqnrahsbvcssf2xe4iqhn2fnjw7utmvrbif2v36tqe3r5iqill7i
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const record: Value = .{ .map = &.{
        .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "createdAt", .value = .{ .text = "2022-11-17T00:39:00.477Z" } },
        .{ .key = "text", .value = .{ .text = "First!" } },
    } };

    const encoded = try encodeAlloc(alloc, record);
    const cid = try Cid.forDagCbor(alloc, encoded);

    // verify against known production digest
    const expected_digest = [_]u8{
        0x10, 0x6c, 0x40, 0x79, 0x06, 0xa2, 0x94, 0x8b,
        0xab, 0x93, 0x88, 0x81, 0xdb, 0xa2, 0xb5, 0x36,
        0xfd, 0x26, 0xca, 0xc4, 0x28, 0x2e, 0xab, 0xbf,
        0x4e, 0x04, 0xdc, 0x7a, 0x88, 0x21, 0x6b, 0xfa,
    };

    try std.testing.expectEqualSlices(u8, &expected_digest, cid.digest().?);
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(Codec.dag_cbor, cid.codec().?);
    try std.testing.expectEqual(HashFn.sha2_256, cid.hashFn().?);
}

test "real record: firehose post with emoji/langs/reply is byte-identical after re-encode" {
    // captured from live firehose: app.bsky.feed.post with emoji, langs, and reply
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original_cbor = &[_]u8{
        0xa5, 0x64, 0x74, 0x65, 0x78, 0x74, 0x6b, 0xf0, 0x9f, 0xa5, 0xb5, 0x20, 0x6d, 0x65, 0x20, 0x74,
        0x6f, 0x6f, 0x65, 0x24, 0x74, 0x79, 0x70, 0x65, 0x72, 0x61, 0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b,
        0x79, 0x2e, 0x66, 0x65, 0x65, 0x64, 0x2e, 0x70, 0x6f, 0x73, 0x74, 0x65, 0x6c, 0x61, 0x6e, 0x67,
        0x73, 0x81, 0x62, 0x65, 0x6e, 0x65, 0x72, 0x65, 0x70, 0x6c, 0x79, 0xa2, 0x64, 0x72, 0x6f, 0x6f,
        0x74, 0xa2, 0x63, 0x63, 0x69, 0x64, 0x78, 0x3b, 0x62, 0x61, 0x66, 0x79, 0x72, 0x65, 0x69, 0x62,
        0x33, 0x70, 0x77, 0x72, 0x66, 0x66, 0x32, 0x79, 0x61, 0x64, 0x7a, 0x6e, 0x6f, 0x70, 0x68, 0x7a,
        0x66, 0x34, 0x68, 0x63, 0x76, 0x74, 0x79, 0x6f, 0x63, 0x74, 0x77, 0x7a, 0x63, 0x75, 0x6a, 0x76,
        0x7a, 0x37, 0x78, 0x34, 0x70, 0x6e, 0x67, 0x6b, 0x32, 0x69, 0x73, 0x69, 0x63, 0x7a, 0x37, 0x79,
        0x73, 0x7a, 0x71, 0x63, 0x75, 0x72, 0x69, 0x78, 0x46, 0x61, 0x74, 0x3a, 0x2f, 0x2f, 0x64, 0x69,
        0x64, 0x3a, 0x70, 0x6c, 0x63, 0x3a, 0x34, 0x6e, 0x65, 0x6e, 0x64, 0x77, 0x71, 0x72, 0x73, 0x37,
        0x35, 0x34, 0x67, 0x74, 0x36, 0x71, 0x76, 0x67, 0x72, 0x35, 0x36, 0x6a, 0x6d, 0x6e, 0x2f, 0x61,
        0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b, 0x79, 0x2e, 0x66, 0x65, 0x65, 0x64, 0x2e, 0x70, 0x6f, 0x73,
        0x74, 0x2f, 0x33, 0x6d, 0x65, 0x64, 0x67, 0x32, 0x71, 0x76, 0x63, 0x75, 0x63, 0x32, 0x63, 0x66,
        0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0xa2, 0x63, 0x63, 0x69, 0x64, 0x78, 0x3b, 0x62, 0x61, 0x66,
        0x79, 0x72, 0x65, 0x69, 0x62, 0x33, 0x70, 0x77, 0x72, 0x66, 0x66, 0x32, 0x79, 0x61, 0x64, 0x7a,
        0x6e, 0x6f, 0x70, 0x68, 0x7a, 0x66, 0x34, 0x68, 0x63, 0x76, 0x74, 0x79, 0x6f, 0x63, 0x74, 0x77,
        0x7a, 0x63, 0x75, 0x6a, 0x76, 0x7a, 0x37, 0x78, 0x34, 0x70, 0x6e, 0x67, 0x6b, 0x32, 0x69, 0x73,
        0x69, 0x63, 0x7a, 0x37, 0x79, 0x73, 0x7a, 0x71, 0x63, 0x75, 0x72, 0x69, 0x78, 0x46, 0x61, 0x74,
        0x3a, 0x2f, 0x2f, 0x64, 0x69, 0x64, 0x3a, 0x70, 0x6c, 0x63, 0x3a, 0x34, 0x6e, 0x65, 0x6e, 0x64,
        0x77, 0x71, 0x72, 0x73, 0x37, 0x35, 0x34, 0x67, 0x74, 0x36, 0x71, 0x76, 0x67, 0x72, 0x35, 0x36,
        0x6a, 0x6d, 0x6e, 0x2f, 0x61, 0x70, 0x70, 0x2e, 0x62, 0x73, 0x6b, 0x79, 0x2e, 0x66, 0x65, 0x65,
        0x64, 0x2e, 0x70, 0x6f, 0x73, 0x74, 0x2f, 0x33, 0x6d, 0x65, 0x64, 0x67, 0x32, 0x71, 0x76, 0x63,
        0x75, 0x63, 0x32, 0x63, 0x69, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x78, 0x18,
        0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x38, 0x54, 0x30, 0x37, 0x3a, 0x34, 0x39,
        0x3a, 0x32, 0x30, 0x2e, 0x37, 0x37, 0x32, 0x5a,
    };

    // expected CID digest from the firehose frame
    const expected_digest = [_]u8{
        0x80, 0x01, 0x66, 0x46, 0x81, 0x57, 0x18, 0xaf, 0xc9, 0x34, 0xcf, 0xbf,
        0x3b, 0x3e, 0x57, 0x04, 0x24, 0x17, 0x90, 0x29, 0x2f, 0x7b, 0xc4, 0xe0,
        0xf4, 0xcf, 0xe6, 0xe6, 0xb5, 0xad, 0x11, 0x28,
    };

    // decode → re-encode → verify byte-identical
    const decoded = try decodeAll(alloc, original_cbor);
    const re_encoded = try encodeAlloc(alloc, decoded);
    try std.testing.expectEqualSlices(u8, original_cbor, re_encoded);

    // verify CID matches the production CID
    const cid = try Cid.forDagCbor(alloc, re_encoded);
    try std.testing.expectEqualSlices(u8, &expected_digest, cid.digest().?);
}
