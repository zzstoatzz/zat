//! RFC 8949 test vector compliance for DAG-CBOR
//!
//! runs the canonical CBOR specification test vectors from RFC 8949 Appendix A.
//! vectors are classified into three categories:
//!   1. invalid — must be rejected by the decoder
//!   2. valid + canonical — must decode and re-encode to identical bytes
//!   3. valid + non-canonical — must be rejected by DAG-CBOR (requires shortest form)
//!
//! vector source: https://github.com/cbor/test-vectors

const std = @import("std");
const cbor = @import("cbor.zig");

const vectors_json = @embedFile("testdata/rfc8949-vectors.json");

const Vector = struct {
    hex: []const u8,
    flags: []const []const u8,
    features: []const []const u8 = &.{},
    diagnostic: []const u8 = "",

    fn hasFlag(self: Vector, flag: []const u8) bool {
        for (self.flags) |f| {
            if (std.mem.eql(u8, f, flag)) return true;
        }
        return false;
    }

    fn hasFeature(self: Vector, feature: []const u8) bool {
        for (self.features) |f| {
            if (std.mem.eql(u8, f, feature)) return true;
        }
        return false;
    }
};

fn parseVectors(allocator: std.mem.Allocator) !std.json.Parsed([]const Vector) {
    return std.json.parseFromSlice(
        []const Vector,
        allocator,
        vectors_json,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    );
}

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

/// features and patterns that are outside DAG-CBOR's subset
fn isOutsideDagCbor(v: Vector) bool {
    // floats (DAG-CBOR / DASL forbids all floats)
    if (v.hasFeature("float16")) return true;
    // bignums
    if (v.hasFeature("bignum") or v.hasFeature("!bignum")) return true;
    // simple values beyond false/true/null
    if (v.hasFeature("simple")) return true;
    // u64 overflow (values > i64 max that we store as unsigned)
    if (v.hasFeature("int64")) return true;
    // special float diagnostics
    if (std.mem.indexOf(u8, v.diagnostic, "NaN") != null) return true;
    if (std.mem.indexOf(u8, v.diagnostic, "Infinity") != null) return true;
    if (std.mem.eql(u8, v.diagnostic, "undefined")) return true;
    // float32/float64 prefix (DASL forbids all floats)
    if (v.hex.len >= 2 and std.mem.eql(u8, v.hex[0..2], "fa")) return true;
    if (v.hex.len >= 2 and std.mem.eql(u8, v.hex[0..2], "fb")) return true;
    // non-42 tags: c0, c1, d7xx, d8xx (but not d82a which is tag 42)
    if (v.hex.len >= 2) {
        if (std.mem.eql(u8, v.hex[0..2], "c0")) return true;
        if (std.mem.eql(u8, v.hex[0..2], "c1")) return true;
        if (v.hex.len >= 4 and std.mem.eql(u8, v.hex[0..2], "d7")) return true;
        if (v.hex.len >= 4 and std.mem.eql(u8, v.hex[0..2], "d8")) {
            // d82a = tag(42) which IS valid DAG-CBOR
            if (!std.mem.eql(u8, v.hex[0..4], "d82a")) return true;
        }
        if (v.hex.len >= 6 and std.mem.eql(u8, v.hex[0..4], "d820")) return true;
    }
    // map with integer keys
    if (std.mem.eql(u8, v.hex, "a201020304")) return true;
    return false;
}

test "RFC 8949: invalid vectors must be rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = try parseVectors(alloc);
    defer parsed.deinit();

    var tested: usize = 0;
    for (parsed.value) |v| {
        if (!v.hasFlag("invalid")) continue;

        const data = hexToBytes(alloc, v.hex) catch continue;
        if (cbor.decodeAll(alloc, data)) |_| {
            std.debug.print("FAIL: invalid vector accepted: hex={s} diag={s}\n", .{ v.hex, v.diagnostic });
            return error.TestExpectedError;
        } else |_| {}
        tested += 1;
    }
    // sanity check: we should have tested hundreds of invalid vectors
    try std.testing.expect(tested > 600);
}

test "RFC 8949: valid canonical vectors round-trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = try parseVectors(alloc);
    defer parsed.deinit();

    var tested: usize = 0;
    for (parsed.value) |v| {
        if (!v.hasFlag("valid")) continue;
        if (!v.hasFlag("canonical")) continue;
        if (isOutsideDagCbor(v)) continue;

        const data = hexToBytes(alloc, v.hex) catch continue;
        const decoded = cbor.decodeAll(alloc, data) catch |err| {
            std.debug.print("FAIL: valid vector rejected: hex={s} diag={s} err={s}\n", .{ v.hex, v.diagnostic, @errorName(err) });
            return error.TestUnexpectedResult;
        };

        // re-encode and verify byte-identical (canonical round-trip)
        const re_encoded = cbor.encodeAlloc(alloc, decoded) catch |err| {
            std.debug.print("FAIL: re-encode failed: hex={s} diag={s} err={s}\n", .{ v.hex, v.diagnostic, @errorName(err) });
            return error.TestUnexpectedResult;
        };

        if (!std.mem.eql(u8, data, re_encoded)) {
            std.debug.print("FAIL: round-trip mismatch: hex={s} diag={s}\n", .{ v.hex, v.diagnostic });
            return error.TestExpectedEqual;
        }
        tested += 1;
    }
    // sanity check: we should have tested dozens of valid vectors
    try std.testing.expect(tested > 30);
}

test "RFC 8949: valid non-canonical vectors must be rejected by DAG-CBOR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const parsed = try parseVectors(alloc);
    defer parsed.deinit();

    var tested: usize = 0;
    for (parsed.value) |v| {
        if (!v.hasFlag("valid")) continue;
        if (v.hasFlag("canonical")) continue;
        // skip features outside DAG-CBOR scope
        if (v.hasFeature("float16")) continue;
        if (v.hasFeature("bignum")) continue;
        if (v.hasFeature("simple")) continue;
        if (std.mem.indexOf(u8, v.diagnostic, "NaN") != null) continue;
        if (std.mem.indexOf(u8, v.diagnostic, "Infinity") != null) continue;

        const data = hexToBytes(alloc, v.hex) catch continue;
        const result = cbor.decodeAll(alloc, data);
        if (result) |_| {
            std.debug.print("FAIL: non-canonical vector accepted: hex={s} diag={s}\n", .{ v.hex, v.diagnostic });
            return error.TestExpectedError;
        } else |_| {}
        tested += 1;
    }
    try std.testing.expect(tested > 10);
}
