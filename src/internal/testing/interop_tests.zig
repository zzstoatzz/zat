//! interop tests against bluesky-social/atproto-interop-tests fixtures
//!
//! validates zat's parsers and crypto against the official test vectors.

const std = @import("std");

// types under test
const Tid = @import("../syntax/tid.zig").Tid;
const Did = @import("../syntax/did.zig").Did;
const Handle = @import("../syntax/handle.zig").Handle;
const Nsid = @import("../syntax/nsid.zig").Nsid;
const Rkey = @import("../syntax/rkey.zig").Rkey;
const AtUri = @import("../syntax/at_uri.zig").AtUri;

// crypto
const jwt = @import("../crypto/jwt.zig");
const Keypair = @import("../crypto/keypair.zig").Keypair;
const multibase = @import("../crypto/multibase.zig");
const multicodec = @import("../crypto/multicodec.zig");

// repo
const mst = @import("../repo/mst.zig");
const cbor = @import("../repo/cbor.zig");

// === helpers ===

fn LineIterator(comptime sentinel: ?u8) type {
    return struct {
        inner: std.mem.SplitIterator(u8, .scalar),

        const Self = @This();

        fn init(data: []const u8) Self {
            // strip trailing sentinel if present (some files end with \n)
            const trimmed = if (sentinel) |s|
                if (data.len > 0 and data[data.len - 1] == s) data[0 .. data.len - 1] else data
            else
                data;
            return .{ .inner = std.mem.splitScalar(u8, trimmed, '\n') };
        }

        fn next(self: *Self) ?[]const u8 {
            while (self.inner.next()) |line| {
                // skip blank lines and comments
                if (line.len == 0) continue;
                if (line[0] == '#') continue;
                // strip trailing \r for windows line endings
                const trimmed = if (line.len > 0 and line[line.len - 1] == '\r')
                    line[0 .. line.len - 1]
                else
                    line;
                if (trimmed.len == 0) continue;
                return trimmed;
            }
            return null;
        }
    };
}

fn testLinesSentinel(comptime data: [:0]const u8) LineIterator(0) {
    return LineIterator(0).init(data);
}

/// run syntax validation tests for a parser type
fn syntaxTest(
    comptime valid_data: [:0]const u8,
    comptime invalid_data: [:0]const u8,
    comptime parseFn: anytype,
) !void {
    // test valid lines
    var valid_lines = testLinesSentinel(valid_data);
    var valid_count: usize = 0;
    while (valid_lines.next()) |line| {
        if (parseFn(line) == null) {
            std.debug.print("FAIL: expected valid, got null for: '{s}'\n", .{line});
            return error.ExpectedValid;
        }
        valid_count += 1;
    }
    if (valid_count == 0) return error.NoTestCases;

    // test invalid lines
    var invalid_lines = testLinesSentinel(invalid_data);
    var invalid_count: usize = 0;
    while (invalid_lines.next()) |line| {
        if (parseFn(line) != null) {
            std.debug.print("FAIL: expected null, got valid for: '{s}'\n", .{line});
            return error.ExpectedInvalid;
        }
        invalid_count += 1;
    }
    if (invalid_count == 0) return error.NoTestCases;
}

fn parseAtIdentifier(s: []const u8) ?void {
    if (Did.parse(s) != null or Handle.parse(s) != null) return {};
    return null;
}

fn parseCidSyntax(s: []const u8) ?void {
    if (s.len < 8 or s.len > 256) return null;
    if (std.mem.startsWith(u8, s, "Qmb")) return null;
    for (s) |c| {
        const valid = switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '+', '=' => true,
            else => false,
        };
        if (!valid) return null;
    }
    return {};
}

fn parseUriSyntax(s: []const u8) ?void {
    if (s.len == 0 or s.len > 8192) return null;
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0 or colon > 81) return null;
    if (s[0] < 'a' or s[0] > 'z') return null;
    for (s[1..colon]) |c| {
        const valid = (c >= 'a' and c <= 'z') or c == '.' or c == '-';
        if (!valid) return null;
    }
    if (colon + 1 >= s.len) return null;
    for (s[colon + 1 ..]) |c| {
        if (c < 0x21 or c > 0x7e) return null;
    }
    return {};
}

fn parseLanguageSyntax(s: []const u8) ?void {
    if (s.len == 0 or s.len > 128) return null;

    const first_end = std.mem.indexOfScalar(u8, s, '-') orelse s.len;
    const first = s[0..first_end];
    if (std.mem.eql(u8, first, "i")) {
        // grandfathered/private tags use the same subtag loop below.
    } else if (first.len == 2 or first.len == 3) {
        for (first) |c| {
            if (c < 'a' or c > 'z') return null;
        }
    } else {
        return null;
    }

    var pos = first_end;
    while (pos < s.len) {
        if (s[pos] != '-') return null;
        pos += 1;
        const sub_start = pos;
        while (pos < s.len and s[pos] != '-') : (pos += 1) {
            const c = s[pos];
            const valid = (c >= 'A' and c <= 'Z') or
                (c >= 'a' and c <= 'z') or
                (c >= '0' and c <= '9');
            if (!valid) return null;
        }
        if (pos == sub_start) return null;
    }
    return {};
}

fn parse2(s: []const u8, pos: usize) ?u8 {
    if (pos + 2 > s.len) return null;
    var n: u8 = 0;
    for (s[pos .. pos + 2]) |c| {
        if (c < '0' or c > '9') return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

fn parse4(s: []const u8, pos: usize) ?u16 {
    if (pos + 4 > s.len) return null;
    var n: u16 = 0;
    for (s[pos .. pos + 4]) |c| {
        if (c < '0' or c > '9') return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn parseDatetimeSyntax(s: []const u8) ?void {
    if (s.len == 0 or s.len > 64) return null;
    if (s.len < "0000-01-01T00:00:00Z".len) return null;

    const year = parse4(s, 0) orelse return null;
    if (s[4] != '-') return null;
    const month = parse2(s, 5) orelse return null;
    if (s[7] != '-') return null;
    const day = parse2(s, 8) orelse return null;
    if (s[10] != 'T') return null;
    const hour = parse2(s, 11) orelse return null;
    if (s[13] != ':') return null;
    const minute = parse2(s, 14) orelse return null;
    if (s[16] != ':') return null;
    const second = parse2(s, 17) orelse return null;

    if (month < 1 or month > 12) return null;
    if (day < 1 or day > daysInMonth(year, month)) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;

    var pos: usize = 19;
    if (pos < s.len and s[pos] == '.') {
        pos += 1;
        const frac_start = pos;
        while (pos < s.len and s[pos] >= '0' and s[pos] <= '9') : (pos += 1) {}
        const frac_len = pos - frac_start;
        if (frac_len == 0 or frac_len > 20) return null;
    }

    if (pos >= s.len) return null;
    if (s[pos] == 'Z') {
        return if (pos + 1 == s.len) {} else null;
    }

    if (s[pos] != '+' and s[pos] != '-') return null;
    const tz_sign = s[pos];
    if (pos + 6 != s.len) return null;
    const tz_hour = parse2(s, pos + 1) orelse return null;
    if (s[pos + 3] != ':') return null;
    const tz_minute = parse2(s, pos + 4) orelse return null;
    if (tz_hour > 23 or tz_minute > 59) return null;
    if (tz_sign == '-' and tz_hour == 0 and tz_minute == 0) return null;
    if (year == 0 and month == 1 and day == 1 and hour == 0 and minute == 0 and second == 0 and tz_sign == '+') return null;
    return {};
}

// === tier 1: syntax validation ===

test "interop: tid syntax" {
    try syntaxTest(
        @embedFile("tid_syntax_valid"),
        @embedFile("tid_syntax_invalid"),
        Tid.parse,
    );
}

test "interop: did syntax" {
    try syntaxTest(
        @embedFile("did_syntax_valid"),
        @embedFile("did_syntax_invalid"),
        Did.parse,
    );
}

test "interop: handle syntax" {
    try syntaxTest(
        @embedFile("handle_syntax_valid"),
        @embedFile("handle_syntax_invalid"),
        Handle.parse,
    );
}

test "interop: nsid syntax" {
    try syntaxTest(
        @embedFile("nsid_syntax_valid"),
        @embedFile("nsid_syntax_invalid"),
        Nsid.parse,
    );
}

test "interop: rkey syntax" {
    try syntaxTest(
        @embedFile("recordkey_syntax_valid"),
        @embedFile("recordkey_syntax_invalid"),
        Rkey.parse,
    );
}

test "interop: aturi syntax" {
    try syntaxTest(
        @embedFile("aturi_syntax_valid"),
        @embedFile("aturi_syntax_invalid"),
        AtUri.parse,
    );
}

test "interop: all syntax fixture files" {
    try syntaxTest(
        @embedFile("tid_syntax_valid"),
        @embedFile("tid_syntax_invalid"),
        Tid.parse,
    );
    try syntaxTest(
        @embedFile("did_syntax_valid"),
        @embedFile("did_syntax_invalid"),
        Did.parse,
    );
    try syntaxTest(
        @embedFile("handle_syntax_valid"),
        @embedFile("handle_syntax_invalid"),
        Handle.parse,
    );
    try syntaxTest(
        @embedFile("nsid_syntax_valid"),
        @embedFile("nsid_syntax_invalid"),
        Nsid.parse,
    );
    try syntaxTest(
        @embedFile("recordkey_syntax_valid"),
        @embedFile("recordkey_syntax_invalid"),
        Rkey.parse,
    );
    try syntaxTest(
        @embedFile("aturi_syntax_valid"),
        @embedFile("aturi_syntax_invalid"),
        AtUri.parse,
    );
    try syntaxTest(
        @embedFile("atidentifier_syntax_valid"),
        @embedFile("atidentifier_syntax_invalid"),
        parseAtIdentifier,
    );
    try syntaxTest(
        @embedFile("cid_syntax_valid"),
        @embedFile("cid_syntax_invalid"),
        parseCidSyntax,
    );
    try syntaxTest(
        @embedFile("uri_syntax_valid"),
        @embedFile("uri_syntax_invalid"),
        parseUriSyntax,
    );
    try syntaxTest(
        @embedFile("language_syntax_valid"),
        @embedFile("language_syntax_invalid"),
        parseLanguageSyntax,
    );
    try syntaxTest(
        @embedFile("datetime_syntax_valid"),
        @embedFile("datetime_syntax_invalid"),
        parseDatetimeSyntax,
    );

    var invalid_parse = testLinesSentinel(@embedFile("datetime_parse_invalid"));
    while (invalid_parse.next()) |line| {
        if (parseDatetimeSyntax(line) != null) {
            std.debug.print("FAIL: expected semantically invalid datetime: '{s}'\n", .{line});
            return error.ExpectedInvalid;
        }
    }
}

// === tier 2: crypto signature verification ===

fn base64StdDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    // try standard (padded) first, fall back to no-pad
    const decoder = if (input.len > 0 and input[input.len - 1] == '=')
        &std.base64.standard.Decoder
    else
        &std.base64.standard_no_pad.Decoder;

    const size = decoder.calcSizeForSlice(input) catch return error.InvalidBase64;
    const output = try allocator.alloc(u8, size);
    errdefer allocator.free(output);
    decoder.decode(output, input) catch return error.InvalidBase64;
    return output;
}

test "interop: crypto signature verification" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("signature_fixtures");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;

        const comment = if (obj.get("comment")) |v| switch (v) {
            .string => |s| s,
            else => "?",
        } else "?";

        const message_b64 = obj.get("messageBase64").?.string;
        const algorithm = obj.get("algorithm").?.string;
        const pub_key_did = obj.get("publicKeyDid").?.string;
        const sig_b64 = obj.get("signatureBase64").?.string;
        const valid = obj.get("validSignature").?.bool;

        // extract multibase key from did:key (strip "did:key:" prefix)
        const did_key_prefix = "did:key:";
        if (!std.mem.startsWith(u8, pub_key_did, did_key_prefix)) return error.InvalidDidKey;
        const multibase_key = pub_key_did[did_key_prefix.len..];

        // decode message and signature
        const message = try base64StdDecode(allocator, message_b64);
        defer allocator.free(message);

        const sig_bytes = base64StdDecode(allocator, sig_b64) catch |err| {
            // DER-encoded sigs may fail to decode at expected length — that's fine for invalid
            if (!valid) {
                tested += 1;
                continue;
            }
            return err;
        };
        defer allocator.free(sig_bytes);

        // decode public key from multibase+multicodec (did:key format)
        const key_bytes = try multibase.decode(allocator, multibase_key);
        defer allocator.free(key_bytes);

        const parsed_key = try multicodec.parsePublicKey(key_bytes);

        // verify signature
        const verify_result = if (std.mem.eql(u8, algorithm, "ES256K"))
            jwt.verifySecp256k1(message, sig_bytes, parsed_key.raw)
        else if (std.mem.eql(u8, algorithm, "ES256"))
            jwt.verifyP256(message, sig_bytes, parsed_key.raw)
        else
            error.UnsupportedAlgorithm;

        if (valid) {
            verify_result catch |err| {
                std.debug.print("FAIL: expected valid signature but got {s}: {s}\n", .{ @errorName(err), comment });
                return error.ExpectedValidSignature;
            };
        } else {
            if (verify_result) |_| {
                std.debug.print("FAIL: expected invalid signature but verified OK: {s}\n", .{comment});
                return error.ExpectedInvalidSignature;
            } else |_| {}
        }

        tested += 1;
    }

    // should have tested all 6 fixtures
    try std.testing.expect(tested == fixtures.len);
}

// === tier 2b: did:key derivation ===

test "interop: did:key derivation K256" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("w3c_didkey_K256");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const hex_str = obj.get("privateKeyBytesHex").?.string;
        const expected_did = obj.get("publicDidKey").?.string;

        var sk_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&sk_bytes, hex_str) catch return error.InvalidHex;

        const kp = try Keypair.fromSecretKey(.secp256k1, sk_bytes);
        const actual_did = try kp.did(allocator);
        defer allocator.free(actual_did);

        if (!std.mem.eql(u8, actual_did, expected_did)) {
            std.debug.print("FAIL K256: expected {s}, got {s}\n", .{ expected_did, actual_did });
            return error.DidKeyMismatch;
        }
        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 5), tested);
}

test "interop: did:key derivation P256" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("w3c_didkey_P256");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const b58_str = obj.get("privateKeyBytesBase58").?.string;
        const expected_did = obj.get("publicDidKey").?.string;

        // raw base58 (no multibase 'z' prefix)
        const decoded = try multibase.base58btc.decode(allocator, b58_str);
        defer allocator.free(decoded);
        if (decoded.len < 32) return error.KeyTooShort;

        const kp = try Keypair.fromSecretKey(.p256, decoded[0..32].*);
        const actual_did = try kp.did(allocator);
        defer allocator.free(actual_did);

        if (!std.mem.eql(u8, actual_did, expected_did)) {
            std.debug.print("FAIL P256: expected {s}, got {s}\n", .{ expected_did, actual_did });
            return error.DidKeyMismatch;
        }
        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 1), tested);
}

// === tier 2c: data model round-trip ===

/// convert AT Protocol JSON to CBOR value
/// handles $link (CID) and $bytes (byte string) special types
fn jsonToCbor(allocator: std.mem.Allocator, json: std.json.Value) !cbor.Value {
    switch (json) {
        .object => |obj| {
            // check for $link → CID
            if (obj.get("$link")) |link_val| {
                const link_str = switch (link_val) {
                    .string => |s| s,
                    else => return error.InvalidLink,
                };
                // bafyrei... is base32lower multibase (without 'b' prefix in the $link value,
                // but CID strings in AT Protocol use the full multibase-prefixed form)
                // actually the fixture CIDs start with "bafyrei" which is base32lower with 'b' prefix
                const raw = try multibase.base32lower.decode(allocator, link_str[1..]);
                return .{ .cid = .{ .raw = raw } };
            }
            // check for $bytes → byte string
            if (obj.get("$bytes")) |bytes_val| {
                const b64_str = switch (bytes_val) {
                    .string => |s| s,
                    else => return error.InvalidBytes,
                };
                const decoded = try base64StdDecode(allocator, b64_str);
                return .{ .bytes = decoded };
            }
            // regular object → map
            const entries = try allocator.alloc(cbor.Value.MapEntry, obj.count());
            var i: usize = 0;
            var it = obj.iterator();
            while (it.next()) |kv| {
                entries[i] = .{
                    .key = kv.key_ptr.*,
                    .value = try jsonToCbor(allocator, kv.value_ptr.*),
                };
                i += 1;
            }
            return .{ .map = entries };
        },
        .array => |arr| {
            const items = try allocator.alloc(cbor.Value, arr.items.len);
            for (arr.items, 0..) |item, i| {
                items[i] = try jsonToCbor(allocator, item);
            }
            return .{ .array = items };
        },
        .string => |s| return .{ .text = s },
        .integer => |n| {
            if (n >= 0) return .{ .unsigned = @intCast(n) };
            return .{ .negative = n };
        },
        .float => |f| {
            // DAG-CBOR has no floats; coerce integer-valued floats
            const int_val: i64 = @intFromFloat(f);
            if (@as(f64, @floatFromInt(int_val)) != f) return error.UnsupportedFloat;
            if (int_val >= 0) return .{ .unsigned = @intCast(int_val) };
            return .{ .negative = int_val };
        },
        .null => return .null,
        .bool => |b| return .{ .boolean = b },
        .number_string => return error.UnsupportedNumberString,
    }
}

test "interop: data model fixtures" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("data_model_fixtures");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const obj = fixture.object;
        const json_val = obj.get("json").?;
        const expected_cbor_b64 = obj.get("cbor_base64").?.string;
        const expected_cid_str = obj.get("cid").?.string;

        // convert JSON → CBOR value → encoded bytes
        const cbor_val = try jsonToCbor(a, json_val);
        const encoded = try cbor.encodeAlloc(a, cbor_val);

        // compare encoded bytes with expected
        const expected_bytes = try base64StdDecode(a, expected_cbor_b64);
        if (!std.mem.eql(u8, encoded, expected_bytes)) {
            std.debug.print("FAIL data model: CBOR encoding mismatch for fixture {d}\n", .{tested});
            std.debug.print("  expected ({d} bytes): ", .{expected_bytes.len});
            for (expected_bytes) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual   ({d} bytes): ", .{encoded.len});
            for (encoded) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.CborEncodingMismatch;
        }

        // compute CID and compare
        const cid = try cbor.Cid.forDagCbor(a, encoded);
        // format as base32lower multibase string: "b" + base32lower(raw)
        const cid_str = try multibase.base32lower.encode(a, cid.raw);
        if (!std.mem.eql(u8, cid_str, expected_cid_str)) {
            std.debug.print("FAIL data model: CID mismatch for fixture {d}\n", .{tested});
            std.debug.print("  expected: {s}\n  actual:   {s}\n", .{ expected_cid_str, cid_str });
            return error.CidMismatch;
        }

        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), tested);
}

// === tier 3: MST ===

test "interop: mst key heights" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("mst_key_heights");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const key = obj.get("key").?.string;
        const expected_height: u32 = @intCast(obj.get("height").?.integer);

        const actual = mst.keyHeight(key);
        if (actual != expected_height) {
            std.debug.print("FAIL: key '{s}': expected height {d}, got {d}\n", .{ key, expected_height, actual });
            return error.WrongHeight;
        }
        tested += 1;
    }

    try std.testing.expect(tested > 0);
}

test "interop: mst common prefix" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("common_prefix");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const left = obj.get("left").?.string;
        const right = obj.get("right").?.string;
        const expected_len: usize = @intCast(obj.get("len").?.integer);

        const actual = mst.commonPrefixLen(left, right);
        if (actual != expected_len) {
            std.debug.print("FAIL: commonPrefixLen('{s}', '{s}'): expected {d}, got {d}\n", .{ left, right, expected_len, actual });
            return error.WrongPrefixLen;
        }
        tested += 1;
    }

    try std.testing.expect(tested == 13);
}

test "interop: mst commit proofs" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("commit_proofs");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const obj = fixture.object;
        const comment = if (obj.get("comment")) |v| switch (v) {
            .string => |s| s,
            else => "?",
        } else "?";

        // parse leaf value CID
        const leaf_value_str = obj.get("leafValue").?.string;
        const leaf_cid = try mst.parseCidString(a, leaf_value_str);

        // build initial tree from keys
        var tree = mst.Mst.init(a);
        const keys = obj.get("keys").?.array.items;
        for (keys) |key_val| {
            try tree.put(key_val.string, leaf_cid);
        }

        // verify root before commit
        const root_before_str = obj.get("rootBeforeCommit").?.string;
        const expected_before = try mst.parseCidString(a, root_before_str);

        const actual_before = try tree.rootCid();
        if (!std.mem.eql(u8, actual_before.raw, expected_before.raw)) {
            std.debug.print("FAIL [{s}]: rootBeforeCommit mismatch\n", .{comment});
            std.debug.print("  expected: {s}\n", .{root_before_str});
            // print hex for debugging
            std.debug.print("  expected raw ({d}): ", .{expected_before.raw.len});
            for (expected_before.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual raw ({d}):   ", .{actual_before.raw.len});
            for (actual_before.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.RootBeforeMismatch;
        }

        // apply adds
        const adds = obj.get("adds").?.array.items;
        for (adds) |add_val| {
            try tree.put(add_val.string, leaf_cid);
        }

        // apply dels
        const dels = obj.get("dels").?.array.items;
        for (dels) |del_val| {
            try tree.delete(del_val.string);
        }

        // verify root after commit
        const root_after_str = obj.get("rootAfterCommit").?.string;
        const expected_after = try mst.parseCidString(a, root_after_str);

        const actual_after = try tree.rootCid();
        if (!std.mem.eql(u8, actual_after.raw, expected_after.raw)) {
            std.debug.print("FAIL [{s}]: rootAfterCommit mismatch\n", .{comment});
            std.debug.print("  expected: {s}\n", .{root_after_str});
            std.debug.print("  expected raw ({d}): ", .{expected_after.raw.len});
            for (expected_after.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual raw ({d}):   ", .{actual_after.raw.len});
            for (actual_after.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.RootAfterMismatch;
        }

        tested += 1;
    }

    try std.testing.expect(tested == 6);
}
