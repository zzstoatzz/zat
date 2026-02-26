//! interop tests against bluesky-social/atproto-interop-tests fixtures
//!
//! validates zat's parsers and crypto against the official test vectors.

const std = @import("std");

// types under test
const Tid = @import("tid.zig").Tid;
const Did = @import("did.zig").Did;
const Handle = @import("handle.zig").Handle;
const Nsid = @import("nsid.zig").Nsid;
const Rkey = @import("rkey.zig").Rkey;
const AtUri = @import("at_uri.zig").AtUri;

// crypto
const jwt = @import("jwt.zig");
const multibase = @import("multibase.zig");
const multicodec = @import("multicodec.zig");

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

// === tier 3: MST key heights ===

/// compute MST tree depth for a record key.
/// depth = count leading zero bits in SHA-256(key), divided by 2, rounded down.
fn mstKeyHeight(key: []const u8) u32 {
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

        const actual = mstKeyHeight(key);
        if (actual != expected_height) {
            std.debug.print("FAIL: key '{s}': expected height {d}, got {d}\n", .{ key, expected_height, actual });
            return error.WrongHeight;
        }
        tested += 1;
    }

    try std.testing.expect(tested > 0);
}
