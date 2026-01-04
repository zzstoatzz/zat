//! JWT parsing and verification for AT Protocol
//!
//! parses and verifies JWTs used in AT Protocol service auth.
//! supports ES256 (P-256) and ES256K (secp256k1) signing.
//!
//! see: https://atproto.com/specs/xrpc#service-auth

const std = @import("std");
const crypto = std.crypto;
const json = @import("json.zig");
const multibase = @import("multibase.zig");
const multicodec = @import("multicodec.zig");

/// JWT signing algorithm
pub const Algorithm = enum {
    ES256, // P-256 / secp256r1
    ES256K, // secp256k1

    pub fn fromString(s: []const u8) ?Algorithm {
        if (std.mem.eql(u8, s, "ES256")) return .ES256;
        if (std.mem.eql(u8, s, "ES256K")) return .ES256K;
        return null;
    }
};

/// parsed JWT header
pub const Header = struct {
    alg: Algorithm,
    typ: []const u8,
};

/// parsed JWT payload (AT Protocol service auth claims)
pub const Payload = struct {
    /// issuer DID (account making the request)
    iss: []const u8,
    /// audience DID (service receiving the request)
    aud: []const u8,
    /// expiration timestamp (unix seconds)
    exp: i64,
    /// issued-at timestamp (unix seconds)
    iat: ?i64 = null,
    /// unique nonce for replay prevention
    jti: ?[]const u8 = null,
    /// lexicon method (optional, may become required)
    lxm: ?[]const u8 = null,
};

/// parsed JWT with raw components
pub const Jwt = struct {
    allocator: std.mem.Allocator,

    /// decoded header
    header: Header,
    /// decoded payload
    payload: Payload,
    /// raw signature bytes (r || s, 64 bytes)
    signature: []u8,
    /// the signed portion (header.payload) for verification
    signed_input: []const u8,
    /// original token for reference
    raw_token: []const u8,

    /// parse a JWT token string
    pub fn parse(allocator: std.mem.Allocator, token: []const u8) !Jwt {
        // split on dots: header.payload.signature
        var parts: [3][]const u8 = undefined;
        var part_idx: usize = 0;
        var it = std.mem.splitScalar(u8, token, '.');

        while (it.next()) |part| {
            if (part_idx >= 3) return error.InvalidJwt;
            parts[part_idx] = part;
            part_idx += 1;
        }

        if (part_idx != 3) return error.InvalidJwt;

        const header_b64 = parts[0];
        const payload_b64 = parts[1];
        const sig_b64 = parts[2];

        // find signed input (everything before last dot)
        const last_dot = std.mem.lastIndexOfScalar(u8, token, '.') orelse return error.InvalidJwt;
        const signed_input = token[0..last_dot];

        // decode header
        const header_json = try base64UrlDecode(allocator, header_b64);
        defer allocator.free(header_json);

        const header = try parseHeader(allocator, header_json);

        // decode payload
        const payload_json = try base64UrlDecode(allocator, payload_b64);
        defer allocator.free(payload_json);

        const payload = try parsePayload(allocator, payload_json);

        // decode signature
        const signature = try base64UrlDecode(allocator, sig_b64);
        errdefer allocator.free(signature);

        // JWT signatures should be 64 bytes (r || s)
        if (signature.len != 64) {
            allocator.free(signature);
            return error.InvalidSignatureLength;
        }

        return .{
            .allocator = allocator,
            .header = header,
            .payload = payload,
            .signature = signature,
            .signed_input = signed_input,
            .raw_token = token,
        };
    }

    /// verify the JWT signature against a public key
    /// public_key should be multibase-encoded (from DID document)
    pub fn verify(self: *const Jwt, public_key_multibase: []const u8) !void {
        // decode multibase key
        const key_bytes = try multibase.decode(self.allocator, public_key_multibase);
        defer self.allocator.free(key_bytes);

        // parse multicodec to get key type and raw bytes
        const parsed_key = try multicodec.parsePublicKey(key_bytes);

        // verify key type matches algorithm
        switch (self.header.alg) {
            .ES256K => {
                if (parsed_key.key_type != .secp256k1) return error.AlgorithmKeyMismatch;
                try verifySecp256k1(self.signed_input, self.signature, parsed_key.raw);
            },
            .ES256 => {
                if (parsed_key.key_type != .p256) return error.AlgorithmKeyMismatch;
                try verifyP256(self.signed_input, self.signature, parsed_key.raw);
            },
        }
    }

    /// check if the token is expired
    pub fn isExpired(self: *const Jwt) bool {
        const now = std.time.timestamp();
        return now > self.payload.exp;
    }

    /// check if the token is expired with clock skew tolerance (in seconds)
    pub fn isExpiredWithSkew(self: *const Jwt, skew_seconds: i64) bool {
        const now = std.time.timestamp();
        return now > (self.payload.exp + skew_seconds);
    }

    pub fn deinit(self: *Jwt) void {
        self.allocator.free(self.signature);
        self.allocator.free(self.payload.iss);
        self.allocator.free(self.payload.aud);
        if (self.payload.jti) |s| self.allocator.free(s);
        if (self.payload.lxm) |s| self.allocator.free(s);
    }
};

// === internal helpers ===

fn base64UrlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoder = &std.base64.url_safe_no_pad.Decoder;
    const size = try decoder.calcSizeForSlice(input);
    const output = try allocator.alloc(u8, size);
    errdefer allocator.free(output);
    try decoder.decode(output, input);
    return output;
}

fn parseHeader(allocator: std.mem.Allocator, header_json: []const u8) !Header {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, header_json, .{});
    defer parsed.deinit();

    const alg_str = json.getString(parsed.value, "alg") orelse return error.MissingAlgorithm;
    const alg = Algorithm.fromString(alg_str) orelse return error.UnsupportedAlgorithm;

    return .{
        .alg = alg,
        .typ = "JWT", // static string, no need to dupe
    };
}

fn parsePayload(allocator: std.mem.Allocator, payload_json: []const u8) !Payload {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();

    const iss_raw = json.getString(parsed.value, "iss") orelse return error.MissingIssuer;
    const aud_raw = json.getString(parsed.value, "aud") orelse return error.MissingAudience;
    const exp = json.getInt(parsed.value, "exp") orelse return error.MissingExpiration;

    // dupe strings so they outlive parsed
    const iss = try allocator.dupe(u8, iss_raw);
    errdefer allocator.free(iss);

    const aud = try allocator.dupe(u8, aud_raw);
    errdefer allocator.free(aud);

    const jti: ?[]const u8 = if (json.getString(parsed.value, "jti")) |s|
        try allocator.dupe(u8, s)
    else
        null;
    errdefer if (jti) |s| allocator.free(s);

    const lxm: ?[]const u8 = if (json.getString(parsed.value, "lxm")) |s|
        try allocator.dupe(u8, s)
    else
        null;

    return .{
        .iss = iss,
        .aud = aud,
        .exp = exp,
        .iat = json.getInt(parsed.value, "iat"),
        .jti = jti,
        .lxm = lxm,
    };
}

fn verifySecp256k1(message: []const u8, sig_bytes: []const u8, public_key_raw: []const u8) !void {
    const Scheme = crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

    // parse signature (r || s, 64 bytes)
    if (sig_bytes.len != 64) return error.InvalidSignature;
    const sig = Scheme.Signature.fromBytes(sig_bytes[0..64].*);

    // parse public key from SEC1 compressed format
    if (public_key_raw.len != 33) return error.InvalidPublicKey;
    const public_key = Scheme.PublicKey.fromSec1(public_key_raw) catch return error.InvalidPublicKey;

    // verify
    sig.verify(message, public_key) catch return error.SignatureVerificationFailed;
}

fn verifyP256(message: []const u8, sig_bytes: []const u8, public_key_raw: []const u8) !void {
    const Scheme = crypto.sign.ecdsa.EcdsaP256Sha256;

    // parse signature (r || s, 64 bytes)
    if (sig_bytes.len != 64) return error.InvalidSignature;
    const sig = Scheme.Signature.fromBytes(sig_bytes[0..64].*);

    // parse public key from SEC1 compressed format
    if (public_key_raw.len != 33) return error.InvalidPublicKey;
    const public_key = Scheme.PublicKey.fromSec1(public_key_raw) catch return error.InvalidPublicKey;

    // verify
    sig.verify(message, public_key) catch return error.SignatureVerificationFailed;
}

// === tests ===

test "parse jwt structure" {
    // a minimal valid JWT structure (signature won't verify, just testing parsing)
    // header: {"alg":"ES256K","typ":"JWT"}
    // payload: {"iss":"did:plc:test","aud":"did:plc:service","exp":9999999999}
    const token = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6cGxjOnRlc3QiLCJhdWQiOiJkaWQ6cGxjOnNlcnZpY2UiLCJleHAiOjk5OTk5OTk5OTl9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    try std.testing.expectEqual(Algorithm.ES256K, jwt.header.alg);
    try std.testing.expectEqualStrings("did:plc:test", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:plc:service", jwt.payload.aud);
    try std.testing.expectEqual(@as(i64, 9999999999), jwt.payload.exp);
}

test "reject invalid jwt format" {
    // missing parts
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "onlyonepart"));
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "two.parts"));
    try std.testing.expectError(error.InvalidJwt, Jwt.parse(std.testing.allocator, "too.many.parts.here"));
}

test "verify ES256K signature - official fixture" {
    // test vector from bluesky-social/indigo atproto/auth/jwt_test.go
    // pubkey: did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4
    // iss: did:example:iss, aud: did:example:aud, exp: 1713571012
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzEwMTJ9.J_In_PQCMjygeeoIKyjybORD89ZnEy1bZTd--sdq_78qv3KCO9181ZAh-2Pl0qlXZjfUlxgIa6wiak2NtsT98g";

    // extract multibase key from did:key (strip "did:key:" prefix)
    const did_key = "did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4";
    const multibase_key = did_key["did:key:".len..];

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // verify claims
    try std.testing.expectEqual(Algorithm.ES256K, jwt.header.alg);
    try std.testing.expectEqualStrings("did:example:iss", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:example:aud", jwt.payload.aud);

    // verify signature
    try jwt.verify(multibase_key);
}

test "verify ES256 signature - official fixture" {
    // test vector from bluesky-social/indigo atproto/auth/jwt_test.go
    // pubkey: did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART
    // iss: did:example:iss, aud: did:example:aud, exp: 1713571554
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzE1NTR9.FFRLm7SGbDUp6cL0WoCs0L5oqNkjCXB963TqbgI-KxIjbiqMQATVCalcMJx17JGTjMmfVHJP6Op_V4Z0TTjqog";

    // extract multibase key from did:key
    const did_key = "did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART";
    const multibase_key = did_key["did:key:".len..];

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // verify claims
    try std.testing.expectEqual(Algorithm.ES256, jwt.header.alg);
    try std.testing.expectEqualStrings("did:example:iss", jwt.payload.iss);
    try std.testing.expectEqualStrings("did:example:aud", jwt.payload.aud);

    // verify signature
    try jwt.verify(multibase_key);
}

test "reject signature with wrong key" {
    // ES256K token
    const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzEwMTJ9.J_In_PQCMjygeeoIKyjybORD89ZnEy1bZTd--sdq_78qv3KCO9181ZAh-2Pl0qlXZjfUlxgIa6wiak2NtsT98g";

    // different ES256K key (second fixture from indigo)
    const wrong_key = "zQ3shqKrpHzQ5HDfhgcYMWaFcpBK3SS39wZLdTjA5GeakX8G5";

    var jwt = try Jwt.parse(std.testing.allocator, token);
    defer jwt.deinit();

    // should fail verification with wrong key
    try std.testing.expectError(error.SignatureVerificationFailed, jwt.verify(wrong_key));
}
