//! Framework-neutral ATProto OAuth client helpers.
//!
//! This module owns protocol ceremony: metadata discovery, client metadata,
//! PAR, token exchange, refresh, DPoP nonce retry, and authenticated resource
//! requests. Applications still own cookies, redirects, sessions, and storage.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Keypair = @import("../crypto/keypair.zig").Keypair;
const zat_json = @import("../xrpc/json.zig");
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;
const primitives = @import("primitives.zig");

pub const AuthorizationServerMetadata = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    pushed_authorization_request_endpoint: []const u8,
    response_types_supported: []const []const u8 = &.{},
    grant_types_supported: []const []const u8 = &.{},
    code_challenge_methods_supported: []const []const u8 = &.{},
    token_endpoint_auth_methods_supported: []const []const u8 = &.{},
    token_endpoint_auth_signing_alg_values_supported: []const []const u8 = &.{},
    scopes_supported: []const []const u8 = &.{},
    dpop_signing_alg_values_supported: []const []const u8 = &.{},
    authorization_response_iss_parameter_supported: bool = false,
    require_pushed_authorization_requests: bool = false,
    require_request_uri_registration: bool = true,
    client_id_metadata_document_supported: bool = false,

    pub fn deinit(self: *AuthorizationServerMetadata, allocator: Allocator) void {
        allocator.free(self.issuer);
        allocator.free(self.authorization_endpoint);
        allocator.free(self.token_endpoint);
        allocator.free(self.pushed_authorization_request_endpoint);
        freeStringList(allocator, self.response_types_supported);
        freeStringList(allocator, self.grant_types_supported);
        freeStringList(allocator, self.code_challenge_methods_supported);
        freeStringList(allocator, self.token_endpoint_auth_methods_supported);
        freeStringList(allocator, self.token_endpoint_auth_signing_alg_values_supported);
        freeStringList(allocator, self.scopes_supported);
        freeStringList(allocator, self.dpop_signing_alg_values_supported);
        self.* = undefined;
    }
};

pub const AuthRequestSecrets = struct {
    state: []const u8,
    pkce_verifier: []const u8,
    pkce_challenge: []const u8,
    dpop_keypair: Keypair,

    pub fn deinit(self: *AuthRequestSecrets, allocator: Allocator) void {
        allocator.free(self.state);
        allocator.free(self.pkce_verifier);
        allocator.free(self.pkce_challenge);
        self.* = undefined;
    }
};

pub const ClientMetadataParams = struct {
    client_id: []const u8,
    client_name: []const u8,
    client_uri: []const u8,
    redirect_uris: []const []const u8,
    scope: []const u8,
    keypair: *const Keypair,
    token_endpoint_auth_method: []const u8 = "private_key_jwt",
    token_endpoint_auth_signing_alg: ?[]const u8 = null,
    application_type: []const u8 = "web",
};

pub const ParParams = struct {
    par_url: []const u8,
    authserver_issuer: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    scope: []const u8,
    state: []const u8,
    pkce_challenge: []const u8,
    login_hint: ?[]const u8 = null,
    client_keypair: *const Keypair,
    dpop_keypair: *const Keypair,
};

pub const ParResult = struct {
    request_uri: []const u8,
    dpop_nonce: ?[]const u8 = null,

    pub fn deinit(self: *ParResult, allocator: Allocator) void {
        allocator.free(self.request_uri);
        if (self.dpop_nonce) |nonce| allocator.free(nonce);
        self.* = undefined;
    }
};

pub const CodeTokenParams = struct {
    token_url: []const u8,
    authserver_issuer: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    code: []const u8,
    pkce_verifier: []const u8,
    client_keypair: *const Keypair,
    dpop_keypair: *const Keypair,
    dpop_nonce: ?[]const u8 = null,
};

pub const RefreshTokenParams = struct {
    token_url: []const u8,
    authserver_issuer: []const u8,
    client_id: []const u8,
    refresh_token: []const u8,
    client_keypair: *const Keypair,
    dpop_keypair: *const Keypair,
    dpop_nonce: ?[]const u8 = null,
};

pub const TokenResult = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    scope: []const u8,
    sub: ?[]const u8 = null,
    dpop_nonce: ?[]const u8 = null,

    pub fn deinit(self: *TokenResult, allocator: Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.refresh_token);
        allocator.free(self.scope);
        if (self.sub) |sub| allocator.free(sub);
        if (self.dpop_nonce) |nonce| allocator.free(nonce);
        self.* = undefined;
    }
};

pub const DpopRequest = struct {
    url: []const u8,
    method: std.http.Method = .GET,
    access_token: []const u8,
    dpop_keypair: *const Keypair,
    dpop_nonce: ?[]const u8 = null,
    payload: ?[]const u8 = null,
    content_type: ?[]const u8 = "application/json",
    accept: ?[]const u8 = "application/json",
    max_response_size: ?usize = null,
};

pub const DpopResponse = struct {
    status: std.http.Status,
    body: []u8,
    dpop_nonce: ?[]const u8 = null,

    pub fn deinit(self: *DpopResponse, allocator: Allocator) void {
        allocator.free(self.body);
        if (self.dpop_nonce) |nonce| allocator.free(nonce);
        self.* = undefined;
    }
};

pub fn parseTokenResponse(allocator: Allocator, value: std.json.Value, dpop_nonce: ?[]const u8) !TokenResult {
    const scope = zat_json.getString(value, "scope") orelse return error.MissingScope;
    if (!scopeContainsAtproto(scope)) return error.MissingAtprotoScope;
    const access_token = try allocator.dupe(u8, zat_json.getString(value, "access_token") orelse return error.MissingAccessToken);
    errdefer allocator.free(access_token);
    const refresh_token = try allocator.dupe(u8, zat_json.getString(value, "refresh_token") orelse return error.MissingRefreshToken);
    errdefer allocator.free(refresh_token);
    const scope_copy = try allocator.dupe(u8, scope);
    errdefer allocator.free(scope_copy);
    const sub_copy = if (zat_json.getString(value, "sub")) |sub| try allocator.dupe(u8, sub) else null;
    errdefer if (sub_copy) |sub| allocator.free(sub);
    const nonce_copy = if (dpop_nonce) |nonce| try allocator.dupe(u8, nonce) else null;
    errdefer if (nonce_copy) |nonce| allocator.free(nonce);
    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .scope = scope_copy,
        .sub = sub_copy,
        .dpop_nonce = nonce_copy,
    };
}

pub fn prepareAuthRequestSecrets(allocator: Allocator, io: Io) !AuthRequestSecrets {
    const state = try primitives.generateState(allocator, io);
    errdefer allocator.free(state);
    const pkce_verifier = try primitives.generatePkceVerifier(allocator, io);
    errdefer allocator.free(pkce_verifier);
    const pkce_challenge = try primitives.generatePkceChallenge(allocator, pkce_verifier);
    errdefer allocator.free(pkce_challenge);
    var dpop_secret: [32]u8 = undefined;
    io.random(&dpop_secret);
    return .{
        .state = state,
        .pkce_verifier = pkce_verifier,
        .pkce_challenge = pkce_challenge,
        .dpop_keypair = try Keypair.fromSecretKey(.p256, dpop_secret),
    };
}

pub fn clientMetadataJson(allocator: Allocator, params: ClientMetadataParams) ![]u8 {
    if (!scopeContainsAtproto(params.scope)) return error.MissingAtprotoScope;
    const jwk_json = try params.keypair.jwk(allocator);
    defer allocator.free(jwk_json);
    const signing_alg = params.token_endpoint_auth_signing_alg orelse @tagName(params.keypair.algorithm());

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.print(
        \\{{"client_id":{f},"client_name":{f},"client_uri":{f},"application_type":{f},"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"redirect_uris":[
    , .{
        std.json.fmt(params.client_id, .{}),
        std.json.fmt(params.client_name, .{}),
        std.json.fmt(params.client_uri, .{}),
        std.json.fmt(params.application_type, .{}),
    });
    for (params.redirect_uris, 0..) |uri, i| {
        if (i > 0) try out.writer.writeAll(",");
        try out.writer.print("{f}", .{std.json.fmt(uri, .{})});
    }
    try out.writer.print(
        \\],"token_endpoint_auth_method":{f},"token_endpoint_auth_signing_alg":{f},"scope":{f},"dpop_bound_access_tokens":true,"jwks":{{"keys":[{s}]}}}}
    , .{
        std.json.fmt(params.token_endpoint_auth_method, .{}),
        std.json.fmt(signing_alg, .{}),
        std.json.fmt(params.scope, .{}),
        jwk_json,
    });
    return out.toOwnedSlice();
}

pub fn authorizationUrl(
    allocator: Allocator,
    authorization_endpoint: []const u8,
    request_uri: []const u8,
    client_id: []const u8,
    state: []const u8,
) ![]u8 {
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, authorization_endpoint, '?') == null) "?" else "&";
    const request_uri_enc = try percentEncodeAlloc(allocator, request_uri);
    defer allocator.free(request_uri_enc);
    const client_id_enc = try percentEncodeAlloc(allocator, client_id);
    defer allocator.free(client_id_enc);
    const state_enc = try percentEncodeAlloc(allocator, state);
    defer allocator.free(state_enc);
    return std.fmt.allocPrint(allocator, "{s}{s}request_uri={s}&client_id={s}&state={s}", .{
        authorization_endpoint,
        sep,
        request_uri_enc,
        client_id_enc,
        state_enc,
    });
}

pub fn discoverAuthorizationServer(
    allocator: Allocator,
    transport: *HttpTransport,
    pds_url: []const u8,
) ![]const u8 {
    const url = try joinUrl(allocator, pds_url, "/.well-known/oauth-protected-resource");
    defer allocator.free(url);
    var result = try transport.fetch(.{
        .url = url,
        .method = .GET,
        .accept = "application/json",
        .max_response_size = 256 * 1024,
        .redirect_behavior = .unhandled,
        .capture_response_headers = true,
    });
    defer result.deinit(allocator);
    if (result.status != .ok) return error.HttpStatus;
    if (!contentTypeIsJson(result.oauth.content_type)) return error.InvalidContentType;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.body, .{});
    defer parsed.deinit();
    const servers = zat_json.getArray(parsed.value, "authorization_servers") orelse return error.NoAuthorizationServers;
    if (servers.len != 1 or servers[0] != .string) return error.NoAuthorizationServers;
    try validateSimpleHttpsOrigin(servers[0].string);
    return allocator.dupe(u8, servers[0].string);
}

pub fn fetchAuthorizationServerMetadata(
    allocator: Allocator,
    transport: *HttpTransport,
    issuer: []const u8,
) !AuthorizationServerMetadata {
    const url = try joinUrl(allocator, issuer, "/.well-known/oauth-authorization-server");
    defer allocator.free(url);
    var result = try transport.fetch(.{
        .url = url,
        .method = .GET,
        .accept = "application/json",
        .max_response_size = 256 * 1024,
        .redirect_behavior = .unhandled,
        .capture_response_headers = true,
    });
    defer result.deinit(allocator);
    if (result.status != .ok) return error.HttpStatus;
    if (!contentTypeIsJson(result.oauth.content_type)) return error.InvalidContentType;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.body, .{});
    defer parsed.deinit();
    var metadata = try parseAuthorizationServerMetadata(allocator, parsed.value);
    errdefer metadata.deinit(allocator);
    const expected_issuer = try originFromUrl(allocator, issuer);
    defer allocator.free(expected_issuer);
    if (!std.mem.eql(u8, metadata.issuer, expected_issuer)) return error.IssuerMismatch;
    return metadata;
}

pub fn parseAuthorizationServerMetadata(allocator: Allocator, value: std.json.Value) !AuthorizationServerMetadata {
    var metadata = AuthorizationServerMetadata{
        .issuer = try allocator.dupe(u8, zat_json.getString(value, "issuer") orelse return error.MissingIssuer),
        .authorization_endpoint = "",
        .token_endpoint = "",
        .pushed_authorization_request_endpoint = "",
    };
    errdefer metadata.deinit(allocator);
    try validateSimpleHttpsOrigin(metadata.issuer);

    metadata.authorization_endpoint = try allocator.dupe(u8, zat_json.getString(value, "authorization_endpoint") orelse return error.MissingAuthorizationEndpoint);
    metadata.token_endpoint = try allocator.dupe(u8, zat_json.getString(value, "token_endpoint") orelse return error.MissingTokenEndpoint);
    metadata.pushed_authorization_request_endpoint = try allocator.dupe(u8, zat_json.getString(value, "pushed_authorization_request_endpoint") orelse return error.MissingParEndpoint);

    metadata.response_types_supported = try parseRequiredStringArray(allocator, value, "response_types_supported");
    metadata.grant_types_supported = try parseRequiredStringArray(allocator, value, "grant_types_supported");
    metadata.code_challenge_methods_supported = try parseRequiredStringArray(allocator, value, "code_challenge_methods_supported");
    metadata.token_endpoint_auth_methods_supported = try parseRequiredStringArray(allocator, value, "token_endpoint_auth_methods_supported");
    metadata.token_endpoint_auth_signing_alg_values_supported = try parseRequiredStringArray(allocator, value, "token_endpoint_auth_signing_alg_values_supported");
    metadata.scopes_supported = try parseRequiredStringArray(allocator, value, "scopes_supported");
    metadata.dpop_signing_alg_values_supported = try parseRequiredStringArray(allocator, value, "dpop_signing_alg_values_supported");
    metadata.authorization_response_iss_parameter_supported = zat_json.getBool(value, "authorization_response_iss_parameter_supported") orelse false;
    metadata.require_pushed_authorization_requests = zat_json.getBool(value, "require_pushed_authorization_requests") orelse false;
    metadata.require_request_uri_registration = zat_json.getBool(value, "require_request_uri_registration") orelse true;
    metadata.client_id_metadata_document_supported = zat_json.getBool(value, "client_id_metadata_document_supported") orelse false;
    try validateAuthorizationServerMetadata(metadata);
    return metadata;
}

pub fn sendParRequest(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    params: ParParams,
) !ParResult {
    if (!scopeContainsAtproto(params.scope)) return error.MissingAtprotoScope;
    const client_assertion = try primitives.createClientAssertion(allocator, io, params.client_keypair, params.client_id, params.authserver_issuer);
    defer allocator.free(client_assertion);

    var form_params: std.ArrayList([2][]const u8) = .empty;
    defer form_params.deinit(allocator);
    try form_params.appendSlice(allocator, &.{
        .{ "response_type", "code" },
        .{ "code_challenge", params.pkce_challenge },
        .{ "code_challenge_method", "S256" },
        .{ "redirect_uri", params.redirect_uri },
        .{ "scope", params.scope },
        .{ "state", params.state },
        .{ "client_id", params.client_id },
        .{ "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
        .{ "client_assertion", client_assertion },
    });
    if (params.login_hint) |hint| {
        try form_params.append(allocator, .{ "login_hint", hint });
    }

    const body = try primitives.formEncode(allocator, form_params.items);
    defer allocator.free(body);

    const result = try fetchWithDpopNonceRetry(allocator, io, transport, .{
        .url = params.par_url,
        .method = .POST,
        .payload = body,
        .content_type = "application/x-www-form-urlencoded",
        .dpop_keypair = params.dpop_keypair,
    });
    defer result.deinit(allocator);
    if (result.status != .ok and result.status != .created) return error.ParFailed;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.body, .{});
    defer parsed.deinit();
    return .{
        .request_uri = try allocator.dupe(u8, zat_json.getString(parsed.value, "request_uri") orelse return error.MissingRequestUri),
        .dpop_nonce = if (result.dpop_nonce) |nonce| try allocator.dupe(u8, nonce) else null,
    };
}

pub fn exchangeCodeForToken(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    params: CodeTokenParams,
) !TokenResult {
    const client_assertion = try primitives.createClientAssertion(allocator, io, params.client_keypair, params.client_id, params.authserver_issuer);
    defer allocator.free(client_assertion);
    const form_params = [_][2][]const u8{
        .{ "grant_type", "authorization_code" },
        .{ "code", params.code },
        .{ "redirect_uri", params.redirect_uri },
        .{ "code_verifier", params.pkce_verifier },
        .{ "client_id", params.client_id },
        .{ "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
        .{ "client_assertion", client_assertion },
    };
    return tokenRequest(allocator, io, transport, params.token_url, params.dpop_keypair, params.dpop_nonce, &form_params);
}

pub fn refreshAccessToken(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    params: RefreshTokenParams,
) !TokenResult {
    const client_assertion = try primitives.createClientAssertion(allocator, io, params.client_keypair, params.client_id, params.authserver_issuer);
    defer allocator.free(client_assertion);
    const form_params = [_][2][]const u8{
        .{ "grant_type", "refresh_token" },
        .{ "refresh_token", params.refresh_token },
        .{ "client_id", params.client_id },
        .{ "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
        .{ "client_assertion", client_assertion },
    };
    return tokenRequest(allocator, io, transport, params.token_url, params.dpop_keypair, params.dpop_nonce, &form_params);
}

pub fn dpopRequest(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    params: DpopRequest,
) !DpopResponse {
    const ath = try primitives.accessTokenHash(allocator, params.access_token);
    defer allocator.free(ath);
    return fetchWithDpopNonceRetry(allocator, io, transport, .{
        .url = params.url,
        .method = params.method,
        .payload = params.payload,
        .content_type = params.content_type,
        .accept = params.accept,
        .dpop_keypair = params.dpop_keypair,
        .dpop_nonce = params.dpop_nonce,
        .access_token = params.access_token,
        .access_token_hash = ath,
        .max_response_size = params.max_response_size,
    });
}

pub fn isDpopNonceChallenge(status: std.http.Status, body: []const u8, www_authenticate: ?[]const u8) bool {
    if (status == .bad_request and std.mem.indexOf(u8, body, "use_dpop_nonce") != null) return true;
    if (status == .unauthorized and std.mem.indexOf(u8, body, "use_dpop_nonce") != null) return true;
    if (status == .unauthorized) {
        const header = www_authenticate orelse return false;
        return std.mem.indexOf(u8, header, "use_dpop_nonce") != null;
    }
    return false;
}

const DpopFetchParams = struct {
    url: []const u8,
    method: std.http.Method,
    payload: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    accept: ?[]const u8 = "application/json",
    dpop_keypair: *const Keypair,
    dpop_nonce: ?[]const u8 = null,
    access_token: ?[]const u8 = null,
    access_token_hash: ?[]const u8 = null,
    max_response_size: ?usize = 256 * 1024,
};

fn tokenRequest(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    token_url: []const u8,
    dpop_keypair: *const Keypair,
    dpop_nonce: ?[]const u8,
    form_params: []const [2][]const u8,
) !TokenResult {
    const body = try primitives.formEncode(allocator, form_params);
    defer allocator.free(body);
    var result = try fetchWithDpopNonceRetry(allocator, io, transport, .{
        .url = token_url,
        .method = .POST,
        .payload = body,
        .content_type = "application/x-www-form-urlencoded",
        .dpop_keypair = dpop_keypair,
        .dpop_nonce = dpop_nonce,
    });
    defer result.deinit(allocator);
    if (result.status != .ok) return error.TokenRequestFailed;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.body, .{});
    defer parsed.deinit();
    return parseTokenResponse(allocator, parsed.value, result.dpop_nonce);
}

fn fetchWithDpopNonceRetry(
    allocator: Allocator,
    io: Io,
    transport: *HttpTransport,
    params: DpopFetchParams,
) !DpopResponse {
    var nonce = params.dpop_nonce;
    var retry_nonce: ?[]const u8 = null;
    defer if (retry_nonce) |value| allocator.free(value);

    for (0..2) |_| {
        const htu = try dpopHtu(allocator, params.url);
        defer allocator.free(htu);
        const proof = try primitives.createDpopProof(
            allocator,
            io,
            params.dpop_keypair,
            methodString(params.method),
            htu,
            nonce,
            params.access_token_hash,
        );
        defer allocator.free(proof);

        var auth_buf: [4096]u8 = undefined;
        const auth_header = if (params.access_token) |token|
            try std.fmt.bufPrint(&auth_buf, "DPoP {s}", .{token})
        else
            null;

        const extra = [_]std.http.Header{.{ .name = "DPoP", .value = proof }};
        var fetch_result = try transport.fetch(.{
            .url = params.url,
            .method = params.method,
            .payload = params.payload,
            .authorization = auth_header,
            .accept = params.accept,
            .content_type = params.content_type,
            .extra_headers = &extra,
            .max_response_size = params.max_response_size,
            .capture_response_headers = true,
        });

        const new_nonce = if (fetch_result.oauth.dpop_nonce) |value| try allocator.dupe(u8, value) else null;
        if (new_nonce != null and isDpopNonceChallenge(fetch_result.status, fetch_result.body, fetch_result.oauth.www_authenticate)) {
            fetch_result.deinit(allocator);
            if (retry_nonce) |value| allocator.free(value);
            retry_nonce = new_nonce.?;
            nonce = retry_nonce;
            continue;
        }

        if (new_nonce == null and retry_nonce == null) {
            fetch_result.deinit(allocator);
            return error.MissingDpopNonce;
        }

        const body = fetch_result.body;
        fetch_result.body = &.{};
        const returned_nonce = if (new_nonce) |value|
            value
        else if (retry_nonce) |value|
            try allocator.dupe(u8, value)
        else
            null;
        fetch_result.oauth.deinit(allocator);
        return .{
            .status = fetch_result.status,
            .body = body,
            .dpop_nonce = returned_nonce,
        };
    }
    return error.DpopNonceRetryExhausted;
}

pub fn validateAuthorizationServerMetadata(metadata: AuthorizationServerMetadata) !void {
    try validateSimpleHttpsOrigin(metadata.issuer);
    if (!containsString(metadata.response_types_supported, "code")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.grant_types_supported, "authorization_code")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.grant_types_supported, "refresh_token")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.code_challenge_methods_supported, "S256")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.token_endpoint_auth_methods_supported, "none")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.token_endpoint_auth_methods_supported, "private_key_jwt")) return error.InvalidAuthorizationServerMetadata;
    if (containsString(metadata.token_endpoint_auth_signing_alg_values_supported, "none")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.token_endpoint_auth_signing_alg_values_supported, "ES256")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.scopes_supported, "atproto")) return error.InvalidAuthorizationServerMetadata;
    if (!containsString(metadata.dpop_signing_alg_values_supported, "ES256")) return error.InvalidAuthorizationServerMetadata;
    if (!metadata.authorization_response_iss_parameter_supported) return error.InvalidAuthorizationServerMetadata;
    if (!metadata.require_pushed_authorization_requests) return error.InvalidAuthorizationServerMetadata;
    if (!metadata.require_request_uri_registration) return error.InvalidAuthorizationServerMetadata;
    if (!metadata.client_id_metadata_document_supported) return error.InvalidAuthorizationServerMetadata;
}

fn joinUrl(allocator: Allocator, base: []const u8, path: []const u8) ![]u8 {
    if (base.len > 0 and base[base.len - 1] == '/' and path.len > 0 and path[0] == '/') {
        return std.fmt.allocPrint(allocator, "{s}{s}", .{ base[0 .. base.len - 1], path });
    }
    if (base.len > 0 and base[base.len - 1] != '/' and path.len > 0 and path[0] != '/') {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, path });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ base, path });
}

fn dpopHtu(allocator: Allocator, url: []const u8) ![]u8 {
    const parsed = try std.Uri.parse(url);
    const scheme = parsed.scheme;
    const host = parsed.host orelse return error.InvalidDpopHtu;
    const path = parsed.path.percent_encoded;
    const port = parsed.port;
    if (port) |p| {
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ scheme, host, p, if (path.len == 0) "/" else path });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, host, if (path.len == 0) "/" else path });
}

fn originFromUrl(allocator: Allocator, url: []const u8) ![]const u8 {
    const parsed = try std.Uri.parse(url);
    const scheme = parsed.scheme;
    const host = parsed.host orelse return error.InvalidIssuer;
    if (parsed.port) |port| {
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ scheme, host, port });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme, host });
}

fn validateSimpleHttpsOrigin(url: []const u8) !void {
    const parsed = try std.Uri.parse(url);
    if (!std.mem.eql(u8, parsed.scheme, "https")) return error.InvalidIssuer;
    if (parsed.user != null or parsed.password != null) return error.InvalidIssuer;
    _ = parsed.host orelse return error.InvalidIssuer;
    if (parsed.path.percent_encoded.len != 0 and !std.mem.eql(u8, parsed.path.percent_encoded, "/")) return error.InvalidIssuer;
    if (parsed.query != null or parsed.fragment != null) return error.InvalidIssuer;
    if (parsed.port == 443) return error.InvalidIssuer;
}

fn parseRequiredStringArray(allocator: Allocator, value: std.json.Value, path: []const u8) ![]const []const u8 {
    const items = zat_json.getArray(value, path) orelse return error.MissingMetadataField;
    var out = try allocator.alloc([]const u8, items.len);
    errdefer allocator.free(out);
    var filled: usize = 0;
    errdefer {
        for (out[0..filled]) |item| allocator.free(item);
    }
    for (items) |item| {
        if (item != .string) return error.InvalidAuthorizationServerMetadata;
        out[filled] = try allocator.dupe(u8, item.string);
        filled += 1;
    }
    return out;
}

fn freeStringList(allocator: Allocator, items: []const []const u8) void {
    if (items.len == 0) return;
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn contentTypeIsJson(content_type: ?[]const u8) bool {
    const value = content_type orelse return false;
    var it = std.mem.splitScalar(u8, value, ';');
    const media_type = std.mem.trim(u8, it.next() orelse value, " \t\r\n");
    return std.ascii.eqlIgnoreCase(media_type, "application/json");
}

fn containsString(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn scopeContainsAtproto(scope: []const u8) bool {
    var it = std.mem.splitScalar(u8, scope, ' ');
    while (it.next()) |item| {
        if (std.mem.eql(u8, item, "atproto")) return true;
    }
    return false;
}

fn methodString(method: std.http.Method) []const u8 {
    return @tagName(method);
}

fn percentEncodeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try primitives.percentEncode(&out.writer, input);
    return out.toOwnedSlice();
}

test "parse authorization server metadata" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "issuer": "https://auth.example.com",
        \\  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        \\  "token_endpoint": "https://auth.example.com/oauth/token",
        \\  "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par",
        \\  "response_types_supported": ["code"],
        \\  "grant_types_supported": ["authorization_code", "refresh_token"],
        \\  "code_challenge_methods_supported": ["S256"],
        \\  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        \\  "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        \\  "scopes_supported": ["atproto", "repo:*"],
        \\  "dpop_signing_alg_values_supported": ["ES256"],
        \\  "authorization_response_iss_parameter_supported": true,
        \\  "require_pushed_authorization_requests": true,
        \\  "client_id_metadata_document_supported": true
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var metadata = try parseAuthorizationServerMetadata(allocator, parsed.value);
    defer metadata.deinit(allocator);

    try std.testing.expectEqualStrings("https://auth.example.com", metadata.issuer);
    try std.testing.expectEqualStrings("https://auth.example.com/oauth/authorize", metadata.authorization_endpoint);
    try std.testing.expectEqualStrings("https://auth.example.com/oauth/token", metadata.token_endpoint);
    try std.testing.expectEqualStrings("https://auth.example.com/oauth/par", metadata.pushed_authorization_request_endpoint);
    try std.testing.expect(containsString(metadata.scopes_supported, "atproto"));
}

test "authorization server metadata rejects invalid issuer" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "issuer": "https://auth.example.com/oauth",
        \\  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        \\  "token_endpoint": "https://auth.example.com/oauth/token",
        \\  "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par",
        \\  "response_types_supported": ["code"],
        \\  "grant_types_supported": ["authorization_code", "refresh_token"],
        \\  "code_challenge_methods_supported": ["S256"],
        \\  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        \\  "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        \\  "scopes_supported": ["atproto"],
        \\  "dpop_signing_alg_values_supported": ["ES256"],
        \\  "authorization_response_iss_parameter_supported": true,
        \\  "require_pushed_authorization_requests": true,
        \\  "client_id_metadata_document_supported": true
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidIssuer, parseAuthorizationServerMetadata(allocator, parsed.value));
}

test "authorization server metadata requires atproto support" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{
        \\  "issuer": "https://auth.example.com",
        \\  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
        \\  "token_endpoint": "https://auth.example.com/oauth/token",
        \\  "pushed_authorization_request_endpoint": "https://auth.example.com/oauth/par",
        \\  "response_types_supported": ["code"],
        \\  "grant_types_supported": ["authorization_code", "refresh_token"],
        \\  "code_challenge_methods_supported": ["S256"],
        \\  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        \\  "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        \\  "scopes_supported": ["repo:*"],
        \\  "dpop_signing_alg_values_supported": ["ES256"],
        \\  "authorization_response_iss_parameter_supported": true,
        \\  "require_pushed_authorization_requests": true,
        \\  "client_id_metadata_document_supported": true
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidAuthorizationServerMetadata, parseAuthorizationServerMetadata(allocator, parsed.value));
}

test "client metadata JSON" {
    const allocator = std.testing.allocator;
    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });
    const redirects = [_][]const u8{"https://app.example.com/oauth/callback"};
    const metadata = try clientMetadataJson(allocator, .{
        .client_id = "https://app.example.com/oauth-client-metadata.json",
        .client_name = "example app",
        .client_uri = "https://app.example.com",
        .redirect_uris = &redirects,
        .scope = "atproto repo:example.app.record",
        .keypair = &keypair,
    });
    defer allocator.free(metadata);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, metadata, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("https://app.example.com/oauth-client-metadata.json", zat_json.getString(parsed.value, "client_id").?);
    try std.testing.expectEqualStrings("private_key_jwt", zat_json.getString(parsed.value, "token_endpoint_auth_method").?);
    try std.testing.expectEqualStrings("atproto repo:example.app.record", zat_json.getString(parsed.value, "scope").?);
    try std.testing.expectEqualStrings("https://app.example.com/oauth/callback", zat_json.getArray(parsed.value, "redirect_uris").?[0].string);
    try std.testing.expectEqual(@as(usize, 1), zat_json.getArray(parsed.value, "jwks.keys").?.len);
}

test "client metadata requires atproto scope" {
    const allocator = std.testing.allocator;
    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });
    const redirects = [_][]const u8{"https://app.example.com/oauth/callback"};
    try std.testing.expectError(error.MissingAtprotoScope, clientMetadataJson(allocator, .{
        .client_id = "https://app.example.com/oauth-client-metadata.json",
        .client_name = "example app",
        .client_uri = "https://app.example.com",
        .redirect_uris = &redirects,
        .scope = "repo:example.app.record",
        .keypair = &keypair,
    }));
}

test "authorization URL percent-encodes parameters" {
    const allocator = std.testing.allocator;
    const url = try authorizationUrl(
        allocator,
        "https://auth.example.com/oauth/authorize",
        "urn:ietf:params:oauth:request_uri:abc/123",
        "https://app.example.com/oauth-client-metadata.json",
        "state value",
    );
    defer allocator.free(url);

    try std.testing.expectEqualStrings(
        "https://auth.example.com/oauth/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc%2F123&client_id=https%3A%2F%2Fapp.example.com%2Foauth-client-metadata.json&state=state%20value",
        url,
    );
}

test "DPoP nonce challenge detection" {
    try std.testing.expect(isDpopNonceChallenge(.bad_request, "{\"error\":\"use_dpop_nonce\"}", null));
    try std.testing.expect(isDpopNonceChallenge(.unauthorized, "{}", "DPoP error=\"use_dpop_nonce\""));
    try std.testing.expect(!isDpopNonceChallenge(.ok, "{\"error\":\"use_dpop_nonce\"}", null));
}

test "DPoP htu omits query and fragment" {
    const allocator = std.testing.allocator;
    const htu = try dpopHtu(allocator, "https://pds.example.com/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aabc#frag");
    defer allocator.free(htu);
    try std.testing.expectEqualStrings("https://pds.example.com/xrpc/com.atproto.repo.getRecord", htu);
}

test "DPoP htu preserves non-default port and path" {
    const allocator = std.testing.allocator;
    const htu = try dpopHtu(allocator, "https://pds.example.com:8443/xrpc/app.bsky.actor.getProfile?actor=alice.test");
    defer allocator.free(htu);
    try std.testing.expectEqualStrings("https://pds.example.com:8443/xrpc/app.bsky.actor.getProfile", htu);
}

test "OAuth metadata content type must be JSON" {
    try std.testing.expect(contentTypeIsJson("application/json"));
    try std.testing.expect(contentTypeIsJson("application/json; charset=utf-8"));
    try std.testing.expect(!contentTypeIsJson("text/json"));
    try std.testing.expect(!contentTypeIsJson(null));
}

test "token response requires atproto scope" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"access_token":"access","refresh_token":"refresh","scope":"repo:example.app.record","sub":"did:plc:test"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectError(error.MissingAtprotoScope, parseTokenResponse(allocator, parsed.value, "nonce"));
}

test "token response parses scope and subject" {
    const allocator = std.testing.allocator;
    const json_str =
        \\{"access_token":"access","refresh_token":"refresh","scope":"atproto repo:example.app.record","sub":"did:plc:test"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var token = try parseTokenResponse(allocator, parsed.value, "nonce");
    defer token.deinit(allocator);

    try std.testing.expectEqualStrings("access", token.access_token);
    try std.testing.expectEqualStrings("refresh", token.refresh_token);
    try std.testing.expectEqualStrings("atproto repo:example.app.record", token.scope);
    try std.testing.expectEqualStrings("did:plc:test", token.sub.?);
    try std.testing.expectEqualStrings("nonce", token.dpop_nonce.?);
}

test "prepare auth request secrets" {
    const allocator = std.testing.allocator;
    var secrets = try prepareAuthRequestSecrets(allocator, std.Options.debug_io);
    defer secrets.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 22), secrets.state.len);
    try std.testing.expectEqual(@as(usize, 43), secrets.pkce_verifier.len);
    try std.testing.expectEqual(@as(usize, 43), secrets.pkce_challenge.len);
    _ = try secrets.dpop_keypair.publicKey();
}
