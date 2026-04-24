//! XRPC Client - AT Protocol RPC calls
//!
//! simplifies calling AT Protocol endpoints.
//! handles query (GET) and procedure (POST) methods.
//!
//! see: https://atproto.com/specs/xrpc

const std = @import("std");
const Nsid = @import("../syntax/nsid.zig").Nsid;
const HttpTransport = @import("transport.zig").HttpTransport;
const json_helpers = @import("json.zig");

pub const XrpcClient = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,

    /// pds or appview host (e.g., "https://bsky.social")
    host: []const u8,

    /// bearer token for authenticated requests
    access_token: ?[]const u8 = null,

    /// atproto JWTs are ~1KB; buffer needs room for "Bearer " prefix
    const max_auth_header_len = 2048;

    pub fn init(io: std.Io, allocator: std.mem.Allocator, host: []const u8) XrpcClient {
        return .{
            .allocator = allocator,
            .transport = HttpTransport.init(io, allocator),
            .host = host,
        };
    }

    pub fn deinit(self: *XrpcClient) void {
        self.transport.deinit();
    }

    /// set bearer token for authenticated requests
    pub fn setAuth(self: *XrpcClient, token: []const u8) void {
        self.access_token = token;
    }

    /// call a query method (GET)
    pub fn query(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) !Response {
        const url = try self.buildUrl(nsid, params);
        defer self.allocator.free(url);

        return try self.doRequest(url, null);
    }

    /// call a procedure method (POST)
    pub fn procedure(self: *XrpcClient, nsid: Nsid, body: ?[]const u8) !Response {
        const url = try self.buildUrl(nsid, null);
        defer self.allocator.free(url);

        return try self.doRequest(url, body);
    }

    pub fn queryChecked(
        self: *XrpcClient,
        nsid: Nsid,
        params: ?std.StringHashMap([]const u8),
        retry_policy: RetryPolicy,
    ) !Result {
        const url = try self.buildUrl(nsid, params);
        defer self.allocator.free(url);

        return try self.requestCheckedUrl(url, null, retry_policy);
    }

    pub fn procedureChecked(
        self: *XrpcClient,
        nsid: Nsid,
        body: ?[]const u8,
        retry_policy: RetryPolicy,
    ) !Result {
        const url = try self.buildUrl(nsid, null);
        defer self.allocator.free(url);

        return try self.requestCheckedUrl(url, body, retry_policy);
    }

    fn buildUrl(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) ![]u8 {
        var url: std.ArrayList(u8) = .empty;
        errdefer url.deinit(self.allocator);

        try url.appendSlice(self.allocator, self.host);
        try url.appendSlice(self.allocator, "/xrpc/");
        try url.appendSlice(self.allocator, nsid.raw);

        if (params) |p| {
            var first = true;
            var it = p.iterator();
            while (it.next()) |entry| {
                try url.append(self.allocator, if (first) '?' else '&');
                first = false;
                try url.appendSlice(self.allocator, entry.key_ptr.*);
                try url.append(self.allocator, '=');
                // url encode value
                for (entry.value_ptr.*) |c| {
                    if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
                        try url.append(self.allocator, c);
                    } else {
                        try url.print(self.allocator, "%{X:0>2}", .{c});
                    }
                }
            }
        }

        return try url.toOwnedSlice(self.allocator);
    }

    fn doRequest(self: *XrpcClient, url: []const u8, body: ?[]const u8) !Response {
        var auth_header_buf: [max_auth_header_len]u8 = undefined;
        const auth_value: ?[]const u8 = if (self.access_token) |token|
            std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token}) catch null
        else
            null;

        const result = try self.transport.fetch(.{
            .url = url,
            .method = if (body != null) .POST else .GET,
            .payload = body,
            .authorization = auth_value,
        });

        return .{
            .allocator = self.allocator,
            .status = result.status,
            .body = result.body,
            .rate_limit = result.rate_limit,
        };
    }

    fn requestCheckedUrl(self: *XrpcClient, url: []const u8, body: ?[]const u8, retry_policy: RetryPolicy) !Result {
        const attempts = @max(@as(u8, 1), retry_policy.max_attempts);
        var attempt: u8 = 0;

        while (true) : (attempt += 1) {
            var response = self.doRequest(url, body) catch |err| {
                if (attempt + 1 >= attempts or !retry_policy.retry_transient_errors or !isRetryableTransportError(err)) {
                    return err;
                }
                try retry_policy.sleepBeforeRetry(self.transport.io, attempt, null);
                continue;
            };

            if (response.ok()) {
                return .{ .ok = response };
            }

            if (attempt + 1 < attempts and retry_policy.isRetryableStatus(response.status)) {
                const rate_limit = response.rate_limit;
                response.deinit();
                try retry_policy.sleepBeforeRetry(self.transport.io, attempt, rate_limit);
                continue;
            }

            return .{ .err = try XrpcError.fromResponse(response) };
        }
    }

    pub const Response = struct {
        allocator: std.mem.Allocator,
        status: std.http.Status,
        body: []u8,
        rate_limit: HttpTransport.RateLimitHeaders = .{},

        pub fn deinit(self: *Response) void {
            self.allocator.free(self.body);
        }

        /// check if request succeeded
        pub fn ok(self: Response) bool {
            return self.status.class() == .success;
        }

        /// parse body as json
        pub fn json(self: Response) !std.json.Parsed(std.json.Value) {
            return try std.json.parseFromSlice(std.json.Value, self.allocator, self.body, .{});
        }
    };

    pub const Result = union(enum) {
        ok: Response,
        err: XrpcError,

        pub fn deinit(self: *Result) void {
            switch (self.*) {
                .ok => |*response| response.deinit(),
                .err => |*xrpc_error| xrpc_error.deinit(),
            }
        }
    };

    pub const XrpcError = struct {
        allocator: std.mem.Allocator,
        status: std.http.Status,
        error_name: ?[]u8 = null,
        message: ?[]u8 = null,
        body: []u8,
        rate_limit: HttpTransport.RateLimitHeaders = .{},

        pub fn fromResponse(response: Response) !XrpcError {
            var result: XrpcError = .{
                .allocator = response.allocator,
                .status = response.status,
                .body = response.body,
                .rate_limit = response.rate_limit,
            };
            errdefer result.deinit();

            var parsed = std.json.parseFromSlice(std.json.Value, response.allocator, response.body, .{}) catch return result;
            defer parsed.deinit();

            if (json_helpers.getString(parsed.value, "error")) |name| {
                result.error_name = try response.allocator.dupe(u8, name);
            }
            if (json_helpers.getString(parsed.value, "message")) |message| {
                result.message = try response.allocator.dupe(u8, message);
            }

            return result;
        }

        pub fn deinit(self: *XrpcError) void {
            if (self.error_name) |name| self.allocator.free(name);
            if (self.message) |message| self.allocator.free(message);
            self.allocator.free(self.body);
        }
    };

    pub const RetryPolicy = struct {
        max_attempts: u8 = 3,
        base_delay_ms: u64 = 500,
        max_delay_ms: u64 = 30_000,
        jitter_percent: u8 = 20,
        retry_transient_errors: bool = true,

        pub fn none() RetryPolicy {
            return .{ .max_attempts = 1 };
        }

        pub fn isRetryableStatus(_: RetryPolicy, status: std.http.Status) bool {
            return switch (@intFromEnum(status)) {
                429, 500, 502, 503, 504 => true,
                else => false,
            };
        }

        pub fn delayMillis(self: RetryPolicy, attempt: u8, rate_limit: ?HttpTransport.RateLimitHeaders) u64 {
            return self.delayMillisAt(attempt, rate_limit, null);
        }

        pub fn delayMillisAt(
            self: RetryPolicy,
            attempt: u8,
            rate_limit: ?HttpTransport.RateLimitHeaders,
            now_unix_seconds: ?u64,
        ) u64 {
            if (rate_limit) |headers| {
                if (headers.retry_after) |seconds| {
                    const milliseconds = std.math.mul(u64, seconds, std.time.ms_per_s) catch return self.max_delay_ms;
                    return @min(milliseconds, self.max_delay_ms);
                }
                if (now_unix_seconds) |now| {
                    if (headers.reset) |reset| {
                        if (reset > now) {
                            const seconds = reset - now;
                            const milliseconds = std.math.mul(u64, seconds, std.time.ms_per_s) catch return self.max_delay_ms;
                            return @min(milliseconds, self.max_delay_ms);
                        }
                    }
                }
            }

            const shift: u6 = @intCast(@min(attempt, 16));
            const base = self.base_delay_ms * (@as(u64, 1) << shift);
            return @min(base, self.max_delay_ms);
        }

        pub fn sleepBeforeRetry(self: RetryPolicy, io: std.Io, attempt: u8, rate_limit: ?HttpTransport.RateLimitHeaders) !void {
            const now_seconds: ?u64 = if (rate_limit != null)
                @intCast(@max(@as(i64, 0), std.Io.Clock.real.now(io).toSeconds()))
            else
                null;
            var delay_ms = self.delayMillisAt(attempt, rate_limit, now_seconds);
            delay_ms = self.jitteredDelayMillis(io, delay_ms);
            if (delay_ms == 0) return;
            try io.sleep(std.Io.Duration.fromMilliseconds(@intCast(delay_ms)), .awake);
        }

        fn jitteredDelayMillis(self: RetryPolicy, io: std.Io, delay_ms: u64) u64 {
            if (delay_ms == 0 or self.jitter_percent == 0) return delay_ms;

            const spread = delay_ms * @as(u64, self.jitter_percent) / 100;
            if (spread == 0) return delay_ms;

            var source: std.Random.IoSource = .{ .io = io };
            const random = source.interface();
            const min = delay_ms - spread;
            const max = std.math.add(u64, delay_ms, spread) catch std.math.maxInt(u64);
            return @min(random.intRangeAtMost(u64, min, max), self.max_delay_ms);
        }
    };
};

fn isRetryableTransportError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.NetworkDown,
        error.Timeout,
        error.TlsInitializationFailed,
        error.Unexpected,
        error.ReadFailed,
        error.WriteFailed,
        => true,
        else => false,
    };
}

// === tests ===

test "build url without params" {
    var client = XrpcClient.init(std.Options.debug_io, std.testing.allocator, "https://bsky.social");
    defer client.deinit();

    const nsid = Nsid.parse("app.bsky.actor.getProfile").?;
    const url = try client.buildUrl(nsid, null);
    defer std.testing.allocator.free(url);

    try std.testing.expectEqualStrings("https://bsky.social/xrpc/app.bsky.actor.getProfile", url);
}

test "build url with params" {
    var client = XrpcClient.init(std.Options.debug_io, std.testing.allocator, "https://bsky.social");
    defer client.deinit();

    var params = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer params.deinit();
    try params.put("actor", "did:plc:test123");

    const nsid = Nsid.parse("app.bsky.actor.getProfile").?;
    const url = try client.buildUrl(nsid, params);
    defer std.testing.allocator.free(url);

    try std.testing.expect(std.mem.startsWith(u8, url, "https://bsky.social/xrpc/app.bsky.actor.getProfile?"));
    try std.testing.expect(std.mem.indexOf(u8, url, "actor=did%3Aplc%3Atest123") != null);
}

test "xrpc error parses atproto error envelope and rate limits" {
    const body = try std.testing.allocator.dupe(u8,
        \\{"error":"RateLimitExceeded","message":"slow down"}
    );

    const response: XrpcClient.Response = .{
        .allocator = std.testing.allocator,
        .status = .too_many_requests,
        .body = body,
        .rate_limit = .{
            .limit = 3000,
            .remaining = 0,
            .reset = 1710000000,
            .retry_after = 2,
        },
    };

    var xrpc_error = try XrpcClient.XrpcError.fromResponse(response);
    defer xrpc_error.deinit();

    try std.testing.expectEqual(.too_many_requests, xrpc_error.status);
    try std.testing.expectEqualStrings("RateLimitExceeded", xrpc_error.error_name.?);
    try std.testing.expectEqualStrings("slow down", xrpc_error.message.?);
    try std.testing.expectEqual(@as(?u64, 3000), xrpc_error.rate_limit.limit);
    try std.testing.expectEqual(@as(?u64, 0), xrpc_error.rate_limit.remaining);
    try std.testing.expectEqual(@as(?u64, 1710000000), xrpc_error.rate_limit.reset);
    try std.testing.expectEqual(@as(?u64, 2), xrpc_error.rate_limit.retry_after);
}

test "retry policy is conservative and deterministic" {
    const policy: XrpcClient.RetryPolicy = .{
        .base_delay_ms = 100,
        .max_delay_ms = 1000,
        .jitter_percent = 0,
    };

    try std.testing.expect(policy.isRetryableStatus(.too_many_requests));
    try std.testing.expect(policy.isRetryableStatus(.internal_server_error));
    try std.testing.expect(policy.isRetryableStatus(.bad_gateway));
    try std.testing.expect(policy.isRetryableStatus(.service_unavailable));
    try std.testing.expect(policy.isRetryableStatus(.gateway_timeout));
    try std.testing.expect(!policy.isRetryableStatus(.bad_request));
    try std.testing.expect(!policy.isRetryableStatus(.unauthorized));
    try std.testing.expect(!policy.isRetryableStatus(.not_found));

    try std.testing.expectEqual(@as(u64, 100), policy.delayMillis(0, null));
    try std.testing.expectEqual(@as(u64, 200), policy.delayMillis(1, null));
    try std.testing.expectEqual(@as(u64, 1000), policy.delayMillis(10, null));
    try std.testing.expectEqual(@as(u64, 1000), policy.delayMillis(0, .{ .retry_after = 5 }));
    try std.testing.expectEqual(@as(u64, 1000), policy.delayMillisAt(0, .{ .reset = 1005 }, 1000));
    try std.testing.expectEqual(@as(u64, 100), policy.delayMillisAt(0, .{ .reset = 999 }, 1000));
}
