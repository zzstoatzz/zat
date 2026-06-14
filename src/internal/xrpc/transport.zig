//! HTTP Transport - wraps std.http.Client for AT Protocol requests
//!
//! provides a simple fetch() interface over zig's HTTP client.
//! requires std.Io for networking (zig 0.16+).

const std = @import("std");

pub const HttpTransport = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    http_client: std.http.Client,
    keep_alive: bool = true,

    pub fn init(io: std.Io, allocator: std.mem.Allocator) HttpTransport {
        return .{
            .allocator = allocator,
            .io = io,
            .http_client = .{ .allocator = allocator, .io = io },
        };
    }

    pub fn deinit(self: *HttpTransport) void {
        self.http_client.deinit();
    }

    /// fetch a URL and write response to provided writer
    pub fn fetch(self: *HttpTransport, options: FetchOptions) !FetchResult {
        var headers: std.http.Client.Request.Headers = .{
            .accept_encoding = .{ .override = "identity" }, // disable gzip - zig stdlib issue
            .content_type = if (options.payload != null) .{ .override = "application/json" } else .default,
        };

        // apply custom headers
        if (options.authorization) |auth| {
            headers.authorization = .{ .override = auth };
        }
        if (options.content_type) |ct| {
            headers.content_type = .{ .override = ct };
        }

        // build extra headers array for accept and any custom headers
        var extra_buf: [8]std.http.Header = undefined;
        var extra_count: usize = 0;

        if (options.accept) |accept| {
            extra_buf[extra_count] = .{ .name = "accept", .value = accept };
            extra_count += 1;
        }

        if (options.extra_headers) |hdrs| {
            for (hdrs) |h| {
                if (extra_count < extra_buf.len) {
                    extra_buf[extra_count] = h;
                    extra_count += 1;
                }
            }
        }

        if (options.resolved_connection) |resolved| {
            return try self.fetchResolved(options, resolved, headers, extra_buf[0..extra_count]);
        }

        return try self.fetchUrl(options, headers, extra_buf[0..extra_count]);
    }

    fn fetchUrl(
        self: *HttpTransport,
        options: FetchOptions,
        headers: std.http.Client.Request.Headers,
        extra_headers: []const std.http.Header,
    ) !FetchResult {
        const uri = try std.Uri.parse(options.url);
        const redirect_behavior = redirectBehavior(options);
        var request = try self.http_client.request(options.method, uri, .{
            .headers = headers,
            .extra_headers = extra_headers,
            .keep_alive = self.keep_alive,
            .redirect_behavior = redirect_behavior,
        });
        defer request.deinit();

        if (options.payload) |payload| {
            request.transfer_encoding = .{ .content_length = payload.len };
            var body = try request.sendBodyUnflushed(&.{});
            try body.writer.writeAll(payload);
            try body.end();
            try request.connection.?.flush();
        } else {
            try request.sendBodiless();
        }

        const redirect_buffer = try self.allocRedirectBuffer(redirect_behavior);
        defer self.freeRedirectBuffer(redirect_buffer, redirect_behavior);

        var response = try request.receiveHead(redirect_buffer);
        return try self.readFetchResult(options, &response);
    }

    fn fetchResolved(
        self: *HttpTransport,
        options: FetchOptions,
        resolved: ResolvedConnection,
        headers: std.http.Client.Request.Headers,
        extra_headers: []const std.http.Header,
    ) !FetchResult {
        const uri = try std.Uri.parse(options.url);
        const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.UnsupportedUriScheme;

        var uri_host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const uri_host = try uri.getHost(&uri_host_buf);
        if (!std.ascii.eqlIgnoreCase(uri_host.bytes, resolved.logical_host)) {
            return error.ResolvedHostMismatch;
        }

        const dial_host = try std.Io.net.HostName.init(resolved.dial_host);
        const logical_host = try std.Io.net.HostName.init(resolved.logical_host);
        const connection = try self.http_client.connectTcpOptions(.{
            .host = dial_host,
            .port = uri.port orelse defaultPort(protocol),
            .protocol = protocol,
            .proxied_host = logical_host,
        });

        const redirect_behavior = redirectBehavior(options);
        var request = self.http_client.request(options.method, uri, .{
            .connection = connection,
            .headers = headers,
            .extra_headers = extra_headers,
            .keep_alive = self.keep_alive,
            .redirect_behavior = redirect_behavior,
        }) catch |err| {
            self.http_client.connection_pool.release(connection, self.io);
            return err;
        };
        defer request.deinit();

        if (options.payload) |payload| {
            request.transfer_encoding = .{ .content_length = payload.len };
            var body = try request.sendBodyUnflushed(&.{});
            try body.writer.writeAll(payload);
            try body.end();
            try request.connection.?.flush();
        } else {
            try request.sendBodiless();
        }

        const redirect_buffer = try self.allocRedirectBuffer(redirect_behavior);
        defer self.freeRedirectBuffer(redirect_buffer, redirect_behavior);

        var response = try request.receiveHead(redirect_buffer);
        return try self.readFetchResult(options, &response);
    }

    fn allocRedirectBuffer(self: *HttpTransport, behavior: std.http.Client.Request.RedirectBehavior) ![]u8 {
        if (behavior == .unhandled) return &.{};
        return try self.allocator.alloc(u8, 8 * 1024);
    }

    fn freeRedirectBuffer(self: *HttpTransport, buffer: []u8, behavior: std.http.Client.Request.RedirectBehavior) void {
        if (behavior != .unhandled) self.allocator.free(buffer);
    }

    fn readFetchResult(
        self: *HttpTransport,
        options: FetchOptions,
        response: *std.http.Client.Response,
    ) !FetchResult {
        const rate_limit = RateLimitHeaders.fromResponseHead(response.head);
        var oauth = if (options.capture_response_headers)
            try OAuthHeaders.fromResponseHead(self.allocator, response.head)
        else
            OAuthHeaders{};
        errdefer oauth.deinit(self.allocator);

        if (options.max_response_size) |max| {
            const body_buf = try self.allocator.alloc(u8, max);
            defer self.allocator.free(body_buf);
            var writer = std.Io.Writer.fixed(body_buf);
            try streamResponseBody(response, &writer);
            return .{
                .status = response.head.status,
                .body = try self.allocator.dupe(u8, writer.buffered()),
                .rate_limit = rate_limit,
                .oauth = oauth,
            };
        }

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        try streamResponseBody(response, &aw.writer);
        return .{
            .status = response.head.status,
            .body = try self.allocator.dupe(u8, aw.written()),
            .rate_limit = rate_limit,
            .oauth = oauth,
        };
    }

    pub const FetchOptions = struct {
        url: []const u8,
        method: std.http.Method = .GET,
        payload: ?[]const u8 = null,
        authorization: ?[]const u8 = null,
        accept: ?[]const u8 = null,
        content_type: ?[]const u8 = null,
        extra_headers: ?[]const std.http.Header = null,
        max_response_size: ?usize = null,
        redirect_behavior: ?std.http.Client.Request.RedirectBehavior = null,
        resolved_connection: ?ResolvedConnection = null,
        capture_response_headers: bool = false,
    };

    pub const ResolvedConnection = struct {
        /// Checked address to dial. Currently IPv4 text, which std.Io.net.HostName accepts.
        dial_host: []const u8,
        /// Original URL host, used by std.http for TLS/SNI and connection identity.
        logical_host: []const u8,
    };

    pub const FetchResult = struct {
        status: std.http.Status,
        body: []u8,
        rate_limit: RateLimitHeaders = .{},
        oauth: OAuthHeaders = .{},

        pub fn deinit(self: *FetchResult, allocator: std.mem.Allocator) void {
            allocator.free(self.body);
            self.oauth.deinit(allocator);
        }
    };

    pub const OAuthHeaders = struct {
        content_type: ?[]const u8 = null,
        dpop_nonce: ?[]const u8 = null,
        www_authenticate: ?[]const u8 = null,

        pub fn fromResponseHead(allocator: std.mem.Allocator, head: std.http.Client.Response.Head) !OAuthHeaders {
            var result: OAuthHeaders = .{};
            errdefer result.deinit(allocator);
            var it = head.iterateHeaders();
            while (it.next()) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
                    result.content_type = try allocator.dupe(u8, header.value);
                } else if (std.ascii.eqlIgnoreCase(header.name, "dpop-nonce")) {
                    result.dpop_nonce = try allocator.dupe(u8, header.value);
                } else if (std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) {
                    result.www_authenticate = try allocator.dupe(u8, header.value);
                }
            }
            return result;
        }

        pub fn deinit(self: *OAuthHeaders, allocator: std.mem.Allocator) void {
            if (self.content_type) |value| allocator.free(value);
            if (self.dpop_nonce) |value| allocator.free(value);
            if (self.www_authenticate) |value| allocator.free(value);
            self.* = .{};
        }
    };

    pub const RateLimitHeaders = struct {
        limit: ?u64 = null,
        remaining: ?u64 = null,
        reset: ?u64 = null,
        retry_after: ?u64 = null,

        pub fn fromResponseHead(head: std.http.Client.Response.Head) RateLimitHeaders {
            var result: RateLimitHeaders = .{};
            var it = head.iterateHeaders();
            while (it.next()) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "ratelimit-limit")) {
                    result.limit = parseHeaderInt(header.value);
                } else if (std.ascii.eqlIgnoreCase(header.name, "ratelimit-remaining")) {
                    result.remaining = parseHeaderInt(header.value);
                } else if (std.ascii.eqlIgnoreCase(header.name, "ratelimit-reset")) {
                    result.reset = parseHeaderInt(header.value);
                } else if (std.ascii.eqlIgnoreCase(header.name, "retry-after")) {
                    result.retry_after = parseHeaderInt(header.value);
                }
            }
            return result;
        }

        pub fn isEmpty(self: RateLimitHeaders) bool {
            return self.limit == null and self.remaining == null and self.reset == null and self.retry_after == null;
        }
    };
};

fn redirectBehavior(options: HttpTransport.FetchOptions) std.http.Client.Request.RedirectBehavior {
    return options.redirect_behavior orelse if (options.payload == null)
        std.http.Client.Request.RedirectBehavior.init(3)
    else
        .unhandled;
}

fn parseHeaderInt(value: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, value, " \t");
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

fn streamResponseBody(response: *std.http.Client.Response, writer: *std.Io.Writer) !void {
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    _ = reader.streamRemaining(writer) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        error.WriteFailed => return error.ResponseTooLarge,
        else => |e| return e,
    };
}

fn defaultPort(protocol: std.http.Client.Protocol) u16 {
    return switch (protocol) {
        .plain => 80,
        .tls => 443,
    };
}

// === tests ===

test "transport init/deinit" {
    const io = std.Options.debug_io;
    var transport = HttpTransport.init(io, std.testing.allocator);
    defer transport.deinit();
}

test "transport fixed writer maps overflow to ResponseTooLarge" {
    var buf: [0]u8 = .{};
    var writer = std.Io.Writer.fixed(&buf);
    try std.testing.expectError(error.WriteFailed, writer.writeAll("x"));
}

test "resolved transport rejects mismatched logical host" {
    const io = std.Options.debug_io;
    var transport = HttpTransport.init(io, std.testing.allocator);
    defer transport.deinit();

    try std.testing.expectError(error.ResolvedHostMismatch, transport.fetch(.{
        .url = "http://example.com/",
        .resolved_connection = .{
            .dial_host = "127.0.0.1",
            .logical_host = "other.example",
        },
    }));
}

test "transport parses rate limit headers" {
    const response_bytes = "HTTP/1.1 429 Too Many Requests\r\n" ++
        "RateLimit-Limit: 3000\r\n" ++
        "ratelimit-remaining: 0\r\n" ++
        "RateLimit-Reset: 1710000000\r\n" ++
        "Retry-After: 2\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    const headers = HttpTransport.RateLimitHeaders.fromResponseHead(head);

    try std.testing.expectEqual(@as(?u64, 3000), headers.limit);
    try std.testing.expectEqual(@as(?u64, 0), headers.remaining);
    try std.testing.expectEqual(@as(?u64, 1710000000), headers.reset);
    try std.testing.expectEqual(@as(?u64, 2), headers.retry_after);
    try std.testing.expect(!headers.isEmpty());
}

test "transport parses oauth headers" {
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "DPoP-Nonce: nonce-123\r\n" ++
        "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var headers = try HttpTransport.OAuthHeaders.fromResponseHead(std.testing.allocator, head);
    defer headers.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("nonce-123", headers.dpop_nonce.?);
    try std.testing.expectEqualStrings("DPoP error=\"use_dpop_nonce\"", headers.www_authenticate.?);
}

test "transport parses oauth content type header" {
    const response_bytes = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json; charset=utf-8\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var headers = try HttpTransport.OAuthHeaders.fromResponseHead(std.testing.allocator, head);
    defer headers.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("application/json; charset=utf-8", headers.content_type.?);
}
