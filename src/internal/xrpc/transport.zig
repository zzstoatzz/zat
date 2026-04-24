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

        if (options.max_response_size) |max| {
            const body_buf = try self.allocator.alloc(u8, max);
            defer self.allocator.free(body_buf);
            var writer = std.Io.Writer.fixed(body_buf);

            const result = self.http_client.fetch(.{
                .location = .{ .url = options.url },
                .response_writer = &writer,
                .method = options.method,
                .payload = options.payload,
                .headers = headers,
                .extra_headers = extra_buf[0..extra_count],
                .keep_alive = self.keep_alive,
                .redirect_behavior = options.redirect_behavior,
            }) catch |err| switch (err) {
                error.WriteFailed => return error.ResponseTooLarge,
                else => |e| return e,
            };

            return .{
                .status = result.status,
                .body = try self.allocator.dupe(u8, writer.buffered()),
            };
        }

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = try self.http_client.fetch(.{
            .location = .{ .url = options.url },
            .response_writer = &aw.writer,
            .method = options.method,
            .payload = options.payload,
            .headers = headers,
            .extra_headers = extra_buf[0..extra_count],
            .keep_alive = self.keep_alive,
            .redirect_behavior = options.redirect_behavior,
        });

        return .{
            .status = result.status,
            .body = try self.allocator.dupe(u8, aw.written()),
        };
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

        var request = self.http_client.request(options.method, uri, .{
            .connection = connection,
            .headers = headers,
            .extra_headers = extra_headers,
            .keep_alive = self.keep_alive,
            .redirect_behavior = options.redirect_behavior orelse .unhandled,
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

        var response = try request.receiveHead(&.{});
        if (options.max_response_size) |max| {
            const body_buf = try self.allocator.alloc(u8, max);
            defer self.allocator.free(body_buf);
            var writer = std.Io.Writer.fixed(body_buf);
            try streamResponseBody(&response, &writer);
            return .{
                .status = response.head.status,
                .body = try self.allocator.dupe(u8, writer.buffered()),
            };
        }

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        try streamResponseBody(&response, &aw.writer);
        return .{
            .status = response.head.status,
            .body = try self.allocator.dupe(u8, aw.written()),
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
    };
};

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
