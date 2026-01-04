//! XRPC Client - AT Protocol RPC calls
//!
//! simplifies calling AT Protocol endpoints.
//! handles query (GET) and procedure (POST) methods.
//!
//! see: https://atproto.com/specs/xrpc

const std = @import("std");
const Nsid = @import("nsid.zig").Nsid;

pub const XrpcClient = struct {
    allocator: std.mem.Allocator,
    http_client: std.http.Client,

    /// pds or appview host (e.g., "https://bsky.social")
    host: []const u8,

    /// bearer token for authenticated requests
    access_token: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, host: []const u8) XrpcClient {
        return .{
            .allocator = allocator,
            .http_client = std.http.Client{ .allocator = allocator },
            .host = host,
        };
    }

    pub fn deinit(self: *XrpcClient) void {
        self.http_client.deinit();
    }

    /// set bearer token for authenticated requests
    pub fn setAuth(self: *XrpcClient, token: []const u8) void {
        self.access_token = token;
    }

    /// call a query method (GET)
    pub fn query(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) !Response {
        const url = try self.buildUrl(nsid, params);
        defer self.allocator.free(url);

        return try self.doRequest(.GET, url, null);
    }

    /// call a procedure method (POST)
    pub fn procedure(self: *XrpcClient, nsid: Nsid, body: ?[]const u8) !Response {
        const url = try self.buildUrl(nsid, null);
        defer self.allocator.free(url);

        return try self.doRequest(.POST, url, body);
    }

    fn buildUrl(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) ![]u8 {
        var url = std.ArrayList(u8).init(self.allocator);
        errdefer url.deinit();

        try url.appendSlice(self.host);
        try url.appendSlice("/xrpc/");
        try url.appendSlice(nsid.raw);

        if (params) |p| {
            var first = true;
            var it = p.iterator();
            while (it.next()) |entry| {
                try url.append(if (first) '?' else '&');
                first = false;
                try url.appendSlice(entry.key_ptr.*);
                try url.append('=');
                // url encode value
                for (entry.value_ptr.*) |c| {
                    if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
                        try url.append(c);
                    } else {
                        try url.writer().print("%{X:0>2}", .{c});
                    }
                }
            }
        }

        return try url.toOwnedSlice();
    }

    fn doRequest(self: *XrpcClient, method: std.http.Method, url: []const u8, body: ?[]const u8) !Response {
        const uri = try std.Uri.parse(url);

        var header_buf: [8192]u8 = undefined;
        var req = try self.http_client.open(method, uri, .{
            .server_header_buffer = &header_buf,
            .extra_headers = if (self.access_token) |token| &.{
                .{ .name = "Authorization", .value = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token}) },
            } else &.{},
        });
        defer req.deinit();

        req.transfer_encoding = if (body) |b| .{ .content_length = b.len } else .none;

        try req.send();

        if (body) |b| {
            try req.writer().writeAll(b);
            try req.finish();
        }

        try req.wait();

        // read response body
        var response_body = std.ArrayList(u8).init(self.allocator);
        errdefer response_body.deinit();

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try req.reader().read(&buf);
            if (n == 0) break;
            try response_body.appendSlice(buf[0..n]);
        }

        return .{
            .allocator = self.allocator,
            .status = req.status,
            .body = try response_body.toOwnedSlice(),
        };
    }

    pub const Response = struct {
        allocator: std.mem.Allocator,
        status: std.http.Status,
        body: []u8,

        pub fn deinit(self: *Response) void {
            self.allocator.free(self.body);
        }

        /// check if request succeeded
        pub fn ok(self: Response) bool {
            return self.status == .ok;
        }

        /// parse body as json
        pub fn json(self: Response) !std.json.Parsed(std.json.Value) {
            return try std.json.parseFromSlice(std.json.Value, self.allocator, self.body, .{});
        }
    };
};

// === tests ===

test "build url without params" {
    var client = XrpcClient.init(std.testing.allocator, "https://bsky.social");
    defer client.deinit();

    const nsid = Nsid.parse("app.bsky.actor.getProfile").?;
    const url = try client.buildUrl(nsid, null);
    defer std.testing.allocator.free(url);

    try std.testing.expectEqualStrings("https://bsky.social/xrpc/app.bsky.actor.getProfile", url);
}

test "build url with params" {
    var client = XrpcClient.init(std.testing.allocator, "https://bsky.social");
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
