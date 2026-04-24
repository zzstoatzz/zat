//! Network safety checks for identity resolution.

const std = @import("std");
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;

pub const NetworkSafetyError = error{
    MissingHost,
    UnsafeIdentityHost,
    IdentityDnsResolutionFailed,
};

const max_dns_response_size = 1 * 1024 * 1024;

pub const CheckedIdentityUrl = struct {
    host: []u8,
    dial_host: ?[]u8,

    pub fn deinit(self: *CheckedIdentityUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        if (self.dial_host) |dial_host| allocator.free(dial_host);
    }

    pub fn resolvedConnection(self: CheckedIdentityUrl) ?HttpTransport.ResolvedConnection {
        return .{
            .dial_host = self.dial_host orelse return null,
            .logical_host = self.host,
        };
    }
};

pub fn checkIdentityUrl(url: []const u8) (std.Uri.ParseError || NetworkSafetyError)!void {
    const uri = try std.Uri.parse(url);
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host_name = uri.getHost(&host_buf) catch return error.MissingHost;
    try checkIdentityHost(host_name.bytes);
}

pub fn checkIdentityUrlResolved(
    allocator: std.mem.Allocator,
    transport: *HttpTransport,
    doh_endpoint: []const u8,
    url: []const u8,
) (std.Uri.ParseError || NetworkSafetyError || error{ OutOfMemory, ResponseTooLarge })!void {
    var checked = try resolveIdentityUrl(allocator, transport, doh_endpoint, url);
    checked.deinit(allocator);
}

pub fn resolveIdentityUrl(
    allocator: std.mem.Allocator,
    transport: *HttpTransport,
    doh_endpoint: []const u8,
    url: []const u8,
) (std.Uri.ParseError || NetworkSafetyError || error{ OutOfMemory, ResponseTooLarge })!CheckedIdentityUrl {
    const host = try hostFromUrlAlloc(allocator, url);
    errdefer allocator.free(host);
    try checkIdentityHost(host);

    // Literal IPs were fully checked above. Only DNS names need DoH preflight.
    if (isIpLiteral(host)) {
        return .{ .host = host, .dial_host = null };
    }

    var saw_address = false;
    const dial_host = try checkDnsAnswers(allocator, transport, doh_endpoint, host, "A", &saw_address);
    errdefer if (dial_host) |addr| allocator.free(addr);
    const maybe_ip6 = try checkDnsAnswers(allocator, transport, doh_endpoint, host, "AAAA", &saw_address);
    if (maybe_ip6) |ip6| allocator.free(ip6);
    if (!saw_address) return error.IdentityDnsResolutionFailed;
    if (dial_host == null) return error.IdentityDnsResolutionFailed;

    return .{ .host = host, .dial_host = dial_host };
}

fn hostFromUrlAlloc(
    allocator: std.mem.Allocator,
    url: []const u8,
) (std.Uri.ParseError || NetworkSafetyError || error{OutOfMemory})![]u8 {
    const uri = try std.Uri.parse(url);
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host_name = uri.getHost(&host_buf) catch |err| switch (err) {
        error.UriMissingHost => return error.MissingHost,
    };
    return try allocator.dupe(u8, host_name.bytes);
}

pub fn checkIdentityHost(host: []const u8) NetworkSafetyError!void {
    if (host.len == 0) return error.MissingHost;

    const host_without_trailing_dot = stripTrailingDot(host);
    if (std.ascii.eqlIgnoreCase(host_without_trailing_dot, "localhost")) {
        return error.UnsafeIdentityHost;
    }

    if (std.Io.net.Ip4Address.parse(host, 0)) |ip4| {
        if (isNonRoutableIp4(ip4.bytes)) return error.UnsafeIdentityHost;
        return;
    } else |_| {}

    const ip6_text = stripIp6Brackets(host);
    if (std.Io.net.Ip6Address.parse(ip6_text, 0)) |ip6| {
        if (ip4FromIp6Mapped(ip6.bytes)) |ip4| {
            if (isNonRoutableIp4(ip4)) return error.UnsafeIdentityHost;
        }
        if (isNonRoutableIp6(ip6.bytes)) return error.UnsafeIdentityHost;
        return;
    } else |_| {}
}

fn isIpLiteral(host: []const u8) bool {
    if (std.Io.net.Ip4Address.parse(host, 0)) |_| return true else |_| {}

    const ip6_text = stripIp6Brackets(host);
    if (std.Io.net.Ip6Address.parse(ip6_text, 0)) |_| return true else |_| {}

    return false;
}

fn checkDnsAnswers(
    allocator: std.mem.Allocator,
    transport: *HttpTransport,
    doh_endpoint: []const u8,
    host: []const u8,
    record_type: []const u8,
    saw_address: *bool,
) (NetworkSafetyError || error{ OutOfMemory, ResponseTooLarge })!?[]u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}?name={s}&type={s}",
        .{ doh_endpoint, host, record_type },
    );
    defer allocator.free(url);

    const result = transport.fetch(.{
        .url = url,
        .accept = "application/dns-json",
        .max_response_size = max_dns_response_size,
        .redirect_behavior = .not_allowed,
    }) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.ResponseTooLarge => |e| return e,
        else => return error.IdentityDnsResolutionFailed,
    };
    defer allocator.free(result.body);

    if (result.status != .ok) return error.IdentityDnsResolutionFailed;

    const parsed = std.json.parseFromSlice(DnsResponse, allocator, result.body, .{}) catch
        return error.IdentityDnsResolutionFailed;
    defer parsed.deinit();

    const answers = parsed.value.Answer orelse return null;
    var first_ip4: ?[]u8 = null;
    errdefer if (first_ip4) |ip| allocator.free(ip);

    for (answers) |answer| {
        const data = answer.data orelse continue;
        switch (answer.type) {
            1 => {
                saw_address.* = true;
                try checkIdentityHost(data);
                if (first_ip4 == null) first_ip4 = try allocator.dupe(u8, data);
            },
            28 => {
                saw_address.* = true;
                try checkIdentityHost(data);
            },
            else => {},
        }
    }
    return first_ip4;
}

fn stripIp6Brackets(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return host[1 .. host.len - 1];
    }
    return host;
}

fn stripTrailingDot(host: []const u8) []const u8 {
    if (host.len > 0 and host[host.len - 1] == '.') return host[0 .. host.len - 1];
    return host;
}

fn isNonRoutableIp4(ip: [4]u8) bool {
    return ip[0] == 0 or
        ip[0] == 10 or
        ip[0] == 127 or
        (ip[0] == 169 and ip[1] == 254) or
        (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or
        (ip[0] == 192 and ip[1] == 168);
}

fn isNonRoutableIp6(ip: [16]u8) bool {
    const all_zero = for (ip) |b| {
        if (b != 0) break false;
    } else true;

    return all_zero or
        isIp6Loopback(ip) or
        (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) or // fe80::/10 link-local
        (ip[0] & 0xfe) == 0xfc; // fc00::/7 unique local
}

fn isIp6Loopback(ip: [16]u8) bool {
    for (ip[0..15]) |b| {
        if (b != 0) return false;
    }
    return ip[15] == 1;
}

fn ip4FromIp6Mapped(ip: [16]u8) ?[4]u8 {
    for (ip[0..10]) |b| {
        if (b != 0) return null;
    }
    if (ip[10] != 0xff or ip[11] != 0xff) return null;
    return ip[12..16].*;
}

const DnsResponse = struct {
    Status: i32,
    TC: bool = false,
    RD: bool = false,
    RA: bool = false,
    AD: bool = false,
    CD: bool = false,
    Question: ?[]Question = null,
    Answer: ?[]Answer = null,
};

const Question = struct {
    name: []const u8,
    type: i32,
};

const Answer = struct {
    name: []const u8,
    type: i32,
    TTL: i32,
    data: ?[]const u8 = null,
};

test "identity host rejects obvious non-routable hosts" {
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("localhost"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("localhost."));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("127.0.0.1"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("10.1.2.3"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("172.16.0.1"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("192.168.1.1"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("169.254.1.1"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("[::1]"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("::ffff:127.0.0.1"));
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("fc00::1"));
    try checkIdentityHost("example.com");
    try checkIdentityHost("8.8.8.8");
}

test "identity url check rejects literal localhost" {
    try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityUrl("https://127.0.0.1/.well-known/did.json"));
}

test "identity dns answers reject non-routable addresses" {
    const json =
        \\{
        \\  "Status": 0,
        \\  "Answer": [
        \\    {"name": "evil.example.", "type": 1, "TTL": 60, "data": "127.0.0.1"}
        \\  ]
        \\}
    ;

    const parsed = try std.json.parseFromSlice(DnsResponse, std.testing.allocator, json, .{});
    defer parsed.deinit();

    var saw_address = false;
    for (parsed.value.Answer.?) |answer| {
        if (answer.type == 1 or answer.type == 28) {
            saw_address = true;
            try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost(answer.data.?));
        }
    }
    try std.testing.expect(saw_address);
}
