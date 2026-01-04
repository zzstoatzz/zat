//! JSON path helpers
//!
//! simplifies navigating nested json structures.
//! eliminates the verbose nested if-checks.

const std = @import("std");

/// navigate a json value by dot-separated path
/// returns null if any segment is missing or wrong type
pub fn getPath(value: std.json.Value, path: []const u8) ?std.json.Value {
    var current = value;
    var it = std.mem.splitScalar(u8, path, '.');

    while (it.next()) |segment| {
        switch (current) {
            .object => |obj| {
                current = obj.get(segment) orelse return null;
            },
            .array => |arr| {
                const idx = std.fmt.parseInt(usize, segment, 10) catch return null;
                if (idx >= arr.items.len) return null;
                current = arr.items[idx];
            },
            else => return null,
        }
    }

    return current;
}

/// get a string at path
pub fn getString(value: std.json.Value, path: []const u8) ?[]const u8 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// get an integer at path
pub fn getInt(value: std.json.Value, path: []const u8) ?i64 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

/// get a float at path
pub fn getFloat(value: std.json.Value, path: []const u8) ?f64 {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

/// get a bool at path
pub fn getBool(value: std.json.Value, path: []const u8) ?bool {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

/// get an array at path
pub fn getArray(value: std.json.Value, path: []const u8) ?[]std.json.Value {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .array => |a| a.items,
        else => null,
    };
}

/// get an object at path
pub fn getObject(value: std.json.Value, path: []const u8) ?std.json.ObjectMap {
    const v = getPath(value, path) orelse return null;
    return switch (v) {
        .object => |o| o,
        else => null,
    };
}

// === tests ===

test "getPath simple" {
    const json_str =
        \\{"name": "alice", "age": 30}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("alice", getString(parsed.value, "name").?);
    try std.testing.expectEqual(@as(i64, 30), getInt(parsed.value, "age").?);
}

test "getPath nested" {
    const json_str =
        \\{"embed": {"external": {"uri": "https://example.com"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("https://example.com", getString(parsed.value, "embed.external.uri").?);
}

test "getPath array index" {
    const json_str =
        \\{"items": ["a", "b", "c"]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("b", getString(parsed.value, "items.1").?);
}

test "getPath missing returns null" {
    const json_str =
        \\{"name": "alice"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expect(getString(parsed.value, "missing") == null);
    try std.testing.expect(getString(parsed.value, "name.nested") == null);
}

test "getPath deeply nested real-world example" {
    // the exact painful example from user feedback
    const json_str =
        \\{
        \\  "embed": {
        \\    "$type": "app.bsky.embed.external",
        \\    "external": {
        \\      "uri": "https://tangled.sh",
        \\      "title": "Tangled",
        \\      "description": "Git hosting on AT Protocol"
        \\    }
        \\  }
        \\}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    // instead of 6 nested if-checks:
    const uri = getString(parsed.value, "embed.external.uri");
    try std.testing.expectEqualStrings("https://tangled.sh", uri.?);

    const title = getString(parsed.value, "embed.external.title");
    try std.testing.expectEqualStrings("Tangled", title.?);
}
