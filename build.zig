const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zat", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "run unit tests");
    test_step.dependOn(&run_tests.step);

    // publish-docs script (uses zat to publish docs to ATProto)
    const publish_docs = b.addExecutable(.{
        .name = "publish-docs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/publish-docs.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(publish_docs);
}
