const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const websocket = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("zat", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "websocket", .module = websocket.module("websocket") },
        },
    });

    const tests = b.addTest(.{ .root_module = mod });

    // add interop test fixtures (lazy — only fetched when running tests)
    if (b.lazyDependency("atproto-interop-tests", .{})) |interop| {
        const interop_files = .{
            // syntax fixtures
            .{ "tid_syntax_valid", "syntax/tid_syntax_valid.txt" },
            .{ "tid_syntax_invalid", "syntax/tid_syntax_invalid.txt" },
            .{ "did_syntax_valid", "syntax/did_syntax_valid.txt" },
            .{ "did_syntax_invalid", "syntax/did_syntax_invalid.txt" },
            .{ "handle_syntax_valid", "syntax/handle_syntax_valid.txt" },
            .{ "handle_syntax_invalid", "syntax/handle_syntax_invalid.txt" },
            .{ "nsid_syntax_valid", "syntax/nsid_syntax_valid.txt" },
            .{ "nsid_syntax_invalid", "syntax/nsid_syntax_invalid.txt" },
            .{ "recordkey_syntax_valid", "syntax/recordkey_syntax_valid.txt" },
            .{ "recordkey_syntax_invalid", "syntax/recordkey_syntax_invalid.txt" },
            .{ "aturi_syntax_valid", "syntax/aturi_syntax_valid.txt" },
            .{ "aturi_syntax_invalid", "syntax/aturi_syntax_invalid.txt" },
            .{ "atidentifier_syntax_valid", "syntax/atidentifier_syntax_valid.txt" },
            .{ "atidentifier_syntax_invalid", "syntax/atidentifier_syntax_invalid.txt" },
            .{ "cid_syntax_valid", "syntax/cid_syntax_valid.txt" },
            .{ "cid_syntax_invalid", "syntax/cid_syntax_invalid.txt" },
            .{ "uri_syntax_valid", "syntax/uri_syntax_valid.txt" },
            .{ "uri_syntax_invalid", "syntax/uri_syntax_invalid.txt" },
            .{ "language_syntax_valid", "syntax/language_syntax_valid.txt" },
            .{ "language_syntax_invalid", "syntax/language_syntax_invalid.txt" },
            .{ "datetime_syntax_valid", "syntax/datetime_syntax_valid.txt" },
            .{ "datetime_syntax_invalid", "syntax/datetime_syntax_invalid.txt" },
            .{ "datetime_parse_invalid", "syntax/datetime_parse_invalid.txt" },
            // crypto fixtures
            .{ "signature_fixtures", "crypto/signature-fixtures.json" },
            .{ "w3c_didkey_K256", "crypto/w3c_didkey_K256.json" },
            .{ "w3c_didkey_P256", "crypto/w3c_didkey_P256.json" },
            // data model fixtures
            .{ "data_model_fixtures", "data-model/data-model-fixtures.json" },
            // mst fixtures
            .{ "mst_key_heights", "mst/key_heights.json" },
            .{ "common_prefix", "mst/common_prefix.json" },
            .{ "commit_proofs", "firehose/commit-proof-fixtures.json" },
        };
        inline for (interop_files) |entry| {
            tests.root_module.addAnonymousImport(entry[0], .{
                .root_source_file = interop.path(entry[1]),
            });
        }
    }

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "run unit tests");
    test_step.dependOn(&run_tests.step);

    // jetstream smoke test
    const jetstream_smoke = b.addExecutable(.{
        .name = "jetstream-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/jetstream_smoke.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(jetstream_smoke);

    const run_smoke = b.addRunArtifact(jetstream_smoke);
    const smoke_step = b.step("smoke", "run jetstream smoke test");
    smoke_step.dependOn(&run_smoke.step);

    // firehose smoke test (CBOR + CAR + CID on live data)
    const firehose_smoke = b.addExecutable(.{
        .name = "firehose-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/firehose_smoke.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(firehose_smoke);

    const run_firehose_smoke = b.addRunArtifact(firehose_smoke);
    const firehose_smoke_step = b.step("firehose-smoke", "run firehose smoke test (CBOR/CAR/CID on live data)");
    firehose_smoke_step.dependOn(&run_firehose_smoke.step);

    // firehose decodeFrame benchmark over atproto-bench fixtures
    const firehose_decode_bench = b.addExecutable(.{
        .name = "firehose-decode-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/firehose_decode_bench.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(firehose_decode_bench);

    const run_firehose_decode_bench = b.addRunArtifact(firehose_decode_bench);
    if (b.args) |args| run_firehose_decode_bench.addArgs(args);
    const firehose_decode_bench_step = b.step("firehose-decode-bench", "benchmark FirehoseClient.decodeFrame over atproto-bench fixtures");
    firehose_decode_bench_step.dependOn(&run_firehose_decode_bench.step);

    // CBOR codec benchmarks
    const cbor_bench = b.addExecutable(.{
        .name = "cbor-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/internal/repo/cbor_bench.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(cbor_bench);

    const run_bench = b.addRunArtifact(cbor_bench);
    const bench_step = b.step("bench", "run CBOR codec benchmarks");
    bench_step.dependOn(&run_bench.step);

    // commit build + sign benchmark (PDS write hot path)
    const commit_sign_bench = b.addExecutable(.{
        .name = "commit-sign-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/commit_sign_bench.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "zat", .module = mod }},
        }),
    });
    b.installArtifact(commit_sign_bench);

    const run_commit_sign_bench = b.addRunArtifact(commit_sign_bench);
    const commit_sign_bench_step = b.step("commit-sign-bench", "benchmark zat.signCommit across key types");
    commit_sign_bench_step.dependOn(&run_commit_sign_bench.step);

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
