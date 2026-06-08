//! benchmark FirehoseClient.decodeFrame over an atproto-bench firehose corpus.

const std = @import("std");
const zat = @import("zat");

const Allocator = std.mem.Allocator;

const warmup_passes: usize = 2;
const measured_passes: usize = 5;
const default_fixture = "../zzstoatzz.io/atproto-bench/fixtures/firehose-frames.bin";

const Corpus = struct {
    frames: []const []const u8,
    total_bytes: usize,
    min_frame: usize,
    max_frame: usize,
};

const PassResult = struct {
    frames: usize,
    commits: usize,
    records: usize,
    errors: usize,
    elapsed_ns: u64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip();
    const fixture = args.next() orelse default_fixture;

    const corpus = try loadCorpus(allocator, fixture);

    std.debug.print("\n=== zat firehose decodeFrame benchmark ===\n\n", .{});
    std.debug.print("corpus: {d} frames, {d} bytes total\n", .{ corpus.frames.len, corpus.total_bytes });
    std.debug.print("  frame sizes: {d}..{d} bytes\n", .{ corpus.min_frame, corpus.max_frame });
    std.debug.print("  passes: {d} warmup, {d} measured\n\n", .{ warmup_passes, measured_passes });

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const result = decodeOne(arena.allocator(), corpus.frames[0]);
        std.debug.print("first frame: commits={d} records={d} errors={d}\n\n", .{
            result.commits, result.records, result.errors,
        });
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    for (0..warmup_passes) |_| {
        for (corpus.frames) |frame| {
            _ = arena.reset(.retain_capacity);
            _ = decodeOne(arena.allocator(), frame);
        }
    }

    var results: [measured_passes]PassResult = undefined;
    var total_commits: usize = 0;
    var total_records: usize = 0;
    var total_errors: usize = 0;

    for (0..measured_passes) |pass| {
        var commits: usize = 0;
        var records: usize = 0;
        var errors: usize = 0;
        const start_ns = nowNs();
        for (corpus.frames) |frame| {
            _ = arena.reset(.retain_capacity);
            const result = decodeOne(arena.allocator(), frame);
            commits += result.commits;
            records += result.records;
            errors += result.errors;
        }
        results[pass] = .{
            .frames = corpus.frames.len,
            .commits = commits,
            .records = records,
            .errors = errors,
            .elapsed_ns = nowNs() - start_ns,
        };
        total_commits += commits;
        total_records += records;
        total_errors += errors;
    }

    report(corpus, &results, total_commits, total_records, total_errors);
}

fn decodeOne(allocator: Allocator, frame: []const u8) struct { commits: usize, records: usize, errors: usize } {
    const event = zat.firehose.decodeFrame(allocator, frame) catch {
        return .{ .commits = 0, .records = 0, .errors = 1 };
    };
    return switch (event) {
        .commit => |commit| blk: {
            var records: usize = 0;
            for (commit.ops) |op| {
                if (op.record != null) records += 1;
            }
            break :blk .{ .commits = 1, .records = records, .errors = 0 };
        },
        else => .{ .commits = 0, .records = 0, .errors = 0 },
    };
}

fn report(
    corpus: Corpus,
    results: []const PassResult,
    total_commits: usize,
    total_records: usize,
    total_errors: usize,
) void {
    var fps_values: [measured_passes]f64 = undefined;
    var total_ns: u64 = 0;
    for (results, 0..) |r, i| {
        const elapsed_s = @as(f64, @floatFromInt(r.elapsed_ns)) / 1_000_000_000.0;
        fps_values[i] = @as(f64, @floatFromInt(r.frames)) / elapsed_s;
        total_ns += r.elapsed_ns;
    }
    std.mem.sort(f64, &fps_values, {}, std.sort.asc(f64));

    const elapsed_s = @as(f64, @floatFromInt(total_ns)) / 1_000_000_000.0;
    const total_bytes = @as(f64, @floatFromInt(corpus.total_bytes)) * @as(f64, @floatFromInt(measured_passes));
    const mb_s = total_bytes / (1024.0 * 1024.0) / elapsed_s;

    std.debug.print("decodeFrame     {d:>10.0} frames/sec  {d:>8.1} MB/s  commits={d} records={d} errors={d}\n", .{
        fps_values[measured_passes / 2],
        mb_s,
        total_commits,
        total_records,
        total_errors,
    });
    std.debug.print("                variance: min={d:.0} median={d:.0} max={d:.0} frames/sec\n", .{
        fps_values[0],
        fps_values[measured_passes / 2],
        fps_values[measured_passes - 1],
    });
}

fn nowNs() u64 {
    return @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds());
}

fn loadCorpus(allocator: Allocator, path: []const u8) !Corpus {
    const io = std.Options.debug_io;
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(50 * 1024 * 1024)) catch |err| {
        std.debug.print("cannot open {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    if (data.len < 4) return error.InvalidFormat;

    const frame_count = std.mem.readInt(u32, data[0..4], .big);
    var frames: std.ArrayListUnmanaged([]const u8) = .empty;
    var pos: usize = 4;
    var total_bytes: usize = 0;
    var min_frame: usize = std.math.maxInt(usize);
    var max_frame: usize = 0;

    for (0..frame_count) |_| {
        if (pos + 4 > data.len) return error.InvalidFormat;
        const frame_len = std.mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        if (pos + frame_len > data.len) return error.InvalidFormat;
        const frame = data[pos..][0..frame_len];
        try frames.append(allocator, frame);
        pos += frame_len;
        total_bytes += frame_len;
        min_frame = @min(min_frame, frame_len);
        max_frame = @max(max_frame, frame_len);
    }

    return .{
        .frames = try frames.toOwnedSlice(allocator),
        .total_bytes = total_bytes,
        .min_frame = min_frame,
        .max_frame = max_frame,
    };
}
