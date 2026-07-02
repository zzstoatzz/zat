//! commit build + sign benchmark (PDS write hot path)
//!
//! measures `zat.signCommit`: canonical unsigned-commit encode, ECDSA sign,
//! signed-commit encode, and commit CID computation. this is the producer-side
//! counterpart to the decode/verify benchmarks — the work a PDS does on every
//! record write.
//!
//! run: zig build commit-sign-bench -Doptimize=ReleaseFast

const std = @import("std");
const zat = @import("zat");

const warmup_iters = 1_000;
const min_iters = 2_000;
const target_ns: u64 = 500_000_000; // ~500ms per bench

fn clockNs() u64 {
    const ts = std.Io.Timestamp.now(std.Options.debug_io, .awake);
    return @intCast(ts.nanoseconds);
}

fn bench(name: []const u8, comptime func: anytype) void {
    for (0..warmup_iters) |_| func();

    var start = clockNs();
    for (0..min_iters) |_| func();
    const calibrate_ns = clockNs() - start;
    const iters: u64 = if (calibrate_ns == 0)
        min_iters * 100
    else
        @max(min_iters, target_ns * min_iters / calibrate_ns);

    start = clockNs();
    for (0..iters) |_| func();
    const elapsed_ns = clockNs() - start;
    const ns_per_op = elapsed_ns / iters;
    const ops_per_sec = if (ns_per_op == 0) 0 else 1_000_000_000 / ns_per_op;
    std.debug.print("  {s:<28} {d:>8} ns/op  {d:>10} ops/sec  ({d} iters)\n", .{ name, ns_per_op, ops_per_sec, iters });
}

var keypair_p256: zat.Keypair = undefined;
var keypair_k256: zat.Keypair = undefined;
var commit_did: []const u8 = undefined;
var data_cid: zat.cbor.Cid = undefined;

fn signWith(keypair: *const zat.Keypair) void {
    var scratch: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const signed = zat.signCommit(fba.allocator(), .{
        .did = commit_did,
        .rev = "3k2abcdefghij",
        .data = data_cid,
    }, keypair) catch @panic("signCommit");
    std.mem.doNotOptimizeAway(signed.cid.raw);
    std.mem.doNotOptimizeAway(signed.bytes);
}

fn benchP256() void {
    signWith(&keypair_p256);
}

fn benchK256() void {
    signWith(&keypair_k256);
}

pub fn main() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    keypair_p256 = zat.Keypair.fromSecretKey(.p256, .{7} ** 32) catch @panic("keypair p256");
    keypair_k256 = zat.Keypair.fromSecretKey(.secp256k1, .{7} ** 32) catch @panic("keypair k256");
    commit_did = keypair_p256.did(a) catch @panic("did");
    data_cid = zat.cbor.Cid.forDagCbor(a, "mst-root") catch @panic("data cid");

    std.debug.print("\ncommit build + sign (PDS write hot path)\n", .{});
    std.debug.print("{s}\n\n", .{"=" ** 68});
    bench("signCommit (p256)", benchP256);
    bench("signCommit (secp256k1)", benchK256);
    std.debug.print("\n", .{});
}
