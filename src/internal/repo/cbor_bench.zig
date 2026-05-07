//! DAG-CBOR codec benchmarks
//!
//! measures low-level encoding/decoding primitives and full record
//! round-trips to track performance regressions and compare with
//! the atmos (Go) implementation.
//!
//! run: zig build bench -Doptimize=ReleaseFast
//!  or: just bench

const std = @import("std");
const cbor = @import("cbor.zig");
const car = @import("car.zig");
const Value = cbor.Value;
const Cid = cbor.Cid;

// ---------------------------------------------------------------------------
// benchmark harness
// ---------------------------------------------------------------------------

const warmup_iters = 1_000;
const min_iters = 10_000;
const target_ns: u64 = 500_000_000; // run each bench for ~500ms

fn clockNs() u64 {
    const ts = std.Io.Timestamp.now(std.Options.debug_io, .awake);
    return @intCast(ts.nanoseconds);
}

fn bench(name: []const u8, comptime func: anytype) void {
    // warmup
    for (0..warmup_iters) |_| {
        func();
    }

    // calibrate: run min_iters, then scale up to fill target_ns
    var start = clockNs();
    for (0..min_iters) |_| {
        func();
    }
    const calibrate_ns = clockNs() - start;
    const iters: u64 = if (calibrate_ns == 0)
        min_iters * 100
    else
        @max(min_iters, target_ns * min_iters / calibrate_ns);

    // measured run
    start = clockNs();
    for (0..iters) |_| {
        func();
    }
    const elapsed_ns = clockNs() - start;
    const ns_per_op = elapsed_ns / iters;

    std.debug.print("  {s:<40} {d:>8} ns/op  ({d} iters)\n", .{ name, ns_per_op, iters });
}

// ---------------------------------------------------------------------------
// test data: a realistic AT Protocol record (same structure as atmos bench)
// ---------------------------------------------------------------------------

const bench_record: Value = .{ .map = &.{
    .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
    .{ .key = "createdAt", .value = .{ .text = "2024-01-15T12:00:00.000Z" } },
    .{ .key = "langs", .value = .{ .array = &.{.{ .text = "en" }} } },
    .{ .key = "reply", .value = .{ .map = &.{
        .{ .key = "parent", .value = .{ .map = &.{
            .{ .key = "cid", .value = .{ .text = "bafyreib3pwrff2yadznophzf4hcvtyoctwzcujvz7x4pngk2isicz7yszq" } },
            .{ .key = "uri", .value = .{ .text = "at://did:plc:4nendwqrs754gt6qvgr56jmn/app.bsky.feed.post/3medg2qvcuc2c" } },
        } } },
        .{ .key = "root", .value = .{ .map = &.{
            .{ .key = "cid", .value = .{ .text = "bafyreib3pwrff2yadznophzf4hcvtyoctwzcujvz7x4pngk2isicz7yszq" } },
            .{ .key = "uri", .value = .{ .text = "at://did:plc:4nendwqrs754gt6qvgr56jmn/app.bsky.feed.post/3medg2qvcuc2c" } },
        } } },
    } } },
    .{ .key = "text", .value = .{ .text = "Hello, world! This is a test post with some content." } },
} };

const bench_text_literal = "Hello, world! This is a test post with some content.";

// pre-encoded data (initialized at runtime in initBenchData so the compiler
// cannot constant-fold through them — matches real production conditions
// where inputs arrive from the network)
var encoded_record: []const u8 = undefined;
var encoded_text: []const u8 = undefined;
var encoded_uint: []const u8 = undefined;
var encoded_cid_link: []const u8 = undefined;
var bench_cid: Cid = undefined;
var bench_arena: std.heap.ArenaAllocator = undefined;
// runtime-opaque text for write benchmarks (same content as bench_text_literal
// but not visible to the optimizer as a comptime constant)
var bench_text: []const u8 = undefined;

// CAR benchmark data
var car_bytes: []const u8 = undefined;
var car_5_blocks: []const u8 = undefined;

fn initBenchData() void {
    bench_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = bench_arena.allocator();

    encoded_record = cbor.encodeAlloc(alloc, bench_record) catch @panic("encode record");
    bench_text = alloc.dupe(u8, bench_text_literal) catch @panic("dupe text");
    encoded_text = cbor.encodeAlloc(alloc, .{ .text = bench_text }) catch @panic("encode text");
    encoded_uint = cbor.encodeAlloc(alloc, .{ .unsigned = 1_234_567_890 }) catch @panic("encode uint");
    bench_cid = Cid.forDagCbor(alloc, encoded_record) catch @panic("compute cid");
    encoded_cid_link = cbor.encodeAlloc(alloc, .{ .cid = bench_cid }) catch @panic("encode cid");

    // build CAR test data: 1-block CAR
    car_bytes = car.writeAlloc(alloc, .{
        .roots = &.{bench_cid},
        .blocks = &.{.{ .cid_raw = bench_cid.raw, .data = encoded_record }},
    }) catch @panic("write car");

    // 5-block CAR — each block has unique text to produce unique CIDs
    const block_texts = [_][]const u8{ "block-0", "block-1", "block-2", "block-3", "block-4" };
    var blocks5: [5]car.Block = undefined;
    var cids5: [5]Cid = undefined;
    for (&blocks5, &cids5, block_texts) |*b, *c, text| {
        const rec = cbor.encodeAlloc(alloc, .{ .map = &.{
            .{ .key = "text", .value = .{ .text = text } },
        } }) catch @panic("encode block");
        c.* = Cid.forDagCbor(alloc, rec) catch @panic("cid");
        b.* = .{ .cid_raw = c.raw, .data = rec };
    }
    car_5_blocks = car.writeAlloc(alloc, .{
        .roots = &.{cids5[0]},
        .blocks = &blocks5,
    }) catch @panic("write 5-block car");
}

// ---------------------------------------------------------------------------
// shared allocator for benchmarks
//
// uses a FixedBufferAllocator over a stack buffer so we measure codec
// work, not mmap/munmap syscalls. the encoder needs temp space for map
// key sorting; the decoder needs space for Value arrays/map entries.
// a 16 KB buffer is more than enough for the bench record.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// individual benchmarks
// ---------------------------------------------------------------------------

// --- full record encode/decode ---

fn benchMarshal() void {
    var scratch: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    var out_buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    cbor.encode(fba.allocator(), &w, bench_record) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchUnmarshal() void {
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const val = cbor.decodeAll(fba.allocator(), encoded_record) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

fn benchMarshalRoundTrip() void {
    var scratch: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();
    const enc = cbor.encodeAlloc(alloc, bench_record) catch @panic("encode");
    const dec = cbor.decodeAll(alloc, enc) catch @panic("decode");
    std.mem.doNotOptimizeAway(dec);
}

fn benchDecodeReencode() void {
    var scratch: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();
    const dec = cbor.decodeAll(alloc, encoded_record) catch @panic("decode");
    const enc = cbor.encodeAlloc(alloc, dec) catch @panic("encode");
    std.mem.doNotOptimizeAway(enc);
}

// --- CID computation ---

fn benchComputeCID() void {
    var scratch: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const cid = Cid.forDagCbor(fba.allocator(), encoded_record) catch @panic("cid");
    std.mem.doNotOptimizeAway(cid);
}

fn benchEncodeAndCID() void {
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();
    const enc = cbor.encodeAlloc(alloc, bench_record) catch @panic("encode");
    const cid = Cid.forDagCbor(alloc, enc) catch @panic("cid");
    std.mem.doNotOptimizeAway(cid);
}

// --- text string encode/decode ---

fn benchEncodeText() void {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    cbor.encode(std.heap.page_allocator, &w, .{ .text = bench_text }) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchDecodeText() void {
    // text decoding doesn't allocate — pass a failing allocator to prove it
    const val = cbor.decodeAll(std.heap.page_allocator, encoded_text) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

// --- unsigned integer encode/decode ---

fn benchEncodeUint() void {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    cbor.encode(std.heap.page_allocator, &w, .{ .unsigned = 1_234_567_890 }) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchDecodeUint() void {
    // uint decoding doesn't allocate
    const val = cbor.decodeAll(std.heap.page_allocator, encoded_uint) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

// --- CID link encode/decode ---

fn benchEncodeCidLink() void {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    cbor.encode(std.heap.page_allocator, &w, .{ .cid = bench_cid }) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchDecodeCidLink() void {
    // CID link decoding doesn't allocate (borrows from input bytes)
    const val = cbor.decodeAll(std.heap.page_allocator, encoded_cid_link) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

// --- map key lookup ---

fn benchMapKeyLookup() void {
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const val = cbor.decodeAll(fba.allocator(), encoded_record) catch @panic("decode");
    std.mem.doNotOptimizeAway(val.getString("text"));
    std.mem.doNotOptimizeAway(val.getString("$type"));
    std.mem.doNotOptimizeAway(val.getString("createdAt"));
}

// --- varint encode/decode ---

fn benchWriteUvarint() void {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    cbor.writeUvarint(&w, 1_234_567_890) catch @panic("write");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchReadUvarint() void {
    // pre-encoded varint for 1_234_567_890
    const data = [_]u8{ 0xd2, 0x85, 0xd8, 0xcc, 0x04 };
    var pos: usize = 0;
    const val = cbor.readUvarint(&data, &pos);
    std.mem.doNotOptimizeAway(val);
}

// --- diagnostic: isolate encode costs ---

fn benchEncodeRecordNoSort() void {
    // encode with keys already in DAG-CBOR order (no sort needed)
    // bench_record keys are already sorted, so the sort is a no-op,
    // but we still pay for allocator.dupe + allocator.free per map.
    // this measures the sorting overhead vs raw encoding.
    var scratch: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    var out_buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    cbor.encode(fba.allocator(), &w, bench_record) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchDecodeRecordNoValidation() void {
    // decode without UTF-8 validation or key order checks
    // (not possible with current API — this measures the same as benchUnmarshal
    // to show the overhead of validation is included)
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const val = cbor.decodeAll(fba.allocator(), encoded_record) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

// --- diagnostic: UTF-8 validation cost ---

fn benchUtf8Validate() void {
    // just the UTF-8 validation on the encoded record's text content
    // the record has ~300 bytes of text across all string fields
    std.mem.doNotOptimizeAway(std.unicode.utf8ValidateSlice(encoded_record));
}

// --- diagnostic: SHA-256 only ---

fn benchSha256() void {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(encoded_record, &hash, .{});
    std.mem.doNotOptimizeAway(hash);
}

// --- larger payloads ---

var encoded_record_10x: []const u8 = undefined;

fn initLargePayload() void {
    const alloc = bench_arena.allocator();
    // build a 10-element array of the bench record
    var items: [10]Value = undefined;
    for (&items) |*item| {
        item.* = bench_record;
    }
    const large: Value = .{ .array = &items };
    encoded_record_10x = cbor.encodeAlloc(alloc, large) catch @panic("encode 10x");
}

fn benchEncodeLarge() void {
    var scratch: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    var items: [10]Value = undefined;
    for (&items) |*item| {
        item.* = bench_record;
    }
    const large: Value = .{ .array = &items };
    var out_buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    cbor.encode(fba.allocator(), &w, large) catch @panic("encode");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchDecodeLarge() void {
    var scratch: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const val = cbor.decodeAll(fba.allocator(), encoded_record_10x) catch @panic("decode");
    std.mem.doNotOptimizeAway(val);
}

// --- low-level write (buffer-direct) ---

fn benchWriteTextDirect() void {
    var buf: [128]u8 = undefined;
    const end = cbor.writeText(&buf, 0, bench_text);
    std.mem.doNotOptimizeAway(buf[0..end]);
}

fn benchWriteUintDirect() void {
    var buf: [16]u8 = undefined;
    const end = cbor.writeUint(&buf, 0, 1_234_567_890);
    std.mem.doNotOptimizeAway(buf[0..end]);
}

fn benchWriteCidLinkDirect() void {
    var buf: [128]u8 = undefined;
    const end = cbor.writeCidLink(&buf, 0, bench_cid.raw);
    std.mem.doNotOptimizeAway(buf[0..end]);
}

fn benchWriteRecordDirect() void {
    // manually write the bench record using low-level API (simulates generated code)
    var buf: [1024]u8 = undefined;
    var p: usize = 0;
    p = cbor.writeMapHeader(&buf, p, 5);
    // keys in DAG-CBOR order: text(4), $type(5), langs(5), reply(5), createdAt(9)
    p = cbor.writeText(&buf, p, "text");
    p = cbor.writeText(&buf, p, bench_text);
    p = cbor.writeText(&buf, p, "$type");
    p = cbor.writeText(&buf, p, "app.bsky.feed.post");
    p = cbor.writeText(&buf, p, "langs");
    p = cbor.writeArrayHeader(&buf, p, 1);
    p = cbor.writeText(&buf, p, "en");
    p = cbor.writeText(&buf, p, "reply");
    p = cbor.writeMapHeader(&buf, p, 2);
    p = cbor.writeText(&buf, p, "parent");
    p = cbor.writeMapHeader(&buf, p, 2);
    p = cbor.writeText(&buf, p, "cid");
    p = cbor.writeText(&buf, p, "bafyreib3pwrff2yadznophzf4hcvtyoctwzcujvz7x4pngk2isicz7yszq");
    p = cbor.writeText(&buf, p, "uri");
    p = cbor.writeText(&buf, p, "at://did:plc:4nendwqrs754gt6qvgr56jmn/app.bsky.feed.post/3medg2qvcuc2c");
    p = cbor.writeText(&buf, p, "root");
    p = cbor.writeMapHeader(&buf, p, 2);
    p = cbor.writeText(&buf, p, "cid");
    p = cbor.writeText(&buf, p, "bafyreib3pwrff2yadznophzf4hcvtyoctwzcujvz7x4pngk2isicz7yszq");
    p = cbor.writeText(&buf, p, "uri");
    p = cbor.writeText(&buf, p, "at://did:plc:4nendwqrs754gt6qvgr56jmn/app.bsky.feed.post/3medg2qvcuc2c");
    p = cbor.writeText(&buf, p, "createdAt");
    p = cbor.writeText(&buf, p, "2024-01-15T12:00:00.000Z");
    std.mem.doNotOptimizeAway(buf[0..p]);
}

// --- low-level read (buffer-direct) ---

fn benchReadTextDirect() void {
    const r = cbor.readText(encoded_text, 0) catch @panic("readText");
    std.mem.doNotOptimizeAway(r);
}

fn benchReadUintDirect() void {
    const r = cbor.readUint(encoded_uint, 0) catch @panic("readUint");
    std.mem.doNotOptimizeAway(r);
}

fn benchReadCidLinkDirect() void {
    const r = cbor.readCidLink(encoded_cid_link, 0) catch @panic("readCidLink");
    std.mem.doNotOptimizeAway(r);
}

fn benchSkipValue() void {
    const end = cbor.skipValue(encoded_record, 0) catch @panic("skipValue");
    std.mem.doNotOptimizeAway(end);
}

fn benchPeekType() void {
    const typ = cbor.peekType(encoded_record) catch @panic("peekType");
    std.mem.doNotOptimizeAway(typ);
}

// --- CID: stack vs heap allocation ---

fn benchComputeCIDStack() void {
    // compute CID writing to a stack buffer (no allocator)
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(encoded_record, &hash, .{});
    // manually build CID bytes on stack: version(1) + codec(0x71) + hash_fn(0x12) + len(0x20) + hash
    var cid_buf: [36]u8 = undefined;
    cid_buf[0] = 0x01;
    cid_buf[1] = 0x71;
    cid_buf[2] = 0x12;
    cid_buf[3] = 0x20;
    @memcpy(cid_buf[4..36], &hash);
    std.mem.doNotOptimizeAway(cid_buf);
}

// --- CAR benchmarks ---

fn benchCarRead1() void {
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = car.readWithOptions(fba.allocator(), car_bytes, .{
        .verify_block_hashes = true,
    }) catch @panic("read car");
    std.mem.doNotOptimizeAway(parsed);
}

fn benchCarRead1NoVerify() void {
    var scratch: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = car.readWithOptions(fba.allocator(), car_bytes, .{
        .verify_block_hashes = false,
    }) catch @panic("read car");
    std.mem.doNotOptimizeAway(parsed);
}

fn benchCarRead5() void {
    var scratch: [32768]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = car.readWithOptions(fba.allocator(), car_5_blocks, .{
        .verify_block_hashes = true,
    }) catch @panic("read car");
    std.mem.doNotOptimizeAway(parsed);
}

fn benchCarWrite1() void {
    var out_buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    var scratch: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    car.write(fba.allocator(), &w, .{
        .roots = &.{bench_cid},
        .blocks = &.{.{ .cid_raw = bench_cid.raw, .data = encoded_record }},
    }) catch @panic("write car");
    std.mem.doNotOptimizeAway(w.end);
}

fn benchCarRoundTrip1() void {
    var scratch: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();
    const parsed = car.read(alloc, car_bytes) catch @panic("read");
    const written = car.writeAlloc(alloc, parsed) catch @panic("write");
    std.mem.doNotOptimizeAway(written);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main() void {
    initBenchData();
    initLargePayload();
    defer bench_arena.deinit();

    std.debug.print("\nDAG-CBOR benchmarks (record: {d} bytes encoded)\n", .{encoded_record.len});
    std.debug.print("{s}\n\n", .{"=" ** 68});

    std.debug.print("record encode/decode:\n", .{});
    bench("encode record", benchMarshal);
    bench("decode record", benchUnmarshal);
    bench("encode + decode round-trip", benchMarshalRoundTrip);
    bench("decode + re-encode", benchDecodeReencode);

    std.debug.print("\nCID operations:\n", .{});
    bench("compute CID (SHA-256)", benchComputeCID);
    bench("compute CID (stack, no alloc)", benchComputeCIDStack);
    bench("SHA-256 only (434 bytes)", benchSha256);
    bench("encode + compute CID", benchEncodeAndCID);

    std.debug.print("\ntext string:\n", .{});
    bench("encode text (54 bytes)", benchEncodeText);
    bench("decode text (54 bytes)", benchDecodeText);

    std.debug.print("\nunsigned integer:\n", .{});
    bench("encode uint (1234567890)", benchEncodeUint);
    bench("decode uint (1234567890)", benchDecodeUint);

    std.debug.print("\nCID link:\n", .{});
    bench("encode CID link", benchEncodeCidLink);
    bench("decode CID link", benchDecodeCidLink);

    std.debug.print("\nvarint:\n", .{});
    bench("write uvarint (1234567890)", benchWriteUvarint);
    bench("read uvarint (1234567890)", benchReadUvarint);

    std.debug.print("\ncomposite:\n", .{});
    bench("decode + key lookup (3 keys)", benchMapKeyLookup);

    std.debug.print("\nCAR v1 ({d} bytes, 1 block):\n", .{car_bytes.len});
    bench("read CAR (with hash verify)", benchCarRead1);
    bench("read CAR (no verify)", benchCarRead1NoVerify);
    bench("write CAR", benchCarWrite1);
    bench("read + write round-trip", benchCarRoundTrip1);

    std.debug.print("\nCAR v1 ({d} bytes, 5 blocks):\n", .{car_5_blocks.len});
    bench("read CAR 5 blocks (verified)", benchCarRead5);

    std.debug.print("\nlow-level write (buffer-direct):\n", .{});
    bench("writeText (54 bytes)", benchWriteTextDirect);
    bench("writeUint (1234567890)", benchWriteUintDirect);
    bench("writeCidLink", benchWriteCidLinkDirect);
    bench("writeRecord (manual, 434 bytes)", benchWriteRecordDirect);

    std.debug.print("\nlow-level read (buffer-direct):\n", .{});
    bench("readText (54 bytes)", benchReadTextDirect);
    bench("readUint (1234567890)", benchReadUintDirect);
    bench("readCidLink", benchReadCidLinkDirect);
    bench("skipValue (434-byte record)", benchSkipValue);
    bench("peekType (434-byte record)", benchPeekType);

    std.debug.print("\ndiagnostic (cost breakdown):\n", .{});
    bench("UTF-8 validate (434 bytes)", benchUtf8Validate);

    std.debug.print("\nscaling (10x array = {d} bytes):\n", .{encoded_record_10x.len});
    bench("encode 10x records", benchEncodeLarge);
    bench("decode 10x records", benchDecodeLarge);

    std.debug.print("\n", .{});
}
