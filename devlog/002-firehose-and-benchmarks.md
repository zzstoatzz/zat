# consuming the firehose, then benchmarking it

since the last devlog (self-publishing docs), zat grew from a collection of string parsers and HTTP clients into something that can consume the full AT Protocol event stream — both jetstream (JSON) and the raw firehose (binary DAG-CBOR). then we benchmarked it against every other AT Protocol SDK.

## what we built

### jetstream client (0.1.3)

the easier of the two event streams. jetstream is a JSON WebSocket — you connect, receive typed events (commits, identity changes, account status updates), and process them. zat's client handles reconnection with exponential backoff, cursor tracking so you don't miss events on disconnect, and typed event parsing via the json helpers.

### firehose support (0.1.4)

this was the real work. the raw firehose (`com.atproto.sync.subscribeRepos`) sends binary DAG-CBOR frames over WebSocket. each frame is two concatenated CBOR objects: a header (`{op, t}`) and a payload. commit payloads contain a CAR (Content Addressable aRchive) file embedded as a byte string, which contains the actual records.

so to decode one firehose frame you need:
1. a DAG-CBOR codec (subset of CBOR with deterministic encoding rules)
2. a CAR codec (multicodec-prefixed CID + data blocks)
3. CID parsing (version, codec, multihash)
4. the actual record extraction (match CIDs from ops to CAR blocks, decode record CBOR)

all of these are hand-rolled in zig. `firehose.decodeFrame(allocator, data)` does the full pipeline in one call — frame bytes in, typed `CommitEvent` with decoded records out.

### performance work (0.1.7)

once the firehose decoder worked, we profiled and optimized:

- **slimmed `Cid` from 56 to 16 bytes** — store only the raw byte reference, parse version/codec/digest lazily. most code paths just need to compare or look up CIDs, not inspect their internals.
- **`Value` union shrunk from 64 to 24 bytes, `MapEntry` from 80 to 40 bytes** — these are the hot types in CBOR decoding. thousands per frame. smaller means better cache behavior.
- **zero-copy everywhere** — CBOR strings and byte strings are slices into the input buffer, not copies. CIDs reference the raw bytes directly. the only allocations are for array/map containers (which go into the arena).
- **inline map key reading** — CBOR map keys in DAG-CBOR are always text strings, so we inline the key read instead of going through the full `decodeAt` → `Value` union construction per key.

### round-robin host rotation (0.1.6)

both clients now rotate through multiple hosts on reconnect. the firehose defaults to `bsky.network` plus three `firehose.network` regional endpoints. jetstream defaults to 12+ hosts. backoff resets when switching to a fresh host.

## the benchmarks

we built [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench) — a cross-SDK benchmark that captures ~10 seconds of live firehose traffic, then decodes the full corpus with four SDKs.

every SDK does the same work per frame: decode CBOR header → decode CBOR payload → parse CAR → decode every CAR block as DAG-CBOR. block counts and error counts are reported per SDK so you can verify parity. per-pass variance (min/median/max) is reported so you can see how stable the numbers are.

the corpus is captured with a CBOR header peek (check `t == "#commit"` and `ops` is non-empty) using zat's CBOR decoder. this is standard CBOR parsing — not zat's typed firehose decoder — but it does mean frames that zat's CBOR decoder rejects won't appear in the corpus.

the original version of these benchmarks had work asymmetry: zat only decoded op-linked blocks (~2.3k per corpus), while rust and go decoded all CAR blocks (~23k). python parsed CAR structure but didn't iterate blocks. the numbers below are from the corrected version where all SDKs decode every block.

### results

3,298 frames (16.2 MB), 5 measured passes, macOS arm64 (M3 Max):

| SDK | frames/sec (median) | MB/s | blocks/frame |
|-----|--------:|-----:|-----:|
| zig (zat, arena reuse) | 628,091 | 3,044.8 | 9.98 |
| zig (zat, alloc per frame) | 559,825 | 2,662.0 | 9.98 |
| rust (raw, arena reuse) | 244,113 | 1,171.0 | 9.98 |
| rust (raw, alloc per frame) | 186,962 | 919.4 | 9.98 |
| rust (jacquard) | 47,881 | 238.9 | 9.98 |
| python (atproto) | 29,675 | 146.1 | 9.98 |
| go (indigo) | 11,548 | 58.0 | 9.98 |

all SDKs: 0 errors. run-to-run variance is ~30-40% — compare ratios within a single run, not across runs.

### why zat is fast

three things compound:

**zero-copy vs owned allocations.** zat returns slices pointing into the input buffer — strings and byte data are a pointer and a length, zero bytes copied. the "rust (raw)" benchmark uses the same approach via minicbor's borrowed decoder, which narrows the gap from ~10x (jacquard) to ~2.5x.

**block decode cardinality.** each firehose frame contains a CAR with ~10 blocks (MST nodes + records). decoding every block as DAG-CBOR is the dominant cost — it's where most of the per-frame CPU time goes across all SDKs.

**arena allocation.** zat uses one arena per frame — a single `malloc` on the first frame, then `reset` (no syscall) on every subsequent frame. rust (raw) uses bumpalo for the same pattern. the remaining ~2.5x gap is likely due to Value type size (zig's 24-byte union vs rust's larger enum), arena implementation differences, and CBOR parser codegen.

### how architecture affects rust

we include two rust implementations to isolate the effect of SDK architecture:

**rust (raw)** uses minicbor (zero-copy CBOR), a hand-rolled sync CAR parser, and bumpalo arena allocation. it matches zat's architectural choices: borrowed strings, flat map representation, no async. result: ~244k fps (arena reuse).

**rust (jacquard)** is the real AT Protocol SDK. it pays for serde-based owned deserialization (`String`, `BTreeMap<String, Ipld>`), async CAR parsing (tokio poll/wake per block via iroh-car), and per-object heap allocation. result: ~48k fps — 5x slower than the raw variant on the same data.

the difference between these two (~5x) is entirely SDK architecture, not language. the remaining difference between rust (raw) and zig (~2.5x) is language-level: enum layout, arena implementation, codegen.

### python

python's atproto SDK uses libipld (Rust via PyO3) under the hood, which does the entire CAR parse + per-block DAG-CBOR decode in one synchronous C-extension call. python beats jacquard because libipld avoids async overhead and uses a different (faster) Rust CBOR library internally.

### go

indigo — bluesky's own production relay — is the slowest. go-car is synchronous (no async overhead excuse), and cbor-gen is code-generated (no reflection). the cost is GC pressure: every string, byte slice, and block is a heap allocation that the garbage collector has to sweep. at ~10 blocks/frame, that's a lot of short-lived objects per decode.

indigo handles the live firehose fine at ~1k events/sec. but it explains why bluesky runs beefy relay infrastructure.

### does this matter?

for live firehose consumption: no. the network delivers ~500-1000 events/sec. any of these SDKs handle that.

where it matters: backfill (replaying months of data), relays (fanning out to many consumers), and anything where you're processing stored firehose data as fast as possible.
