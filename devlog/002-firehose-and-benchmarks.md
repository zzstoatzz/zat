# consuming the firehose, then benchmarking it

since the last devlog (self-publishing docs), zat grew from a collection of string parsers and HTTP clients into something that can consume the full AT Protocol event stream — both jetstream (JSON) and the raw firehose (binary DAG-CBOR). then we benchmarked it against every other AT Protocol SDK and the numbers were... surprising.

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

we built [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench) — a cross-SDK benchmark that captures ~10 seconds of live firehose traffic (~2400 frames, ~12 MB), then decodes the full corpus with four SDKs. each SDK calls its real consumer API: raw frame bytes in, typed commit with decoded records out. no synthetic shortcuts.

the results on macOS arm64, 5 measured passes over the corpus:

| SDK | frames/sec | MB/s |
|-----|--------:|-----:|
| zig (zat, arena reuse) | 1,852k | 9,079 |
| zig (zat, alloc per frame) | 1,277k | 6,260 |
| rust (jacquard-style) | 45k | 223 |
| python (atproto) | 24k | 115 |
| go (indigo) | 11k | 52 |

the "alloc per frame" variant is the fair cross-language comparison — fresh allocator per frame, just like the other SDKs. even so, zat is 28x faster than rust, 54x faster than python, and 120x faster than go.

### why the gap

two things compound:

**zero-copy vs owned allocations.** when rust deserializes a `Commit`, serde allocates a new `String` for every string field and copies the entire CAR blob into a `Vec<u8>`. go's code-generated unmarshal does the same. zat returns slices pointing into the input buffer — the `repo` field is a pointer and a length, zero bytes copied.

**sync vs async CAR parsing.** rust's `iroh-car` is an async library. every `next_block().await` goes through tokio's poll/wake state machine to read from an in-memory buffer. zat's CAR reader is synchronous and zero-copy. you can see it in the old numbers: rust did 501k frames/sec for just the CBOR decode (no CAR), but drops to 45k when CAR parsing kicks in.

### does this matter?

for live firehose consumption: no. the network delivers ~500-1000 events/sec. any of these SDKs handle that easily. where it matters: backfill (replaying months of data), relays (fanning out to many consumers), and anything where you're processing stored firehose data as fast as possible.

for now, we ship features. the headroom is there when we need it.
