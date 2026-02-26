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

we built [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench) — a cross-SDK benchmark that captures ~10 seconds of live firehose traffic, then decodes the full corpus with four SDKs.

every SDK does the same work per frame: decode CBOR header → decode CBOR payload → parse CAR → decode every CAR block as DAG-CBOR. block counts, error counts, and per-pass variance (min/median/max) are reported so you can verify parity.

the corpus is captured with a minimal CBOR header peek (check `t == "#commit"` and `ops` is non-empty) — no SDK-specific decode in the capture path, so the corpus isn't biased toward any particular decoder's capabilities.

the original version of these benchmarks had work asymmetry: zat's `firehose.decodeFrame` only decoded op-linked blocks (~2.3k per corpus), while rust and go decoded all CAR blocks (~23k). python parsed CAR structure but didn't iterate blocks. the numbers below are from the corrected version where all SDKs decode every block.

run `just capture && just bench` in [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench) to get numbers on your machine.

### why zat is fast

three things compound:

**zero-copy vs owned allocations.** when rust deserializes a `Commit`, serde allocates a new `String` for every string field and copies the entire CAR blob into a `Vec<u8>`. go's code-generated unmarshal does the same. zat returns slices pointing into the input buffer — the `repo` field is a pointer and a length, zero bytes copied.

**block decode cardinality.** each firehose frame contains a CAR with ~10 blocks (MST nodes + records). decoding every block as DAG-CBOR is the dominant cost — it's where most of the per-frame CPU time goes across all SDKs.

**sync vs async CAR parsing.** rust's `iroh-car` is an async library. every `next_block().await` goes through tokio's poll/wake state machine to read from an in-memory buffer. this is bad enough that python (via libipld, a *different* Rust library that works synchronously) outperforms the rust benchmark. the async overhead compounds on top of the per-block decode cost — ~10 awaits per frame adds up.

### the go result

indigo — bluesky's own production relay implementation — is the slowest of the four. go-car is synchronous (no async overhead excuse), and cbor-gen is code-generated (no reflection). the cost is allocations and GC pressure: go copies every string, every byte slice, every block into heap-allocated objects, and the garbage collector has to clean it all up. at ~10 blocks/frame, that's a lot of short-lived allocations per decode.

this doesn't mean indigo is bad software — it handles the live firehose fine at ~1k events/sec. but it explains why bluesky runs beefy relay infrastructure: the decode path has no room to spare at scale.

### does this matter?

for live firehose consumption: no. the network delivers ~500-1000 events/sec. any of these SDKs handle that easily. where it matters: backfill (replaying months of data), relays (fanning out to many consumers), and anything where you're processing stored firehose data as fast as possible.

for now, we ship features. the headroom is there when we need it.
