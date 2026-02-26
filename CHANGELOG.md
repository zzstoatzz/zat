# changelog

## 0.2.0

- **feat**: end-to-end repo verification — `verifyRepo(allocator, identifier)` exercises the full AT Protocol trust chain: handle → DID → DID document → signing key → fetch repo CAR → verify commit signature → walk MST → rebuild tree → CID match
- **refactor**: organize `src/internal/` into domain subdirectories following bluesky-social/indigo: `syntax/`, `crypto/`, `identity/`, `repo/`, `xrpc/`, `streaming/`, `testing/`

## 0.1.9

- **feat**: merkle search tree (MST) — `mst.Mst` with `put`, `get`, `delete`, `rootCid`
- **feat**: ECDSA signing — `signSecp256k1`, `signP256` with low-S normalization (RFC 6979)
- **feat**: `did:key` construction — `multicodec.formatDidKey`, `multicodec.encodePublicKey`
- **feat**: multibase encoding — base58btc encode, base32lower encode/decode
- interop tests: MST common prefix (13 vectors), commit proofs (6 fixtures)

## 0.1.8

- **fix**: NSID parser rejects TLD starting with digit (e.g. `1.0.0.127.record`)
- **fix**: AT-URI parser validates authority (DID/handle), collection (NSID), and rkey components; rejects `#`, `?`, spaces
- **fix**: reject high-S ECDSA signatures — atproto requires low-S normalization (BIP-62 style)
- `verifySecp256k1` and `verifyP256` are now `pub`
- atproto interop test suite: syntax validation (6 types), crypto signature verification (6 vectors), MST key heights (9 vectors)

## 0.1.7

- slim `Cid` struct from 56 to 16 bytes — store only raw bytes, parse version/codec/digest lazily on demand
- `Value` union shrinks from 64 to 24 bytes, `MapEntry` from 80 to 40 bytes
- zero-cost CID decode — tag 42 handler stores a byte slice reference instead of parsing varint fields
- inline map key reading in CBOR decoder — skips full `decodeAt` + union construction per key
- comptime size assertions for `Value` and `MapEntry`
- **breaking**: `Cid` fields (`version`, `codec`, `hash_fn`, `digest`) are now accessor methods returning optionals — e.g. `cid.version` → `cid.version().?`
- `parseCid` simplified to a trivial raw-bytes wrapper

## 0.1.6

- round-robin host rotation for jetstream and firehose clients
- `Options.host` → `Options.hosts` with sensible defaults (bsky + community relays)
- backoff resets on host switch, jetstream rewinds cursor by 10s
- default jetstream hosts: 4 official bsky, waow.tech, fire.hose.cam, 6 firehose.stream regions
- default firehose hosts: bsky.network + 3 firehose.network regions

## 0.1.5

- align firehose event types with AT Protocol sync spec

## 0.1.4

- firehose support: DAG-CBOR codec, CAR codec, CID creation, firehose client
- encode and decode `com.atproto.sync.subscribeRepos` binary frames

## 0.1.3

- jetstream WebSocket client with typed events, reconnection, and cursor tracking
- `extractAt` ignores unknown JSON fields by default
- HTTP I/O isolated behind `HttpTransport` for 0.16 prep
- websocket dependency pinned to specific commit

## 0.1.2

- `extractAt` logs diagnostic info on parse failures (enable with `.zat` debug scope)

## 0.1.1

- xrpc client sets `Content-Type: application/json` for POST requests
- docs published as `site.standard.document` records on tag releases

## 0.1.0

sync types for firehose consumption:

- `CommitAction` - `.create`, `.update`, `.delete`
- `EventKind` - `.commit`, `.sync`, `.identity`, `.account`, `.info`
- `AccountStatus` - `.takendown`, `.suspended`, `.deleted`, `.deactivated`, `.desynchronized`, `.throttled`

these integrate with `std.json` for automatic parsing.

## 0.0.2

- xrpc client with gzip workaround for zig 0.15.x deflate bug
- jwt parsing and verification

## 0.0.1

- string primitives (Tid, Did, Handle, Nsid, Rkey, AtUri)
- did/handle resolution
- json helpers
