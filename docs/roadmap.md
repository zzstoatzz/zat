# roadmap

zat started as a small set of string primitives for AT Protocol — the types everyone reimplements (`Tid`, `Did`, `Handle`, `Nsid`, `Rkey`, `AtUri`). the scope grew based on real usage.

## current status

**v0.3.1** — zig 0.16, `std.Io` throughout.

the v0.3.0 migration replaced all networking and concurrency primitives with zig 0.16's [`std.Io`](https://ziglang.org/documentation/master/std/#std.Io) interface. the API change is mechanical: every networking type takes `io: std.Io` as its first parameter. streaming clients moved from `connect()` + `next()` loops to `subscribe(handler)` with automatic reconnection, backoff, and host rotation.

the library is stable and tested. downstream consumers continue to drive hardening work, especially around network safety and XRPC error handling.

## history

**what grew from usage:**
- string primitives with parsing and validation — the initial scope
- DID/handle resolution — `DidResolver`, `DidDocument`, `HandleResolver`
- XRPC client and JSON helpers
- JWT verification for service auth
- jetstream client — typed JSON event stream with reconnection (v0.1.3)
- firehose client — raw CBOR event stream, DAG-CBOR codec, CAR codec, CID creation (v0.1.4)
- MST, ECDSA signing, `did:key` construction, multibase encoding (v0.1.9)
- full repo verification — end-to-end trust chain from handle to MST root CID match (v0.2.0)
- CID hash verification in CAR parser (v0.2.1), size limits (v0.2.2)
- OAuth 2.1 DPoP client (v0.2.14)
- configurable keep-alive, transport options (v0.2.12–v0.2.18)
- `std.Io` migration, `subscribe(handler)` streaming API (v0.3.0)
- checked XRPC results, retry policy, and identity network safety (v0.3.1)

this pattern — start minimal, expand based on real pain — continues.

## what's next

the library covers the full AT Protocol verification pipeline: identity resolution, repo parsing, signature verification, and MST validation. benchmarked against Go (indigo) and Rust (rsky) in [atproto-bench](https://tangled.org/zzstoatzz.io/atproto-bench).

near-term:
- keep validating the v0.3.x surface in production consumers
- promote repeated downstream patterns into the library once they prove stable
- candidates surfaced by the `publish-docs` showcase, which still hand-rolls plumbing on top of `XrpcClient`: typed `com.atproto.repo` write helpers (`createRecord` / `putRecord` / `applyWrites`) and a `Tid.now(io)` constructor (today only `fromTimestamp` exists). session/login stays app-specific — see "maybe later".

what's missing will show up when people build things. until then, no speculative features.

## maybe later

these stay out of scope unless real demand emerges:

- lexicon codegen — probably a separate project
- higher-level clients/frameworks — too opinionated
- token refresh/session management — app-specific
- feed generator scaffolding — each feed is unique

## non-goals

zat is not trying to be:

- a "one true SDK" that does everything
- an opinionated app framework
- a replacement for understanding the protocol
