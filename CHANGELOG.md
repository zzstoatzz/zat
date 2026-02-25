# changelog

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
