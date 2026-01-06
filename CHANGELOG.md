# changelog

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
