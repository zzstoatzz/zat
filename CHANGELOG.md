# changelog

## 0.1.0

first feature release. adds protocol-level enums for firehose consumption.

### what's new

**sync types** - enums from `com.atproto.sync.subscribeRepos` lexicon:

- `CommitAction` - `.create`, `.update`, `.delete`
- `EventKind` - `.commit`, `.sync`, `.identity`, `.account`, `.info`
- `AccountStatus` - `.takendown`, `.suspended`, `.deleted`, `.deactivated`, `.desynchronized`, `.throttled`

these integrate with zig's `std.json` for automatic parsing. define struct fields as enums instead of strings, and get exhaustive switch checking.

### migration

if you're currently doing string comparisons:

```zig
// before: string comparisons everywhere
const TapRecord = struct {
    action: []const u8,
    collection: []const u8,
    // ...
};

if (mem.eql(u8, rec.action, "create") or mem.eql(u8, rec.action, "update")) {
    // handle upsert
} else if (mem.eql(u8, rec.action, "delete")) {
    // handle delete
}
```

switch to enum fields:

```zig
// after: type-safe enums
const TapRecord = struct {
    action: zat.CommitAction,  // parsed automatically by std.json
    collection: []const u8,
    // ...
};

switch (rec.action) {
    .create, .update => processUpsert(rec),
    .delete => processDelete(rec),
}
```

the compiler enforces exhaustive handling - if AT Protocol adds a new action, your code won't compile until you handle it.

**this is backwards compatible.** your existing code continues to work. adopt the new types when you're ready.

### library overview

zat provides zig primitives for AT Protocol:

| feature | description |
|---------|-------------|
| string primitives | `Tid`, `Did`, `Handle`, `Nsid`, `Rkey`, `AtUri` - parsing and validation |
| did resolution | resolve `did:plc` and `did:web` to documents |
| handle resolution | resolve handles to DIDs via HTTP well-known |
| xrpc client | call AT Protocol endpoints (queries and procedures) |
| sync types | enums for firehose consumption |
| json helpers | navigate nested json without verbose if-chains |
| jwt verification | verify service auth tokens (ES256, ES256K) |
| multibase/multicodec | decode public keys from DID documents |

### install

```bash
zig fetch --save https://tangled.sh/zzstoatzz.io/zat/archive/main
```

```zig
// build.zig
const zat = b.dependency("zat", .{}).module("zat");
exe.root_module.addImport("zat", zat);
```

## 0.0.2

- xrpc client with gzip workaround for zig 0.15.x deflate bug
- jwt parsing and verification

## 0.0.1

- initial release
- string primitives (Tid, Did, Handle, Nsid, Rkey, AtUri)
- did/handle resolution
- json helpers
