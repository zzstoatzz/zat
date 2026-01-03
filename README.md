# zat

zig atproto primitives. parsing utilities for TID, AT-URI, and DID.

## status

alpha (`0.0.1-alpha`). APIs are in `internal` module while we iterate.

## install

```zig
// build.zig.zon
.dependencies = .{
    .zat = .{
        .url = "https://tangled.sh/@zzstoatzz.io/zat/archive/main.tar.gz",
        .hash = "...", // zig build will tell you
    },
},
```

## usage

```zig
const zat = @import("zat");

// TID - timestamp identifiers
const tid = zat.internal.Tid.parse("3jui7kze2c22s") orelse return error.InvalidTid;
const ts = tid.timestamp();  // microseconds since epoch
const clock = tid.clockId(); // 10-bit clock id

// AT-URI - at://did/collection/rkey
const uri = zat.internal.AtUri.parse("at://did:plc:xyz/app.bsky.feed.post/abc123") orelse return error.InvalidUri;
const did = uri.did();           // "did:plc:xyz"
const collection = uri.collection(); // "app.bsky.feed.post"
const rkey = uri.rkey();         // "abc123"

// DID - did:plc and did:web
const d = zat.internal.Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur") orelse return error.InvalidDid;
const id = d.identifier();  // "z72i7hdynmk6r22z27h6tvur"
const is_plc = d.isPlc();   // true
```

## why internal?

new APIs start in `internal` and get promoted to root when stable. if you need bleeding edge, use `zat.internal.*` and expect breakage.
