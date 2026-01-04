# zat

zig primitives for AT Protocol.

## install

```bash
zig fetch --save https://tangled.org/zzstoatzz.io/zat/archive/main
```

then in `build.zig`:

```zig
const zat = b.dependency("zat", .{}).module("zat");
exe.root_module.addImport("zat", zat);
```

## what's here

### string primitives

parsing and validation for atproto string identifiers:

- **Tid** - timestamp identifiers (base32-sortable)
- **Did** - decentralized identifiers
- **Handle** - domain-based handles
- **Nsid** - namespaced identifiers (lexicon types)
- **Rkey** - record keys
- **AtUri** - `at://` URIs

```zig
const zat = @import("zat");

if (zat.AtUri.parse(uri_string)) |uri| {
    const authority = uri.authority();
    const collection = uri.collection();
    const rkey = uri.rkey();
}
```

### did resolution

resolve `did:plc` and `did:web` identifiers to their documents:

```zig
var resolver = zat.DidResolver.init(allocator);
defer resolver.deinit();

const did = zat.Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?;
var doc = try resolver.resolve(did);
defer doc.deinit();

const handle = doc.handle();           // "jay.bsky.social"
const pds = doc.pdsEndpoint();         // "https://..."
const key = doc.signingKey();          // verification method
```

### xrpc client

call AT Protocol endpoints:

```zig
var client = zat.XrpcClient.init(allocator, "https://bsky.social");
defer client.deinit();

const nsid = zat.Nsid.parse("app.bsky.actor.getProfile").?;
var response = try client.query(nsid, params);
defer response.deinit();

if (response.ok()) {
    var json = try response.json();
    defer json.deinit();
    // use json.value
}
```

### json helpers

navigate nested json without verbose if-chains:

```zig
// runtime paths for one-offs:
const uri = zat.json.getString(value, "embed.external.uri");
const count = zat.json.getInt(value, "meta.count");

// comptime extraction for complex structures:
const FeedPost = struct {
    uri: []const u8,
    cid: []const u8,
    record: struct {
        text: []const u8 = "",
    },
};
const post = try zat.json.extractAt(FeedPost, allocator, value, .{"post"});
```

## specs

validation follows [atproto.com/specs](https://atproto.com/specs/atp).
