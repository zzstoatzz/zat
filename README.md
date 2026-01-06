# [zat](https://zat.dev)

AT Protocol building blocks for zig. [roadmap](docs/roadmap.md) · [atproto records](https://at-me.zzstoatzz.io/view?handle=zat.dev)

## install

```bash
zig fetch --save https://tangled.sh/zzstoatzz.io/zat/archive/main
```

then in `build.zig`:

```zig
const zat = b.dependency("zat", .{}).module("zat");
exe.root_module.addImport("zat", zat);
```

## what's here

<details>
<summary><strong>string primitives</strong> - parsing and validation for atproto identifiers</summary>

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

</details>

<details>
<summary><strong>did resolution</strong> - resolve did:plc and did:web to documents</summary>

```zig
var resolver = zat.DidResolver.init(allocator);
defer resolver.deinit();

const did = zat.Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?;
var doc = try resolver.resolve(did);
defer doc.deinit();

const handle = doc.handle();           // "bsky.app"
const pds = doc.pdsEndpoint();         // "https://..."
const key = doc.signingKey();          // verification method
```

</details>

<details>
<summary><strong>handle resolution</strong> - resolve handles to DIDs via HTTP well-known</summary>

```zig
var resolver = zat.HandleResolver.init(allocator);
defer resolver.deinit();

const handle = zat.Handle.parse("bsky.app").?;
const did = try resolver.resolve(handle);
defer allocator.free(did);
// did = "did:plc:z72i7hdynmk6r22z27h6tvur"
```

</details>

<details>
<summary><strong>xrpc client</strong> - call AT Protocol endpoints</summary>

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

</details>

<details>
<summary><strong>sync types</strong> - enums for firehose/event stream consumption</summary>

```zig
// use in struct definitions for automatic json parsing:
const RepoOp = struct {
    action: zat.CommitAction,  // .create, .update, .delete
    path: []const u8,
    cid: ?[]const u8,
};

// then exhaustive switch:
switch (op.action) {
    .create, .update => processUpsert(op),
    .delete => processDelete(op),
}
```

- **CommitAction** - `.create`, `.update`, `.delete`
- **EventKind** - `.commit`, `.sync`, `.identity`, `.account`, `.info`
- **AccountStatus** - `.takendown`, `.suspended`, `.deleted`, `.deactivated`, `.desynchronized`, `.throttled`

</details>

<details>
<summary><strong>json helpers</strong> - navigate nested json without verbose if-chains</summary>

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

</details>

<details>
<summary><strong>jwt verification</strong> - verify service auth tokens</summary>

```zig
var jwt = try zat.Jwt.parse(allocator, token_string);
defer jwt.deinit();

// check claims
if (jwt.isExpired()) return error.TokenExpired;
if (!std.mem.eql(u8, jwt.payload.aud, expected_audience)) return error.InvalidAudience;

// verify signature against issuer's public key (from DID document)
try jwt.verify(public_key_multibase);
```

supports ES256 (P-256) and ES256K (secp256k1) signing algorithms.

</details>

<details>
<summary><strong>multibase decoding</strong> - decode public keys from DID documents</summary>

```zig
const key_bytes = try zat.multibase.decode(allocator, "zQ3sh...");
defer allocator.free(key_bytes);

const parsed = try zat.multicodec.parsePublicKey(key_bytes);
// parsed.key_type: .secp256k1 or .p256
// parsed.raw: 33-byte compressed public key
```

</details>

## specs

validation follows [atproto.com/specs](https://atproto.com/specs/atp).

## versioning

pre-1.0 semver:
- `0.x.0` - new features (backwards compatible)
- `0.x.y` - bug fixes

breaking changes bump the minor version and are documented in commit messages.

## license

MIT
