# zat

zig primitives for AT Protocol string formats.

## install

```bash
zig fetch --save https://github.com/zzstoatzz/zat/archive/main.tar.gz
```

then in `build.zig`:

```zig
const zat = b.dependency("zat", .{}).module("zat");
exe.root_module.addImport("zat", zat);
```

## what's here

parsing and validation for atproto string identifiers:

- **Tid** - timestamp identifiers (base32-sortable)
- **Did** - decentralized identifiers
- **Handle** - domain-based handles
- **Nsid** - namespaced identifiers (lexicon types)
- **Rkey** - record keys
- **AtUri** - `at://` URIs

all types follow a common pattern: `parse()` returns an optional, accessors extract components.

```zig
const zat = @import("zat");

if (zat.AtUri.parse(uri_string)) |uri| {
    const authority = uri.authority();
    const collection = uri.collection();
    const rkey = uri.rkey();
}
```

## specs

validation follows [atproto.com/specs](https://atproto.com/specs/atp).
