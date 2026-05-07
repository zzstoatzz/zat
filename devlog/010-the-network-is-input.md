# the network is input

devlog 009 ended with "zat is v0.3.0-alpha. no API changes from this." the next release is different. `v0.3.1` is small in surface area, but it changes how the library treats two pieces of AT Protocol reality:

1. identity strings are not just syntax. resolving them crosses a network boundary.
2. failed XRPC calls are not just failed HTTP. the body is protocol data.

the release is three commits:

- [`8287ff2`](https://tangled.org/zat.dev/zat/commit/8287ff2) - harden identity network resolution
- [`8ba4cc0`](https://tangled.org/zat.dev/zat/commit/8ba4cc0) - add checked xrpc errors and retries
- [`8de5f40`](https://tangled.org/zat.dev/zat/commit/8de5f40) - release: v0.3.1

## identity resolution is a fetch

AT Protocol makes identity resolution look friendly:

- `did:plc:...` goes to `plc.directory`
- `did:web:example.com` goes to `https://example.com/.well-known/did.json`
- `handle.example.com` goes to `https://handle.example.com/.well-known/atproto-did` or `_atproto.handle.example.com` TXT

that last sentence hides the problem. handles and DIDs are user-controlled strings that can make the library issue HTTP requests. validating the syntax is not enough. `did:web:127.0.0.1` is syntactically ordinary and operationally not something a server should fetch on behalf of an untrusted caller.

the first chunk adds `src/internal/identity/network_safety.zig`. before `did:web` or handle HTTP resolution fetches anything, zat now checks the host and the resolved addresses. the obvious unsafe cases are rejected directly:

```zig
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("localhost"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("127.0.0.1"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("10.1.2.3"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("192.168.1.1"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("[::1]"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("::ffff:127.0.0.1"));
```

the less obvious case is DNS. `evil.example` can be a public name that resolves to `127.0.0.1`, `10.0.0.5`, `fc00::1`, or a link-local address. so the resolver does a DoH preflight before the HTTP fetch. it asks for `A` and `AAAA`, rejects non-routable answers, and only then dials.

for `did:web` and handle well-known HTTP, redirects are disabled. redirecting from a safe-looking public URL to a private address is the same bug with one extra step.

## dialing one host while speaking for another

the DoH preflight created a second constraint: once we have checked an address, the actual HTTP request should use that checked address, not resolve the hostname again underneath `std.http.Client`.

`HttpTransport` now has an internal `ResolvedConnection` path:

```zig
pub const ResolvedConnection = struct {
    dial_host: []const u8,
    logical_host: []const u8,
};
```

the transport connects to `dial_host`, but keeps `logical_host` for HTTP/TLS identity. that preserves the thing callers intended to fetch while avoiding a second unchecked resolver hop. it also checks that the request URL still matches the logical host, so the preflight result cannot be accidentally reused for a different URL.

this is not meant to be a general proxy API. it is just enough machinery for identity resolution to say: "I already checked where this name points; use that."

## XRPC errors are data

the second chunk came from downstream use. the original XRPC API made this easy:

```zig
var response = try client.query(nsid, params);
if (!response.ok()) return error.ApiFailed;
```

that is fine for a prototype. it is not enough for a client that needs to understand AT Protocol behavior. a non-2xx response can still contain a structured XRPC envelope:

```json
{"error":"RateLimitExceeded","message":"slow down"}
```

throwing that away means callers lose the difference between `InvalidRequest`, `ExpiredToken`, `RateLimitExceeded`, and an arbitrary 500. it also makes retry behavior hard to centralize because the transport sees the status and headers, while application code sees only a boolean.

`v0.3.1` adds checked XRPC calls:

```zig
var result = try client.queryChecked(nsid, params, .{});
defer result.deinit();

switch (result) {
    .ok => |response| {
        // parse success body
        _ = response;
    },
    .err => |xrpc_error| {
        // status, error_name, message, body, rate_limit
        _ = xrpc_error;
    },
}
```

the old `query` and `procedure` calls stay. the checked calls are additive, and the return type forces the caller to decide what to do with protocol errors.

## retries belong with the client

the same change adds `XrpcClient.RetryPolicy`. the default is conservative: retry transient transport errors and HTTP `429`, `500`, `502`, `503`, `504`; do not retry ordinary client errors. the delay is exponential, capped, and jittered. if the server sends `retry-after`, that wins. if a rate-limit reset timestamp is available, the policy can use that too.

`HttpTransport.fetch` now preserves:

- `ratelimit-limit`
- `ratelimit-remaining`
- `ratelimit-reset`
- `retry-after`

those fields are present on both successful responses and `XrpcError`. that matters because a caller might need to surface the error immediately but still update local rate-limit state.

## proof belongs downstream

we did not put the smoke harness in zat. zat has unit tests for the pieces:

- unsafe identity hosts
- unsafe DNS answers
- resolved-host mismatch
- rate-limit header parsing
- XRPC error-envelope parsing
- deterministic retry delay behavior

the end-to-end smoke went into [`atproto-bench`](https://tangled.org/zzstoatzz.io/atproto-bench), where this kind of protocol harness belongs. the harness runs a local HTTP fixture, makes `queryChecked` hit a `429`, verifies the retry succeeds, then verifies a structured `400` comes back as `XrpcError` with rate-limit headers intact.

then [`music-atmosphere-feed`](https://tangled.org/zzstoatzz.io/music-atmosphere-feed) adopted `queryChecked` for its public AppView calls. that is the useful downstream shape: application code still returns its own `ApiFailed`, but it logs the actual XRPC status, error name, and message instead of flattening everything to "not ok."

## the release

`v0.3.1` is a patch release because the existing API remains available. the new calls are additive, and the identity hardening is a fix to behavior that should not have been allowed by default.

there is one practical compatibility note: if someone was intentionally resolving `did:web` or handles to private infrastructure through zat's identity resolvers, that now fails with `error.UnsafeIdentityHost`. that is the correct default for a public AT Protocol library. private-network fetching needs an explicit escape hatch, not accidental behavior.

the local release checks are boring, which is what a patch release should be:

```text
zig build
zig build test --summary all  # 427/427
just check
just test                     # 427/427
```

zat is `v0.3.1`.
