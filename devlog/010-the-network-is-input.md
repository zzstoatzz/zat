# the network is input

devlog 009 ended with "zat is v0.3.0-alpha. no API changes from this." the next release is different. `v0.3.1` is small in surface area, but it changes two parts of zat's network behavior:

1. resolving [AT Protocol handles](https://atproto.com/specs/handle) and [DIDs](https://atproto.com/specs/did) can require DNS lookups and HTTP fetches.
2. [XRPC](https://atproto.com/specs/xrpc) error responses can carry a JSON error envelope that callers need to inspect.

the release is three commits:

- [`8287ff2`](https://tangled.org/zat.dev/zat/commit/8287ff2) - harden identity network resolution
- [`8ba4cc0`](https://tangled.org/zat.dev/zat/commit/8ba4cc0) - add checked xrpc errors and retries
- [`8de5f40`](https://tangled.org/zat.dev/zat/commit/8de5f40) - release: v0.3.1

## identity resolution performs network requests

AT Protocol account identity uses two related identifiers: [handles and DIDs](https://atproto.com/guides/identity#identifiers). handles are DNS names that resolve to DIDs; DIDs resolve to DID documents with the account's signing key and PDS service endpoint.

when zat resolves those identifiers, it may issue these network requests:

- `did:plc:...` resolves through the PLC directory
- `did:web:example.com` resolves through `https://example.com/.well-known/did.json`
- `handle.example.com` resolves through `https://handle.example.com/.well-known/atproto-did` or the `_atproto.handle.example.com` DNS TXT record

handles and DIDs often come from user input, API parameters, repo records, or event streams. when zat resolves one, the library may fetch a URL or ask DNS for an address. syntax validation does not make that safe. `did:web:127.0.0.1` is syntactically ordinary and operationally not something a server should fetch on behalf of an untrusted caller.

this comes up directly in [`atproto-bench`](https://tangled.org/zzstoatzz.io/atproto-bench). the [full trust-chain verifier](https://tangled.org/zzstoatzz.io/atproto-bench/blob/main/zig/src/verify.zig) accepts a handle or DID, resolves the handle when needed, then resolves the DID document before fetching and verifying the repo. the relay and signature capture harnesses also resolve DIDs from live firehose frames to build signing-key corpora.

the first chunk adds `src/internal/identity/network_safety.zig`. before `did:web` or handle HTTP resolution fetches anything, zat checks the host and the resolved addresses. obvious unsafe targets are rejected directly:

```zig
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("localhost"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("127.0.0.1"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("10.1.2.3"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("192.168.1.1"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("[::1]"));
try std.testing.expectError(error.UnsafeIdentityHost, checkIdentityHost("::ffff:127.0.0.1"));
```

DNS needs a separate check. `evil.example` can be a public name that resolves to `127.0.0.1`, `10.0.0.5`, `fc00::1`, or a link-local address. the resolver now does a DNS-over-HTTPS preflight before the HTTP fetch. it asks for `A` and `AAAA`, rejects non-routable answers, and only then dials.

for `did:web` and [handle well-known HTTP](https://atproto.com/specs/handle#handle-resolution), redirects are disabled. otherwise, an attacker could provide a safe-looking public URL that redirects zat's server-side fetch to a private address.

## using the checked address

the DNS-over-HTTPS preflight means zat has to preserve the checked address through the HTTP request. once zat has checked an address, it should not hand the hostname back to `std.http.Client` and let it resolve the name a second time.

`HttpTransport` now has an internal `ResolvedConnection` mode:

```zig
pub const ResolvedConnection = struct {
    dial_host: []const u8,
    logical_host: []const u8,
};
```

the transport connects to `dial_host`, but keeps `logical_host` for the HTTP `Host` header and TLS server name. that preserves the caller's intended URL while avoiding a second unchecked resolver hop. it also checks that the request URL still matches the logical host, so the preflight result cannot be accidentally reused for a different URL.

this is narrow internal plumbing for identity resolution: "I already checked where this name points; use that address for this request."

## XRPC errors are data

the second chunk came from downstream use. the original XRPC API made this pattern easy:

```zig
var response = try client.query(nsid, params);
if (!response.ok()) return error.ApiFailed;
```

that collapses protocol errors into a boolean. the [XRPC specification](https://atproto.com/specs/xrpc#error-responses) says unsuccessful responses should use a JSON object with an `error` string and optional `message` string:

```json
{"error":"RateLimitExceeded","message":"slow down"}
```

discarding that body loses the difference between `InvalidRequest`, `ExpiredToken`, `RateLimitExceeded`, and an arbitrary 500. it also makes retry behavior hard to centralize because the transport sees the status and headers, while application code sees only a boolean.

`v0.3.1` adds checked XRPC calls:

```zig
var query_result = client.queryChecked(nsid, params, .{}) catch |err| {
    log.err("getAuthorFeed API error for {s}: {}", .{ actor_did, err });
    return error.ApiFailed;
};
defer query_result.deinit();

const response = switch (query_result) {
    .ok => |response| response,
    .err => |xrpc_error| {
        logXrpcError("getAuthorFeed", actor_did, xrpc_error);
        return error.ApiFailed;
    },
};
```

that is the pattern now used in [`music-atmosphere-feed`](https://tangled.org/zzstoatzz.io/music-atmosphere-feed/blob/main/src/bsky/api.zig): public functions still return the application's `ApiFailed` error, but logs keep the XRPC status, error name, and message for AppView calls like `app.bsky.graph.getFollows` and `app.bsky.feed.getAuthorFeed`. the old `query` and `procedure` calls stay. the checked calls are additive, and the return type forces the caller to decide what to do with protocol errors.

## retries belong with the client

the same change adds `XrpcClient.RetryPolicy`. the default is conservative: retry transient transport errors and HTTP `429`, `500`, `502`, `503`, `504`; do not retry ordinary client errors. the delay is exponential, capped, and jittered. if the server sends `retry-after`, that wins. if a rate-limit reset timestamp is available, the policy can use that too.

`HttpTransport.fetch` now preserves:

- `ratelimit-limit`
- `ratelimit-remaining`
- `ratelimit-reset`
- `retry-after`

those fields are present on both successful responses and `XrpcError`. that matters because a caller might need to surface the error immediately but still update local rate-limit state.

the local smoke in [`atproto-bench`](https://tangled.org/zzstoatzz.io/atproto-bench/blob/main/zig/src/xrpc_checked.zig) uses this API directly. it runs a fixture server, asks `queryChecked` to retry a `429`, then verifies that a structured `400` carries `InvalidRequest`, `message`, and rate-limit headers through `XrpcError`.

## smoke tests belong downstream

we did not put the smoke harness in zat. zat has unit tests for the pieces:

- unsafe identity hosts
- unsafe DNS answers
- resolved-host mismatch
- rate-limit header parsing
- XRPC error-envelope parsing
- deterministic retry delay behavior

the end-to-end smoke went into [`atproto-bench`](https://tangled.org/zzstoatzz.io/atproto-bench). that repository already holds protocol harnesses and benchmark fixtures, so it is the right place to exercise behavior that spans zat plus a local HTTP server.

then [`music-atmosphere-feed`](https://tangled.org/zzstoatzz.io/music-atmosphere-feed/blob/main/src/bsky/api.zig) adopted `queryChecked` for its public AppView calls. application code keeps returning its own errors, while logs preserve the protocol error details.

## the release

`v0.3.1` is a patch release because the existing API remains available. the new calls are additive, and the identity hardening changes the default from "fetch any syntactically valid identity target" to "reject private-network identity targets."

there is one practical compatibility note: if someone was intentionally resolving `did:web` or handles to private infrastructure through zat's identity resolvers, that now fails with `error.UnsafeIdentityHost`. for code that resolves identifiers from untrusted public inputs, blocking private-network targets is the safer default. private-network identity resolution is still a legitimate use case, but it should be configured explicitly instead of happening by accident.

the local release checks are boring, which is what a patch release should be:

```text
zig build
zig build test --summary all  # 427/427
just check
just test                     # 427/427
```

zat is `v0.3.1`.
