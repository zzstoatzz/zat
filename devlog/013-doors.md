# doors

devlog 012 ended at `v0.3.5`. this covers `v0.3.6` and `v0.3.7`, and there is no grand thesis in it. the recurring shape of these notes — a downstream app reaches for something zat half-has, and the reach becomes the next change — is by now house lore. 010 called it "the network is input" and let downstream use drive the XRPC error API; 011 was zds surfacing the high-S bug; 012's "missing middle" was ZDS reaching through MST internals until `collectBlocks` and `walk` existed. so this is the same loop, not a discovery. what's worth writing down is the two specific doors that opened, because they are a different kind of gap than the ones before.

## a capability with no door

the new consumer this cycle is [leaflet-search](https://tangled.org/zzstoatzz.io/leaflet-search) (now pub-search), which grew its own firehose ingester to replace indigo's `tap`. the ingester's last blocker was verification: it wanted to consume the firehose and verify each commit in-process before trusting it.

zat already had the verifier for exactly this. `repo_verifier.verifyCommitCar` says so in its own doc comment — "used by the relay to verify firehose commit frames directly" — and takes the raw CAR bytes from a frame's `blocks` field plus a resolved signing key. the function was right there.

the problem was that you could not get the bytes to it. every prior verification story in these notes is *low-level*: the relay (devlog 006), zlay, and zds all decode firehose frames themselves, so they were already holding the raw CAR when it came time to verify. a high-level `FirehoseClient` consumer was not. `decodeFrame` read the `blocks`, parsed the CAR to hydrate each op's record, and then **discarded the raw bytes**. `CommitEvent` exposed `seq`, `repo`, `rev`, `ops`, `blobs`, `too_big` — and nothing you could hand to `verifyCommitCar`. the documented path was real and unreachable at the same time.

this is not 012's gap. "the missing middle" was a consumer reaching *through* internals that then needed to change. this was the opposite: a public capability that had no public entrance. the fix is small and purely additive — [`f0d781e`](https://tangled.org/zat.dev/zat/commit/f0d781e) puts the bytes back on the event:

```zig
pub const CommitEvent = struct {
    seq: i64,
    repo: []const u8,
    rev: []const u8,
    // ...
    blocks: []const u8 = &.{}, // raw CAR diff bytes
    prev_data: ?cbor.Cid = null, // MST root CID of the previous revision
    // ...
};
```

now the high-level consumer does what the relay always could:

```zig
try zat.repo_verifier.verifyCommitCar(allocator, event.commit.blocks, signing_key, .{});
```

the same change carries `prev_data` and the per-op `prev` CIDs through, adds a `toMstOperations()` helper, and decodes `#sync` events — so a consumer that wants the stronger [`verifyCommitDiff`](https://tangled.org/zat.dev/zat/blob/main/src/internal/repo/repo_verifier.zig) (invert the ops, prove the previous root) has the inputs for that too. CAR parse failure during hydration is now non-fatal: the wire event still surfaces, and a consumer rejects it by verifying `blocks` explicitly rather than by never seeing it. leaflet-search's ingester verifies in-consumer now, which was the sole thing standing between it and replacing `tap`.

## the boundary 011 drew, crossed on purpose

011 was careful about a line. zds runs a full OAuth authorization server — PAR, DPoP, client assertions, permission sets — and that devlog kept it on zds's side: zat supplies protocol primitives, the application keeps "cookies, redirects, sessions, and storage policy." that was the right call then. the ceremony was new, only one app did it, and it was tangled up with zds's own persistence.

a second OAuth consumer makes the same line look different. the primitives were never the hard part; the *ceremony* is — discovery, building the authorization URL, PAR, the code and refresh exchanges, DPoP nonce retry, DPoP-authenticated resource requests. every consumer reimplements the same dance around the same primitives, and the storage policy 011 fenced off is genuinely the only part that differs between apps.

so [`1f7dbc5`](https://tangled.org/zat.dev/zat/commit/1f7dbc5) splits `zat.oauth` into two halves and lifts the framework-neutral one into the library. `oauth/primitives.zig` keeps PKCE, DPoP, client assertions, and form/JWKS encoding. `oauth/client.zig` is the ceremony:

```zig
const authserver = try zat.oauth.discoverAuthorizationServer(allocator, &transport, pds_url);
var metadata = try zat.oauth.fetchAuthorizationServerMetadata(allocator, &transport, authserver);
var secrets = try zat.oauth.prepareAuthRequestSecrets(allocator, io);
var par = try zat.oauth.sendParRequest(allocator, io, &transport, .{ ... });
// then authorizationUrl, exchangeCodeForToken, refreshAccessToken, dpopRequest
```

the line 011 drew did not move — cookies, sessions, redirects, and persistence still stay with the app. what moved is everything *up to* that line. the OAuth client also stays on the shared `HttpTransport` instead of dropping to raw `std.http.Client`, because [`FetchResult`](https://tangled.org/zat.dev/zat/blob/main/src/internal/xrpc/transport.zig) now captures the response headers OAuth needs — `Content-Type`, `DPoP-Nonce`, `WWW-Authenticate`.

this is not a new insight, it is the boundary from 011 acted on once a second app proved the part below it was reusable.

## the small correctness fix

leaflet-search also left the other door ajar. its author filtering was silently no-opping for `dholms.at`, and the cause was DNS-over-HTTPS handle resolution. Cloudflare appends a `Comment` field to DoH JSON for handles in DNSSEC zones:

```json
{"Status":0, ...,
 "Answer":[{"name":"_atproto.dholms.at","type":16,"data":"\"did=did:plc:...\""}],
 "Comment":["EDE(10): RRSIGs Missing for DNSKEY at., id = 1253"]}
```

`HandleResolver` parsed that body strictly, so the undeclared `Comment` aborted the parse with `error.InvalidDnsResponse`. `.well-known` HTTP handles were fine, so the failure looked intermittent — it only hit handles whose `_atproto` TXT record lives in a DNSSEC zone. [`27f810b`](https://tangled.org/zat.dev/zat/commit/27f810b) parses with `ignore_unknown_fields` and pins the behavior with a network-free regression test built from a real Cloudflare DNSSEC body.

## also in these releases

the rest is hygiene, not story:

- websocket.zig moved to `v0.1.7` (an IPv6 `Address` shim and socket-race fixes), and the re-export from `zat`'s root was added and then dropped so the dependency stays a dependency.
- `repo_verifier.invertOp` had its error handling made exhaustive.
- MST `collectBlocks` now caches node encodings across passes and keeps the `(cid, encoded)` pair consistent in `nodeCid`, so gathering commit blocks does not re-serialize clean nodes — a small follow-on to 012's hot-path work.

## the releases

`v0.3.6` is the firehose verification inputs plus the websocket and `invertOp` items. `v0.3.7` is the OAuth toolkit, the DoH fix, and the MST encoding cache. both are patch releases: every public change is additive, and nothing that verified or resolved before stops doing so.

zat is `v0.3.7`.
