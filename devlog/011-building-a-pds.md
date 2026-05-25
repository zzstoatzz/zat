# building a pds

devlog 010 ended at `v0.3.1`; `v0.3.2` bumped websocket.zig. this one is about [`zds`](https://tangled.org/zat.dev/zds) — an AT Protocol Personal Data Server written in Zig and built on zat — and the one change building it pushed back into the library, now `v0.3.3`.

zds is live at [pds.zat.dev](https://pds.zat.dev), with real accounts on it.

## what it does

a PDS is a lot of surface. zds handles account creation and sessions, the OAuth authorization server ([PAR, DPoP, client assertions, permission sets](https://tangled.org/zat.dev/zds/blob/main/src/atproto/oauth.zig)), invite-code gating, transactional email for account flows, blob storage on disk, repo reads and writes, a `subscribeRepos` firehose, crawl requests to relays, and account migration. it uses zat for the protocol primitives and keeps policy and persistence — SQLite, the blobstore, routing — to itself. there's no appview; `app.bsky.*` requests are forwarded through [`atproto-proxy`](https://tangled.org/zat.dev/zds/blob/main/src/atproto/proxy.zig).

## authoring repos

zat had been worked hard before zds. [zlay](https://tangled.org/zzstoatzz.io/zlay) verifies firehose commits and fans them out to downstream consumers; [labelz](https://tangled.org/zzstoatzz.io/labelz) signs labels with secp256k1 and serves them over XRPC. zds drives the full repo write loop. a single `createRecord` touches most of zat's authoring surface:

- a TID record key (`zat.Tid`)
- the record encoded as DAG-CBOR, and its CID (`zat.cbor`)
- the record spliced into the account's MST (`zat.mst`)
- a new commit, signed with the account's key (`zat.Keypair`, `zat.jwt`)
- a `#commit` event on its `subscribeRepos` firehose, carrying the changed blocks as a CAR slice (`zat.car`)

migration runs the same primitives in reverse — zds verifies an imported repo with `zat.verifyCommitCar` before accepting the account.

## it federates

[`bufo.uk`](https://bsky.app/profile/bufo.uk) and [`waow.tech`](https://bsky.app/profile/waow.tech) keep their repos on zds. their DID documents name `pds.zat.dev` as the PDS and carry the public signing key zds signs their commits with — that is what resolves the accounts to zds, and what a consumer verifies signatures against.

a relay aggregates many PDS firehoses into one stream. zds joins that set by sending a `requestCrawl` at startup to its configured endpoints — the `bsky.network` relay, and [`vsky.network`](https://vsky.network), which forwards the request on to community relays. a subscribed relay then reads zds's `#commit` events, resolves each account's signing key from its DID document, and verifies the commit signature before re-emitting it on its merged firehose — the verification [zlay](https://tangled.org/zzstoatzz.io/zlay) does with zat. Bluesky runs its own relay and appview, independent of anything we operate, and both accounts render there. an invalid commit signature wouldn't propagate, so the records appearing means the commits zat signed verify under another implementation.

their repos also hold records in lexicons zat has no built-in knowledge of — `fm.plyr.track`, `app.blento.card`, `sh.tangled.string` — which it encodes as DAG-CBOR like any other record.

## the change: high-S signatures

building zds's OAuth path surfaced the one place zat was wrong.

zat's `Jwt.verify` enforced low-S signatures. that is correct for atproto's content-addressed data: [the cryptography spec](https://atproto.com/specs/cryptography) requires low-S, because a malleable commit signature would give two valid byte encodings — two CIDs — for one commit. but a JWT is not atproto data. it is a [JOSE](https://www.rfc-editor.org/rfc/rfc7515) token, and JOSE never required low-S. OAuth client assertions and DPoP proofs are routinely signed with WebCrypto, which emits high-S signatures about half the time, and zat rejected them. zds worked around it with [its own lenient verifier](https://tangled.org/zat.dev/zds/blob/main/src/internal/jose.zig), and carried the same strictness as a latent bug on its inbound [service-auth path](https://tangled.org/zat.dev/zds/blob/main/src/atproto/server.zig).

both reference SDKs already split verification along this line:

| | content-addressed (strict low-S) | JOSE / JWT (lenient) |
|---|---|---|
| [`@atproto/crypto`](https://github.com/bluesky-social/atproto/tree/main/packages/crypto) | default `allowMalleableSig: false` | JWT verification passes `true` |
| [`atmos`](https://github.com/jcalabro/atmos) (jim's, Go) | `HashAndVerify` — commits, PLC, labels | `HashAndVerifyLenient` — service auth |

`v0.3.3` adds `jwt.verifyJose` — lenient ES256/ES256K, for OAuth assertions and DPoP — and makes `Jwt.verify` lenient. the strict path does not move: `verifyCommitCar`, `verifyCommitDiff`, and `verifyDidKeySignature` still reject high-S. a [test](https://tangled.org/zat.dev/zat/blob/main/src/internal/crypto/jwt.zig) pins the split with one high-S signature that `verifyP256` rejects and `verifyJose` accepts. it is a patch — nothing that verified before stops verifying.

zds bumps its pin to `v0.3.3` and drops its workaround.

zat is `v0.3.3`.
