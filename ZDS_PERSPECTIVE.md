# ZDS Perspective On Zat Boundaries

This note is written from the perspective of implementing ZDS, a Zig AT
Protocol PDS that consumes Zat for protocol primitives. It is not a directive
for Zat, and it is not meant to prescribe a roadmap. The Zat maintainer should
decide what belongs in Zat based on Zat's own taste, API standards, and
evidence from more than one consumer.

The useful thing this note can offer is a record of where ZDS reached for
reusable protocol machinery, where that machinery already moved into Zat, and
where future Zat affordances might reduce whole classes of mistakes.

## Current Boundary

The boundary that has worked best is:

- Zat owns protocol primitives and reusable protocol ceremony.
- ZDS owns PDS policy, operator behavior, persistence, migrations, UI, and
  experimental product surface.

That boundary is not perfectly static. A thing tends to become a good Zat
candidate when it is:

- protocol-shaped rather than product-shaped
- useful to more than one consumer
- independent of storage and deployment policy
- easy to test against specs or known interop fixtures
- more likely to prevent subtle protocol bugs if centralized

Conversely, a thing should probably stay in ZDS when it depends on local
database schema, admin/operator UX, feature flags, product experiments, or
protocol proposals that are still moving.

## What ZDS Has Already Pulled Into Zat

### MST And Repo Write Support

ZDS exposed pressure around repo writes and large repos. That led to useful
Zat work around lazy MST behavior, block collection, ordered traversal, cached
clean-node CIDs, and avoiding repeated serialization when gathering commit
blocks.

This feels like the right kind of Zat work. The details are pure repo/MST
machinery, and consumers should not need to reach through MST internals to
write or verify repos efficiently.

### Firehose Verification Inputs

ZDS and other consumers made it clear that a high-level firehose decoder should
not hide the data needed for verification. Zat now exposes raw commit `blocks`,
`prevData`, per-op `prev`, `toMstOperations()`, and `#sync` decoding.

That also feels squarely in Zat's domain. A firehose consumer should be able to
decode an event and pass the right bytes and metadata into repo verification
without re-parsing raw frames by hand.

### OAuth Client Ceremony

ZDS originally kept OAuth ceremony local because it was entangled with PDS
state, sessions, redirects, consent, cookies, and token storage. Once more
than one consumer needed the client side of the OAuth dance, Zat grew a
framework-neutral OAuth client toolkit for discovery, PAR, code exchange,
refresh, DPoP nonce retry, and DPoP-authenticated resource requests.

That split still seems right. Zat can own reusable OAuth client ceremony while
applications own sessions, persistence, redirects, and UI.

## Places Where ZDS Still Has Local Code

### OAuth Authorization Server

ZDS implements an OAuth authorization server: PAR handling, consent, token
families, refresh rotation, passkey login, DPoP-bound access tokens, session
inspection, and token storage.

Some pure helpers inside that work might eventually belong in Zat, but the
authorization-server behavior as a whole is not obviously a Zat primitive.
It is tightly coupled to account storage, operator expectations, login UI,
session policy, and audit/debug surfaces.

### DPoP Resource Server Verification

ZDS currently has local DPoP verification code. Some of it is policy:
nonce lifetime, nonce derivation, replay storage, challenge behavior, and how
failures are surfaced through XRPC responses. That should stay with ZDS.

Some of it is pure protocol work: parsing DPoP JWTs, verifying JOSE signatures,
checking `htm`, normalizing and checking `htu`, validating `ath`, deriving the
JWK thumbprint, and comparing it to a token binding. That pure layer may be
worth considering for Zat if another server-side consumer appears or if ZDS
keeps finding subtle edge cases there.

### Permissioned Data

Permissioned data should remain ZDS-local for now.

The protocol shape is still experimental, active design discussion is ongoing,
and ZDS is acting as an early implementation with product pressure from
plyr.fm. That makes it a poor fit for Zat until the reusable primitive boundary
is clearer.

Good future Zat candidates might exist here, but they should emerge from a
settled protocol shape: space URI parsing, credential signing/verification,
or CAR/repo helpers for permissioned repos. The whole application model should
not be prematurely centralized.

### Operator And Resident UX

Stats pages, sessions pages, private-space viewers, email providers, Comail,
invite codes, Fly deployment behavior, and operator documentation are ZDS
concerns. They are valuable, but they are not Zat concerns.

## Future Zat Candidates

These are not requests. They are areas where ZDS's implementation experience
suggests that reusable Zat APIs could reduce mistakes or duplication.

### Firehose Commit Event Builder

ZDS recently had a bug where `#commit.since` was emitted as the previous commit
CID instead of the previous repo revision/TID. The protocol distinction is:

- `commit`: CID of the current commit object
- `rev`: current repo revision/TID
- `since`: previous repo revision/TID, or null for an initial/full event
- `prevData`: previous MST root CID

ZDS stored the previous commit CID correctly for internal commit linkage, but
used that value in the wrong protocol field when encoding firehose events.

This is the kind of mistake a typed Zat builder could make less likely. An API
that names fields as `commit_cid`, `rev`, `since_rev`, and `prev_data` would
encode the vocabulary in the call site and avoid ambiguous `prev` plumbing.

This does not have to mean Zat owns ZDS sequencing, SQLite storage, migrations,
or event persistence. The potentially reusable piece is just the protocol
encoding of a commit event once the caller already has the correct inputs.

### Firehose Commit Event Validation

Adjacent to a builder, Zat might eventually offer a lightweight structural
validator for decoded commit events:

- `rev` and `since` are syntactically valid TIDs when present
- `commit` is a CID
- `prevData` is a CID or null
- op paths split into valid NSID/rkey pairs
- operation CID fields have the expected nullability by action

This would not replace repo verification. It would catch structural protocol
mistakes earlier and produce sharper diagnostics for strict consumers.

### DPoP Verification Core

The pure DPoP verification core may be reusable:

- decode DPoP proof JWT
- verify `typ`, `alg`, and embedded JWK
- verify JOSE signature
- derive JWK thumbprint
- check `htm`
- normalize/check `htu`
- check `iat` freshness
- check optional `ath`

ZDS would still own nonce generation, nonce acceptance windows, replay storage,
challenge responses, and token/session lookup.

This split mirrors the OAuth client toolkit split: Zat owns protocol ceremony
and cryptographic checks; applications own state and policy.

### Permissioned Data Primitives, Later

If permissioned data settles, Zat may eventually be a good home for small,
stable pieces:

- `ats://` space URI parsing/formatting
- permissioned record URI parsing/formatting
- space credential signing and verification
- permissioned repo CAR verification helpers
- lexicon-independent scope/permission-set parsing helpers, if the shape
  stabilizes

For now, this would be premature. ZDS can keep absorbing change locally while
the design is still fluid.

## ZDS Should Probably Consume Newer Zat

As of this note, ZDS is still pinned to `zat v0.3.5`, while Zat has moved on
to `v0.3.7`. Some of that newer work came directly from the same exploration:
firehose verification inputs and the OAuth client toolkit.

That does not mean ZDS should bump casually. It does mean a careful ZDS
dependency upgrade is worth doing, with the usual ZDS checks and benchmarks.
The upgrade would confirm that the Zat changes are actually useful to the PDS,
not merely useful in theory.

## Guiding Principle

The best Zat changes from this cycle were not attempts to move "more code" out
of ZDS. They were places where ZDS discovered a stable protocol-shaped gap:

- MST block collection was too internal.
- Firehose verification inputs were not exposed.
- OAuth client ceremony was being repeated by multiple consumers.

That is the pattern to keep following. Let ZDS keep the messy, local,
operator-shaped, experimental work. Move things into Zat when a small primitive
or framework-neutral protocol helper becomes obvious enough that future
consumers should not have to rediscover it.
