# roadmap

zat started as a small set of string primitives for AT Protocol - the types everyone reimplements (`Tid`, `Did`, `Handle`, `Nsid`, `Rkey`, `AtUri`). the scope grew based on real usage.

## history

**initial scope** - string primitives with parsing and validation. the philosophy: primitives not frameworks, layered design, zig idioms, minimal scope.

**what grew from usage:**
- DID resolution was originally "out of scope" - real projects needed it, so `DidResolver` and `DidDocument` got added
- XRPC client and JSON helpers - same story
- JWT verification for service auth
- handle resolution via HTTP well-known
- handle resolution via DNS-over-HTTP (community contribution)
- sync types for firehose consumption (`CommitAction`, `EventKind`, `AccountStatus`)

this pattern - start minimal, expand based on real pain - continues.

## now

use zat in real projects. let usage drive what's next.

the primitives are reasonably complete. what's missing will show up when people build things. until then, no speculative features.

## maybe later

these stay out of scope unless real demand emerges:

- lexicon codegen - probably a separate project
- higher-level clients/frameworks - too opinionated
- token refresh/session management - app-specific
- feed generator scaffolding - each feed is unique

## non-goals

zat is not trying to be:

- a "one true SDK" that does everything
- an opinionated app framework
- a replacement for understanding the protocol
