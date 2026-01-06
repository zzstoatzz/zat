# roadmap

`zat` is a grab bag of **AT Protocol building blocks** in Zig: parsers, validators, resolvers, and small protocol helpers.

This roadmap is intentionally short. If it doesn’t fit into one file, it probably belongs in issues.

## now

- keep current APIs stable (0.x semver)
- tighten docs/examples as real apps discover sharp edges
- keep the “primitives, not framework” ethos

## next

### polish

- improve docs around common workflows:
  - resolving handle → DID → PDS
  - making XRPC calls + parsing JSON
  - verifying JWTs from DID documents
- add more integration tests that hit real-world edge cases (without becoming flaky)

### primitives

- fill gaps that show up repeatedly in other atproto projects:
  - CIDs and common multiformats plumbing
  - richer `AtUri` helpers (safe joins, parsing variants)
  - more ergonomic JSON navigation patterns (still optional, no forced codegen)

## later (maybe)

- lexicon codegen is still “probably a separate project”
- higher-level clients/frameworks stay out of scope

## non-goals

- token refresh/session frameworks
- opinionated app scaffolding
- “one true SDK” that tries to do everything

