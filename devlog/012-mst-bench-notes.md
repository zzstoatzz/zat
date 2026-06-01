# copying the boring parts

this one starts with a benchmark and ends, happily, with less code to be clever about.

zat's MST implementation had grown up around repo verification. it could load partial trees from commit CARs, invert firehose operations against a post-state tree, and prove the previous root. that machinery mattered. it was introduced in `fff8599` for sync 1.1: missing child blocks became stubs, `putReturn` and `deleteReturn` made operation inversion possible, and `verifyCommitDiff` could reject a commit if the inverted tree did not hash back to `prevData`.

that is real semantic work. but it does not follow that every hot path should pay for the representation that made it possible.

the comparison target was [Atmos](https://github.com/jcalabro/atmos), Jim's Go implementation. that is not just another library on the internet; it is written by the person operating almost all production PDS infrastructure. if Atmos is boring in some place, that boringness has earned respect.

the rule for this pass was simple: match semantics first, benchmark second. if Zat and Atmos do not produce the same root bytes, the benchmark is noise. if they produce the same root bytes while doing different practical work, the benchmark is still muddy.

## what changed

the old hot shape used a tagged child representation. that made partial trees explicit: a child was either absent, loaded, or a CID stub. Atmos uses something plainer. children are nullable pointers, and an unloaded subtree is a node that carries a CID until `ensureLoaded` mutates it into the loaded node.

Zat now follows that shape. `Node.left` and `Entry.right` are nullable `*Node`; unloaded nodes carry cached CIDs; lazy loading mutates the selected node in place. partial-tree behavior still exists, but it is no longer a tag on every child edge.

the other changes were in the same spirit:

- clean nodes cache their CIDs, so `rootCid` does not re-hash the whole tree
- MST nodes serialize directly to DAG-CBOR bytes instead of building generic `cbor.Value` maps
- insertion can borrow caller-owned keys for benchmark/import paths
- ATProto key comparison uses chunked big-endian reads instead of scalar byte comparison
- lookup walks entries linearly and follows the ordered tree by key, like Atmos

that last one took the longest to deserve.

## the tempting mistake

MST node entries are sorted, so binary search looks attractive. it was also wrong for this workload.

the benchmark tree had:

| shape | value |
|---|---:|
| entries | 50,000 |
| nodes | 13,443 |
| max entries per node | 32 |
| average lookup depth | 7.66 nodes |

with nodes this small, binary search mostly bought unpredictable midpoint branches and worse locality. Atmos scans each node's entries in order. once Zat did the same, lookup stopped looking like a mystery.

there was one more mismatch. Zat was still using key height and layer arithmetic to decide how lookup should descend. Atmos does not do that. it compares the target key against entries in order, chooses `left` or the previous entry's `right`, and loads that child only if it is the selected path. height still belongs in insertion, deletion, splitting, and normalization. plain lookup does not need it.

so `getWithHeight` remains as an API compatibility surface, but lookup ignores the height. that is a little funny, and also the right kind of boring.

## the numbers

the publishable benchmark is the official `atproto-bench` MST run: one Zat path, one Atmos path, same corpus, same work, same root.

median of three `just bench-mst` runs, each with one warmup pass and five measured passes over 50k deterministic records and 500k lookups per pass:

![Zat and Atmos MST benchmark throughput chart](https://zat.dev/docs/devlog/img/mst-throughput.svg?v=c03ec5e)

| implementation | insert + root | lookup |
|---|---:|---:|
| Zat | 5,728,470 records/sec | 6,540,333 lookups/sec |
| Atmos | 4,147,900 records/sec | 5,512,120 lookups/sec |
| Zat / Atmos | 1.38x | 1.19x |

both implementations produced the same root bytes:

`01711220d59a82ffb8968ab6ff46354b382a18072f382240bc447c70e8cbc579221c8c2e`

and the same lookup checksum.

there were diagnostic benches too, but those stay out of the official table. they were useful for seeing where time went: height calculation, direct CID access, alternate comparators, miss paths, recursive versus iterative lookup. the useful result was not a magic Zig trick. it was deleting unnecessary cleverness until the hot path had the same problem shape as Atmos: pointer children, fast comparison, tiny-node linear scan.

## why insert moved

insert plus root computation got faster for more direct reasons.

first, dirty CID caching stopped recomputing roots for clean subtrees. then direct node serialization removed a pile of generic CBOR construction from the root path. after chunked key comparison, insertion was spending less time re-reading the same long ATProto key prefixes byte by byte.

Atmos is still excellent code. Zat's advantage here is mostly that the current path is arena-friendly, allocation-light, and direct about the bytes it needs to hash.

## the missing middle

the representation cleanup also exposed an API gap. ZDS was reaching through Zat internals to do two jobs:

- collect MST DAG-CBOR blocks for a commit CAR
- walk repo records in MST key order

that was fine while the internal shape was stable, and exactly wrong once the internal shape needed to change.

Zat now exposes `Mst.collectBlocks` and `Mst.walk`. `collectBlocks` emits newly materialized MST blocks and skips clean unresolved stubs, matching the old ZDS commit-CAR behavior where existing repo blocks do not need to be re-exported on every write. `walk` resolves lazy nodes when a block reader is available and returns `PartialTree` if the caller asks to walk through an unresolved stub.

ZDS adopted both APIs first. record writes now use `collectBlocks`, and repo import uses `walk`, so the new MST layer is exercised by a real PDS rather than only by benchmarks. ZDS was deployed with Zat commit `485f1d485a9b8e7b703e8627a6b6a8c3e3c36a0e` before this release was prepared.

## release shape

this is `v0.3.5`.

the public API change is additive: `Mst.collectBlocks` and `Mst.walk`. the rest is internal representation and hot-path behavior. existing callers should not need to change, and the root parity checks are the important proof that the MST semantics did not drift.

the release checks were:

| check | result |
|---|---:|
| Zat tests | 439/439 passed |
| `zig zen` | ran |
| ZDS with local Zat fork | passed |
| atproto-bench with local Zat path | passed |
| find-bufo with local Zat fork | passed |
| pollz with local Zat fork | passed |
| typeahead with local Zat fork | passed |

some older sibling apps currently fail before they reach this change because of their own dependency graphs: duplicate websocket modules in a few apps, missing local llama/ggml dylibs in Ken, and an older build API in relay-eval. those are release hygiene items for those projects, not MST correctness findings.

the lesson, if there is one, is not "Zig beat Go." the lesson is more useful than that: when a production implementation is doing something plain, copy the plain thing before inventing a smarter one.
