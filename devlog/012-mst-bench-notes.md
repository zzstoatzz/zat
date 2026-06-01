# mst bench notes

working notes for the eventual devlog entry on the MST work. this is not polished yet; it is the factual trail while the numbers are still moving.

## why atmos

Jim's Atmos MST is the reference worth copying for practical reasons: it is written by the person operating the overwhelming majority of production PDS infrastructure, and its implementation has a lot of hard-won engineering choices that are not visible from the AT Protocol spec alone.

The rule for this pass was semantic consistency first, then benchmark interpretation. If Zat and Atmos disagree on root bytes, the benchmark is meaningless. If they agree on root bytes but take different engineering shortcuts, the comparison is still muddy.

## why zat grew child refs

The `ChildRef` machinery was introduced in `fff8599` (`feat: sync 1.1 — partial MST, commit diff verification via inversion`). The commit message is explicit:

- `ChildRef` union (`none/node/stub`) represented partial trees loaded from commit CAR blocks
- `putReturn` / `deleteReturn` returned displaced CIDs for inversion
- `copy()` deep-cloned partial post-state trees before inversion
- `loadFromBlocks()` deserialized the CAR slice into an MST where missing child blocks became stubs
- `verifyCommitDiff()` inverted firehose ops against the post-commit partial MST and checked the resulting root against `prevData`

So the richer machinery was not for normal repo authoring or steady-state lookup. It was for sync 1.1 diff verification against partial CAR data, where some child CIDs may be known but their blocks may not be present.

The current verifier still uses that path: `verifyCommitDiff` loads the post-commit root with `Mst.loadFromBlocks`, copies it, normalizes ops, applies `invertOp`, and compares `rootCid()` to `prevData`. If inversion needs to descend into a missing subtree, it returns `PartialTree`.

The question now is whether that partial-tree machinery needs to be the default in-memory shape for all MSTs. Atmos suggests no: it represents children as plain pointers and uses an unloaded `node{cid: root}` / `node{cid: child}` stub shape, with `ensureLoaded` mutating that node into a loaded node on demand. That collapses the hot loaded state back to pointer chasing without a tagged child union.

We tried that. `ChildRef` is gone from the hot structure: `Node.left` and `Entry.right` are nullable `*Node`, and an unloaded subtree is just a node with a cached CID and no entries/children yet. `ensureNodeLoaded` mutates that node in place. The partial/lazy tests still pass, so the semantic machinery survived without the tagged edge representation.

## changes copied into zat

- lazy MST loading from a root CID plus block reader
- unloaded nodes that carry CID and expected layer, so empty intermediate nodes keep canonical height
- dirty nodes with cached CIDs, matching Atmos's content-addressed lifecycle
- parent dirty propagation after child mutation
- direct MST node serialization instead of generic CBOR value construction
- borrowed-key insertion for benchmark and caller-owned-key use cases
- hot entry layout matching Atmos's `key/right/value` ordering
- chunked MST key comparison instead of generic scalar byte ordering
- `getWithHeight` kept as API compatibility for callers that already know the
  key height, but lookup no longer needs the height
- nullable child pointers instead of `ChildRef` union tags

## what moved

The first big win was dirty CID caching. Recomputing every subtree root was the wrong shape for repo authoring. Once clean nodes could return their cached CID, insert+root moved much closer to Atmos.

The second win was direct serialization. Atmos writes the MST node schema straight into a pre-sized byte buffer. Zat was building generic `cbor.Value` maps and allocating per entry during root computation. Replacing that with direct DAG-CBOR bytes moved insert+root again.

The third win was key comparison. This was the surprise. Zig's `std.mem.order(u8, ...)` is generic and scalar. ATProto keys share long prefixes, so lookup and insertion were spending a lot of time walking identical bytes one at a time. Atmos's Go string comparison goes through a much faster runtime/compiler path. A chunked big-endian comparator moved Zat's core traversal into the same neighborhood.

## current selected benchmark path

The benchmark now reports one Zat path, not a menu of experiments:

- borrowed tree keys
- cached node CIDs
- direct MST node serialization
- chunked key comparison
- Atmos-style ordered-tree lookup through tiny MST nodes

Latest cleaned run:

| implementation | insert + root | lookup |
|---|---:|---:|
| Zat | 5,728,470 records/sec | 6,540,333 lookups/sec |
| Atmos | 4,147,900 records/sec | 5,512,120 lookups/sec |

Both implementations produced the same root bytes:

`01711220d59a82ffb8968ab6ff46354b382a18072f382240bc447c70e8cbc579221c8c2e`

Those rows are the median of three official `just bench-mst` runs after the
lookup path was changed to match Atmos semantically. Each run still uses one
warmup pass and five measured passes over the same deterministic 50k-record
corpus, with 500k lookups/pass.

## why zat now wins insert

Insert exercises ordered search plus mutation plus root computation. Zat now has three advantages there:

- arena allocation makes short-lived tree construction cheap
- direct serialization is fast and allocation-light
- cached dirty-node CIDs prevent unnecessary subtree hashing

Atmos still has excellent insertion code, but it is doing this in Go with heap objects and slices. After Zat stopped using generic CBOR and scalar key comparison, the arena/direct-bytes path became very favorable.

## why lookup flipped

The lookup gap did not turn out to be MST semantics or tree shape. Zat and Atmos build the same root and the same 50k-record tree shape:

- 13,443 nodes
- 50,000 entries
- max entries per node: 32
- average lookup depth: 7.66 nodes

The gap was in the hot in-memory traversal algorithm.

Atmos lookup has:

- plain `*node` child pointers (`nil` for absent)
- linear scan through each node's entries
- compact node header with hot fields first
- no CID slice return copy at the exact match site; it returns a pointer to the stored CID

Zat had been using binary lower-bound for lookup because entries are sorted. That is asymptotically attractive and practically wrong here. With at most 32 entries per node, binary search pays for unpredictable midpoint branches and worse locality. Linear scan is more predictable, walks memory contiguously, and matches the practical Atmos shape.

After switching lookup to an Atmos-style ordered walk, Zat's selected lookup
path moved ahead of Atmos in the apples-to-apples bench while keeping the same
root bytes. That walk does not use the key height to decide when to stop. It
compares the target key against entries in order, chooses `left` or the
previous entry's `right` child, and loads that selected child on the lazy path.

Zat lookup now keeps:

- nullable `*Node` child pointers
- unloaded stubs represented as nodes with only a CID
- slice-shaped CIDs and keys
- one representation that supports loaded, lazy, partial, and authoring use cases
- linear scan for lookup, binary lower-bound for mutation positioning

The old factor-of-two story was mostly scalar comparison, tagged child edges, and then the final "smart for no reason" binary lookup. Once lookup became a dumb contiguous scan, the remaining constants favored Zat.

## diagnostic lookup attribution

This is intentionally separate from the apples-to-apples benchmark. `just diag-mst-lookup` measures local components that are useful for diagnosis but should not be mixed into the publishable result table.

Latest diagnostic run, median ns/op over 5M lookups/pass:

| implementation | plan loop | direct CID | height only | selected lookup | normal lookup |
|---|---:|---:|---:|---:|---:|
| Zat | 0.69 | 1.10 | 16.06 | 135.78 (`getWithHeight`) | 157.73 (`get`) |
| Atmos | 0.71 | 3.60 | 38.75 | 181.46 (`Get`) | 181.46 (`Get`) |

The next diagnostic row tested the obvious college-math suspicion: Zat was using binary lower-bound for lookup while Atmos scans node entries linearly. MST nodes are tiny, so the asymptotic win was losing to branch prediction and cache locality. Switching Zat lookup to linear scan moved `getWithHeight` from the ~213-235 ns/op band to 135.78 ns/op. Atmos's `Get` in the same diagnostic run was 181.46 ns/op.

So yes: we were choosing to be smart for no reason. Binary search still makes sense for insert/split positioning, but lookup wants the dumb contiguous scan.

## next things to test

- check whether `getWithHeight` fully inlines through the benchmark when called from another package
- compare recursive lookup vs iterative lookup to reduce call overhead
- check node/entry field layout again after removing `ChildRef`

The likely direction is not "make Zig act like Go." It is to keep giving the hot path the same simple problem Atmos gives Go: pointer children, fast key compare, small-node linear scan, and fewer representation states in the inner loop.

One empirical note from the final cleanup: adding a per-entry key ownership bit made borrowed keys safer in the abstract but fattened the hot `Entry` layout and immediately showed up in lookup. The better match for this MST is arena/lifetime ownership: copied keys live with the tree, borrowed keys must outlive the tree, and delete removes logical entries without trying to reclaim per-key storage.

The last lookup cleanup removed the remaining height/layer branch from lookup
itself. That leaves height where the MST semantics need it, namely insertion,
deletion, splitting, and normalization. Plain lookup now matches Atmos: walk
the ordered tree by key and load child nodes only when that child is the chosen
path.

## missing middle

The first downstream adoption pass found the expected gap: ZDS was still doing
MST work by reaching through Zat internals. It serialized `Node` values directly,
walked `node.left` and `entry.right`, and knew about the old `ChildRef` union.
That was a useful alarm bell. If the Atmos-shaped internal representation is
allowed to change, consumers need a stable layer that names the actual jobs:

- collect MST DAG-CBOR blocks for a commit CAR
- walk repo records in MST key order

Zat now exposes those as `Mst.collectBlocks` and `Mst.walk`. `collectBlocks`
emits the loaded tree surface and intentionally skips clean unresolved stubs,
matching the old ZDS commit-CAR behavior where existing blocks stay in repo
storage instead of being re-exported every write. `walk` resolves lazy nodes
when a block reader is available and returns `PartialTree` if a consumer asks
to walk through an unresolved stub.

ZDS is the first proof consumer: record writes now call `tree.collectBlocks`,
and repo import now calls `tree.walk` instead of traversing MST internals. That
keeps the new MST machinery exercised by a real service without preserving the
old public internals by accident.

## release checkpoint

The intended patch release line is `0.3.5`; the package is still stamped
`0.3.4` until we decide ZDS has soaked long enough. The ZDS deployment proof is
explicitly tied to Zat commit
`485f1d485a9b8e7b703e8627a6b6a8c3e3c36a0e`, not to a floating branch. ZDS main
commit `8d1a8182dace` pins that exact commit and exercises both new public MST
APIs in production paths.

`zig zen` was part of the release-prep pass. The relevant bits for this change:

- "Communicate intent precisely." The release notes should say this is an
  internal representation change plus additive public API, not a consumer
  rewrite requirement.
- "Edge cases matter." `collectBlocks` deliberately skips clean unresolved
  stubs because commit CARs only need newly materialized MST blocks.
- "Avoid local maximums." The lookup win came from deleting clever binary
  search on tiny nodes, not from making the code more sophisticated.
- "Together we serve the users." ZDS is the real-world proof consumer before
  tagging the library release.
