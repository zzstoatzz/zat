# post shaped files

Dan Abramov spent part of June 30 trying to explain why atproto still feels worth arguing for. the good posts were not about Bluesky feature work. they were about the shape under it. he wrote that he was "just putting post shaped files into my pds," that the app can be forked "together with all of its users and data," and that the topology makes other things changeable later. later in the thread he tried a shorter handle: atproto as a "model layer" for the web, "web for json." ([one](https://bsky.app/profile/danabra.mov/post/3mphos3a2d22o), [two](https://bsky.app/profile/danabra.mov/post/3mphq66fkec2o), [three](https://bsky.app/profile/danabra.mov/post/3mphqcfwres2o), [four](https://bsky.app/profile/danabra.mov/post/3mpjcy44xoc2z))

I keep coming back to that when working on zat.

most atproto projects should never care about CAR block boundaries or secp256k1 high-S signatures. still, if this record web is going to grow past Bluesky-the-app, people need small pieces of infrastructure they can actually run: relays, PDSs, indexers, backfill workers, verifiers, exporters, search systems, weird appviews, boring CLIs. those programs live below product taste. they move bytes, check signatures, walk repos, and decide whether a piece of network state deserves to be trusted.

zat lives there.

![records first, apps after](https://zat.dev/docs/devlog/img/record-projections.svg)

## rss was right

Paul Frazee put the same idea another way: RSS was an underpowered database replication protocol. Google Open Source replied with the joke query, `SELECT <field1 path>, <field2 path> FROM <rss uri>?`, and Paul answered with the atproto database he has been playing with:

```js
atdb.query({
  from: {collection: "app.bsky.feed.post"},
  where: [{eq: {field: "/lang", value: "en"}}],
  order: {by: "@indexedAt", dir: "desc"},
  limit: 50
})
```

the joke works because RSS really did have part of the shape: publish something at a URL, let other programs fetch and transform it, stop asking one website to be every interface at once. atproto keeps that instinct and adds the parts RSS never had: portable identity, signed repositories, typed record collections, content-addressed blocks, a firehose, and a repo format that can express mutations instead of only snapshots.

Dan's gloss was less SQL and more files: the old Web 2.0 dream of services talking to each other broke because every service had to expose an API and any service could break the chain. "here there's no API because we just aggregate from files. RSS was right." ([post](https://bsky.app/profile/danabra.mov/post/3mpjdarnoc22z))

I would not take that line literally. there are APIs all over atproto. XRPC exists. relays and PDSs have behavior, policy, rate limits, bugs, and bills. the useful point is where the durable state lives. a post is also a record in a repo, under a DID, with a key, a collection, a CID, and a signature chain.

apps can project that state differently. one app can care about replies. another can care about bookmarks. another can index `site.standard.document` records. another can rebuild a feed from records whose lexicons Bluesky does not understand. people can disagree about ranking, moderation, logged-out discovery, or blocking semantics without needing the underlying data to move first.

I am excited about that.

## why another sdk

there are already atproto SDKs. the TypeScript packages are the reference surface for app developers. Indigo and Atmos prove a lot of production infrastructure in Go. Python is good glue. Rust has serious pieces for people already in that ecosystem.

zat is aimed lower in the stack:

- parse DIDs, handles, NSIDs, TIDs, record keys, and AT URIs
- encode and decode DAG-CBOR
- read and write CARs
- verify CID hashes and commit signatures
- load and walk Merkle Search Trees
- consume Jetstream and raw firehose events
- resolve identity without turning untrusted handles into SSRF
- make checked XRPC calls where errors keep their protocol envelope
- help programs author records, commits, and firehose frames

some of that is user-facing. most of it is plumbing. I do not want every downstream program to re-learn the same unpleasant facts about canonical CBOR, repo completeness, rate-limit headers, DID documents, websocket frames, or high-S JOSE signatures.

the current consumers are the reason this has not stayed theoretical.

[`zlay`](https://tangled.org/zzstoatzz.io/zlay) uses zat's bytes-and-trust layer to run relay-shaped work: decode event streams, track hosts, validate commits, and fan out frames. [`zds`](https://tangled.org/zat.dev/zds) uses zat to build a real PDS: write records, update MSTs, sign commits, emit `subscribeRepos`, import repos, and handle OAuth-adjacent protocol work. [`pub-search`](https://tangled.org/zzstoatzz.io/pub-search) grew out of leaflet search and uses the network as a corpus rather than treating Bluesky as the product boundary. [`atproto-bench`](https://tangled.org/zzstoatzz.io/atproto-bench) keeps us honest by making implementation claims measurable. the docs publisher in this repo is smaller, but I still like it: zat publishes its own docs as `site.standard.document` records, through zat.

different programs, same annoying substrate.

![zat as substrate](https://zat.dev/docs/devlog/img/zat-substrate.svg)

## why zig

Zig is a good fit for parsers, verifiers, stream processors, and little deployable tools.

atproto has a lot of work where allocation shape matters. a firehose frame is DAG-CBOR plus an embedded CAR. repo verification walks content-addressed blocks and MST nodes. search and backfill systems may read huge numbers of records whose schema they mostly do not care about. a PDS needs to author the same structures without smuggling in a runtime that dominates the service.

Zig lets zat keep those paths close to the bytes. CBOR strings and byte strings can be slices into the input. CIDs can be small references until a caller asks for fields. arena allocation can match frame and repo lifetimes. the same package can expose a library and also build tiny tools: smoke tests, decode benchmarks, a docs publisher. shipping one binary is handy when the programs are infrastructure-shaped.

as of this writing, zat has one runtime dependency, [`websocket.zig`](https://tangled.org/zzstoatzz.io/websocket.zig), and a lazy test dependency on the official [`atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests) fixtures. the rest is stdlib and repo-local code. I like that for boring reasons. when an MST node with duplicate keys is accepted or rejected, I want the answer to be in a file we can read.

the Zig project also has a pretty unusual rule for its own work spaces: no LLM-generated code or prose, no LLM editing, no LLM-assisted bug finding, no LLM brainstorming brought back into project discussion. the page says exactly which spaces it governs: Zig's Codeberg organization, IRC, and project Zulip. ([policy](https://ziglang.org/code-of-conduct/#strict-no-llm-no-ai-policy))

that does not describe every Zig project. people build Zig applications with all sorts of workflows. Ghostty, Mitchell Hashimoto's terminal emulator, is a large Zig app, and Mitchell has been open about using AI heavily in application work. ([Ghostty](https://ghostty.org/), [Mitchell Hashimoto](https://mitchellh.com/))

I do not want to launder that into a cheap point about virtue. I am using AI while writing this devlog. the thing I admire in Zig is more practical: small surfaces, explicit allocation, explicit errors, dependency skepticism, and a culture that still expects the person changing the system to understand it. Zig has plenty of churn. the 0.16 I/O migration hit zat directly. async has taken more than one pass. some people reasonably get tired of that.

still, for this library, those tradeoffs are acceptable. I want to know what allocates. I want network parsing code that can be read without spelunking through ten packages. I want tests that pull in the official corpus, not a runtime dependency that changes protocol behavior under us. I want binaries that can go run as small tools.

## fast is part of the deal

performance is practical here. if reading and verifying the network requires a large team and expensive managed infrastructure, the record web drifts back toward platform gravity. fewer people build indexers. fewer people keep backups. fewer people run alternate appviews. fewer experiments survive contact with the firehose.

so zat spends time on boring speed. CBOR values got smaller. CID parsing became lazy. CAR lookup became O(1). secp256k1 verification got its own optimized path. MST lookup copied the plain Atmos shape after benchmarks showed our clever version was worse. full repo verification learned to reject incomplete CARs that parsed cleanly. XRPC stopped retrying non-idempotent POSTs on 5xx. handle DNS resolution stopped accepting ambiguous `did=` TXT records.

that list sounds like release notes because it is. the through-line is simple enough: a replicated record network needs cheap readers that distrust what they read.

Jim Calabro's [`Atmos`](https://github.com/jcalabro/atmos) has been useful for exactly that reason. it comes from production PDS work, so its refusals are interesting. when Atmos rejects non-canonical MST nodes, incomplete repo CARs, ambiguous DNS identity records, or unsafe POST retries, that is not pedantry. that is a production implementation finding the weak boards.

zat should learn from that.

## what I want from this

I want atproto projects to get to the weird part faster.

if someone wants to make a search engine for long-form records, they should not start by writing a CAR parser. if someone wants to run a tiny PDS, they should not rediscover repo signing and MST block collection from scratch. if someone wants to benchmark a relay path, they should not first spend a week finding out that a syntactically valid repo export can be missing blocks. if someone wants to publish a new record type, they should not need Bluesky-the-app to understand it before the network can carry it.

the bet is that a small, fast, fairly complete Zig implementation makes more experiments possible at the layer where atproto is most interesting.

posts are files now, sort of. files with DIDs, CIDs, collections, signatures, lexicons, and awkward edge cases. that is enough of a new primitive to be worth building good tools around.
