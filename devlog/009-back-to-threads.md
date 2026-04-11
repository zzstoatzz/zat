# back to threads

the last devlog ended with: "the relay runs on Evented with ReleaseFast in production, processes the full firehose at ~2,800 PDS connections, and has been stable since the websocket fix." that was april 5. by april 9, we'd shipped three wrong fixes for a problem we couldn't diagnose, rolled back to a week-old build, and ultimately abandoned the Evented backend entirely. the relay is back on Io.Threaded — one OS thread per PDS, ~2,800 threads, the same model as 0.15. this is what happened.

## the slow bleed

after the websocket CRLF fix and the Evented re-enable on april 5, relay-eval coverage started dropping. not dramatically — from 99% to roughly 85-90%. there was always a plausible local explanation. the host_authority resolver pool might be poisoned. the consumer buffer might be too small. the reconnect cron might be disrupting things.

we chased each one. none of them were wrong, exactly — they were all real issues. but none of them explained the gap.

## april 8-9: the acute outage

two things happened at once:

1. external HTTP stopped responding after 10-40 minutes of uptime
2. host_authority rejection spiked to 88-99%

the HTTP hang was the worse problem. `/_health` would return 200 for a while, then start timing out. internal metrics kept ticking — `frames_received_total` climbed, workers were active, CPU was low (~0.26 cores), all threads sleeping. but external consumers couldn't complete a WebSocket handshake. k8s marked the pod Not Ready. relay-eval reported 0% coverage.

we had five commits in the suspect window between the last good build (`b91382b`) and the broken state:

```
1eec324  fix UAF: dupe FrameWork.hostname per submit instead of borrowing
31825b2  subscriber: extract prepareFrameWork + add UAF regression test
168d9f1  bump websocket.zig + zat: fix requestCrawl POST hang
3dc21b9  fix gcLoop: silently exited after one tick
fbdffbe  mark DB success on did_cache hits
```

we shipped three hypotheses in one day:

1. **"zig 0.16 `std.http.Client` stale keep-alive handling"** — falsified by a standalone reproduction that worked fine.
2. **"broadcaster writeLoop scheduler starvation"** — the operator caught this one. the proposed fix (move writeLoop to `pool_io`) would re-enter the cross-Io crash class from devlog 008. do not call Threaded Io primitives from Evented fibers.
3. **"gcLoop + malloc_trim stalls every 10 minutes"** — disabled `malloc_trim`, bumped gc interval from 10 minutes to 1 hour. the symptom returned at 35 minutes instead of 10. delayed, not fixed.

the situation report we wrote at this point opened with: "we need help getting to a correct fourth hypothesis rather than shipping a fourth wrong one."

## the rollback

the operator rolled back to `b91382b`. the measurements, ten minutes apart on the same cluster:

| signal | 4f3d1d4 (broken) | b91382b (rollback) |
|---|---|---|
| external /_health | 503 (ingress, pod Not Ready) | 200 in 0.29s |
| 15s websocket consumer | 6 frames in 170s (0.035 fps) | 5,896 frames (395 fps) |
| delivery ratio | ~5% of received frames reaching broadcast | 99.4% (6,801/6,843 in 15s) |
| host_authority reject rate | 88% | 1.3% |

same code paths, same PDS pool, same cluster. b91382b was the april 6 build — pre-outage, still on Evented. it worked. every build after it didn't.

## the reframe

a reviewer read the full git history and the operator's measurements and made one observation: the coverage degradation didn't start with the april 8 commits. it started with `9cc1ba3` — the 0.16 migration itself. the later bugs were real, but they were layered on top of an already-degraded Evented baseline.

the reviewer recommended Tracy-based tracing to diagnose fiber scheduling inside the Evented runtime. trace cold-start behavior, steady-state with a consumer attached, find where fibers are monopolizing time or where yields are missing.

we went a different direction.

## the question

is the Evented model defensible?

the full ledger, as of april 9:

- 9 crash classes in 8 days, 3 of them silent heap corruption
- a custom uring networking patch against an experimental backend where all 6 networking operations were stubbed upstream
- forced into ReleaseFast by a codegen bug in fiber context-switching (the same bug that hid the websocket CRLF crash in devlog 008)
- a persistent ~10-15% coverage degradation nobody could trace
- the zig team's [own position](https://ziglang.org/devlog/2026/#2026-02-13): the Evented backends "should be considered **experimental** because there is important followup work to be done before they can be used reliably and robustly"

the relay ran on 0.15 from late february through early april — about five weeks — at 2,800 threads and 99%+ coverage. the benefit of Evented was thread count: ~35 instead of ~2,800. the cost was everything else.

## the fix

```zig
const Backend = Io.Threaded;  // was Io.Evented
```

this works because the relay was already written against the [`Io`](https://ziglang.org/documentation/master/std/#std.Io) abstraction, not against `Io.Evented` directly. [`io.concurrent()`](https://ziglang.org/documentation/master/std/#std.Io.concurrent) — which the stdlib describes as calling a function "such that the return value is not guaranteed to be available until `await` is called, allowing the caller to progress" — spawns [fibers](https://ziglang.org/devlog/2026/#2026-02-13) under Evented and OS threads under Threaded. `Io.Mutex`, `Io.Condition`, `Io.Future` — all backend-agnostic. the same code runs on both, which is the promise 0.16 made and actually delivered on.

one line. tests pass, formatting clean, production build succeeds. and because the fiber context-switch GPF was Evented-specific, we could switch back to `ReleaseSafe` — safety checks in production for the first time since the migration.

## what ReleaseSafe found in 80 minutes

```
thread 952 panic: reached unreachable code
/lib/std/c.zig:77:26: in setsockopt
/websocket/src/server/server.zig:647:33: in readLoop
```

a pre-existing bug in the consumer drop path. when a downstream consumer falls behind, the broadcaster calls `dropSlowConsumer`, which closes the socket to unblock the consumer's read loop. but the websocket server's `readLoop` runs on a different thread and was about to call `setsockopt` on the same fd. `setsockopt` gets `EBADF`, zig's stdlib wrapper hits `unreachable`, ReleaseSafe turns that into a panic with a stack trace.

under ReleaseFast, `unreachable` is undefined behavior. this bug existed on every prior build — every Evented deploy, every 0.15 deploy. it manifested as... nothing, usually. occasionally, whatever the compiler feels like.

the fix: move socket close ownership from the broadcast thread to the consumer's writeLoop thread. `dropSlowConsumer` signals the consumer to stop (`alive.store(false, .release)`). the writeLoop checks `alive`, exits its loop, drains remaining frames, and closes the connection itself. no race.

we also bumped the consumer ring buffer from 8,192 to 65,536 entries — ~3 minutes of headroom at current ingest rates instead of ~24 seconds. fewer ConsumerTooSlow kicks means the close path fires less often.

the pattern from devlog 008 repeats: ReleaseSafe finds the bug on the first occurrence with a stack trace. ReleaseFast hides it until something unrelated goes wrong and you blame the wrong thing.

## the numbers

`4735725` (Threaded + ReleaseSafe + consumer fix), 16 hours uptime:

| signal | value | vs Evented |
|---|---|---|
| uptime | 16h, 0 restarts | crashed at 10-80 min |
| health | 200 in 0.31s | hung after 10-40 min |
| delivery | 460 fps peak | 0 fps at failure |
| persist_order_spins | 38.6k/s | 33M/s (850x higher) |
| broadcast_queue_depth_hwm | 36 | 8,191 |
| RSS | 2.09 GiB, flat | comparable |
| threads | ~2,700 | ~35 |

the persist_order_spins metric tells the real story. this is a spinlock counter on the frame persistence ordering mutex — same mutex, same code, same workload. under Evented, 33 million spins per second. under Threaded, 38 thousand. the Evented scheduler was creating contention that didn't exist under normal OS thread scheduling.

## what this means for the Io abstraction

the good news: `std.Io`'s abstraction held. one line changed the backend, the relay kept running, every `io.concurrent()` call site worked. the dual-Io architecture we built (Evented for network orchestration, Threaded for blocking work) was unnecessary but harmless — under all-Threaded, `pool_io` and the `DbRequestQueue` bridge are redundant but functional. we can clean them up later without urgency.

the bad news: the backend-agnostic promise has a sharp edge. `Io.Mutex.lock(io)` compiles and type-checks regardless of whether `io` matches the calling thread's execution context. the cross-Io crash class — the central lesson of devlog 008 — only manifests at runtime, under load, as memory corruption. the abstraction is correct in the sense that the same code runs on both backends. it's dangerous in the sense that mixing backends within a single process produces no compile error and corrupts your heap.

for zat: the library doesn't care. `Io` is threaded through as a parameter. callers pick the backend. the streaming client's `subscribe(handler)` works identically on both backends.

for zlay: we're on Threaded for the foreseeable future. the Evented code paths, the uring networking patch, and the cross-Io segregation rules stay in the tree but inert. we'll revisit when zig's Evented backend is no longer experimental and when the ReleaseSafe GPF is fixed upstream.

for anyone else considering `Io.Evented` in production: the Evented backends are ["based on userspace stack switching, sometimes called 'fibers', 'stackful coroutines', or 'green threads'"](https://ziglang.org/devlog/2026/#2026-02-13). they can work. they did work, for stretches. but the support surface is thin — you'll need to patch the networking layer, work around DNS, build cross-Io bridges for any Threaded dependency, and run ReleaseFast (hiding real bugs). the thread-count savings are real. whether they're worth the cost depends on how much time you have to spend on runtime issues that aren't your application logic.

zat is v0.3.0-alpha. no API changes from this — the `Io` parameter is already the interface.
