# the io migration

zig 0.16 replaced the networking and concurrency primitives. `std.net`, `std.Thread.Pool`, `std.Thread.Mutex` — all gone, replaced by `std.Io`. this is the story of migrating zat and zlay to the new system, the eight crashes that followed, and the rule we discovered that isn't documented anywhere.

## what changed in 0.16

`std.Io` is a backend-agnostic interface for all I/O and concurrency. two backends:

- **Threaded** — always available. `io.concurrent()` spawns OS threads.
- **Evented** — fiber-based. io_uring on linux, GCD on macOS, kqueue on BSD. `io.concurrent()` creates cheap userspace coroutines.

same code runs on both. you write against `Io`, pick the backend at init, and the scheduler does the rest. `io.async()` for CPU work (bounded pool, overflow runs inline). `io.concurrent()` for I/O tasks (unbounded under Threaded, fibers under Evented). `io.sleep()` is cancellation-aware. `Io.Mutex` integrates with the scheduler's futex.

the promise: write once, switch backends, get threads or fibers for free.

the catch: the scheduler integration means `Io.Mutex`, `Io.Condition`, and `io.sleep()` are not just synchronization primitives — they're scheduler entry points. call them from the wrong execution context and the scheduler dereferences state that doesn't exist.

## the library migration

zat's migration was straightforward. every networking type gained `io: std.Io` as its first init parameter:

```zig
// 0.15
var resolver = zat.HandleResolver.init(allocator);
var client = zat.XrpcClient.init(allocator, "https://bsky.social");

// 0.16
var resolver = zat.HandleResolver.init(io, allocator);
var client = zat.XrpcClient.init(io, allocator, "https://bsky.social");
```

the streaming clients got a bigger change. `connect()` + `next()` loops became `subscribe(handler)`:

```zig
// 0.15
var client = zat.JetstreamClient.init(allocator, .{...});
try client.connect();
while (try client.next()) |event| { ... }

// 0.16
var client = zat.JetstreamClient.init(io, allocator, .{...});
try client.subscribe(&handler);
```

`subscribe` blocks forever — reconnects with exponential backoff, rotates hosts, calls `handler.onEvent()` for each frame. the handler is `anytype` with optional `onError` and `onConnect` callbacks. cancellation propagates through `Io.Cancelable`.

internally: `std.crypto.random` → `io.random()`. `std.posix.nanosleep` → `io.sleep()`. `libc.gettimeofday` → `Io.Timestamp`. websocket.zig took `io` in its client and server init.

zat and websocket.zig migrated in lockstep over a day. 203 tests pass. the library side was clean.

then we deployed the relay.

## the relay migration

[zlay](https://tangled.sh/zzstoatzz.io/zlay) is an AT Protocol relay — ~8,400 lines of zig, ~2,750 PDS subscribers, WebSocket fan-out to downstream consumers. it was the heaviest consumer of the 0.15 API surface. migrating it to 0.16 compiled on the first try.

eight crashes followed.

## crash 1: SIGSEGV on startup

the build auto-selected `Io.Evented` (io_uring available on linux). the relay printed "io backend: Evented" and immediately segfaulted. exit code 139.

the cause: zlay's frame processing pool spawns plain `std.Thread` workers. under Evented, any `Io.Mutex` operation calls into the Uring scheduler, which accesses `Thread.current()` — a threadlocal that's only initialized on Uring-managed fibers. plain threads have it set to `null`. in ReleaseFast, `self.?` on null gives a NULL pointer, not a panic. the mutex dereferences a field at an offset from NULL.

fix: force `Backend = Io.Threaded` in main.zig. we'd come back to Evented later.

## crash 2: pool acquire panic

30-60 seconds into processing, `unreachable` panic in `Io.Event.waitTimeout`. stack trace: `event_log.zig uidForDid → pg pool.zig acquire → Io.zig`.

pg.zig (the postgres driver) used `Io.Event` as a connection-available signal. `Io.Event.reset()` has an invariant in the stdlib: it assumes no pending call to `wait`. with 16 frame workers contending for 5 database connections, `set()` wakes all waiters, one calls `reset()`, others hit `unreachable`.

fix (in pg.zig fork): replaced `Io.Event` with a monotonic `u32` futex counter. `release()` increments + `futexWake(1)`. `acquire()` snapshots counter + `futexWaitTimeout()` with snapshot. no `reset()`, no single-waiter constraint. also bumped pool size to 20 (was hardcoded 5).

## crash 3: GPF in websocket write

30-60 seconds in, general protection fault in `memcpy → Writer.zig → websocket client.zig writeFrame`.

the websocket `Client` had no write serialization. three concurrent writers:

1. `pingLoop` — `writeFrame(.ping, ...)` every 30s
2. `readLoop` auto-pong — `writeFrame(.pong, ...)` on upstream ping
3. close path — `writeFrame(.close, ...)` on failure

interleaved frame headers corrupt the shared TLS writer state. the server-side `Conn` already had a write lock; the client was missing it.

fix (in websocket.zig fork): added `_write_lock: Io.Mutex` to `Client`, acquired around both `writeAll` calls in `writeFrame()`.

## crash 4: use-after-free in ping loop

same GPF stack trace as crash 3, but after the write lock fix. every ~60-90 seconds.

`pingLoop` runs as an `io.concurrent` task and sleeps in 1-second increments. when the connection dies, `readLoop` returns and the defer chain runs: `ping_future.cancel(io)` then `client.deinit()`. but `pingLoop` had `io.sleep(...) catch {}` — swallowing all errors, including `error.Canceled`. so `cancel()` couldn't stop it. `deinit()` freed the client's buffers while `pingLoop` was still running.

fix: `catch {}` → `catch return`. makes the ping loop cancellation-cooperative. added `isClosed()` guard before `writeFrame` as defense-in-depth.

## fix 5: HTTP fallback for health probes

not a crash — a deployment failure. k8s health probes on port 3000 got 400 responses. the websocket server's handshake handler sent 400 on any non-upgrade HTTP request.

fix (in websocket.zig fork): intercept `MissingHeaders`, `InvalidConnection`, `InvalidUpgrade` errors from the handshake parser. for these, re-parse as plain HTTP and dispatch to `Handler.httpFallback()` if it exists (comptime check). k8s probes hit `/_health`, get a 200.

## crash 6: SIGSEGV in the resyncer

after switching back to `Io.Evented`: SIGSEGV at startup. `dmesg` showed crash addresses in `Uring.zig` at `Thread` struct field offsets from NULL — the same signature as crash 1 but in a different code path.

`addr2line` traced it to the resyncer thread. it was spawned via `io.concurrent()`, which under Evented creates a fiber. but the resync work called `DiskPersist` methods that lock `self.mutex` with `pool_io` (Threaded). Threaded futex from an Evented fiber → NULL `Thread.current()` → SIGSEGV.

this was the moment the pattern became clear: **you cannot call Threaded Io primitives from Evented fibers, or vice versa.** the futex dispatch goes through the scheduler, and the scheduler has thread-local state that only exists in its own managed execution context.

fix: run the resyncer on a plain `std.Thread` with `pool_io`. the thread checks a `shutdown_flag` atomic to exit.

## fix 7: startup connection storm

~2,750 simultaneous WebSocket connects at startup starved the io_uring submission queue. event loop couldn't process completions fast enough.

fix: throttle startup — connect in batches, give the ring time to drain between waves.

## crash 8: cross-Io heap corruption

the relay ran for hours, then SIGSEGV. zero downstream consumers connected. `dmesg` showed crash addresses in `Uring.zig` at `Thread` struct field offsets from NULL — same signature as crashes 1 and 6, but in steady-state operation.

two cross-Io violations were active:

1. **GC loop** — ran as an Evented fiber (`io.concurrent(gcLoop, ...)`), but called `dp.gc()` which locks a mutex with `pool_io` (Threaded) and queries postgres through `pg.Pool` (also Threaded). Threaded futex from Evented fiber → NULL deref.

2. **health check endpoints** — `/_readyz`, `/_health`, `/xrpc/_health` on the metrics and API servers. executed `db.exec("SELECT 1")` through the Threaded `pg.Pool` from an Evented HTTP handler context. same violation.

fix: GC loop moved from `io.concurrent()` to `std.Thread.spawn()` with `pool_io`. health checks replaced with an atomic `last_db_success` timestamp — Threaded workers set it after successful queries, Evented handlers read it. no cross-Io boundary.

## the cross-Io rule

the central discovery from eight crashes across five days:

**`Io.Mutex`, `Io.Condition`, `io.sleep()`, and any library that uses them internally (pg.Pool, etc.) must be called from the same Io backend they were initialized with.**

the mechanism: these primitives dispatch through the Io backend's scheduler via futex. each backend has thread-local state — `Thread.current()` under Uring is a `threadlocal var self: ?*Thread = null`, only set inside `Uring.Thread.run()`. calling from outside that context dereferences NULL.

```
Evented fiber → Io.Mutex.lock(pool_io) → Threaded futex
    → Thread.current() → threadlocal is NULL
    → field access at offset from NULL → SIGSEGV
```

this isn't documented in the stdlib. the API compiles and type-checks — `Io.Mutex.lock` takes any `Io`. the crash only manifests at runtime when the calling thread's execution context doesn't match the Io's backend.

**safe cross-Io patterns:**
- raw atomics (`std.atomic.Value`, `fetchAdd`, CAS)
- `Io.Mutex.tryLock()` — non-blocking CAS, no futex
- MPSC ring buffers with atomic spinlocks
- atomic timestamps for health checks

**unsafe cross-Io patterns:**
- `Io.Mutex.lock()` / `lockUncancelable()` with wrong Io
- `Io.Condition.wait()` / `signal()` / `broadcast()`
- `io.sleep()` from wrong context
- any library that internally uses the above (pg.Pool, etc.)

## the fix: DbRequestQueue

~40 call sites across the relay needed database access from Evented fibers, but `pg.Pool` requires Threaded. the initial approach — a second pool on Evented Io — failed because `netLookup` is unimplemented in Uring. three deploy attempts, three rollbacks.

the solution: an MPSC ring buffer with typed request structs.

```zig
pub const DbRequest = struct {
    callback: *const fn(*DbRequest, *DiskPersist) void,
    done: std.atomic.Value(bool) = .{ .raw = false },
    err: ?anyerror = null,

    pub fn wait(self: *DbRequest) void {
        while (!self.done.load(.acquire)) {
            std.atomic.spinLoopHint();
        }
    }
};
```

callers define typed structs that embed `DbRequest` and use `@fieldParentPtr`:

```zig
const ListActiveHostsReq = struct {
    base: DbRequest = .{ .callback = &execute },
    allocator: Allocator,
    result: ?[]Host = null,

    fn execute(b: *DbRequest, dp: *DiskPersist) void {
        const self: *@This() = @fieldParentPtr("base", b);
        self.result = dp.listActiveHosts(self.allocator) catch |e| {
            b.err = e;
            return;
        };
    }
};
```

the queue itself: 4096 slots, CAS-based spinlock for producers (Evented fibers), 2 worker threads on `pool_io` (Threaded). workers call `req.callback(req, persist)` then `req.done.store(true, .release)`. fibers spin on `done` with `spinLoopHint()`. shutdown drain marks unprocessed requests as done with `error.ShuttingDown`.

no futex. no cross-Io boundary. the queue is pure atomics — safe from any execution context.

the final architecture:

```
Evented fibers              atomic boundary              Threaded workers
─────────────────────────── ─────────────────── ──────────────────────────
PDS subscribers                                 DbRequestQueue (2 workers)
downstream consumers         DbRequest.push()      → pg.Pool queries
broadcast loop               ──────────────→        → DiskPersist writes
API/admin handlers                                  → host ops
                              atomic timestamp
health checks ←──────────── last_db_success ←── set by workers after query

                             std.Thread.spawn()
                                                GC loop (pool_io)
                                                resyncer (pool_io)
                                                backfiller (pool_io)
```

## what this means for zat

the library held up. CBOR, CAR, commit parsing, verification, multibase — all chain correctly through the Io migration. the API change was mechanical: add `io` as first parameter, thread it through.

one bug surfaced at the relay level: `tooBig` omission from passthrough frames. the lexicon requires the field on `#commit` events. some PDSes omit it (it's deprecated, always false). zlay's passthrough re-encoding preserved the omission. downstream consumers with strict deserialization (no `#[serde(default)]`) rejected the frames. fix: inject `tooBig: false` when missing during resequencing.

the streaming client redesign — `subscribe(handler)` instead of `connect()` + `next()` — was the right call. the handler pattern gives the library control over reconnection, backoff, and host rotation. the caller implements `onEvent` and gets reliable delivery without managing connection lifecycle.

six patches were needed against the zig stdlib or its Uring backend for zlay to run on Evented. `netLookup` is still unimplemented. the cross-Io hazard is still undocumented. but the Io abstraction itself — write once, pick your scheduler — delivered on its promise. the same relay code runs on Threaded (production) and Evented (local development on macOS via GCD) without conditional compilation.

zat is v0.3.0. the Io parameter is the only breaking change.
