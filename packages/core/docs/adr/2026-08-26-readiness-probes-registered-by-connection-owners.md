# ADR 2026-08-26 — Readiness probes are registered by whoever opens the connection

## Status

Accepted (2026-08-26). Introduces `BuilderContext.readiness`, the
boot-planner-owned `readinessRegistrar` bootstrap slot,
`AppHandle.readinessProbes`, and `routes/Readiness.mts`.

## Context

The provider shipped one health surface: a static `200` at `/_healthcheck`
that touches nothing. In the deployable defaults Redis is load-bearing for
sessions, authorization codes, and refresh-token families, so a Redis
partition left every login and token flow failing while the orchestrator and
load balancer went on calling the pod healthy. Nothing restarted, nothing
paged, and traffic kept landing on a dead IdP.

Adding a readiness endpoint is easy. Deciding *who can answer it* is the part
that constrained the design.

The obvious shape — let the composition root ping the clients it wired — does
not work in this codebase, for two independent reasons:

1. **The typed clients have no `ping`.** `makeIoredisClients()` derives nine
   narrow per-purpose surfaces from one connection: `{ set, pttl, del }`,
   `{ zadd, zrange, zrem }`, and so on. Narrowness is the point — it keeps the
   Redis command surface each adapter may use explicit and reviewable — and a
   liveness command belongs to none of them.

2. **Some connections never escape their builder.** The session store's
   node-redis client is created inside the `"redis"` adapter builder and
   wrapped; what the builder returns is a connect-redis `RedisStore`, not a
   connection. It is not reachable from `handle.components` at all.

So the only code holding a reference to a connection is the builder that
opened it — which is already true of *cleanup*, and is why
`BuilderContext.lifecycle` exists.

## Decision

**A builder that opens a connection owns its probe, exactly as it owns its
cleanup.**

`BuilderContext` gains an optional `readiness` registrar beside `lifecycle`:

```ts
ctx.lifecycle?.register(async () => { await client.quit(); });
ctx.readiness?.register({ name: "redis", check: () => client.ping() });
```

It is fed by a boot-planner-owned `readinessRegistrar` bootstrap component,
pre-seeded in `createApp` the same way `lifecycleRegistrar` is, and reserved in
`SYNTHETIC_COMPONENT_KEYS` against consumer override. The reservation is not
ceremony: a second registrar supplied by a consumer would collect probes the
planner never reads, and `/readyz` would answer `ready` with nothing actually
probed — a failure that looks exactly like success.

Collected probes surface on `AppHandle.readinessProbes`. The composition root
mounts `createReadinessRouter` on the **host app, ahead of the composed auth
router**, so readiness keeps answering while the auth pipeline is degraded —
which is the only time it has anything to say.

### Consequences that follow from the shape

- **A deployment with no probes is ready.** Absence of a wired dependency is
  not evidence of a broken one; a memory-only composition has nothing to be
  unready for.
- **One probe per connection, not per consumed slot.** Six adapters drawing on
  one shared ioredis socket produce one `redis` probe, because registration
  happens where the socket is constructed.
- **Probes run concurrently under a per-probe deadline.** A partitioned Redis
  does not refuse the connection — it accepts the command and never answers —
  so without a deadline the endpoint inherits that silence and hangs, which an
  orchestrator reads as a slow replica rather than an unready one. The deadline
  is `http.readinessTimeoutMs`, validated as a positive integer because HOCON
  substitutes a blank environment variable as `""`, which coerces to `0` and
  would fail every probe against a healthy backend.
- **`readinessProbes` is a snapshot, and that is sound today.** Every provider
  factory runs in stage 3 and every contribution factory in stage 4, both
  before `assembleApp` in stage 6. A future lazily-materialized component would
  break this; that is the invariant to re-check before introducing one.

## Liveness stays separate, and stays static

`/_healthcheck` is unchanged and remains a static `200`. Restarting a process
does not reconnect Redis, so a partition must not read as "kill this pod":
wiring liveness to a dependency probe turns one backend outage into a
cluster-wide restart loop that reconnects nothing and adds cold starts to an
incident. Losing Redis is a reason to stop *routing* to a replica, not to kill
it.

The same reasoning governs the container image. Docker exposes exactly one
health signal, and on Swarm and ECS an unhealthy container is stopped and
replaced — so the shipped `HEALTHCHECK` probes `/_healthcheck`. `/readyz` is
the load-balancer and Kubernetes `readinessProbe` target.

## Rejected alternatives

- **Expose the raw connections as components.** Would widen every adapter's
  public surface to the full driver API purely to enable a `ping`, and undo the
  narrowing that makes the Redis command surface auditable.
- **Give each adapter interface a `ping()`.** Pushes a liveness concern into
  nine unrelated storage contracts, and every custom adapter implementer then
  has to write one.
- **Probe from the route by dialing Redis itself.** The route would need the
  connection config, would open a second connection per scrape, and would
  report on a connection the application is not actually using.

## Response body

`/readyz` reports `{ name, ok, durationMs }` per probe and omits the failure
message by default. The endpoint is unauthenticated by construction — an
orchestrator has no credentials — and driver errors carry internal topology
(`connect ECONNREFUSED 10.0.3.14:6379`). The failing dependency's *name* is
what a probe consumer acts on; the message goes to the log, where the reader
has already authenticated. `includeErrorDetail: true` opts back in for
deployments where the endpoint is reachable only from inside.
