# composition — every workspace package, booted together

Last updated: 2026-09-25

The contracts that exist only when all of this repository's modules are
composed: the standalone template's composition with every package it does not
depend on added to it, booted through core's `createApp` and held to one
discovery document, each module's routes and body rules, its store outages,
and replica safety on real Redis.

## Responsibility

**Role.** A safety net for defects no package's own suite can see. Each package
boots alone or against stand-ins, so a discovery document made invalid by a
neighbour, a disabled grant still advertised, one module's parser setting
another's body limit, or a memory store booting under `deployment.mode =
"multi"` went unnoticed until the modules met in a deployment.

**Owns.** The full-set suite in [`src/__tests__/`](src/__tests__/):

- [`full-set.fixture.mts`](src/__tests__/full-set.fixture.mts) — the template's
  composition (its fixture,
  [`all-modules-composition.fixture.mts`](../../templates/standalone/src/__tests__/all-modules-composition.fixture.mts),
  imported whole) with the device grant, DPoP, mTLS, token exchange, WebAuthn,
  and the Apple and GitHub federations added as a deployment adds them, plus
  the small modules a deployment writes itself (config bridges, a grant
  policy). Its header says what is real and what is substituted.
- [`full-set.test.mts`](src/__tests__/full-set.test.mts) — one replica, memory
  stores: the added modules' boot, discovery and its switches, their flows,
  body limits in two mount orders, and one store outage per added module.
- [`full-set.redis.test.mts`](src/__tests__/full-set.redis.test.mts) — every
  shared store on real Redis under `deployment.mode = "multi"`: nothing
  declares replica-unsafe state, each added memory store is refused by name,
  and two replicas on one database finish each other's flows.

**Does not own.** The template's own composition, which its suite pins and
ships in every scaffold
([`all-modules-composition.test.mts`](../../templates/standalone/src/__tests__/all-modules-composition.test.mts)
and its `.multi` sibling). This suite does not repeat those contracts; it
re-checks one only where the added modules can change the answer.

**Why a separate workspace.** Booting every package needs a dependency on
every package. The template depends only on what it ships, and a scaffold
would carry anything added to it, so the full set lives in a private workspace
that is never published and has no build output. A drift check fails when a
package is added to `packages/` without being added here.

## Invariants

- Every `packages/*` workspace is a devDependency of this one
  ([`full-set.test.mts`](src/__tests__/full-set.test.mts), "what the full set
  covers").
- A contract the full set breaks today is an `it.fails` whose entry names the
  defect; the fix that mends it turns the case red and turns it into a plain
  `it`.

## Running it

```sh
pnpm install
pnpm run build            # the packages resolve through their dist/
pnpm --filter @o3co/auth-provider-composition run test -- --maxWorkers=2
```

The Redis-backed file uses the Redis package's shared test container
([`redis-container.global.mts`](../../packages/redis/__tests__/support/redis-container.global.mts)),
so it needs a container runtime, as `packages/redis` does. CI runs the suite
in the `build-and-test` job's workspace test step.
