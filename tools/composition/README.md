# composition — every workspace package, booted together

Last updated: 2026-09-30

The contracts that exist only when all of this repository's modules are
composed: the standalone template's composition with every package it does not
depend on added to it, booted through core's `createApp` and held to one
discovery document, each module's routes and body rules, its store outages,
and replica safety on real Redis.

## Responsibility

**Role.** A safety net for defects no package's own suite can see. Each package
boots alone or against stand-ins, so a discovery document made invalid by a
neighbour, a disabled grant still advertised, one module's parser setting
another's body limit, or a memory store booting under `core.deployment.mode =
"multi"` went unnoticed until the modules met in a deployment.

**Owns.** The full set and the contracts checked on it
([`src/__tests__/`](src/__tests__/)):

- **What it boots.** The template's composition with every package the
  template does not depend on added the way a deployment adds them to that
  manifest — the device grant, DPoP, mTLS, token exchange, WebAuthn, the MFA
  package (its modules over the MFA stores, `mfa.mode = "optional"`, and
  `mfa` added to the template's `core.sessionRequirements.expected`), and the
  Apple and GitHub federations — plus the small modules
  a deployment writes itself (config bridges, a grant policy, a session-to-WebAuthn-subject
  bridge, and two session requirements — each with the completion route a
  requirement's module contributes, built on the session package's exported
  `establishSession` and `answerInterruption`), and a mail sender — core's
  recording one, handed to the tests as `mail`, since the template's SMTP
  sender's module provides none. The composition, the body and outage helpers and the outage runner
  are not copied: they are the template suite's, exported by its fixture,
  [`all-modules-composition.fixture.mts`](../../templates/standalone/src/__tests__/all-modules-composition.fixture.mts).
  Upstream identity providers are fakes; nothing reaches the network.
- **What it checks, on one replica with every store in memory.** What the
  added modules contribute: their boot, discovery and each added feature's
  switch, their flows, their body limits in both mount orders, and one outage
  per added store under the #685 rule. The two session requirements are
  registered, declared and said at boot, refused when the declaration
  disagrees or names a requirement nothing registers, and a password login that both requirements interrupt is
  resumed through each one's completion route and established once (the
  session-admission ADR's acceptance criterion 2). The fixtures' completion
  routes are a sketch, not a route to copy: the real one (the MFA package's)
  sits behind the session's CSRF guard, projects every error it logs, and
  answers a `RangeError` from `resumePrimary` — a continuation naming a
  requirement a deploy removed, say — as "log in again".
- **The budget in force for each prefix a package owns, on both bundled
  limiters.** `login`, `device_verification`,
  `webauthn-authentication-options` and `mfa` — each the budget its owning
  module contributes — and `token`, which the oauth module claims with no budget of its own (`null`), so it falls to the limiter's `defaultLimit`, asked of the limiter
  the full set hands a consumer, on the in-process limiter and on the Redis
  one: with the shipped configuration, with each owner's own key set, with the
  limiter's own `limits` declaring every prefix (which wins), and with the
  owners switched off.
- **What it checks on real Redis, under `core.deployment.mode = "multi"`.** That
  nothing in the full set declares replica-unsafe state, that each added
  memory store is refused at boot by name, and that two replicas on one
  database finish each other's flows.

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
  `it`. A store-outage case pins only the part of the #685 rule that is
  broken and asserts the rest, one test per part (`describeOutages` in the
  template's fixture). A row whose composition writes no line today names no
  `event`, so nothing checks the name of the line a fix adds: the fix that
  flips such a row adds its `event` in the same change.
- The fakes are shared by every boot in a file and put back as they were made
  before each one; a test that rotates a fake's key, or sets
  `refreshTokenOnlyOnConsent` (it reads closure state no reset restores), is
  refused, and makes a fake of its own instead.

## Known gaps

- **No WebAuthn ceremony.** The WebAuthn grant is advertised and its three
  routes are mounted, but the suite runs only the options routes
  (authentication, and registration through the deployment's subject bridge).
  A registration or an authentication needs an authenticator's signed
  response, and the repository has no software authenticator: the WebAuthn
  package's own ceremony tests mock the verification. A helper that produces a
  real `none`-attestation credential and assertion would let one registration
  and one authentication run through the composed app.
- **No mTLS outage.** In `self-signed` mode the mechanism reads no store; the
  `full-pki` revocation outage needs a CRL distribution point or an OCSP
  responder, which the mTLS package tests against its own fakes.

## Running it

```sh
pnpm install
pnpm run build            # the packages resolve through their dist/
pnpm --filter @o3co/auth-provider-composition run test                          # tsc, then vitest
pnpm --filter @o3co/auth-provider-composition exec vitest run --maxWorkers=2    # vitest alone
```

The real-Redis cases run on the Redis package's shared test container
([`redis-container.global.mts`](../../packages/redis/__tests__/support/redis-container.global.mts)),
so they need a container runtime, as `packages/redis` does. CI runs the suite
in the `test` job; `.github/scripts/test-shards.sh` says which shard.
