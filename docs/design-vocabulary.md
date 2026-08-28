# Design vocabulary — top-down concepts, bottom-up homes

Each row binds one **top-down design concept** (the semantic a spec, ADR, or
review names) to the one **bottom-up module** that implements it (the shared
implementation deduplication produced), so the two directions cannot drift
apart silently. See issue #370 for the origin of this map.

The binding runs both ways:

- **Writing a helper that implements a named concept?** Import (or re-export)
  the mapped home instead. If no row fits, you are naming a new concept — add
  a row.
- **Naming a new concept in a spec or ADR?** Give it exactly one home before a
  second implementation can exist, and add a row.

Rows marked *guarded* are enforced by
[`packages/core/src/__tests__/designVocabulary.drift.test.mts`](../packages/core/src/__tests__/designVocabulary.drift.test.mts),
which fails CI when the concept's definition signature appears in any shipped
source outside its home. Re-exports and imports never trip the guard — that is
how consumers are *supposed* to reach a home. When you add a guardable row
here, add its signature to the test's `VOCABULARY` table in the same PR; the
test asserts this document names every home it enforces, so the two lists
cannot drift either.

Why this exists: the 2026-08-28 design-erosion review of the 38-commit
campaign found that erosion in this repository does not live in files — it
lives in vocabularies. `isLoopbackHostname` was defined twice under identical
doc comments with different behavior (#364), one commit after the decision
not to unify them was written down. Per-PR review structurally cannot see a
second definition it was never shown; a drift guard can.

## The map

| Concept | Home (single definition site) | Consumers | Established by | Guarded |
| --- | --- | --- | --- | --- |
| Loopback hostname — "http:// is accepted for loopback hosts only" carve-outs | `packages/core/src/net/loopback.mts` | foundation `checkSecureEndpoint` (#285), session `checkRedirectShape` (#278) | #364 | yes |
| Trusted-proxy address vocabulary — "is this hop one of ours?" | `packages/core/src/net/trusted-proxy.mts` | `http.trustProxy` schema, mtls `trusted-proxies` (#280) | #292 | yes |
| Canonical request URL — "the URL this request reached": configured origin + `req.originalUrl`, never `req.protocol` + `Host` | `packages/core/src/net/request-url.mts` | dpop htu comparison (#292), oauth `/authorize` login round-trip (#356) | #292, #356 | yes |
| cnf / token-binding comparison matrix | `packages/core/src/grants/confirmationMatch.mts` | oauth refresh grant, token-exchange, protected-resource binding, introspection | #324 | yes |
| Rate-limit guard — check + outage policy for security throttles | `packages/core/src/ratelimit/guard.mts` | `/oauth/token` `/oauth/authorize` `/oauth/introspect`, `/session/login`, webauthn options | #325 | yes |
| Canonical issuer — what `oauth.jwt.issuer` may be | `packages/core/src/issuer/canonical.mts` | config schema, oauth router re-check | unreleased (issuer-required fix) | no (single consumer signature) |
| Secret entropy floor | `packages/core/src/keys/secretEntropy.mts` | key factory, `session.secret` schema | #282 | no |
| Built-in audit-event names | `packages/core/src/audit/types.mts` (`BUILT_IN_AUDIT_EVENT_TYPES`) | every `emitAuditEvent` / sink `record` site | #369 | yes (`audit/__tests__/auditEventInventory.drift.test.mts`, both directions) |
| Retired config key — how a removed key dies | `packages/core/src/config/removed-keys.mts` (`withRemovedKeys`; decision rule in `docs/release-policy.md` §"Retiring a config key") | `oauth.refreshToken` / `oauth.authorize` tombstones; warn-path stays with `INERT_PKCE_KEYS` per the rule | #366 | yes |
| Declared absence — optional DI slot whose absence must be stated | `packages/core/src/modules/manifest/absence-policy.mts` (enforced by `checkDeclaredAbsence` in the post-config check registry) | `auditSink` via `AUDIT_SINK_ABSENCE_POLICY` (oauth, session, webauthn); `accessTokenDenylist` via `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` (oauth, token-exchange — #375 folded #277's bespoke check onto it) | #363, #375 | no |

## What does not belong here

- **Package-local helpers** with one caller — a map row is earned by a second
  consumer, not by existing.
- **Genuinely different constraints that share prose**: `checkSecureEndpoint`
  and `checkRedirectShape` stay separate on purpose (an issuer may not carry a
  query string; a Store endpoint may) — the map binds the *shared* concept
  (loopback) they both consume, not their differing policies.
- **Cross-repo contracts** (JWT alg symmetry, JWKS): those live in the
  workspace-level `Dependency_map.xml`, one level up. This map is
  intra-repository, where this repo's CI can enforce it.
