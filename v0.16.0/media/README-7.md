# user-sessions

Last updated: 2026-09-24

## Responsibility

The provider-side record of an authenticated user, keyed two ways. Sid-keyed: `UserSessionStore` (the session aggregate), `SessionRPRegistry` (relying parties for logout fan-out), `SessionFamilyIndex` (refresh-token families to revoke), `SessionFederationIndex` (upstream IdPs linked to the session). Subject-keyed: `SubjectSessionIndex` (which sessions a subject holds) and `SubjectRevocation` — the not-before boundary for issued tokens, which carries a second, independent boundary for federation grants (`SupportsSessionsOnlyRevocation`). With them: the in-process adapters, `memorySessionStoresModule`, the `AdapterFactory` aliases, the retention arithmetic, and subject-wide revocation — `revokeAllForSubject`, `cascadeSubjectSessions`, `createSubjectRevocationService`.

State ownership: these stores hold the session state; the browser cookie session is `packages/session`'s; the ordered per-session teardown (`cascadeLogout`) is `packages/oauth`'s and is injected as `CascadeSession`, because core cannot import it. The Redis adapters are `packages/redis`. The two-boundary design (D13) is recorded in the ADR [2026-09-17-federation-grants-offline-delegation.md](../../docs/adr/2026-09-17-federation-grants-offline-delegation.md); this README does not restate it.

It is separate because these stores are read by `oauth` (logout, userinfo, the refresh grant), `session`, `redis` and `federation-grants`. The sid-keyed stores end with the session; the subject-keyed revocation boundary deliberately outlives it — for as long as the longest grant, refresh token, access token or session it covers ([`retention.mts`](./retention.mts)) — because a store that expired the boundary with the session would let revoked tokens and grants come back. Subject-wide revocation lives here too, because the subject boundary is the one it stamps; it reaches into [`../federation-grants/`](../federation-grants/README.md) for the grant lifetime ceiling and to end a subject's grants, so the two directories depend on each other at run time — recorded in [the directory map](../README.md#where-a-boundary-is-a-judgement-call).

## Public contract

- [`types.mts`](./types.mts) — the six store interfaces, `UserSession` / `UserSessionClaims` / `RegisteredRP`, `SUBJECT_REVOCATION_ABSENCE_POLICY`, `supportsSessionsOnlyRevocation`, the factory aliases, and the six optional `ComponentMap` slots.
- The in-process adapters are [`memory/`](./memory/), one per store over two private primitives (a sid-keyed hash and a sorted set); `memorySessionStoresModule` is [`modules/memory.mts`](./modules/memory.mts) and the factory aliases are [`factory.mts`](./factory.mts). `memory/` and `modules/` are described here rather than given a README of their own.
- Subject-wide revocation is `revokeAllForSubject`, `cascadeSubjectSessions` and `createSubjectRevocationService`, each in the file of its name; the retention horizon is [`retention.mts`](./retention.mts).
- Package README: [Session stores and federation tokens](../../README.md#session-stores-and-federation-tokens).

## Inputs and outputs

- A `UserSession` is immutable after `create`; the store is `create` / `get` / `delete` only. `delete(sid)` is the invalidation primitive; the orchestrator calls it last, so a failed sibling cleanup leaves the session retryable.
- Every index write takes the session's `expiresAt`, and the adapter syncs storage TTL to it. Expiry is a `Date` on the store interfaces and epoch-ms in the private primitives; the conversion is explicit at the boundary.
- `listFederations` returns insertion order — load-bearing for the post-logout redirect.
- The watermark is compared inclusively against a token's `iat`. `revokeBefore` advances both boundaries; `revokeSessionsBefore` only the sessions one; neither ever moves a boundary backwards. The `expiresAt` of a stamp is the caller's, sized by `resolveSubjectRevocationHorizonMs`; the memory adapter raises it to `SUBJECT_REVOCATION_MIN_RETENTION_MS` whenever the grants boundary advances.
- `revokeAllForSubject` and the service report backend outcomes rather than throw them: `unavailable` is a composition gap, `failures` are backend outages, and `complete` is the one field a caller checks. What they refuse, they refuse before the first write: a `RangeError` for an invalid `revokeGrantsConsentedSince`, and at construction a `RangeError` for a non-positive watermark TTL and a `TypeError` for allowing keep on an adapter that cannot stamp the sessions-only boundary. A caller may ask for its federation grants to be kept (`SubjectRevocationRequest.federationGrants: "keep"`); whether that is honoured is operator policy (`federationGrants.allowKeepOnSubjectRevocation`, default `false`), a refused keep is carried out as a full revocation, and the report says both what was asked and what happened.

## Dependencies

- Depends on: `federation-grants/` (revocation, the grant lifetime and the store types — for subject-wide revocation and retention), `config/` and `jwt/` (the retention horizon and the clock skew), `modules/manifest/` (the module), `adapters/`, `logging/` (type-only).
- Depended on by: `grants/` (`UserSessionClaims`, type-only), `jwt/` (type-only), `boot/` (replica safety), `federation-grants/` (the capability guard in `types.mts`), the root barrel; downstream `packages/oauth` (logout cascade, userinfo, the wired revocation service), `session`, `redis`, `federation-grants`.
- `federation-grants/` reaches this directory only through `types.mts`, and no import cycle crosses the two directories. Must never import `boot/`, `middleware/`, `routes/`, `packages/oauth` (the cascade is injected), or `testing/`.

## Invariants

The store contracts are shared suites (`*.contract.mts`), run here against the memory adapters and, from copies kept in `packages/redis/__tests__`, against Redis:

- `UserSessionStore`: duplicate `sid` rejected, past `expiresAt` refused, `get` null after expiry, `delete` idempotent, defensive copies, `amr` round-trips — [`userSessionStore.contract.mts`](./__tests__/userSessionStore.contract.mts).
- `SessionRPRegistry` upserts per `clientId`; `SessionFamilyIndex` is append-only and idempotent; `SessionFederationIndex` keeps insertion order and a re-add does not promote — [`sessionRPRegistry.contract.mts`](./__tests__/sessionRPRegistry.contract.mts), [`sessionFamilyIndex.contract.mts`](./__tests__/sessionFamilyIndex.contract.mts), [`sessionFederationIndex.contract.mts`](./__tests__/sessionFederationIndex.contract.mts).
- `SubjectSessionIndex`: each sid expires on its own clock; `removeSid` leaves the others; membership is unordered — [`subjectSessionIndex.contract.mts`](./__tests__/subjectSessionIndex.contract.mts).
- `SubjectRevocation`: monotonic, the longer expiry kept, subjects kept apart; the two boundaries take independent maxima and a sessions-only stamp cannot rescue an ended grant — [`subjectRevocation.contract.mts`](./__tests__/subjectRevocation.contract.mts); the memory adapter's retention floor and its `RangeError` on a non-date — [`subjectRevocation.boundaries.test.mts`](./__tests__/subjectRevocation.boundaries.test.mts), [`subjectStores.test.mts`](./__tests__/subjectStores.test.mts).
- `revokeAllForSubject` stamps the boundary before it cascades, removes an index entry only after that session's cascade succeeded, keeps going past a failure, and never reads an unwired store as success — [`revokeAllForSubject.test.mts`](./__tests__/revokeAllForSubject.test.mts); with a grant store it ends every grant, pending ones included, sampling the clock per write and auditing each — [`revokeAllForSubject.grants.test.mts`](./__tests__/revokeAllForSubject.grants.test.mts).
- The service refuses to allow keeping on an adapter without the second boundary, revokes anyway when policy forbids keeping, and ends the renewal in flight of every grant it keeps — [`subjectRevocationService.test.mts`](./__tests__/subjectRevocationService.test.mts).
- One absence policy covers both subject slots; unfilled and undeclared refuses boot — [`subjectAbsencePolicy.test.mts`](./__tests__/subjectAbsencePolicy.test.mts).
- The retention horizon outlasts the session, the refresh token and the access-token *maximum*, each with the tolerance it is accepted with — [`retention.test.mts`](./__tests__/retention.test.mts).
- `memorySessionStoresModule` provides all six slots and declares `replicaSafety` — [`module.memory.test.mts`](./__tests__/module.memory.test.mts); the type shapes (three methods on `UserSessionStore`, no legacy fields) — [`types.test.mts`](./__tests__/types.test.mts).

## Failure and lifecycle

- Store methods reject on a backend failure; the revocation helpers convert every such rejection into a reported failure and never throw (`cascadeSubjectSessions` in particular), because their callers have already written something they cannot undo.
- The memory adapters GC lazily on read and write, hold no timers and need no disposal. They are single-replica: the module is refused under `deployment.mode = "multi"`.
- No cancellation or deadlines; a subject cascade is sequential by design.

## Contract tests

[`__tests__/`](./__tests__/) — the suites above. The memory adapters are wired to the shared contracts in [`memory.userSessionStore.test.mts`](./__tests__/memory.userSessionStore.test.mts), [`memory.sessionRPRegistry.test.mts`](./__tests__/memory.sessionRPRegistry.test.mts), [`memory.sessionFamilyIndex.test.mts`](./__tests__/memory.sessionFamilyIndex.test.mts), [`memory.sessionFederationIndex.test.mts`](./__tests__/memory.sessionFederationIndex.test.mts) and [`subjectStores.test.mts`](./__tests__/subjectStores.test.mts); [`factory.test.mts`](./__tests__/factory.test.mts) pins the factory kinds; [`internalSidHash.test.mts`](./__tests__/internalSidHash.test.mts) / [`internalSidSortedSet.test.mts`](./__tests__/internalSidSortedSet.test.mts) cover the private primitives.
