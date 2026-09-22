# user-sessions

## Responsibility

The provider-side record of an authenticated user, keyed two ways. Sid-keyed: `UserSessionStore` (the session aggregate), `SessionRPRegistry` (relying parties for logout fan-out), `SessionFamilyIndex` (refresh-token families to revoke), `SessionFederationIndex` (upstream IdPs linked to the session). Subject-keyed: `SubjectSessionIndex` (which sessions a subject holds) and `SubjectRevocation` — the not-before boundary for issued tokens, which since #593 carries a second, independent boundary for federation grants (`SupportsSessionsOnlyRevocation`). With them: the in-process adapters, `memorySessionStoresModule`, the `AdapterFactory` aliases, the retention arithmetic, and subject-wide revocation — `revokeAllForSubject`, `cascadeSubjectSessions`, `createSubjectRevocationService`.

State ownership: these stores hold the session state; the browser cookie session is `packages/session`'s; the ordered per-session teardown (`cascadeLogout`) is `packages/oauth`'s and is injected as `CascadeSession`, because core cannot import it. The Redis adapters are `packages/redis`. The two-boundary design (D13) is recorded in the ADR [2026-09-17-federation-grants-offline-delegation.md](../../docs/adr/2026-09-17-federation-grants-offline-delegation.md); this README does not restate it.

## Public contract

- [`types.mts`](./types.mts) — the six store interfaces, `UserSession` / `UserSessionClaims` / `RegisteredRP`, `SUBJECT_REVOCATION_ABSENCE_POLICY`, `supportsSessionsOnlyRevocation`, the factory aliases, and the six optional `ComponentMap` slots.
- [`factory.mts`](./factory.mts), [`modules/memory.mts`](./modules/memory.mts), [`memory/`](./memory/) — one adapter per store; `internalSidHash.mts` / `internalSidSortedSet.mts` are their private primitives, described here rather than given a README of their own.
- [`revokeAllForSubject.mts`](./revokeAllForSubject.mts), [`cascadeSubjectSessions.mts`](./cascadeSubjectSessions.mts), [`subjectRevocationService.mts`](./subjectRevocationService.mts), [`retention.mts`](./retention.mts).
- Package README: [UserSessionStore / FederationTokenStore](../../README.md#usersessionstore--federationtokenstore-todo-f).

## Inputs and outputs

- A `UserSession` is immutable after `create`; the store is `create` / `get` / `delete` only. `delete(sid)` is the invalidation primitive; the orchestrator calls it last, so a failed sibling cleanup leaves the session retryable.
- Every index write takes the session's `expiresAt`, and the adapter syncs storage TTL to it. Expiry is a `Date` here (the A4 aggregates) and epoch-ms in the A3 primitives; the conversion is explicit at the boundary.
- `listFederations` returns insertion order — load-bearing for the post-logout redirect.
- The watermark is compared inclusively against a token's `iat`. `revokeBefore` advances both boundaries; `revokeSessionsBefore` only the sessions one; neither ever moves a boundary backwards. The `expiresAt` of a stamp is the caller's, sized by `resolveSubjectRevocationHorizonMs`; the memory adapter raises it to `SUBJECT_REVOCATION_MIN_RETENTION_MS` whenever the grants boundary advances.
- `revokeAllForSubject` and the service report rather than throw: `unavailable` is a composition gap, `failures` are backend outages, and `complete` is the one field a caller checks. Keeping grants on a subject-wide revocation is operator policy (`federationGrants.allowKeepOnSubjectRevocation`), not a call argument.

## Dependencies

- Imports: `../adapters/AdapterFactory`, `../logging/Logger`, `../federation-grants/{revoke,store,types,retrieve,lifetime}` (revocation and retention), `../config/application.schema` and `../jwt/verify` (the retention horizon), `../modules/manifest/define-module` (the module).
- Imported by: `../grants/{types,idToken,claimFilter}`, `../jwt/verify.mts`, `../boot/replica-safety.mts`, `../federation-grants/revocationWiring.mts` (`types.mts` only), the root barrel; downstream `packages/oauth` (logout cascade, userinfo, the wired revocation service), `session`, `redis`, `federation-grants`.
- Direction: `user-sessions` → `federation-grants` at runtime; `federation-grants` → `user-sessions` only through `types.mts`. There is no file-level cycle. Must never import `boot/`, `middleware/`, `routes/`, `packages/oauth` (the cascade is injected), or `testing/`.

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
