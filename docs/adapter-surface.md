# Adapter surface contract

Every capability this library does not implement itself is a **typed component
slot**: a named entry in `ComponentMap` with a declared interface, filled by a
composition root and consumed by whichever modules declare it. This document is
the one place that lists them, says what each is for, and states the boundary
that decides what may become one.

It is enforced, not aspirational: `packages/core/src/__tests__/adapterSurface.drift.test.mts`
checks both directions — every slot declared in source appears here, and every
slot named here still exists. A slot added without an entry fails that test.

## The boundary: verify-only

Adapter freedom applies **within** authentication and token issuance. It is not
a licence to grow the responsibility.

`UserRepository` is the clearest case, and the shape of the rule. It is
`authenticate` / `authenticateByToken`, plus one optional member,
`linkFederatedIdentity` (#482). Creating users, changing passwords, flipping
verification state, linking a device to a user, upgrading an anonymous identity
to a registered one — all of that belongs to the Store, and for all of it the
library only ever *reads the result*. The one exception is the link below.

`linkFederatedIdentity` is the one call through which the library causes a
write, and it passes the document's own test: the `?link=1` flow is one this
library drives end to end, so the flow needs the seam. What still holds is the
part that matters — the **Store decides**. The library relays the verified
identity and the session it is bound to, and relays `refused` / `conflict` back
unchanged; it never merges accounts, never links implicitly, and never links on
an unverified or relay e-mail on its own authority. Three call sites already say
so where the temptation is highest:

- `grants/emailVerifiedGate.mts` — the Store "issues the token, delivers it, and
  flips the state; this library only reads".
- `repositories/types.mts` — "Issuing the verification token, delivering it, and
  flipping…" is not this library's.
- `user-sessions/revokeAllForSubject.mts` — the Store issues the reset token,
  delivers it, writes the new credential, and *then* calls in to invalidate what
  was already minted.

That last one is the pattern for anything that looks like it needs a new slot:
the library is downstream of the action, never the one taking it. **Message
delivery is the worked example of a slot that does not belong here** — there is
no flow in this library that sends anything, so a delivery port would be a seam
with no caller on this side of the boundary. Full IdPs ship one because they own
the flows that send; verify/issue-only libraries do not.

The line also cuts the other way, and `assertionVerifier` is the example. A
device presenting a signed credential *is* an authentication modality, so
verifying possession belongs here — but resolving that credential to a person
does not. The RFC 7523 grant (#301) verifies, then hands an opaque handle to
`authenticateByToken` and takes whatever subject the Store returns. Device
registration, device→user linking and anonymous→registered continuity stay
outside; the provider never learns they happened.

Before adding a slot, the question is not "could this be pluggable" but "does a
flow *this library owns* need it". If the answer is that an operator's component
would call it, the slot belongs in the operator's composition, not here.

## Two tiers

Slots come in two layers, and conflating them is how a vendor ends up in
everyone's dependency closure.

**Component slots** are what modules consume — `KeyStore`, `RateLimiter`,
`AuditSink`. They are vendor-neutral by construction: the interface says what the
capability is, never who provides it.

**Client slots** are what a *specific adapter package* needs from a driver —
`accessTokenDenylistClient`, `sessionRPRegistryClient`. They exist so
`@o3co/auth-provider-redis` can be handed one ioredis socket and build every
store on it, rather than opening a connection per store. A core module never
requires one.

## Boot infrastructure

Not adapters. These are the boot machinery every composition has.

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `config` | `AppConfig` | required | `core/boot/types.mts` | The parsed application config. Every module that reads a knob requires it. |
| `lifecycleRegistrar` | `LifecycleRegistrar` | required | `core/boot/types.mts` | Where a component registers its shutdown work, so `dispose()` drains in reverse-topological order. |
| `logger` | `Logger` | optional | `core/logging/Logger.mts` | Structured logger. Optional to wire; bundled modules fall back to a console logger rather than going silent. |
| `pathResolver` | `PathResolver` | required | `core/boot/types.mts` | Resolves a package-relative path (normally `import.meta.resolve`), so `reference.conf` is found without assuming a layout. |
| `readinessRegistrar` | `ReadinessRegistrar` | required | `core/boot/types.mts` | Where a component registers a readiness probe. Distinct from liveness: this answers *can it serve*, not *is it up*. |

## Synthetic keys

Assembled by the boot planner from module contributions rather than supplied by
a composition root. Listed because a module may `require` them.

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `federationRedirectPolicyResolver` | `ReadonlyMap<string, FederationRedirectPolicy>` | optional | `session/federations/contributes.mts` | Synthetic key: the assembled per-federation `redirect_to` policies. |
| `grantHandlerResolver` | `GrantHandlerResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: the assembled grant registry, resolved from every module's `contributes.grants`. |
| `tokenExchangeValidatorResolver` | `TokenExchangeValidatorResolver` | optional | `core/modules/manifest/synthetic-keys.mts` | Synthetic key: the assembled RFC 8693 subject/actor token validators. |

## Component slots

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `accessTokenDenylist` | `AccessTokenDenylist` | optional | `core/access-token-denylist/types.mts` | RFC 7009 access-token revocation by `jti`. Absence must be declared (#375). |
| `consentStore` | `ConsentStore` | optional | `core/consents/types.mts` | What an end-user agreed a client that is not first-party may obtain, read by `/authorize` and written by `POST /oauth/consent`. Absent, such clients are refused as before #527 — nothing to declare. Bundled adapters: memory (single replica) and Redis (`redisConsentStoreModule`, #561). |
| `pendingConsentStore` | `PendingConsentStore` | optional | `core/consents/types.mts` | The `/authorize` request parked under a challenge while the consent page asks; `consume` hands it to exactly one answer, so two answers in flight apply one (#552). Wired with `consentStore` — the bundled memory and Redis modules each provide both, and the OAuth router refuses a composition with one and not the other. Holds each session to `PENDING_CONSENT_PER_SESSION_LIMIT` parked requests. |
| `appleFederationConfig` | `AppleProviderConfig` | optional | `federation-apple/apple.mts` | Config slice for the bundled Sign in with Apple federation module. Carries either a `clientSecret` (string or resolver) or the `.p8` key material the module signs one from — Apple's secret is an ES256 JWT that expires. |
| `assertionVerifier` | `AssertionVerifier` | optional | `core/assertions/types.mts` | Proves possession of a presented assertion (device JWT, platform attestation) and returns the opaque handle the Store resolves. Required once the RFC 7523 jwt-bearer grant is enabled — there is no default, because the only possible one accepts things (#301). `createRegistryAssertionVerifier` over an `AssertionIssuerRegistry` is the bundled one for several issuers, each with its own keys and terms; `createJwtAssertionVerifier` is its one-entry form (#525). A verifier whose credential expires reports `expiresAt` (epoch seconds): the grant caps the issued token there, so it never outlives the assertion. The field is optional for compatibility, and omitting it asserts a credential with no expiry (auth.proxy#90). |
| `auditSink` | `AuditSink` | optional | `core/audit/types.mts` | Where security events go. Optional to wire, **not optional to decide** — an unfilled slot must be declared absent (#363). |
| `challengeCeremony` | `ChallengeCeremony` | optional | `core/challenges/types.mts` | The ceremony driver — issue and verify — kept separate from its storage. |
| `challengeStore` | `ChallengeStore` | optional | `core/challenges/types.mts` | In-flight WebAuthn ceremony challenges. |
| `clientRepository` | `ClientRepository` | required | `core/repositories/ClientRepository.mts` | Registered OAuth clients. Read-only from this library's side. |
| `codeRepository` | `CodeRepository` | required | `core/repositories/CodeRepository.mts` | Authorization codes. Single-use, and replica-shared in any deployment that scales. |
| `deviceCodeStore` | `DeviceCodeStore` | optional | `core/device-authorization/types.mts` | Pending RFC 8628 device authorizations. Written as atomic operations rather than read-then-write pairs: `poll` reads the status *and* consumes an approval in one step, because two concurrent polls that both observe `approved` mint two tokens from one human approval. Absence must be declared (#298). |
| `dpopReplayStore` | `DPoPReplayStore` | optional | `dpop/module.mts` | DPoP proof `jti` replay detection. |
| `federationProviders` | `ReadonlyMap<string, FederationProvider>` | optional | `core/modules/manifest/synthetic-keys.mts`; the contract is `core/src/federations/types.mts` (#626 P1) | Upstream IdP protocol adapters, contributed per federation module. The slot's value type is the contract an adapter implements — it read `unknown` until the contract moved into core. |
| `federationRedirectPolicies` | `{ readonly [name: string]: FederationRedire…` | optional | `session/federations/contributes.mts` | Per-federation `redirect_to` allowlist factories. Paired with the provider at boot; an unpaired one refuses. |
| `federationTokenStore` | `FederationTokenStore` | optional | `core/federation-tokens/types.mts` | Upstream tokens held on behalf of a session. Encrypted at rest by the bundled adapter. |
| `federationGrantBackground` | `FederationGrantBackground` | optional | `federation-grants/background.mts` | Not an adapter seam but lifecycle infrastructure, for work the provider itself starts and deliberately does not make a caller wait for (#593, D12): letting go of a refresh lock, telling the sink, recording a use, and a refresh that outlived the soft deadline and is still holding its lock until the rotated credential is written down. One per application. Its cleanup drains, and its dependency edges on `federationGrantStore`, `subjectRevocation` and `auditSink` are what put that drain ahead of their cleanups — an adapter that closed first would fail the write being waited for. Filled by `federationGrantBackgroundModule`; a deployment mounting it wants at least 45 seconds of cleanup allowance, not the standalone's default ten. |
| `federationGrantIntentStore` | `FederationGrantIntentStore` | optional | `core/federation-grants/intentStore.mts` | Acquisition's records (#593, D16, slice 6), the second port of federation grants: the intent a confidential client lodged, the consent challenge the deployment's page answers, the connect transaction the upstream callback consumes, and the bound on live first-time intents per `(client, subject)` — the only admission control in front of `createPending`, which is why it refuses at capacity instead of evicting. Its keys share a tag of their own and no operation spans this port and the grant store: supersession is settled by the grant's current-intent pointer, and core orders the two writes once. One deadline governs a whole acquisition — the intent's — and the consent and the transaction carry it rather than one of their own, because nothing extends a `pending` grant's pointer. Every operation takes the time from its caller and reclaims on the adapter's own clock; a record it cannot read is refused rather than healed. Bundled adapters: memory (`memoryFederationGrantIntentStoreModule`, single replica) and Redis (`redisFederationGrantIntentStoreModule`). Its consumer is the acquisition routes of #593 slice 6. |
| `federationGrantStore` | `FederationGrantStore` | optional | `core/federation-grants/store.mts` | Federation grants (#593): one user's consent that one client may obtain upstream access tokens through one connection, which outlives the session — the records, the upstream credentials kept beside each (sealed at rest by an adapter that persists them; the bundled one holds them in memory, unsealed), and the lock a refresh holds. Every transition is a guarded write inside the store. Every operation on a record takes the time from its caller, and what a caller is told is judged on that time alone; what an adapter reclaims is judged on its own clock. Its consumer is the federation grant routes of #593. Bundled adapters: memory (single replica) and Redis (`redisFederationGrantStoreModule`, #593 slice 4 — configured by `federationGrants` for what a grant may be, and `redisFederationGrantStore` for this adapter's own layout). |
| `githubFederationConfig` | `GithubProviderConfig` | optional | `federation-github/github.mts` | Config slice for the bundled GitHub federation module. |
| `googleFederationConfig` | `GoogleProviderConfig` | optional | `federation-google/google.mts` | Config slice for the bundled Google federation module. |
| `grantPolicy` | `GrantPolicyHook` | optional | `core/policy/types.mts` | Deployment-supplied hook consulted at grant dispatch, for policy this library does not model. |
| `keyStore` | `KeyStore` | required | `core/keys/KeyStore.mts` | Signing and verification keys. `sign()` is the seam a KMS/HSM implements without surrendering the private key (#303). |
| `oidcFederationConfigs` | `Readonly<Record<string, OidcProviderConfig>>` | optional | `federation-oidc/module.mts` | Config of every generic OpenID Connect federation instance, keyed by federation name; each `oidcFederationModule(<name>)` reads its own entry. `readOidcFederationConfigs` builds it from `config.federations` (#524). |
| `rateLimiter` | `RateLimiter` | optional | `core/ratelimit/types.mts` | Shared counters for the OAuth endpoints and the login brute-force guard. |
| `refreshTokenFamilyRevocation` | `RefreshTokenFamilyRevocation` | optional | `core/refresh-token-family/types.mts` | Family-wide revoke, used on replay detection and on the credential-change cascade. |
| `refreshTokenFamilyRotation` | `RefreshTokenFamilyRotation` | optional | `core/refresh-token-family/types.mts` | Atomic rotate-or-detect-replay. Wired separately so a deployment can have the store without the CAS path. |
| `refreshTokenFamilyStore` | `RefreshTokenFamilyStore` | optional | `core/refresh-token-family/types.mts` | Refresh-token family records — the state rotation and replay detection read. |
| `replaySeenSet` | `ReplaySeenSet` | optional | `core/replay-seen-set/types.mts` | The generic seen-set primitive the replay stores are built on. |
| `sessionFamilyIndex` | `SessionFamilyIndex` | optional | `core/user-sessions/types.mts` | Session → refresh-token families, so logout can revoke them. |
| `sessionFederationIndex` | `SessionFederationIndex` | optional | `core/user-sessions/types.mts` | Session → upstream federations, so logout can propagate. |
| `sessionRPRegistry` | `SessionRPRegistry` | optional | `core/user-sessions/types.mts` | Which RPs a session has authenticated to, for back-channel logout. |
| `subjectRevocation` | `SubjectRevocation` | optional | `core/user-sessions/types.mts` | Per-subject not-before watermark: what a credential change stamps so tokens minted before it stop verifying. Absence must be declared (#406). |
| `subjectRevocationService` | `SubjectRevocationService` | optional | `core/user-sessions/subjectRevocationService.mts` | Not an adapter seam: the composed operation a Store calls to end everything one subject holds (#593, D13) — the boundary, their sessions, and their federation grants. It is a component rather than the free `revokeAllForSubject` because building it needs every session store plus the cascade, and because the one decision it carries — whether a caller MAY ask for the subject's established grants to be kept — belongs to the operator (`federationGrants.allowKeepOnSubjectRevocation`) and not to the caller. Filled by an explicitly installed module in `@o3co/auth-provider-oauth`, where `cascadeLogout` lives. |
| `subjectSessionIndex` | `SubjectSessionIndex` | optional | `core/user-sessions/types.mts` | Subject → live sessions, so a credential change can enumerate what to cascade over. Absence must be declared (#406). |
| `userRepository` | `UserRepository` | required | `core/repositories/UserRepository.mts` | **The verify seam.** `authenticate` / `authenticateByToken`, plus the optional `linkFederatedIdentity` a `?link=1` flow relays to the Store, which decides — see the boundary section. The optional pair `supportsFederatedIdentityLookup` / `findSubjectByFederatedIdentity` is what a federation-grant callback asks (D7 check 5, #611): whether the Store covers a registration with the claims its connection names — asked at boot — and who holds an identity from it, given the registration, the `sub` and those verified claims (Entra's `tid`/`oid` for a directory Store), as `linked` / `unlinked` / `indeterminate`. The bundled `InMemoryUserRepository` covers none. |
| `userSessionStore` | `UserSessionStore` | optional | `core/user-sessions/types.mts` | The session records themselves, keyed by `sid`. |
| `webauthnConfig` | `WebAuthnConfig` | optional | `webauthn/config.mts` | Config slice for the WebAuthn module. |
| `webauthnCredentialStore` | `WebAuthnCredentialStore` | optional | `core/webauthn-credentials/types.mts` | Registered passkeys. |

## Client slots

| Slot | Type | Wiring | Declared in | Purpose |
| --- | --- | --- | --- | --- |
| `accessTokenDenylistClient` | `AccessTokenDenylistClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `challengeStoreClient` | `ChallengeStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `codeRepositoryClient` | `CodeRepositoryClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `consentStoreClient` | `ConsentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`find` / `grant` / `revoke`), because `grant` is the port's union and a read-then-write loses a concurrent grant (#561). |
| `deviceCodeStoreClient` | `DeviceCodeStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`create` / `findPending` / `decide` / `poll` / `remove`) rather than commands, because each must be indivisible (#433). |
| `federationGrantIntentStoreClient` | `FederationGrantIntentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half of acquisition's records (#593, D16, slice 6). Five of its seven operations are single scripts — admission against the bound, parking a challenge, answering it, consuming a transaction, finishing a flow — because each reads, decides and writes across keys, which Redis makes one step only with a script or with WATCH/MULTI on a connection of its own (the cost #449 is removing elsewhere). The two reads are plain commands: whatever they conclude, the write that follows checks again. Every key shares the `{intents}` tag, so a script routed by one key may derive the others. It may be the grant store's own connection. |
| `federationGrantStoreClient` | `FederationGrantStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations rather than commands, because each write is one guarded script; the subject index is reserved and pruned separately, since it is a key of its own and no script may touch it together with a record on a Cluster (#593, D16). |
| `federationTokenStoreClient` | `FederationTokenStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `pendingConsentStoreClient` | `PendingConsentStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. Semantic operations (`set` / `get` / `consume` / `discard`): `consume` reads and removes a parked request with its per-session index entry in one step, and `discard` reclaims one the adapter found corrupt only while it is still the value read (#561). |
| `rateLimiterClient` | `RateLimiterClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `refreshTokenFamilyClient` | `RefreshTokenFamilyClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `replaySeenSetClient` | `ReplaySeenSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionFamilyIndexClient` | `SessionSidSortedSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionFederationIndexClient` | `SessionSidSortedSetClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `sessionRPRegistryClient` | `SessionRPRegistryClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `subjectRevocationClient` | `SubjectRevocationClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `subjectSessionIndexClient` | `SubjectSessionIndexClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |
| `userSessionStoreClient` | `UserSessionStoreClient` | optional | `redis/clients.mts` | Vendor-facing half — what `@o3co/auth-provider-redis` needs from a driver, not what a module consumes. |

## Lifecycle

**Filling a slot.** A composition root supplies it in `bootstrapComponents`, or a
module `provides` it. The boot planner resolves the graph topologically and
refuses a module whose `requires` cannot be met.

**Absence is a decision, not a default.** An `optional` slot means *optional to
wire*, never *optional to decide*. The slots below carry an `AbsencePolicy`
(#363; `packages/core/src/modules/manifest/absence-policy.mts`). Leaving one
unfilled without writing its declaration refuses boot, naming the config line to
write. This is deliberately stronger than defaulting to something harmless — a
default hands a capability to a composition that never asked for it and calls
that safety.

| Slot | Policy | Declared absent by |
| --- | --- | --- |
| `auditSink` | `AUDIT_SINK_ABSENCE_POLICY` | `audit.sink.type = "none"` |
| `accessTokenDenylist` | `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` | `oauth.revocation.accessToken = "unsupported"` |
| `subjectRevocation` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `subjectSessionIndex` | `SUBJECT_REVOCATION_ABSENCE_POLICY` | `oauth.revocation.subject = "unsupported"` |
| `deviceCodeStore` | `DEVICE_CODE_STORE_ABSENCE_POLICY` | `oauth.deviceAuthorization.store = "unsupported"` |

The subject-revocation pair shares one policy on purpose: two components, one
capability, so a deployment without them has one thing to declare rather than
two. `deviceCodeStore` joined with #443, which this paragraph missed while it
still said "three"; the table is now checked against the manifests that attach
each policy, the same way the slot table is (#458).

A declaration says why a slot is empty; it does not stand in for the component
where a feature needs it. `oauth.deviceAuthorization.store = "unsupported"` is
for a deployment that leaves the grant off — `deviceGrantModule` with the grant
enabled refuses to boot without a store, whatever the declaration says (#626).

**Replica safety.** In-process state stores are correct on one node and wrong on
several. `deployment.mode = "multi"` with one wired refuses boot, naming each
offender and what diverges per replica; `"single"` is silent; unset warns. The
list of unsafe modules is drift-guarded (#304), so a new in-memory adapter cannot
be silently replica-unsafe.

**Shutdown.** A component that holds a connection or a timer registers its
teardown with `lifecycleRegistrar`; `dispose()` drains in reverse-topological
order.

**Proving an implementation.** Several ports ship a conformance suite an
out-of-tree adapter can import and run:

| Port | Suite |
| --- | --- |
| `KeyStore` | `packages/core/src/keys/__tests__/keyStore.contract.mts` |
| `SubjectSessionIndex` | `packages/core/src/user-sessions/__tests__/subjectSessionIndex.contract.mts` |
| `SubjectRevocation` | `packages/core/src/user-sessions/__tests__/subjectRevocation.contract.mts` |
| `AccessTokenDenylist` | `packages/core/src/access-token-denylist/__tests__/adapters.contract.mts` |
| `ChallengeStore` | `packages/core/src/challenges/__tests__/adapters.contract.mts` |
| `ConsentStore` | `packages/core/src/consents/__tests__/adapters.contract.mts` |
| `DeviceCodeStore` | `packages/core/src/device-authorization/__tests__/adapters.contract.mts` |
| `FederationGrantStore` | `packages/core/src/federation-grants/__tests__/store.contract.mts` |
| `PendingConsentStore` | `packages/core/src/consents/__tests__/pending.contract.mts` |
| `ReplaySeenSet` | `packages/core/src/replay-seen-set/__tests__/adapters.contract.mts` |
| `RefreshTokenFamilyStore` | `packages/core/src/refresh-token-family/__tests__/adapters.contract.mts` |
| `WebAuthnCredentialStore` | `packages/core/src/webauthn-credentials/__tests__/adapters.contract.mts` |
| `UserSessionStore` | `packages/redis/__tests__/userSessionStore.contract.mts` |
| `SessionRPRegistry` | `packages/redis/__tests__/sessionRPRegistry.contract.mts` |
| `SessionFamilyIndex` | `packages/redis/__tests__/sessionFamilyIndex.contract.mts` |
| `SessionFederationIndex` | `packages/redis/__tests__/sessionFederationIndex.contract.mts` |

Each is run against every in-repo implementation of its port, which is what makes
it a description of the contract rather than of one adapter. Some live in
`packages/redis/__tests__/` because a contract file cannot be imported across a
package boundary — those are duplicated from the core copy, differing only in
how they import the port's type. A new port should
gain one; "typed and swappable" means an implementer can prove they got it right,
not that they read the interface carefully.
