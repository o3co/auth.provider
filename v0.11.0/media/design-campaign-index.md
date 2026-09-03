# Design-campaign provenance index

**This is a historical provenance index — cite it for provenance, never as sole rationale for new code.**

The identifiers below (`A1 §5.1`, `IH-16`, `D-6`, `Wave 5d`, …) were coined inside
development-campaign sessions whose source documents were never committed. Code and
READMEs cite them as design authority; this index re-derives what each identifier
meant from the surviving citation sites, so the citations resolve again. Where a
meaning is inferred rather than certain it is marked, and identifiers whose meaning
did not survive at all are deliberately **absent** (they live only in the inventory
test's exclusion list — do not cite them as rationale for anything).

**Forward rule.** New code MUST NOT cite a session-local campaign identifier as its
sole rationale. Write the rationale itself in place; when linkage to a decision is
wanted, anchor it in a durable artifact — an issue or PR number, a CHANGELOG entry,
an ADR — and add the campaign ID only as an optional suffix. Every meaning this
index could recover survived through exactly those durable anchors; every meaning it
could not recover existed only in a session.

Confidence marks: `[verified]` — unambiguous from citations; `[reconstructed]` —
plausible inference; `[inference-only]` — bare citation, content inferred from
usage alone. The enforcement arm is
`packages/core/src/__tests__/campaignVocabulary.drift.test.mts` (two directions:
every campaign ID cited in shipped source/READMEs must appear here; every ID here
must still be cited somewhere). CHANGELOGs are historical narrative: they count
as occurrence sites for the second direction, but a CHANGELOG citation never
*requires* an index entry. Series-prefix expansions are `[reconstructed]` unless noted —
they name the campaign's own shorthand, and the per-ID meanings do not depend on
them.

## Timeline

| Milestone | What shipped | Anchor |
| --- | --- | --- |
| v0.4.0 (2026-04-22) | TODO-F plan capstone: F-6 federation-token endpoint, federation-interface + session-store redesign | CHANGELOG `[0.4.0]` |
| Phases 1–9 → v0.5.x | Module-system redesign: `defineModule` manifests, boot planner; Phase 9 = A2-γ caller migration, `LegacyModule` removal | CHANGELOG "Phase 1-9"; core README |
| Phase 10 | Redis adapter relocation → `@o3co/auth-provider-redis` | CHANGELOG |
| Wave 5d | Redis adapter switches + external-ioredis migration (OR-9/OR-4/IH-14; pairs with D-2 v2) | `application.schema.mts` redis keys |
| Wave 5g | "ts-safety-batch" type-safety hardening (TS-2/TS-6) | redis/*, foundation |
| Phase F → v0.5.2/0.5.3 (2026-05-09) | Security-audit remediation batches F1–F13: D-* closures, error-envelope unification, TOCTOU re-checks, limiter hardening, OIDC compliance | CHANGELOG "Phase F —" headings |
| Phase G → v0.6.0 (2026-05-12) | Migration-flag removals M1–M6 + S2 `legacyTypAccept` default flip | CHANGELOG |
| Wave 1 → v0.7.0 (2026-05-15) | Roadmap wave 1: RFC 7009 revoke + denylist, `client_credentials`, webauthn first slice, RFC 8707 stage 1 | CHANGELOG `[0.7.0]` |
| Wave 2 → v0.8.0 (2026-05-20) | Token-binding cluster: DPoP, mTLS, the §9.2 refresh-time enforcement matrix, ADR | CHANGELOG `[0.8.0]` |
| v0.9.0 / v0.10.0 | Post-campaign; v0.10.0's erosion review created `docs/design-vocabulary.md` | CHANGELOG |

Three ID-space hazards this structure resolves: **"F6" is two things** (chapter 1's
plan item TODO-F-6 vs chapter 3's Phase-F PR batch "F6 PR1"); **"S2" is two things**
(chapter 3's Phase-G security item vs chapter 5's Claude-review finding); **Wave
numbering is two schemes** (chapter 3's remediation batches 5d/5g vs chapter 4's
roadmap waves 1/2 — waves 3/4 and 5a–c/e–f were never used).

---

## 1. TODO-F plan era (issue #101 → v0.4.0)

The pre-campaign feature plan. All six items shipped by v0.4.0.

- **F-1** — plumbing: `UserSessionStore` + `FederationTokenStore` optional slots (memory/redis; AES-256-GCM for stored refresh_token); the all-or-none boot guard survives in validate-manifests [verified]
- **F-2** — login wiring: federation callback creates the UserSession and writes `sid`; local login mirrored later [reconstructed]
- **F-3** — cascading revocation: `family_id` + `sid` claims, introspect family-revoke fail-closed cascade, CodeData nonce/sid round-trip [verified]
- **F-4** — OIDC id_token + `/userinfo` + scope-gated claim filter [verified]
- **F-5** — logout: `end_session_endpoint`, back/front-channel metadata, logout helpers [verified]
- **F-6** — `POST /oauth/federation/:name/token` proxy (auto-refresh + advisory lock; client opt-in, deny-by-default) [verified]

---

## 2. Module-system redesign — the A-specs (v0.5.0, Phases 5–9)

Five (plus two minor) uncommitted spec documents drove the v0.5.0 redesign. Per-spec
subject, home, and the sections still cited from shipped code:

### A1 — Challenge Store + Replay Seen Set + Default Ceremony (Phase 5) [verified]

Home: `packages/core/src/challenges/`, `packages/core/src/replay-seen-set/` (Redis adapters in `packages/redis`).

§4 breaking changes vs the closed PR #96 spec (SingleUseTokenStore never shipped) · §5.1 `ChallengeStore` primitive: epoch-ms expiry, issue/find/consume atomicity, N-parallel single-winner · §5.2 `ReplaySeenSet` + concurrency contract · §5.3 `ChallengeCeremony` 3-outcome union, no domain throws · §5.4 `ChallengeStorageError` + adapter throw matrix · §5.5 optional ComponentMap slots via declaration merge; unnamespaced names reserved first-party · §5.6 factory register-throws/replace · §6 default ceremony find→consume→markSeen, fail-closed · §6.1 acknowledged consume→markSeen propagation gap (bounded, no security impact) · §7.1 memory adapter contracts · §7.2 Redis adapter (single-key SET-NX, no transactions) · §7.3 canonical key encoding for cross-adapter parity · §8.1 module wiring + override path · §13.1 shared adapter contract-test suite — all [verified]

### A2-α — Module manifest authoring: `ModuleSpec` / `defineModule` [verified]

Home: `packages/core/src/modules/manifest/`.

§2.1 two-type model (authoring `ModuleSpec` vs erased `Module`) · §3 `defineModule` replaces v0.4.x `init(ctx)` · §3.1 inference via TS 5.0 `const` generic modifier · §3.2 provider = one factory over typed deps · §4 `contributes` = protocol-level features · §4.1 per-kind contribution factories (v0.5.0 baseline 7 kinds) · §4.2 contribution factories share the declaring module's deps · §4.5 per-kind collision policy (throw on duplicate; same-instance dedup for auditHooks/grantPolicyHooks) · §4.6 `RouteContribution` (Amendment 1 = dep-using route factories) · §4.7 route handler interior opaque to the planner · §5 `overrides`: explicit replacement, missing target throws · §6.1 ComponentMap slot declaration merge · §6.5 `SYNTHETIC_COMPONENT_KEYS` rejected in provides/bootstrap/override · §7.5 a module MAY have no `contributes` — all [verified]

### A2-β — Boot planner pipeline: 6-stage `createApp`, `BootError`, `AppHandle` [verified]

Home: `packages/core/src/boot/` (validate-manifests → plan-boot → materialize → apply-contributions → freeze-world → assemble-app).

§3.2 stage types · §4.1 `lifecycle` manifest field · §4.2 route advertisements · §5.1 Stage 1 validateManifests normative steps 1–14 (13 = config schema compose/parse; "amendment 2026-05" = issue #101 partial-wiring reasons, steps 13.6/13.7) · §5.2 Stage 2 planBoot: cycle detection, Kahn topo sort + declaration-order tie-break, activation closure · §5.3 Stage 3 materialize: bootstrap → overrides → providers, reverse rollback on throw · §5.4 Stage 4 applyContributions: synthetic projections, partial rollback, list-kinds · §5.5 Stage 5 freezeWorld · §5.6 Stage 6 assembleApp · §5.7 Express-compatible handler shape · §6.1 `BootError` contract (`BootStage`, 26 reason literals, per-reason Details) · §6.2 `CreateAppOptions`, `DefaultBootstrapMap`, collector contracts incl. mandatory `freeze()` · §6.3 `AppHandle` shape · §8.1 `dispose()` reverse-topological cleanup · §9 v0.4.x boot-model removal — [verified]; §6.4 boot barrel export surface, §12 integration-test plan — [inference-only]

### A2-γ — Caller migration (Phase 9): per-package moves to manifests + public-surface cuts [verified]

Home: cross-package (core / oauth / oauth-token-exchange / session / templates-standalone).

§3.1 global mandate: single-phase async `createApp`, ComponentMap decomposition, GrantRegistry internalised · §3.2.1–.3 oauth modules become `({config})` const manifests · §3.3 token-exchange validator registry off the public surface → `contributes.tokenExchangeValidators` · §3.4 `sessionModule` const Module; requires `userRepository` · §3.5 federation registration extracted to per-federation modules · §3.8 standalone module-split worked example · §4 composition-root worked example · §5.3 per-contribution-kind disposal gap · §6.1+§7 prescribed `package.json#exports` subpaths incl. `/testing` · §7.2 `TestInspect` read-only escape hatch, never on `AppHandle` · §9.4 clean break, no deprecation shims · §11.5 synthetic keys = planner projections only · Amendments 1 (routes-factory shape), 3 (`grantHandlerResolver`), 4 (four-store session split), 5 (`sessionModule` requires) — [verified]; §2.4 LegacyModule inventory, Amendment 6 — [reconstructed]

### A3 — Refresh-token family (Phase 6) [verified]

Home: `packages/core/src/refresh-token-family/` (Redis adapter in `packages/redis`).

§4 breaking vs v0.4.x (`RefreshTokenStoreBase` deleted; rotate/revoke move to wrappers) · §5.1 store = "dumb" single-key CAS primitive, epoch-ms `number` expiry, ceremony classification in the wrapper, revoked family retains active jti for audit · §5.2 `RefreshTokenFamilyRotation` · §5.3 `RefreshTokenFamilyRevocation` + cascade checks · §5.4 `RefreshTokenStorageError` (mirrors A1's shape) · §5.5 three ComponentMap slots; legacy `refreshTokenStore` slot name retired · §5.6 factory pattern · §6.1 rotation ceremony (4-outcome) · §6.2 revocation · §7.1 memory adapter · §7.2 Redis WATCH/MULTI/EXEC CAS on a duplicated connection · §8.1 module wiring / direct-adapter path — [verified]; §9 in-tree caller rewiring plan — [inference-only]

### A4 — User-session decomposition (Phase 8): four sibling stores + logout cascade [verified]

Home: `packages/core/src/user-sessions/` (Redis in `packages/redis`; consumers oauth/session).

§3.4 (+§8) all-or-nothing wiring invariant (justifies non-null assertions) · §4 breaking items 1–5 (`UserSessionStoreBase` split into siblings) · §5.1 `UserSessionStore`: post-create immutable, `Date` expiry (deliberate two-tier design vs A3's epoch-ms), delete = global invalidation · §5.2 `SessionRPRegistry` (logout fanout; TTL = session expiry) · §5.3 `SessionFamilyIndex` · §5.4 `SessionFederationIndex` — insertion order LOAD-BEARING for the cascade · §5.6 no legacy broad slots (with A3 §5.5; "spec X1 fix" is the cross-spec amendment) · §5.7 four-factory registry, no `freeze()` · §6 cascade: siblings first, `UserSessionStore.delete` LAST · §6.1 no cross-store atomicity; reverse-order rollback obligation · §6.2 four-step logout cascade in fixed order · §7.1 memory adapters with defensive copies · §7.2 Redis ZADD-NX sorted-set + `${keyPrefix}${sid}` hash schemes · §8.1–8.3 bundled memory module; `overrideComponents` skips `provides[K]` — [verified]; §8.4, §10.1, §11.2, §13.1, §13.5 — [inference-only]

### A5 — Federation redirect-policy split (Phase 7) [verified]

Home: `packages/session/src/federations/` (+ boot enforcement in core; instances in federation-google/github).

§4 breaking: `validateRedirect`/`resolveCallbackRedirect` removed from `FederationProvider`; pairing required · §5.2 `FederationRedirectPolicy` (fail-closed) · §5.3 `FederationRedirectPolicyFactory` · §6 `federationRedirectPolicies` contributes extension + NORMATIVE pairing invariant · §7 synthetic key `federationRedirectPolicyResolver` · §8.1 stable view reference from step 0 · §8.2 validate-manifests step 7.5 pairing check + BootError reason · §10.1 Google worked example · §10.2 GitHub worked example — [verified]; §9 export surface — [inference-only]

### A6 + A7 — registry duplicate-throw policy [reconstructed]

Cited interleaved with A2-γ (CHANGELOG v0.5.0 era): adapter/collector registries
throw on duplicate registration and offer `replace` for intentional swap — the
register/replace pattern A1 §5.6 and A3 §5.6 instantiate.

### Named artifacts

- **Phase 10 addendum §3 — the "backing client interface" pattern** [verified]: narrow, vendor-agnostic Redis-command client interfaces (`ChallengeStoreClient`, `RateLimiterClient`, …) consumed by adapters so the redis package's main entry never pulls ioredis types; `makeIoredisClients` at the `/ioredis` subpath constructs them. Home: `packages/redis/src/clients.mts` + `ioredis.mts`. The "v0.5.0 pre-tag interface review S3" decision relocated the interfaces out of core.
- **"the §9.2 matrix"** [verified]: NOT an A-spec section — Wave 2 token-binding spec §9.2. The five-row refresh-time enforcement matrix correlating a bound refresh token's persisted `cnf` claim with the request-time DPoP proof / mTLS certificate in the `refresh_token` grant. Home: `packages/oauth` refresh grant via core's `confirmationMatch.mts`; integration tests in `packages/dpop` / `packages/mtls`. Anchor: v0.8.0 CHANGELOG; ADR `2026-05-20-token-binding-first-class-abstraction.md`.
- **const-Module pattern (A5 §10.2)** [verified]: a package exports a pre-built `defineModule` **const value** (not a factory); its config arrives through a typed ComponentMap slot listed in `requires`; it contributes the paired `federations.<name>` + `federationRedirectPolicies.<name>`. §10.1/§10.2 are the Google/GitHub instances; webauthn and session cite it as the recommended custom-module shape.

---

## 3. v0.5.x audit campaign (Phase F, Phase G, Waves 5d/5g)

A whole-codebase security/design audit remediated in PR batches ("Phase F — F1…F13"
CHANGELOG headings — a numbering unrelated to chapter 1's TODO-F items). Findings
were tagged by series; prefix expansions are the campaign's own shorthand,
`[reconstructed]` except where noted.

### D-* — design decisions

- **D-1** — Code/CodeData identity binding: identity + grantedScope persist on the authorization-code record; policy evaluated once at `/authorize`; session-side binding removed [verified]
- **D-2 v2** — standalone ioredis unification: one externally-owned client via `standaloneRedisClientsModule` (supersedes the uncited v1 design; pairs with Wave 5d) [verified]
- **D-3** — close SF-11 by documentation rather than `Object.freeze()` on AdapterFactory ("wrong-layer framing") [reconstructed — the resolution document was never committed and is lost]
- **D-4** — structured `Logger` interface + ComponentMap `logger` slot (six levels, consoleLogger fallback) [verified]
- **D-5** — `BuilderContext.lifecycle`: boot-planner-owned LifecycleRegistrar drives `dispose()`; **D-5 v2** — redis adapters expose no dispose; the consumer owns the client lifecycle [verified / reconstructed]
- **D-6** — client-authentication redesign (with PB-2): `clientAuthMw` resolves the client via `findById`; no body-spoofable identity; `azp` = authenticated client; RT bound to authorized party [verified]
- **D-8** — routes detect refresh support by the published `SupportsRefresh` interface name [reconstructed]
- **D-9** — federation-token lock release is atomic compare-and-delete (Lua CAS); closes the TTL-expired-holder race (same bug as OR-13/SF-4/CR-1) [verified]
- **D-10** — Redis 7.2 LTS minimum floor (`EXPIRE NX/GT` semantics; with CR-3) [verified]

### CP-* — grant/policy contract points

CP-1 grantPolicy receives ctx.ip + userAgent · CP-2 initial rt+jwt family registration, graceful skip when unwired · CP-6 rate-limit hook fails OPEN + `rate_limit.unavailable` audit · CP-7 MFA provider throw → controlled 500 + tx delete · CP-10 same normalized IP in limiter key and check context · CP-11 issuer passed to policy is config-only, never Host-derived · CP-12 empty granted-scope → `null` so the token response omits `scope` (never `scope: ""`) · CP-13 policy must not expand the client scope ceiling → `invalid_scope` · CP-14 empty-narrowed grantedScope persisted as `undefined` · CP-15 issued scope ⊆ requested (RFC 6749 §6) · CP-16/CP-17 fail-closed 503 when the family store throws (register / rotate) · CP-18 fail-closed grantPolicy scope/audience validation (granted ⊆ effective request set; audience vs full client ceiling) · CP-20 boot invariant: grantPolicy wired ⇒ non-empty `oauth.jwt.issuer` (`BootError: grant-policy-without-issuer`) — all [verified]

### IH-* — input hardening (expansion [verified])

IH-2 code record persists sid/nonce/redirect_uri/grantedScope/audience (was silently dropped); identity derives from codeData · IH-3 unknown `family_id` no longer falls through to success (`unknownFamilyPolicy`, default reject) · IH-4 strict redirect_uri binding at `/token` (RFC 6749 §4.1.3; no vacuous pass) · IH-6 `/authorize` requires `openid` scope by default as an OIDC OP · IH-8 RFC 8707 resource→audience binding (first in token-exchange, later general) · IH-9 HS256 rotation via `previousSecrets` · IH-10 removed config fields nothing read · IH-11 periodic GC owned by `ctx.lifecycle` · IH-13 RT-family absolute expiry cap set at creation (no sliding window) · IH-14 `buildModules` includes the memory rate-limiter by default · IH-16 nonce hardening (length/charset) · IH-17 schema field tightened to required — all [verified]

### OR-* — operational readiness

OR-1 standalone wires the Redis RT-family store (in-memory broke multi-replica refresh) · OR-2 RedisCodeRepository lifecycle on `ctx.lifecycle` · OR-4 `buildModules` switches the four user-session stores per config · OR-5 rate-limiter `failMode` outage policy · OR-8 Redis sid sorted-set insertion counter stays monotonic across restarts · OR-9 (Wave 5d) Redis code-repository adapter switch; external ioredis, consumer-owned lifecycle · OR-12 production guard refusing plaintext federation-token encryption · OR-13 advisory-lock release race → atomic Lua compare-and-delete (=SF-4/CR-1/D-9) — all [verified]

### SF-* — security findings

SF-1 central JWT `typ` enforcement / `legacyTypAccept` (default flipped by Phase G S2) · SF-3 corrupt PKCE code records no longer pass (S256 and plain) · SF-4 advisory-lock check-then-delete race (=OR-13) · SF-5 token-exchange policy scope ⊆ request set · SF-6 RTs lacking jti/family_id no longer skip rotation (replay-detection bypass) · SF-8 `/introspect` returns `token_type: "Bearer"` and accepts access tokens only · SF-10 bounded in-memory rate-limiter bucket map · SF-12 federation refresh post-lock re-read guard (no `?? ""` fallback) · SF-13 federation refresh error mapping for openid-client v6 structured errors — [verified]; SF-11 AdapterFactory returned-object mutability handled by documentation (per D-3) — [reconstructed]

### MIN-* — minor findings

MIN-2 `__Host-` cookie prefix constraints (Secure, Path=/, no Domain) · MIN-3 preserve the bundled Redis user-session key namespace · MIN-4 constant-time PKCE verifier compare (encode-before-length) — all [verified]

### PB-* — protocol bugs (expansion [reconstructed], low confidence)

PB-1 RT reuse revokes the whole family (RFC 6819 §5.2.2); fail-closed 503 when the revocation dependency is missing · PB-2 client-authentication redesign (with D-6) · PB-4 Google federation OIDC compliance (nonce binding, jwks_uri, alg pin, fail-closed) · PB-5 UserInfo `sub` must bind to id_token `sub` (OIDC §5.3.2; N/A for GitHub — no claim to bind) — all [verified]

### AS-* — API surface

AS-1/AS-2 unified RFC 6749 §5.2 error envelope (+429 body migration) · AS-3 `removeBySid(sid)` rename · AS-4 documented `expiresAtMs: number` two-tier expiry · AS-7 `*Base` alias policy (canonical names carry no suffix) · AS-8 `GrantRegistry` deprecated as a public export, later removed (internal to the boot planner) · AS-9 Redis session sub-adapter builders · AS-10 JSDoc naming consistency (`getByCode`→`findByCode`) · AS-11 map-like store verb renames · AS-12 `legacyTokenCompat` flag (orthogonal to SF-1's `legacyTypAccept`) — all [verified]

### CR-* / CC-* / TS-* / SC-* / TD-* — sibling series

- **CR (concurrency/race)**: CR-1 lock-release race (=OR-13) · CR-2 binding identity persisted onto the code record · CR-3 Redis pipeline TTL truncation under concurrent writes (→ D-10) · CR-4 second-store re-check before `addFamilyId` · CR-5 unknown option shape throws — all [verified]
- **CC (config correctness)**: CC-2 `unknownFamilyPolicy` key · CC-3 production misconfiguration hard-fails (warn-only in dev; residual closed by OR-12) · CC-4 compiled test artifacts must not ship (CI guard) · CC-5 readonly public DTOs — all [verified]
- **TS (type safety, Wave 5g)**: TS-1 code-record payload persistence (=IH-2) · TS-2 runtime validation replaces the `as User` cast in HttpUserRepository · TS-3 corrupt Redis envelope validation replaces `JSON.parse as` · TS-4 `resolvePkceSupportedMethods` per-element narrowing · TS-6 refresh-family builder structural client guard — all [verified]
- **SC (supply chain)**: SC-4 pnpm version pinned in both package.json · SC-5 dependency pin alignment · SC-6 dependency major bump for Express 5 · SC-7 `pnpm audit --prod` CI gate — all [verified]
- **TD (test debt)**: TD-1 code-persistence tests · TD-2 unknown-family tests · TD-4 TTL/extended-field round-trips · TD-5/TD-10 residual OAuth-route + introspection-cascade tests · TD-6 federation cleanup/replay assertions · TD-7 SF-6 rejection tests · TD-9 inspect-pattern for exchangeCode — all [verified]

Phase G's own items were M1–M6 (migration-flag removals) plus its S2 (the
`legacyTypAccept` default flip — see the S-series note in chapter 5).

---

## 4. Roadmap waves (v0.7.0 Wave 1, v0.8.0 Wave 2)

Product roadmap waves, a numbering unrelated to chapter 3's remediation batches.

- **Wave 1 (v0.7.0)** — RFC 7009 revocation + access-token denylist, `client_credentials` grant, the webauthn first slice, RFC 8707 stage 1. Webauthn's plan tasks are the **T-series** (T21–T31): T28 = `POST /oauth/webauthn/registration/verify` route; T31 = `webauthnModule` boot integration. Its spec sections are cited as **S7** (multi-origin `expectedOrigins`), **S9** (Wave 1 spec §4.5: `ignoreExpiration` restricted to the revoke route, with a CI use-site guardrail), **S11** (dogfood baselines: attestation `"none"`, 120s timeout, `"preferred"` UV), **S12** (exact-pin discipline for `@simplewebauthn/server`) — all [verified]. T2 is a review note (widen timing margins against CI flake) [verified].
- **Wave 2 (v0.8.0)** — token-binding cluster: DPoP (RFC 9449), mTLS (RFC 8705), grant-side `cnf` emission, and **the §9.2 matrix** (chapter 2, Named artifacts). Anchored by the token-binding ADR.

---

## 5. Review series (cross-cutting)

Several later review passes reused short S-tags, so **the S-series is not one
campaign**:

| Tag | Campaign | Meaning |
| --- | --- | --- |
| S1 | Claude multi-agent review | missing required dep at apply-time must throw [verified] |
| S2 (a) | Phase G security | flip `legacyTypAccept` default true→false [verified] |
| S2 (b) | Claude multi-agent review | inconsistent diagnostic in validate-manifests [verified] |
| S3 | v0.5.0 pre-tag interface review | backing-client interfaces live in `@o3co/auth-provider-redis`, not core (→ Phase 10 addendum §3) [verified] |
| S7–S12 | webauthn Wave 1 spec / dogfood | see chapter 4 [verified] |

"Codex Delta" tags mark findings from a Codex review pass (e.g. Delta 3:
encode-before-length in MIN-4). A citation of a bare S-number must be read against
its file's campaign context — this table is the disambiguator.
