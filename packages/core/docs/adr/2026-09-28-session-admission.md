# Session admission: one decision point for every consumer of an authenticated browser session, and the requirements that extend it

- Status: accepted (2026-09-28); not implemented yet — the build order below is the plan at acceptance
- Date: 2026-09-28
- Amends: the MFA ADR (`2026-09-25-multi-factor-authentication.md`) — its D8 coordinator slot, D16's per-consumer wiring, D19/D20's `mfa.mode` in core, build-order steps 7, 13, 14 and 22, and O2. The amendments are listed in §7 and recorded in that document.
- Written against: `develop` at `db9c080e2` (#707, the MFA ADR's step 5). Every "today" below was checked there.

## Context

### What the owner decided

MFA is not a feature that adds an endpoint or a grant. It changes what "logged in" means, so every place that lets an authenticated browser session do something must ask the same question. The MFA ADR answered that by giving core a pure rule (`decideMfaRequirement`) and planning to wire it into each consumer, one by one (its build-order steps 13 and 14), with `mfaCoordinator` as an optional slot on the `session` and `oauth` manifests and `mfa.mode` as a core key every consumer reads.

The owner asked for the split to be made explicit instead. **Plugins** add behaviour and never need to know about one another. **Extensions** change what an existing decision means, and reach the plugins only through one port in core. Consumers then depend on the port, not on the extension; a second extension of the same kind — a risk score, a re-consent, an account hold — touches the port's contributors and nothing else.

The MFA work is paused after its step 5 (#707, merged 2026-09-28). This record designs the port, moves the consumers onto it before MFA resumes, and says what MFA becomes on top of it.

### What exists today

**Thirteen consumer sites, each with its own reading.** `/authorize` (`readLiveSession`, private to `packages/oauth/src/routes/authorize.mts`), consent (`refuseUnlessLive`, `consent.mts`), the `session` grant (inline, `grants/session.mts`), the `authorization_code` grant (two inline durable reads, `grants/authorization.mts`), the refresh grant (from the token's `sid`, `grants/refreshToken.mts`), device verification (`livenessOf`, `packages/device-grant/src/verificationEndpoint.mts`), the federation-grants browser half (`judge` / `sessionHolds`, `packages/federation-grants/src/browserRoutes.mts`), the federation link start and callback (inline, `packages/session/src/routes/Federation.mts`), and WebAuthn registration (`req.webauthnSubject`, which the deployment's middleware sets). No core helper reads a live session.

**They disagree.**

- A cookie with `isAuthenticated` but no `sid`, while a store is wired, is open at `/authorize` and consent — a code is then minted without `sid` and refused at `/token` — `400 invalid_grant` at the two grants, `401 login_required` at device verification, `403` in federation grants, `401` at the link start.
- The durable record's `sub` is compared with the cookie's `user.id` by the grants, device verification and federation grants, and not by `/authorize` or consent.
- A session-store outage on an interactive `/authorize` is answered with a redirect to the login page (`authorize.mts`, the non-silent branch), not `temporarily_unavailable`.
- The subject-revocation boundary (`subjectRevocation.revokedBefore`, read against `authTime` with `coveredByRevocationBoundary`) is applied by device verification and federation grants, and through `verifyJwt` on the token side, and by nothing else. `/authorize`, consent, the `session` grant, the `authorization_code` grant and the link flow admit a session established before the subject's sessions were revoked, until the session's own expiry. The `subjectSessionIndex` write at login is best-effort (`Session.mts`, `Federation.mts`), so the boundary is the only thing that stops a session the index missed — and it does not reach the consumers that mint codes.

**What the MFA ADR already put in core** (its steps 3–5, none of it released): `sessionAuthentication` / `vouchedAmr` / `requirementSession` (`user-sessions/authentication.mts`); the `authentication` key on `UserSession`, the upstream split and `recordSecondFactor` (#707); `selectAcr` / `stepUpReach` / `readAcrTable` / `producibleAmr` / `vouchableAcrTable` and the merged rule `decideMfaRequirement` (`mfa/requirement.mts`); the `mfaCoordinator` slot with `MFA_ABSENCE_POLICY` (`mfa/coordinator.mts`); the `mfaFactors` kind with its synthetic `mfaFactorResolver`; the factor and transaction stores, `mail/`, the witness; `mfa.mode` locked to `"off"` in core's schema. `decideMfaRequirement` has no product caller; `selectAcr` has one (`/authorize`); `mfaCoordinator` is declared and consulted by nobody.

**The module system's constraints** (checked against `packages/core/src/boot/` and `modules/manifest/`):

- A contribution kind shared by bundled packages must be a core built-in: its collector, its read-side projection and its value checks are hard-coded in `boot/` (`BUILTIN_CONTRIBUTION_KINDS`, `mergeWithBuiltins`, `prepareSyntheticProjections`, `checkNameKeyedValue`).
- Only name-keyed kinds have a read-side projection — a synthetic key, always present, never provided, bootstrapped or overridden — and a provider must read it lazily, because contributions register in stage 4, after the `provides` factories of stage 3 (`readableFromStage4`). `mfaFactors` → `mfaFactorResolver` → `MfaCoordinator.secondFactorMethods` is the one precedent.
- Core's own middleware (CORS, token binding, the protected-resource binding, `grantMiddleware`) is mounted before every route contribution, `session-middleware` included, so it cannot see `req.session`; and a route contribution's `before:` target becomes mandatory in every composition. There is no "before every consumer" middleware.
- An `AbsencePolicy` fires when a slot is not in the planned keys and the config lacks the declaration; a synthetic key is never planned, so a policy cannot express "nobody contributed to a kind".
- An override of a name-keyed kind can `replace` a contribution by name, and a nullable factory lets it answer `null`.

### Conventions this design keeps

A store outage is `503 temporarily_unavailable`, logged once at error with `store`, `step` and `loggableError`'s projection, and never read as a verdict. An unsupported security-relevant request parameter is refused, not ignored. Every concept has one home (`docs/design-vocabulary.md`), guarded by a drift test. Pages are the deployment's. A PR that adds a module, a slot or a kind adds its rows to `docs/adapter-surface.md`, the replica-safety declarations, the audit inventory, `tools/composition`'s fixture and the template's all-modules test.

## Vocabulary

- **Admission**: the decision that an authenticated browser session — or the primary authentication about to become one — may proceed with an action. Core's `admitSession` and `admitPrimary` make it.
- **Session requirement** (a *requirement*): a condition an extension adds to admission, registered under the `sessionRequirements` contribution kind. MFA is the first.
- **Action**: what the consumer is about to let the session do, named by the consumer (`oauth.authorize`, `device.approve`, …). Requirements decide per action.
- **Reach**: the `amr` values a step-up through a requirement can add to a session — the MFA ADR's `secondFactorMethods`, generalised.
- **Interruption**: a requirement's answer at establishment time — the login does not complete yet, and the browser is told what to do next.

## Decisions

### D1 — One decision point in core, called by every consumer; not middleware, not a module

Core gains a leaf, `packages/core/src/session-admission/`, exporting two async functions with explicit dependencies:

```ts
admitSession(deps: AdmissionDeps, request: AdmissionRequest): Promise<Admission>
admitPrimary(deps: AdmissionDeps, primary: PrimaryAuthentication): Promise<PrimaryAdmission>

interface AdmissionDeps {
	readonly userSessionStore: UserSessionStore | undefined;   // the consumer's slot, as wired
	readonly subjectRevocation: SubjectRevocation | undefined; // the consumer's slot, as wired
	readonly requirements: SessionRequirementResolver;         // the synthetic key (D3)
	readonly acrTable: AcrTable;                                // the vouchable table (D6); empty when the consumer has none
	readonly logger: Logger | undefined;
	readonly now?: () => Date;                                  // test seam, documented as such
}
```

Why a function and not middleware: core's middleware is mounted before `session-middleware` and cannot see the cookie; a route-level middleware would need every consumer route as a `before:` target, making each mandatory in every composition; and the answer to a refusal differs by protocol — a redirect, an RFC 6749 error, a plain `403` — which is the consumer's to give. Why not a module every composition lists: a hand-written composition that forgets it would fail the requires-closure at boot for no gain, and the function needs nothing a module would hold — the slots are the consumer's own, already declared.

The MFA ADR's rule was the same shape — one pure function each consumer calls — for the same reasons. This record widens it from "the MFA requirement" to "the admission", and moves the read of the session into it.

### D2 — What `admitSession` judges, in order, and what it answers

Input: what the consumer holds about the session, and what it is about to do.

```ts
interface AdmissionRequest {
	/** The express session's claim — `isAuthenticated`, `sid`, `user.id` — or the same three from another carrier (D9). */
	readonly claim: {
		readonly authenticated: boolean;
		readonly sid: string | undefined;
		readonly subject: string | undefined;
	};
	readonly action: string;                                       // D4
	readonly asks?: { readonly acrValues?: readonly string[] };    // `/authorize` only
}
```

Steps, each fail-closed:

1. **Claim.** `authenticated !== true` → `unauthenticated`.
2. **Live read.** With a store: no `sid` → `not_live` (`no_sid`); `store.get(sid)` answering `null` → `not_live` (`gone`); a throw → `unavailable` (`store: "user_session"`). Without a store: `session` is `null`, and the requirements decide what that means — the MFA requirement refuses boot without a store (D6), and with no requirement a cookie-only composition is admitted as today.
3. **Subject.** When both are present, the record's `sub` must equal the claim's `subject`; else `not_live` (`subject_mismatch`), logged once at warn.
4. **Revocation boundary.** With `subjectRevocation` wired: `revokedBefore(sub)`; a throw, or a boundary that is not a valid date or `null`, → `unavailable` (`store: "revocation_boundary"`); `coveredByRevocationBoundary(session.authTime, boundary, DEFAULT_SUBJECT_REVOCATION_SKEW_MS)` → `revoked`. This is the reading device verification and federation grants apply today; its home moves to this leaf (D10), and they import it from here.
5. **Requirements.** Each registered requirement's `admit(input)`, in registration order (D3), with `input = { session, authentication: requirementSession(session), action, asks, now }`. The first verdict that is not `met` is taken and the rest are not asked. A requirement that throws → `unavailable` (`store: <its name>`), logged once: a requirement is asked about a session, never trusted to fail open.
6. **`acr_values`.** When `asks.acrValues` is non-empty: `selectAcr(acrValues, vouchedAmr(session), acrTable, reach)`, with `reach` the union of every requirement's `reach`. `oauth.authorize.acrValues` is a core key and the table's drop is core's, so this is a built-in step, not a requirement.
7. **Merge** — the MFA ADR's D16 rule, now the admission's. With `R` = step 5's verdict and `A` = step 6's:

| `R` | `A` | Admission |
| --- | --- | --- |
| met | met, or nothing asked | `admitted`, with `acr` |
| met | unmet | `unmet` (`requirement: "acr"`) |
| met | step_up | `step_up` from the first requirement whose `reach` covers what the reachable entry lacks: its page, `A`'s reachable values as the hint |
| reauthenticate | anything but "no requested value is in the table" | `reauthenticate` (`R`'s name) |
| reauthenticate | no requested value is in the table | `unmet` (`acr`) — no login can meet it |
| step_up | unmet | `unmet` (`acr`) — no step-up can meet the request |
| step_up | met, step_up, or nothing asked | one `step_up`: `R`'s page, `A`'s reachable values as the hint |
| unmet | any | `unmet` (`R`'s name) |

Output:

```ts
type Admission =
	| { readonly outcome: "admitted"; readonly session: UserSession | null; readonly acr: string | undefined }
	| { readonly outcome: "unauthenticated" }
	| { readonly outcome: "not_live"; readonly reason: "no_sid" | "gone" | "subject_mismatch" }
	| { readonly outcome: "revoked" }
	| { readonly outcome: "reauthenticate"; readonly requirement: string }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly page: StepUpPage;
			readonly acrValues: readonly string[];
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string }
	| { readonly outcome: "unavailable"; readonly store: string };

/** The deployment's page for the step-up; the consumer appends its own return parameter. */
interface StepUpPage {
	readonly url: string;
	readonly params: Readonly<Record<string, string>>;
}
```

`admitted.session` is the live record the consumer then uses; it never reads the store again. `not_live`, `revoked` and `reauthenticate` are one class for a consumer — a new login is the remedy — and distinct in the type so a log line and an audit event can say which.

### D3 — The requirement contract, the `sessionRequirements` kind, and its resolver

```ts
interface SessionRequirement {
	/** The key it is contributed under; refused at boot otherwise (the `mfaFactors` rule). */
	readonly name: string;
	/** The `amr` values a step-up through this requirement can add; empty when it offers none. Read at request time. */
	readonly reach: ReadonlySet<string>;
	/** Use-time: the session, read once by admission, and the action. Throws only on an outage. */
	admit(input: RequirementInput): Promise<RequirementVerdict>;
	/** Establishment-time (D5); absent when the requirement never interrupts a login. */
	admitPrimary?(primary: PrimaryAuthentication): Promise<"establish" | Interruption>;
}

interface RequirementInput {
	readonly session: UserSession | null;
	readonly authentication: MfaRequirementSession | null;   // `requirementSession(session)`, renamed (D6)
	readonly action: string;
	readonly asks: AdmissionRequest["asks"];
	readonly now: Date;
}

type RequirementVerdict =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate" }
	| { readonly outcome: "step_up"; readonly page: StepUpPage; readonly whenStillUnmet: "reauthenticate" | "unmet" }
	| { readonly outcome: "unmet" };
```

- **Kind.** `sessionRequirements` is a name-keyed built-in kind (factory `(deps) => Contributed<SessionRequirement>`), collected like `mfaFactors` and projected by the synthetic key `sessionRequirementResolver` (`entries()` in registration order, `get(name)`). Consumers reach requirements only through the resolver, so their manifests name no extension: the resolver is always present and never in the requires-closure.
- **Not nullable, not overridable.** A factory answering `null`, or an `overrides.sessionRequirements` entry, refuses boot — a stage-1 refusal for the override, `contribute-factory-failed` for the value. A requirement is switched off by not installing it. The `dpop` / `mtls` precedent is a `null` mechanism; a mechanism protects a token it issued, a requirement protects every consumer, and nothing may quietly remove it from behind them.
- **Order.** Registration order is init order — topological, with declaration order as tie-break. Two requirements that both step up produce sequential trips; accepted for the first release.
- **One boot line.** `assembleApp` logs once, at `info`, `session_requirements_registered` with the names in order. With none registered and `sessionModule` installed it logs at `warn`: a password login is admitted with the password alone. This is the declared-absence signal a requirement can have (D7).
- **Contract suite.** `session-admission/testing/requirement.contract.mts`, run by every requirement's tests: `name` equals its key; `reach` holds non-empty strings and no primary's marker; `admit` is never called with a dead session; an outage is thrown, never answered `met`.

### D4 — Actions: the consumer names what it does, the requirement decides

Core exports the names as constants (`ADMISSION_ACTIONS`); the type is `string`, so a deployment's own route may name a new one, and a requirement treats an unknown name by its default — for MFA, the baseline applies.

| Action | Consumer |
| --- | --- |
| `oauth.authorize` | `/oauth/authorize` |
| `oauth.consent` | `/oauth/consent` (GET, POST) — liveness and revocation; a requirement's step-up here is answered `login_required` rather than a trip, because `/authorize` decides again after consent |
| `oauth.session_grant` | the `session` grant |
| `oauth.code_exchange` | the `authorization_code` grant's two reads (`claim` from the code's `sid` and `sub`; no cookie) |
| `device.approve` | device verification (`approve` and `deny`) |
| `federation_grants.connect` / `.consent` / `.callback` | the federation-grants browser half |
| `session.link` | the federation `?link=1` start and its callback |
| `webauthn.register` | the deployment's bridge, through core's `webauthnSubjectFromSession` (D8) |
| `mfa.manage` | the MFA package's own routes (list, remove, regenerate) |
| `mfa.step_up` | `POST /session/mfa/step-up`: met by a live session |

### D5 — Establishment: `admitPrimary`, and the interruption

`POST /session/login` and the federation callback's login path each reach a point where the user is verified and nothing has been written. There, they call `admitPrimary(deps, primary)`:

```ts
interface PrimaryAuthentication {              // moves from `mfa/coordinator.mts`, generalised
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	readonly recorded: RecordedAuthentication;   // the `amr` and `authentication` the session would be created with (#707)
	readonly authTime: Date;
	readonly redirectTo: string | undefined;     // already held to the allowlist
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

type PrimaryAdmission =
	| { readonly outcome: "establish" }
	| { readonly outcome: "interrupt"; readonly requirement: string; open(sessionId: string): Promise<InterruptionAnswer> }
	| { readonly outcome: "unavailable"; readonly store: string };

interface Interruption {
	open(sessionId: string): Promise<InterruptionAnswer>;
}

interface InterruptionAnswer {
	readonly status: 403;
	readonly body: { readonly error: string } & Readonly<Record<string, unknown>>;
}
```

- Requirements with `admitPrimary` are asked in order; the first `Interruption` wins; a throw is `unavailable`, and the route answers `503` with nothing written — the MFA ADR's F1, step 1.
- **Two phases**, because the express session is regenerated between them (the MFA ADR's D8): the route regenerates, leaves the session unauthenticated, calls `open(req.sessionID)`, saves, and answers `status` with `body`. `error` is held to the RFC 6749 error-text class by `errorEnvelope`'s rules; the rest of the body is the requirement's — for MFA, `mfa_transaction`, `expires_in`, `enrollable`, `email_proof`.
- The federation callback calls it too. The MFA requirement answers `establish` for a federated primary (the baseline applies after `pwd` only, the MFA ADR's D13), so today's behaviour holds; MFA after a federated login, when the owner wants it, is one change in the MFA requirement and none in `session`.
- `establishSession` is extracted in `packages/session` as the MFA ADR's step 7 planned — the two routes' create → index → regenerate → flags → save sequence, one function, existing tests unchanged — and `admitPrimary` is called before it.

### D6 — MFA becomes the first requirement; what leaves core and what stays

| Today (the MFA ADR's steps 3–5) | After this record |
| --- | --- |
| `mfaCoordinator` slot and `MFA_ABSENCE_POLICY` (`mfa/coordinator.mts`) | Removed. The MFA package contributes `sessionRequirements: { mfa }`; the coordinator is an internal of that package. |
| `decideMfaRequirement`, `MfaRequirementInput`, `MfaRequirementDecision` (`mfa/requirement.mts`) | The merge — its D16 rule — becomes D2's step 7, in core; the baseline becomes the MFA requirement's `admit`, in the MFA package. The function is deleted and its table-driven tests are split the same way (acceptance criterion 4). |
| `readMfaMode`, `MfaMode`, core's `mfa.mode` schema entry and reference default | Move to the MFA package (D7). |
| `selectAcr`, `stepUpReach`, `readAcrTable`, `producibleAmr`, `vouchableAcrTable`, `AcrTable`, `AcrRequirement`, `UnsatisfiableAcrValue` | Stay in core, moved from `mfa/requirement.mts` to `session-admission/acr.mts`: the provider's `acr` vocabulary. `producibleAmr` takes `reach` — the union over the resolver — where it took `secondFactorMethods`. |
| `sessionAuthentication`, `vouchedAmr`, `requirementSession`, `MfaRequirementSession` | Stay in `user-sessions/authentication.mts`; `MfaRequirementSession` is renamed `RequirementSession`. |
| The `mfaFactors` kind, `mfaFactorResolver`, `MfaFactor`, the stores, `mail/`, the witness, `ratelimit/mfaSpec.mts` | Stay in core as step 3 put them: ports the MFA package and its adapters share. |
| `oauthModule` and `deviceGrantModule` refusing boot under `mfa.mode ≠ off` without `userSessionStore` (`mfa-requires-user-session-store`) | Dropped. The MFA package's module `requires: ["userSessionStore"]`, so a composition without one is refused at the requires-closure, naming the slot. |

The MFA requirement, in `packages/mfa`: `name: "mfa"`; `reach` = the coordinator's `secondFactorMethods`; `admit` = the baseline under `mfa.mode` — `required`: a `pwd` primary without `mfaAt` → `step_up` to `endpoints.mfa.url` with `whenStillUnmet: "reauthenticate"`, `session === null` or an unknown primary → `reauthenticate`, `fed` → `met`; `optional`: `met`, except for `mfa.manage`, `session.link` and `webauthn.register`, which need recent MFA — the MFA ADR's D16 rows, now the requirement's own table; `admitPrimary` = `decideAfterPrimary` and `openLoginTransaction` behind one `Interruption`. `/authorize`'s D17 ask handling — the trips, the accumulating record, `prompt=none` → `interaction_required` — stays in `oauth`, driven by `Admission` instead of by `decideMfaRequirement`.

### D7 — A requirement installed is a requirement on; `mfa.mode` is the MFA package's key (re-decides the MFA ADR's O2)

Under the MFA ADR, "on by default" was to be expressed by removing core's default for `mfa.mode`, so that every composition states `required`, `optional` or `off` (O2), with `MFA_ABSENCE_POLICY` on the `session` and `oauth` manifests making an unfilled `mfaCoordinator` a refused boot. That followed the repository's rule for an **optional slot a module reads** with a security consequence.

With D3, MFA is not a slot a consumer reads; it is a contribution to a kind, like a token-binding mechanism. The repository already treats those as features whose absence needs no declaration (`dpop`, `mtls`). This record applies the same reading:

- `mfa.mode` (`required` / `optional`) is declared by the MFA package's `configSchema`; core has no `mfa.*` key. A composition without the package that still writes `mfa.mode` is refused by core's strict schema, naming the key — loud, and the right refusal.
- The template's and create-app's switch stays: `MFA_MODE` selects whether `buildModules` installs the MFA modules, `off` installing nothing, and the default becomes `required` at the flip — the MFA ADR's step 22, now template and create-app only. `create-app --no-mfa` is unchanged.
- A hand-written composition gets D3's boot line: `warn` when no requirement is registered and a password login is installed.
- The MFA ADR's step 22 makes no core change, and there is no `component-absence-undeclared` for MFA.

Rejected: a post-contributions check — "a session module is installed and no requirement named `mfa` is registered, unless `mfa.mode = "off"` is written" — which keeps O2's letter. It needs a new check stage after stage 4, and puts the name `mfa` back into core's boot rules, which is what this record removes.

### D8 — The consumers, and what changes for each

Every site in the inventory calls `admitSession` exactly once per request, with its own slots, and keeps its protocol's answers — what each answers per outcome is the site's, as the MFA ADR's D16 table listed. The table below says what **changes** because the reading is now shared. Each change is breaking for a deployment that relied on the old behaviour, and each is pinned by a test named for it (acceptance criterion 3).

| Consumer | Action | Changes in behaviour |
| --- | --- | --- |
| `/authorize` | `oauth.authorize` | (1) a cookie with `isAuthenticated` but no `sid`, while a store is wired, is `not_live` → the login redirect, instead of a code minted without `sid`; (2) a store outage is `temporarily_unavailable` on the validated redirect URI, or `503` before a client is known — not a redirect to the login page; (3) the record's `sub` must match the cookie's `user.id`; (4) the subject-revocation boundary applies when `subjectRevocation` is wired — the handler receives the slot `oauthModule` already declares. `readLiveSession` and `resolveAcr` are deleted; `evaluateReauthentication` and the ask stay until the MFA ADR's step 13 reshapes them. |
| `/consent` | `oauth.consent` | (1), (3), (4). A store outage stays `503`. |
| `session` grant | `oauth.session_grant` | (4). `step_up` → `400 invalid_grant` with `step_up: "<requirement>"`, the MFA ADR's row. |
| `authorization_code` grant | `oauth.code_exchange` | (4) on both reads, with `claim` built from the code's `sid` and `sub`. |
| device verification | `device.approve` | none in liveness or revocation, already fail-closed; `livenessOf` and the direct `revokedBefore` read are replaced. `step_up` → `403 { error: "step_up_required", requirement }` — one code, whichever requirement asked, so a client's mapping does not depend on the extension. |
| federation-grants connect / consent / callback | `federation_grants.*` | none in liveness or revocation; `judge` / `sessionHolds` keep the intent, binding and client checks and delegate the session part. The grants boundary (`grantsRevokedBefore`) is theirs and stays. |
| federation `?link=1` start and callback | `session.link` | the start reads the live session (today: the flag and `typeof sid` only); (3); (4) once `sessionModule` gains an optional `subjectRevocation` slot — it has none today — attached to `SUBJECT_REVOCATION_ABSENCE_POLICY`, which it already attaches for `subjectSessionIndex`. |
| WebAuthn registration | `webauthn.register` | core exports `webauthnSubjectFromSession(deps)`: an Express middleware the deployment mounts after `session-middleware` and before the registration routes — the composition fixture's `deployment:webauthn-subject` shape — which calls `admitSession` and sets `req.webauthnSubject` on `admitted`. The README's bridge points at it; the package is unchanged. |
| refresh grant, `device_code` grant, introspection, userinfo, federation token, token exchange, logout | — | **not through admission in this release** (D9) |

`403` bodies and `303` redirects on the plain-text federation-grants pages keep their text. `step_up` on a JSON route always carries `requirement`, and on a browser-facing consumer the page.

### D9 — Sessions read from a token stay where they are; the input is shaped so they can move

The refresh grant, the `device_code` grant, introspection, userinfo, the federation-token route, token exchange and the logout routes read a session by a `sid` taken from a token or a record, with the subject-revocation boundary applied through `verifyJwt` where it applies. Their reads are already fail-closed and consistent (`session_invalid`, `503`), and they hold no cookie. They are out of this release's scope. `AdmissionRequest.claim` deliberately carries `{ authenticated, sid, subject }` and not `req.session`, so a later record can route them through `admitSession` with `authenticated: true` and the token's `sid` / `sub`, without changing the port.

### D10 — Outages, logs, audit, and the guards

- **Logs.** `admitSession` logs an outage once, at `error`, object-first: `session_admission_unavailable` with `store` (`user_session`, `revocation_boundary`, or the requirement's name), `action`, and `loggableError`'s projection — never the `sid`. A subject mismatch is `session_admission_subject_mismatch` at `warn` with `action` and no identifier. Nothing else is logged: a refusal is the consumer's line, as today.
- **Audit.** Unchanged: the consumers' events. A requirement that audits — MFA does — audits its own.
- **Drift guards** (`packages/core/src/__tests__/`): a design-vocabulary row for admission, home `session-admission/admit.mts` (`admitSession`, `admitPrimary`), and one for the revocation-boundary reading, home `session-admission/boundary.mts` (`coveredByRevocationBoundary`, moved from `federation-grants/effective-status.mts`); a call-site guard that **no shipped source outside the leaf and D9's list calls `userSessionStore.get(`, `.revokedBefore(` or `selectAcr(`** — the read has one home, and D9's list is an allowlist in the test with a comment per entry, shrunk as D9 proceeds; the existing `requirementSession(` guard is retargeted to the leaf, since consumers no longer build the input.
- **Inventories.** `docs/adapter-surface.md`: the synthetic key `sessionRequirementResolver`, the kind, the removed `mfaCoordinator` and its policy rows; the pins in `contributes-map.test.mts` and `synthetic-keys.test.mts` (7 → 8 keys); the counts in `boot/README.md` and `manifest/README.md`; `tools/composition` gains a fixture requirement (`ADDED`) that interrupts a login and steps a session up, so the composition test exercises both halves without MFA; the template's all-modules test lists the MFA package's requirement once it exists.

## Acceptance criteria

1. Every cookie consumer in D8 calls `admitSession` once per request, and the call-site guard proves no other read exists.
2. The composition test, with the fixture requirement, shows: a login interrupted and completed; `/authorize`, the `session` grant and device approval each answering `step_up` for an unmet session and admitting it after the fixture records the step-up; consent → `/authorize` deciding again; a revoked subject refused at `/authorize`, consent, both grants and the link start; a store outage `503` / `temporarily_unavailable` at every site.
3. With no requirement registered, every consumer behaves as at `db9c080e2` except D8's changes, each pinned by a test named for the change.
4. The MFA ADR's step-4 table (its D16 and D17 rows) passes unchanged against D2's merge with a requirement whose `admit` is the baseline — the split of `decideMfaRequirement` loses no row.
5. Mutation over the merge table and the liveness steps: every row's mutant is killed by the leaf's own tests, not by a consumer's.

## Build order

Each PR is RED → GREEN → REFACTOR, with the reviews the MFA slices had (a design and a security reviewer, Codex, Copilot). No PR touches `CHANGELOG.md` (release-policy R2); each PR's description says what an operator notices.

| PR | Delivers | Notes |
| --- | --- | --- |
| A1. `docs(core)`: this ADR, and the MFA ADR's amendments (§7) | — | the owner's decisions of 2026-09-28 (§9) recorded |
| A2. `feat(core)!`: session admission | the leaf — `admitSession`, `admitPrimary`, the kind, the resolver, the contract suite, `acr.mts` and `boundary.mts` (moved), the merge with step 4's tests re-homed; `mfaCoordinator`, `MFA_ABSENCE_POLICY`, `decideMfaRequirement`, `readMfaMode`, `MfaMode` and core's `mfa.mode` removed; the boot line; the vocabulary rows and the call-site guard with the whole D8 list allowlisted; adapter-surface, the pins, the READMEs | BREAKING for exported types nobody consumes yet (unreleased) |
| A3. `refactor(oauth)!`: `/authorize`, consent, the `session` grant, the `authorization_code` grant on admission | D8's rows for `oauth`; `readLiveSession`, `refuseUnlessLive`, `resolveAcr` deleted; `subjectRevocation` handed to the authorize handler; the allowlist shrinks | BREAKING: D8 (1)–(4) |
| A4. `refactor(device-grant,federation-grants)`: on admission | `livenessOf` and the session half of `judge` / `sessionHolds` replaced; `coveredByRevocationBoundary` imported from its new home; `step_up_required` on approve | no change in behaviour expected; pinned |
| A5. `refactor(session,webauthn)!`: the link flow and the WebAuthn bridge | `session.link` through admission; `sessionModule` gains optional `subjectRevocation`; `webauthnSubjectFromSession`; the README bridge | BREAKING: D8's link rows |
| A6. `feat(session)!`: `establishSession` and `admitPrimary` | the extraction; both login paths call `admitPrimary`; the regenerate-then-`open` sequence; the fixture requirement's interruption test in `tools/composition` | replaces the MFA ADR's step 7 |
| then MFA resumes at its step 6 | step 6 (Redis stores) unchanged; step 8 contributes `sessionRequirements: { mfa }` and takes `readMfaMode` and `mfa.mode` into the package; step 11's `POST /session/mfa/step-up` admits with `mfa.step_up`; steps 13 and 14 shrink to `/authorize`'s ask handling over `Admission` and the MFA requirement's per-action table; step 22 is template and create-app only | |

A2 and A3 are separate PRs (§9), so the port's tests are reviewed on their own before a consumer moves.

## §7 — What this record amends in the MFA ADR

Recorded in that document as "Amended 2026-09-28 (session admission)" notes at each place.

- **D1 / D2**: the ports stay in core; the coordinator is no longer a slot. The dependency directions gain one arrow — the MFA package → `session-admission`, by contribution — and none from a consumer to MFA.
- **D8**: "The coordinator slot" is replaced by the MFA requirement (D6 here).
- **D16**: the rule is split — the merge is admission's (D2, step 7), the baseline the requirement's; the per-consumer table is D8 here; "Conditional requirements are boot checks" is replaced by the MFA module's `requires: ["userSessionStore"]`.
- **D17**: unchanged in substance; "D16's rule" reads "the admission". `Admission.step_up.page` is where `endpoints.mfa.url` comes from, so `/authorize` no longer reads that key.
- **D19 / D20**: `mfa.mode` leaves core; the "off is a statement" paragraph and `MFA_ABSENCE_POLICY` are withdrawn, and D3's boot line replaces them; the refusal table loses its `mfaCoordinator unfilled` and `mfa-requires-user-session-store` rows.
- **Build order**: step 7 → A6; steps 13 and 14 → as above; step 22 → template and create-app only.
- **O2**: re-decided by D7.

The MFA ADR's "today" (its "What exists today", written against `d3d9c8f2`) is left as the snapshot it is; its 2026-09-26 amendment already records that device verification reads the live session, and `FEDERATED_AMR` moved to core at its step 4.

## Consequences

- Adding an extension that changes what "logged in" means is one package contributing one requirement; no consumer changes. Adding a consumer is one `admitSession` call and one outcome mapping.
- The four disagreements the inventory found are gone, and the subject-revocation boundary protects every cookie consumer, not two of them — including the case the best-effort `subjectSessionIndex` write missed.
- The cost is one refactor of every consumer now (A3–A5): the cost the MFA ADR's steps 13 and 14 were going to pay, paid once and generically, and MFA ships later by that much.
- Consumers keep an outcome-to-answer mapping each; what leaves them is the decision, not the protocol.
- Two requirements that both step up cause two trips. A combined page is outside the first release.
- The generic contract is shaped by one real requirement (MFA) and one fixture. D9's second campaign is where it is tested against a second shape.

## Rejected

- **A middleware before every consumer**: core cannot mount one that sees the cookie, and a route-level one makes every consumer route a mandatory `before:` target.
- **A module every composition must list**: the requires-closure would refuse hand-written compositions for nothing the function does not already get from the consumer's slots.
- **A list-shaped kind**: no read-side projection exists for list kinds; name-keyed gives duplicate detection and a boot line with names.
- **Keeping `mfaCoordinator` as a slot with `MFA_ABSENCE_POLICY` on each consumer**: every consumer naming the extension — what this record removes.
- **Overridable or nullable requirements**: a security-relevant contribution nothing may switch off from behind the consumers.
- **Refusing boot when no requirement is registered**: the equivalent of O2's letter; rejected in D7.

## 9. Owner decisions (2026-09-28)

- **D7 confirmed**: a requirement installed is on; `mfa.mode` is the MFA package's key; no requirement registered is a boot `warn`, not a refusal. O2 is re-decided.
- **Names confirmed**: `session-admission`, `admitSession`, `admitPrimary`, `sessionRequirements`, `sessionRequirementResolver`.
- **D8's four changes confirmed**, the `/authorize` store-outage answer included.
- **One step-up code on JSON routes**: `step_up_required` with `requirement` in a field, in place of the MFA ADR's `mfa_step_up_required`.
- **A2 and A3 are separate PRs.**

## Outside the first release

- Token-side session reads through admission (D9).
- A combined step-up page when two requirements step up in one request.
- MFA after a federated login and per-client requirements (the MFA ADR's "not now"): each is one change in the MFA requirement's `admit` / `admitPrimary`.

## References

- The MFA ADR: `2026-09-25-multi-factor-authentication.md` (D8, D9, D13–D20, §8, O2), and #693, #695, #702, #706, #707 — its steps 1–5.
- Token binding as a contribution kind: `2026-05-20-token-binding-first-class-abstraction.md`.
- Readiness probes as a registrar slot: `2026-08-26-readiness-probes-registered-by-connection-owners.md`.
- Boot stages and their guarantees: `packages/core/src/boot/README.md`; the manifest vocabulary: `packages/core/src/modules/manifest/README.md`.
- Module boundaries: o3co/auth.provider#626 (P3: core owns the decision, the packages own the protocol).
