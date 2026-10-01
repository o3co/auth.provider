# Session admission: one decision point for every consumer of an authenticated browser session, and the requirements that extend it

- Status: accepted (2026-09-28); implemented (#715–#719, #730). Amended 2026-09-29 (module review): the build order below is the plan as it was accepted, and it landed as A1 #709, A2 #715, A3 #718, A4 #717, A5 #716 and A6 #719; #730 fixed what the retro reviews of #717–#719 found (D3's retro-review amendment). The review found two decisions the implementation made that this record did not state; they are recorded at D4 and D10.
- Date: 2026-09-28
- Amends: the MFA ADR (`2026-09-25-multi-factor-authentication.md`) — its D1/D2/D3 (the coordinator slot and the dependency rows), D7 (`MfaFactor.amrValues`), D8, F1/F3 (the interruption body), D15 (the drop), D16's per-consumer wiring, D17's ask record, D19/D20's "off is a statement", the upgrade checklist, build-order steps 7, 13, 14 and 22, the "Planned" note on MFA after a federated login, and O2. The amendments are listed in §7 and recorded in that document.
- Written against: `develop` at `db9c080e2` (#707, the MFA ADR's step 5). Every "today" below was checked there — except D5 and the build-order row A6, which are written against #713 (`establishSession`, merged during this record's review; it moved the two login tails, and the best-effort index write the Context cites, into `packages/session/src/establish-session.mts`).
- Reviewed: an adversarial design review and a security review against the code, both on 2026-09-28. Their findings are folded in; where a decision changed because of them, the section says so, and §9 lists what the owner is asked to confirm.

## Context

### What the owner decided

MFA is not a feature that adds an endpoint or a grant. It changes what "logged in" means, so every place that lets an authenticated browser session do something must ask the same question. The MFA ADR answered that by giving core a pure rule (`decideMfaRequirement`) and planning to wire it into each consumer, one by one (its build-order steps 13 and 14), with `mfaCoordinator` as an optional slot on the `session` and `oauth` manifests and `mfa.mode` as a core key every consumer reads.

The owner asked for the split to be made explicit instead. **Plugins** add behaviour and never need to know about one another. **Extensions** change what an existing decision means, and reach the plugins only through one port in core. Consumers then depend on the port, not on the extension; a second extension of the same kind — a risk score, a re-consent, an account hold — touches the port's contributors and nothing else.

The MFA work is paused after its step 5 (#707, merged 2026-09-28). This record designs the port, moves the consumers onto it before MFA resumes, and says what MFA becomes on top of it.

### What exists today

**Thirteen consumer sites, each with its own reading.** `/authorize` (`readLiveSession`, private to `packages/oauth/src/routes/authorize.mts`), consent (`refuseUnlessLive`, `consent.mts`), the `session` grant (inline, `grants/session.mts`), the `authorization_code` grant (two inline durable reads — one before signing, one before linking, compared with each other — `grants/authorization.mts`), the refresh grant (from the token's `sid`, `grants/refreshToken.mts`), device verification (`livenessOf`, `packages/device-grant/src/verificationEndpoint.mts`), the federation-grants browser half (`judge` / `sessionHolds`, `packages/federation-grants/src/browserRoutes.mts`), the federation link start and callback (inline, `packages/session/src/routes/Federation.mts`), and WebAuthn registration (`req.webauthnSubject`, which the deployment's middleware sets). No core helper reads a live session; the readers do not even agree on the cookie flag (truthiness at `/authorize`, consent and the `session` grant; `=== true` at device verification, federation grants and the link start).

**They disagree.**

- A cookie with `isAuthenticated` but no `sid`, while a store is wired, is open at `/authorize` and consent — a code is then minted without `sid` and refused at `/token` — `400 invalid_grant` at the two grants, `401 login_required` at device verification, `403` in federation grants, `401` at the link start.
- A cookie with no `user.id` is refused by the `session` grant, device verification and federation grants, and not by `/authorize` or consent. The durable record's `sub` is compared with the cookie's `user.id` by the same three, and not by `/authorize` or consent; the `authorization_code` grant compares its two reads with each other.
- A session-store outage on an interactive `/authorize` is answered with a redirect to the login page (`authorize.mts`, the non-silent branch), not `temporarily_unavailable` — and the cookie keeps `isAuthenticated`, so a login page that forwards signed-in users loops.
- The subject-revocation boundary (`subjectRevocation.revokedBefore`, read against `authTime` with `coveredByRevocationBoundary`) is applied by device verification and federation grants, and through `verifyJwt` on the token side, and by nothing else. `/authorize`, consent, the `session` grant, the `authorization_code` grant and the link flow admit a session established before the subject's sessions were revoked, until the session's own expiry. The `subjectSessionIndex` write at login is best-effort (`Session.mts`, `Federation.mts`), so the boundary is the only thing that stops a session the index missed — and it does not reach the consumers that mint codes.
- Only federation grants check the record's `expiresAt` themselves; the others rely on the bundled stores filtering an expired session on `get`, which the port does not promise.

**What the MFA ADR already put in core** (its steps 3–5, none of it released): `sessionAuthentication` / `vouchedAmr` / `requirementSession` (`user-sessions/authentication.mts`); the `authentication` key on `UserSession`, the upstream split and `recordSecondFactor` (#707); `selectAcr` / `stepUpReach` / `readAcrTable` / `producibleAmr` / `vouchableAcrTable`, `readMfaMode` and the merged rule `decideMfaRequirement` (`mfa/requirement.mts`); the `mfaCoordinator` slot with `MFA_ABSENCE_POLICY` (`mfa/coordinator.mts`); the `mfaFactors` kind with its synthetic `mfaFactorResolver`; the factor and transaction stores, `mail/`, the witness, `ratelimit/mfaSpec.mts`; the `mfa` section of core's schema, `mfa.mode` locked to `"off"`. `decideMfaRequirement` has no product caller; `selectAcr` has one (`/authorize`); `readMfaMode` has one (`oauth/src/acrValues.mts`, the info-versus-warn rule of the MFA ADR's D15); `mfaCoordinator` is declared and consulted by nobody. The refusal `mfa-requires-user-session-store` the MFA ADR's D16 planned was never built.

**The module system's constraints** (checked against `packages/core/src/boot/` and `modules/manifest/`):

- A contribution kind shared by bundled packages must be a core built-in: its collector, its read-side projection and its value checks are hard-coded in `boot/` (`BUILTIN_CONTRIBUTION_KINDS`, `mergeWithBuiltins`, `prepareSyntheticProjections`, `checkNameKeyedValue`). `createApp({ contributionKinds })` replaces a built-in's collector — its own comment says so — and the projection is built over whatever collector the merged map holds.
- Only name-keyed kinds have a read-side projection — a synthetic key, always present while the built-in collector is, never provided, bootstrapped or overridden, auto-satisfying `requires` — and a provider must read it lazily, because contributions register in stage 4, after the `provides` factories of stage 3 (`readableFromStage4`). List-shaped contributions (routes, `discoveryMetadata`) run after every name-keyed one has registered. `mfaFactors` → `mfaFactorResolver` → `MfaCoordinator.secondFactorMethods` is the one precedent.
- Stage 1 refuses overrides of list-shaped kinds only; a name-keyed override goes through `collector.replace`, and `checkNameKeyedValue` refuses a mismatched `kind` for `mfaFactors` alone. Nothing refuses a `null` answer.
- Core's own middleware (CORS, token binding, the protected-resource binding, `grantMiddleware`) is mounted before every route contribution, `session-middleware` included, so it cannot see `req.session`; and a route contribution's `before:` target becomes mandatory in every composition. There is no "before every consumer" middleware.
- An `AbsencePolicy` fires when a slot is not in the planned keys and the config lacks the declaration; a synthetic key is never planned, so a policy cannot express "nobody contributed to a kind". `FrozenWorld` carries no module list, so a boot check cannot ask "is module X installed" without naming it.
- Core's schema is strip-mode: an unknown top-level section is not refused; boot merges it back unread. A key a package declares through its `configSchema` is composed only while that package is installed, and the parity and reference-conf drift tests require `AppConfigSchema` to declare every key a bundled package reads.
- The two token-binding mechanisms are not silently absent: each is switched by a core config key (`oauth.dpop.enabled`, `oauth.mtls.enabled`) that core's schema carries, and a client that asked for a binding it cannot be given is refused (`SenderConstraint.required`). Their absence is declared, and nobody who asked is downgraded.
- `importBoundaries.drift.test.mts` forbids cycles between core's standing-value directories; `federation-grants/effective-status.mts` (the grants boundary) already imports `coveredByRevocationBoundary`'s home.

### Conventions this design keeps

A store outage is `503 temporarily_unavailable`, logged once at error with `store`, `step` and `loggableError`'s projection, and never read as a verdict. An unsupported security-relevant request parameter is refused, not ignored. Absence is a decision, not a default (`docs/adapter-surface.md`, declared absence). Every concept has one home (`docs/design-vocabulary.md`), guarded by a drift test. Pages are the deployment's. A PR that adds a module, a slot or a kind adds its rows to `docs/adapter-surface.md`, the replica-safety declarations, the audit inventory, `tools/composition`'s fixture and the template's all-modules test.

## Vocabulary

- **Admission**: the decision that an authenticated browser session — or the primary authentication about to become one — may proceed with an action. Core's `admitSession` and `admitPrimary` make it.
- **Session requirement** (a *requirement*): a condition an extension adds to admission, registered under the `sessionRequirements` contribution kind. MFA is the first.
- **Action**: what the consumer is about to let the session do — a name and a **grade**: `use` (exercising the session), `credential_change` (adding or removing a way into the account), `remediation` (a requirement's own route, by which the session meets that requirement). Requirements decide by grade, and may refine by name.
- **Claim**: what a consumer holds about the session before it is read — built by core from the cookie, a code record or a link transaction, never by the consumer.
- **Reach**: the `amr` values a step-up through a requirement can add to a session — the MFA ADR's `secondFactorMethods`, generalised — and the page that step-up starts on.
- **Interruption**: a requirement's answer at establishment time — the login does not complete yet, and the browser is told what to do next.
- **A session read**: one call of `admitSession`. A consumer that must re-check before a write (D8) makes a second read; it never reads the store by other means.

## Decisions

### D1 — One decision point in core, called by every consumer; not middleware, not a module

Core gains a directory, `packages/core/src/session-admission/`, exporting two async functions with explicit dependencies:

```ts
admitSession(deps: AdmissionDeps, request: AdmissionRequest): Promise<Admission>
admitPrimary(deps: AdmissionDeps, primary: PrimaryAuthentication): Promise<PrimaryAdmission>

interface AdmissionDeps {
	readonly userSessionStore: UserSessionStore | undefined;   // the consumer's slot, as wired
	readonly subjectRevocation: SubjectRevocation | undefined; // the consumer's slot, as wired
	readonly requirements: SessionRequirementResolver;         // the synthetic key (D3) — branded; only the boot planner builds one
	readonly acrTable: AcrTable;                                // the vouchable table (D6); empty when the consumer has none
	readonly logger: Logger | undefined;
	readonly auditSink: AuditSink | undefined;                  // the consumer's slot; D10's one event
	readonly now?: () => Date;                                  // defaults to the wall clock; a test seam, documented as such
}
```

Why a function and not middleware: core's middleware is mounted before `session-middleware` and cannot see the cookie; a route-level middleware would need every consumer route as a `before:` target, making each mandatory in every composition; and the answer to a refusal differs by protocol — a redirect, an RFC 6749 error, a plain `403` — which is the consumer's to give. Why not a module every composition lists: a hand-written composition that forgets it would fail the requires-closure at boot for no gain, and the function needs nothing a module would hold — the slots are the consumer's own, already declared.

A consumer receives the resolver by listing `sessionRequirementResolver` in its `requires`, which a synthetic key auto-satisfies. Every consumer factory that can be built by hand (`createOAuthRouter`, `createDeviceVerificationHandler`, the federation-grants and session route factories) takes `requirements` as a **required** option of the branded type and throws at construction without it, as `createDeviceVerificationHandler` refuses a missing store today: a composition that bypasses the planner cannot hand a consumer an empty or home-made resolver, and the boot line (D3) reports the resolver every consumer holds. The brand is not only a type: the planner records each resolver it builds in a module-private `WeakSet`, and `admitSession` refuses one it does not know, so an `as` cast or a home-made object forges nothing. Tests that build a consumer by hand — `oauth` has thirty-three files calling `createOAuthRouter` directly, and `device-grant`, `federation-grants` and `session` build their factories the same way — get theirs from `resolverForTests(requirements)` in core's published `./testing` entry, which registers what it builds in the same set. So the brand stops accidents, not a deployment that imports the testing entry on purpose; that is the deployment's own decision, as `createMemory…` in production is, and the entry's README says so.

The MFA ADR's rule was the same shape — one pure function each consumer calls — for the same reasons. This record widens it from "the MFA requirement" to "the admission", and moves the read of the session into it.

### D2 — What `admitSession` judges, in order, and what it answers

Input: a claim core built, and the action.

```ts
/** Built by core's claim builders and nowhere else (branded, and checked at runtime like the resolver): the one reading of each carrier. */
interface SessionClaim {
	readonly authenticated: boolean;
	readonly sid: string | undefined;
	readonly subject: string | undefined;    // `undefined` only for a carrier that has none (the code record's first read)
	readonly carrier: "cookie" | "code" | "link" | "token";
	readonly tokenAmr?: readonly string[];   // a token carrier only: the `amr` it carries, for the requirements (D9)
}
cookieClaim(req): SessionClaim                       // `authenticated` is `isAuthenticated === true`; `sid` and `subject` (`user.id`) are copied when they are non-empty strings, else `undefined`
codeClaimFirstRead(code): SessionClaim               // `authenticated: true`, the code's `sid`, no subject — `CodeData` carries no `sub`; the one claim that reaches a record without one
codeClaimRevalidation(code, subject): SessionClaim   // the same `sid` with the first read's `sub`, which this builder REQUIRES (a non-empty string, else a `RangeError`) — two builders, so the second read's comparison cannot be omitted
linkClaim(link): SessionClaim                        // `authenticated: true`, the transaction's `sid` and the subject recorded at the start (D8)
tokenClaim(claims): SessionClaim                     // `authenticated: true`, the verified token's `sid` (may be absent), `sub`, and its `amr` — the refresh grant (D9).
                                                     // `sub` must be a non-empty string, else a `RangeError` (the grant answers `invalid_grant`, as it refuses a
                                                     // token without a subject today); an `amr` that is not `wellFormedAmr` reads as absent — an unknown primary

interface AdmissionAction {
	readonly name: string;                                       // D4's constants for the bundled consumers
	readonly grade: "use" | "credential_change" | "remediation";
}
// A `remediation` action is never built by a consumer: core issues it to the requirement that declared the name
// (`issuedRemediationActions(requirement)[route]` on the object its factory returned — never through the resolver —
// branded and runtime-checked like the claims), and the requirement's own route passes that
// object. A `{ name, grade: "remediation" }` literal from anywhere else carries no brand and is normalised to
// `credential_change` (D2, step 5) — the one grade a string can never claim.

interface AdmissionRequest {
	readonly claim: SessionClaim;
	readonly action: AdmissionAction;
	readonly asks?: { readonly acrValues?: readonly string[] };    // `/authorize` only
}
```

Steps, each fail-closed:

0. **Inputs.** The claim must be one a core builder made (the runtime brand); the action's `grade` must be one of the three — anything else (a typo, an `as` cast in a hand-written consumer) is a `RangeError` before anything is read, the consumer's fault, never a skipped requirement. The closed `ADMISSION_ACTIONS` union catches it at compile time for the bundled consumers. *(Amended 2026-09-30: the action is a registered action's name or a remediation core issued; anything else is the `RangeError` — D4's closing note.)*
1. **Claim.** `authenticated !== true` → `unauthenticated`. A cookie claim without a subject (`cookieClaim` found no non-empty `user.id`) is `not_live` (`no_subject`) here, before any read — logged once at warn, not audited, since nothing was compared: the three consumers that refuse such a cookie today keep doing so, and the two that do not join them.
2. **Live read.** With a store: no `sid` → `not_live` (`no_sid`) — except for a token carrier, whose `sid` is optional and whose absence skips the read, as the refresh grant does today (D9); `store.get(sid)` answering `null` or `undefined` → `not_live` (`gone`); a record whose `sub` is not a non-empty string, or whose `expiresAt` is not later than `now()`, → `not_live` (`gone`) — the port does not promise that `get` filters expiry, and federation grants check it today; a throw → `unavailable` (`store: "user_session"`). Without a store: `session` is `null`, and the requirements decide what that means — the MFA requirement refuses boot without a store (D6), and with no requirement a cookie-only composition is admitted as today.
3. **Subject.** A cookie claim always names a subject by now (step 1 refused one that did not). When a record was read and the claim names a subject, the two must be equal; else `not_live` (`subject_mismatch`), logged once at warn and audited (D10). The only claim that reaches a record without a subject is the code record's first read (D4), which compares on its second. With no record — no store, or a token carrier without a `sid` — there is nothing to compare, and the claim's subject is the subject the requirements are asked about.
4. **Revocation boundary.** For a cookie, code or link carrier, with `subjectRevocation` wired **and a live session** (step 2 read one): `revokedBefore(session.sub)`; a throw, or an answer that is neither `null` nor a valid `Date`, → `unavailable` (`store: "revocation_boundary"`); `coveredByRevocationBoundary(session.authTime, boundary, DEFAULT_SUBJECT_REVOCATION_SKEW_MS)` → `revoked`. Without a store there is no record, no `authTime` and no `sub` to compare, so the boundary is not read: a cookie-only composition has no revocation backstop, as it has none today, and the two slots stay independently optional. **A token carrier skips this step whether or not a record was read**: its boundary is `verifyJwt`'s, applied to the token before the grant runs (D9), and one reading per request is enough. This is the reading device verification and federation grants apply today, from its present home (D10).
5. **Requirements.** First the action is normalised by D4's rule: a `remediation` that is not the branded object core issued to the requirement that declared it — a literal from a consumer, or a name no requirement declared — becomes `credential_change` (logged once per process per name); only the issued object keeps its grade. Then, for an action graded `use` or `credential_change`: each registered requirement's `admit(input)`, in registration order (D3), with `input = { session: view, authentication, carrier, action, asks, now }` — `view` a projection of the record (`sid`, `sub`, `authTime`, `expiresAt`), never the record itself, so a requirement cannot read the raw `amr` that `vouchedAmr` would have split; `authentication` is `requirementSession(session)` for a cookie, code or link carrier, and for a **token carrier it is always built from the token's own `amr`** by `requirementSessionFromAmr` — the primary from `fed` / `pwd` / unknown, no `mfaAt`, the token's `amr` as vouched — whether or not a record was read; the record is only the live view. A refresh token is judged on what it was issued with (the MFA ADR's O3): a password-only token does not become acceptable because its session stepped up later. That reading is also how a token issued before #707 reads. The first verdict that is not `met` is taken and the rest are not asked. A requirement that throws → `unavailable` (`store: <its name>`), logged once: a requirement is asked about a session, never trusted to fail open. **Every verdict is validated at the boundary before it is read**: an answer that is not an object with one of the four outcomes, a `step_up` whose `whenStillUnmet` is not one of its two values, a `null`, a promise that resolves to anything else — from a JavaScript or out-of-tree requirement as much as from a bundled one — is `unavailable` (`store: <its name>`), logged once, exactly as a throw; a malformed answer never proceeds past the requirement that gave it. A `step_up` from a requirement whose registered `stepUpPage` is `undefined` (an empty `reach`) is inconsistent — nothing could finish the trip — and is taken as `unmet` (`requirement: <its name>`), fail closed, logged once per process per name as `session_admission_step_up_without_page`. A `step_up` answered when `session` is `null` (no store, or a token carrier without a record) is inconsistent too — there is no live session to add to — and is taken as `reauthenticate` (`requirement: <its name>`), logged once per process per name as `session_admission_step_up_without_session`; `Admission.step_up` therefore always carries a live session. For an action graded `remediation` — a requirement's own route — no requirement is asked: the route belongs to the requirement, which knows what its session is doing; two requirements' remediations cannot block each other.
6. **`acr_values`.** When `asks.acrValues` is non-empty: `selectAcr(acrValues, requirementSession(session)?.amr ?? [], acrTable, reach)` — the vouched `amr`, written that way so the existing call-site guard holds for admission's own call — with `reach` = the union of every requirement's `reach` when the session is live, and `reach = ∅` when `session` is `null` — nothing can be stepped up onto no session. `oauth.authorize.acrValues` is a core key and the table's drop is core's, so this is a built-in step, not a requirement.
7. **Merge** — the MFA ADR's D16 rule, now the admission's. With `R` = step 5's verdict and `A` = step 6's:

| `R` | `A` | Admission |
| --- | --- | --- |
| met | met, or nothing asked | `admitted`, with `acr` |
| met | unmet | `unmet` (`requirement: "acr"`) |
| met | step_up | `step_up`: the registered `stepUpPage` of the first requirement whose own `reach` covers everything one alternative of a reachable entry lacks; the hint is `A`'s reachable values **filtered to the entries that requirement's `reach` alone can finish**, so the page is never told to reach what it cannot; `whenStillUnmet: "unmet"`. When no single requirement covers any reachable entry — only the union does — `unmet` (`acr`): no one trip can finish it |
| reauthenticate | anything but "no requested value is in the table" | `reauthenticate` (`R`'s name) |
| reauthenticate | no requested value is in the table | `unmet` (`acr`) — no login can meet it |
| step_up | unmet | `unmet` (`acr`) — no step-up can meet the request |
| step_up | step_up | one `step_up`: `R`'s requirement's registered `stepUpPage`, `A`'s reachable values that `R`'s requirement's own `reach` can finish as the hint (as in the met + step_up row), `whenStillUnmet: "unmet"` — a session that comes back still unmet is refused for the request, as the rule answers today |
| step_up | met, or nothing asked | `step_up`: `R`'s requirement's registered `stepUpPage`, no hint, `R`'s `whenStillUnmet` |
| unmet | unmet | `unmet` (`acr`) — as the rule answers today: the request first |
| unmet | met, step_up, or nothing asked | `unmet` (`R`'s name) |

The mapping to the rule's `MfaRequirementDecision`, for acceptance criterion 4: its `requirement: "acr"` is `requirement: "acr"` here, its `requirement: "baseline"` is the requirement's name, and its `step_up.requirement` is `whenStillUnmet` — `"acr"` → `"unmet"`, `"baseline"` → the requirement's own answer.

Output:

```ts
type Admission =
	| { readonly outcome: "admitted"; readonly session: UserSession | null; readonly acr: string | undefined }
	| { readonly outcome: "unauthenticated" }
	| { readonly outcome: "not_live"; readonly reason: "no_subject" | "no_sid" | "gone" | "subject_mismatch" }
	| { readonly outcome: "revoked" }
	| { readonly outcome: "reauthenticate"; readonly requirement: string; readonly session: UserSession | null }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly session: UserSession;
			readonly page: StepUpPage;                         // amended 2026-09-29 (review, D8's note): the page as registered, `RegisteredStepUpPage` — with its `href`
			readonly acrValues: readonly string[];
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string; readonly session: UserSession | null }
	| { readonly outcome: "unavailable"; readonly store: string };

/** The deployment's page for the step-up (D3 validates it at registration). */
interface StepUpPage {
	readonly url: string;                                   // a path, or an absolute URL on the issuer's origin
	readonly params: Readonly<Record<string, string>>;      // never the consumer's return parameter (`redirect_to` is reserved)
}
```

`admitted.session` is the live record the consumer then uses. `reauthenticate`, `step_up` and `unmet` carry the session too, because `/authorize` decides freshness — `max_age`, `prompt=login`, the ask's `loginAskedAt` / the per-requirement `stepUpAskedAt` against `authTime` — before it acts on the method verdict (the MFA ADR's D17, "freshness first"), and the step-13 obligation needs the primary. `not_live`, `revoked` and `reauthenticate` are one class for a consumer — a new login is the remedy — and distinct in the type so a log line and an audit event can say which. A consumer that answers them with a redirect regenerates the cookie session first, dropping its authentication, so a login page that forwards signed-in users cannot loop (today's `/authorize` leaves the flag set). *(Amended 2026-09-29, review — D8's note.)* No consumer builds a URL from `page`: registration resolves the page once, on the issuer it was validated on — `new URL(page.url, issuer)` and `searchParams.set`, never concatenation — to `page.href`, and every consumer answers or navigates from `page.href` and resolves nothing itself; `/authorize` adds only its own trip's parameters to it.

**Amended 2026-10-01 (MFA build-order step 11):** `LoginCompletion` gains `renewSession`; an admitted `Admission` (and a `step_up` one) carries the requirement's `SessionView`, core's copy of the record, so a consumer reads the session's facts without reading the record.

### D3 — The requirement contract, the `sessionRequirements` kind, and its resolver

```ts
interface SessionRequirement {
	/** The key it is contributed under; refused at boot otherwise (the `mfaFactors` rule). */
	readonly name: string;
	/** The `amr` values a step-up through this requirement can add; empty when it offers none. */
	readonly reach: ReadonlySet<string>;
	/** Where that step-up starts. Required when `reach` is not empty; may be set when it is (the `mfa` requirement's page is static, its `reach` is not). Copied and validated at registration; a `step_up` verdict names no page of its own — admission answers this one (D2, step 7). */
	readonly stepUpPage: StepUpPage | undefined;
	/**
	 * The names of this requirement's own remediation routes (D4): the only actions admission accepts as `remediation`.
	 * Each is namespaced under the requirement's own name — `<name>.<route>`, as `mfa.step_up` — so no requirement can claim a
	 * consumer's action (`oauth.authorize`) or another requirement's; refused at registration otherwise.
	 */
	readonly remediations: readonly string[];
	/** The keys an interruption's `hints` may carry (D5); declared at registration, so an out-of-tree requirement is held to it at runtime. */
	readonly hintKeys: readonly string[];
	/** Use-time: a view of the session, read once by admission, and the action. Throws only on an outage. */
	admit(input: RequirementInput): Promise<RequirementVerdict>;
	/**
	 * Establishment-time (D5); absent when the requirement never interrupts a login. A requirement's `Interruption` receives
	 * the continuation it must persist: `open(sessionId, continuation)`; the consumer-facing wrapper (`PrimaryAdmission.open`)
	 * takes the session id alone and passes the continuation core built.
	 */
	admitPrimary?(primary: PrimaryAuthentication): Promise<"establish" | RequirementInterruption>;
}

interface RequirementInterruption {
	open(sessionId: string, continuation: PrimaryContinuation): Promise<InterruptionAnswer>;
}

interface RequirementInput {
	readonly subject: string | undefined;                  // the record's `sub` when one was read, else the claim's subject — so a subject-specific requirement (an account hold) knows whose policy to check even with `session: null`; `undefined` only for the code record's first read
	readonly session: SessionView | null;                  // `{ sid, sub, authTime, expiresAt }`
	readonly authentication: RequirementSession | null;   // `requirementSession(session)` (D6), or from a token's `amr` (D2 step 5): the primary, `mfaAt`, the vouched `amr`
	readonly carrier: SessionClaim["carrier"];
	readonly action: AdmissionAction;
	readonly asks: AdmissionRequest["asks"];
	readonly now: Date;
}

type RequirementVerdict =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate" }
	| { readonly outcome: "step_up"; readonly whenStillUnmet: "reauthenticate" | "unmet" }   // the page is the requirement's registered `stepUpPage`; a verdict cannot name another
	| { readonly outcome: "unmet" };
```

- **Kind.** `sessionRequirements` is a name-keyed built-in kind (factory `(deps) => Contributed<SessionRequirement>`), collected like `mfaFactors` and projected by the synthetic key `sessionRequirementResolver` (`entries()` in registration order, `get(name)`). Consumers reach requirements only through the resolver, so their manifests name no extension. **`reach` is read once, at the end of stage 4's name-keyed pass** — not at registration, because the `mfa` requirement's `reach` is a getter over `mfaFactorResolver` and the factors it lists register in the same pass — validated in full by core as it is read (a set of non-empty strings, none a primary's marker, none reserved unless the name is `mfa` — D7; a JavaScript contributor is held to it as a TypeScript one is), and copied into a private set on the registered copy, exposed as a read-only view — `has`, `size` and iteration, no `add` or `delete` (a frozen native `Set` would still accept both) — so neither the contributor's own `Set` nor a consumer of the resolver changes it afterwards. `stepUpPage`, `remediations` (each `<name>.<route>` under the requirement's own name — and, since a consumer's action may share a requirement's namespace (`mfa.manage`), any name present in `ADMISSION_ACTIONS` is refused; another requirement's name is impossible by construction, the route holding no dot) and `hintKeys` are validated in full the same way, at registration. *(Amended 2026-09-30: a registered action's name is refused, where both kinds are known, at the end of stage 4 — D4's closing note.)* **In this release only the requirement named `mfa` may declare a non-empty `reach`**: the one way a completed step-up is written into a live session is `recordSecondFactor`, which is MFA's and stamps `mfaAt`, so another requirement's advertised reach could never be met — a generic, validated "record what a requirement vouched for" capability that leaves `mfaAt` alone is a later record's ("Outside the first release"), and until it exists a non-`mfa` requirement with a non-empty `reach` is refused at the end of stage 4. The drop of unsatisfiable `acr` entries (a list-shaped factory, D6) and admission at request time read the snapshot.
- **Not nullable, not overridable, not replaceable — three channels, three refusals**, none of which exists today: a new stage-1 row, `session-requirement-kind-guard`, refuses an `overrides.sessionRequirements` entry, and `createApp` refuses a host `contributionKinds` entry for `sessionRequirements` — and for `mfaFactors` — before it merges the map (stage 1 receives the merged map and cannot tell a host entry from the built-in; `createApp` holds the raw options), both under one new `BootErrorReason` (`session-requirement-kind-guarded`, so the pins in `types.test.mts` and `check-registry.test.mts` move), so a composition can neither replace a requirement nor swap the collector the projection and the boot line read; and `checkNameKeyedValue` gains a branch, for `sessionRequirements` only, that refuses a `null` answer and a `name` that is not the key (`contribute-factory-failed`, as `mfaFactors` does for `kind`) — `mfaFactors` keeps its accepted `null`, which is how a factor disabled by config stays claimed and invisible. A requirement is switched off by not installing it; nothing may quietly remove it from behind the consumers.
- **What a requirement may vouch for.** The second-factor `amr` values (`otp`, `hwk`, `swk`, `email`, `recovery`, `mfa`) and the session's `mfaAt` are reserved to the requirement named `mfa`: the end-of-stage-4 check refuses them in any other requirement's `reach` (`contribute-factory-failed`, so an out-of-tree requirement is held to it, not only one this repository's tests see), `resumePrimary` refuses them in any other requirement's additions (D5), and a drift guard limits the callers of `recordSecondFactor(` to `packages/mfa` (D10). A risk score or a re-consent cannot make a session meet `urn:o3co:acr:mfa`.
- **`stepUpPage` is copied and validated at registration** — a getter is read once, then — `url` a path or an absolute URL on the issuer's origin, `params` without `redirect_to`; a page that fails is `contribute-factory-failed`. A `step_up` verdict carries no page, so nothing a requirement answers at request time reaches a redirect unvalidated. Likewise `remediations` and `hintKeys` are copied at registration.
- **Order.** Registration order is init order — topological, with declaration order as tie-break — and a requirement's position is what it was registered at. Two requirements that both step up produce sequential trips; accepted for the first release.
- **One boot line**, at the end of stage 4, by `applyContributions`: `session_requirements_registered` at `info` with, in order, each requirement's name, the module that contributed it, and its declared remediations — so a module that merely calls itself `mfa` is visible to whoever reads the boot log — beside the declaration D7 requires. *(Amended 2026-09-30: each entry also says whether the requirement declares the second-factor authority — D3's closing note — so the log tells the authority from a requirement merely named `mfa`.)*
- **Contract suite.** `session-admission/testing/requirement.contract.mts`, run by every requirement's tests: `name` equals its key, and a fixture never uses the name `mfa`; `reach` holds non-empty strings, no primary's marker, and no reserved value unless the name is `mfa`; `stepUpPage` is set whenever `reach` is not empty (checked at the end of stage 4, where `reach` is read), and is valid whenever it is set; `remediations` are non-empty names; `admit` is never called with a dead session, and is never called for a `remediation` action; a `step_up` verdict is answered only when `stepUpPage` is set; an outage is thrown, never answered `met`; an interruption's body carries none of the reserved keys, and no hint value carries an address (D5).

**Amended 2026-09-29 (retro review): a requirement's name.** Above, a name is held only to the key it is contributed under. Registration (`registeredRequirement`) also holds it to two rules, each `contribute-factory-failed` at boot as every registration refusal is. It is RFC 6749's error-code characters — `1*NQSCHAR`, printable ASCII without `"` or `\`, core's `isWellFormedErrorCode` — because a `step_up` names the requirement on the wire under that grammar, and `/oauth/token` drops a member outside it, leaving the client refused with nothing to offer; the check at serialization stays, for a grant built by hand. And it is none of the names admission gives its own stores' outages — `ADMISSION_INFRASTRUCTURE_STORES`, `user_session` and `revocation_boundary` (D10) — because `Admission.store` carries either one of those or a requirement's name, and a consumer tells them apart by the string: core's `describeAdmissionOutage` words an outage for the client from that list — each of those stores by name, anything else as a requirement's — and oauth and device verification answer with it, so a requirement named `user_session` would have been reported as the session store.

**Amended 2026-09-30 (#733): the second-factor authority is declared, not named.** Where this section reserves something to the requirement named `mfa` — the only non-empty `reach`, the second-factor values in a reach, and what a completion may add of them and of `mfaAt` — it reads: to the requirement that declares, in its contract, that it is the second-factor authority (`SessionRequirement.secondFactorAuthority`). Core weighs the declaration and never a requirement's name; `MFA_REQUIREMENT_NAME` leaves core, and `mfa` is the MFA package's name for its requirement, which declares the authority. A requirement that does not declare it — one named `mfa` included — is held to what this section says of every other requirement, and the contract suite's fixture rule reads: a fixture never declares the authority. At most one registered requirement may declare it: a second refuses the boot (`duplicate-second-factor-authority`).

**Amended 2026-09-30 (MFA step 9):** the view also carries what the session recorded of its login's `User` for a first binding (`enrollmentFacts`), never the `User`.

### D4 — Actions: the consumer names what it does and its grade; the requirement decides by grade

Core exports the bundled actions as a closed union, `ADMISSION_ACTIONS`, each with its grade; a requirement's own tests prove its table exhaustive over the union. A deployment's own route builds `{ name, grade }` for what it does, and is treated by its grade — a route that adds a credential and says so gets the recent-MFA rule. The `remediation` grade is not the consumer's to claim: admission accepts it only for a name some registered requirement declared in its `remediations` (D3) — a name namespaced under that requirement, so a requirement cannot claim `oauth.authorize` either — and treats any other `remediation` action as `credential_change`, the strictest grade, logging `session_admission_remediation_undeclared` once per process per name: a route that mislabels itself to skip the requirements gets more of them, not fewer. Between `use` and `credential_change` a deployment's own route states its own grade, and that statement is trusted as the route is — a route the deployment writes protects itself by what it says, and no requirement can know better than the deployment what its route does; the bundled consumers' grades are fixed in `ADMISSION_ACTIONS` and not the deployment's to change. The README says so.

| Action | Grade | Consumer | The claim |
| --- | --- | --- | --- |
| `oauth.authorize` | use | `/oauth/authorize` | `cookieClaim` |
| `oauth.consent` | use | `/oauth/consent` (GET, POST) — liveness and revocation; a requirement's step-up here is answered `login_required` rather than a trip, because `/authorize` decides again after consent | `cookieClaim` |
| `oauth.session_grant` | use | the `session` grant | `cookieClaim` of the cookie handed to the grant |
| `oauth.code_exchange` | use | the `authorization_code` grant's two reads | `codeClaimFirstRead(code)` on the first — no subject — and `codeClaimRevalidation(code, sub)` on the second, whose subject is required, so the two reads are compared as today and the comparison cannot be left out |
| `oauth.refresh` | use | the refresh grant | `tokenClaim` |
| `device.lookup` / `device.approve` / `device.deny` | use | device verification, one per body action; the body is parsed before admission, so a malformed body is `400` before `401` / `503` (a pinned change, D8). `lookup` and `deny` grant nothing, and the MFA requirement refines by name to admit them under `required` (D6): a user refuses a phished device request without a step-up. *(Amended 2026-09-30: graded `grants_nothing` — D4's closing note.)* | `cookieClaim` |
| `federation_grants.connect` / `.consent` / `.callback` | use | the federation-grants browser half; the callback's re-read before activation is a second `admitSession` call with the same claim; a requirement's `step_up` is answered as the route answers a dead session (a plain 403 at connect, 403 reauthentication_required at consent, error=reauthentication_required at the callback) until the MFA ADR's step 14 designs the trip | `cookieClaim` |
| `session.link` | credential_change | the federation `?link=1` start: a linked identity is a new way in, and the recent-MFA rule is decided here, where a step-up has a page to return to | `cookieClaim` |
| `session.link_callback` | use | the link callback: liveness and revocation of the session the start bound; a step-up here would have nowhere to return | `linkClaim` — a form_post callback arrives on a fresh cookie session and has no other binding |
| `webauthn.register` | credential_change | the WebAuthn package's session-subject module (D8) | `cookieClaim` |
| `mfa.manage` | credential_change | the MFA package's own routes (list, remove, regenerate) | `cookieClaim` |
| *(not in the union)* `mfa.step_up` | remediation | `POST /session/mfa/step-up`: liveness and revocation only (D2, step 5). A remediation is never a member of `ADMISSION_ACTIONS` — the union holds the consumers' actions — it is declared by its requirement (`remediations`) and issued by core to that requirement alone (D2) | `cookieClaim` |

**Amended 2026-09-29 (module review): a bundled action is its `ADMISSION_ACTIONS` entry itself.** "The bundled consumers' grades are fixed in `ADMISSION_ACTIONS` and not the deployment's to change" holds at run time as well as at compile time: `admitSession` refuses, with a `RangeError` before anything is read, an action whose `name` is a key of `ADMISSION_ACTIONS` unless the object passed is that frozen entry itself — a copy of it, a literal with the same name and grade, and the name with another grade are all refused. So no consumer restates a bundled grade, even correctly, and a deployment's own route cannot take a bundled name, and with it a bundled grade, by writing a literal: its `{ name, grade }` names an action outside the union, as above. `session-admission/admit.mts` holds it; `session-admission/__tests__/admit.test.mts` pins it.

**Amended 2026-09-30 (#733): actions are a contributed vocabulary.** Each consumer registers the actions it admits (`admissionActions`), each with one of core's grades, and passes the name; core keeps the closed list of grades — adding `grants_nothing`, which the device grant declares for `device.lookup` and `device.deny` and the MFA requirement meets on any live session a record carries — a token is judged on its own `amr` whatever the grade — in place of D6's refinement by name — and names no consumer's action: `ADMISSION_ACTIONS` leaves core, and a name nothing registers is refused — where a consumer is built, or at the call. An action's grade is its registrant's: an override is refused, and boot says each action's grade and module.

### D5 — Establishment: `admitPrimary`, the interruption, and the capability to establish

`POST /session/login` reaches a point where the user is verified and nothing has been written. There it calls `admitPrimary(deps, primary)`:

```ts
interface PrimaryAuthentication {              // moves from `mfa/coordinator.mts`, generalised; branded — built by core, never by a route
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	readonly claims: UserSessionClaims;          // what `establishSession` writes as the session's `claims` (#713's `EstablishSessionInput.claims`): the route's `extractUserClaims(user)` for a password login, the merged federated envelope for a federated one
	readonly recorded: RecordedAuthentication;   // the `amr` and `authentication` the session would be created with (#707)
	readonly authTime: Date;
	readonly redirectTo: string | undefined;     // already held to the allowlist
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}
/** The one builder a password login has: `recorded` is `passwordSessionAuthentication()` — a route cannot hand in an `amr` or an `mfaAt`; `claims` is the route's, as today. */
passwordPrimary(facts: { subject; user; claims; authTime; redirectTo; request }): PrimaryAuthentication
// `establishSession(establishment, deps)` writes the session from `establishment.primary` — `claims`, `recorded`, `authTime`,
// `redirectTo` — and nothing the caller passes beside it; the continuation therefore carries `claims` too (persisted in the MFA
// transaction for the login's ten minutes, as the MFA ADR's D8 already keeps the `user` snapshot there).
// `admitPrimary` accepts only a primary a core builder made (a module-private `WeakSet`, like the claims); `establishWithoutAsking`
// builds the federated one itself (below). No other builder exists. `resumePrimary` reads a continuation a store round-tripped —
// plain data no `WeakSet` can mark — so it checks the continuation's shape (`checkPrimaryContinuation`) and composes `recorded`
// itself; a persisted continuation is inside the trust boundary of the requirement that persisted it, as D5 states.

type PrimaryAdmission =
	| { readonly outcome: "establish"; readonly establishment: Establishment }   // every requirement answered `establish`
	| {
			readonly outcome: "interrupt";
			readonly requirement: string;
			/** What the requirement persists in its own record and presents to `resumePrimary` when its ceremony completes. */
			readonly continuation: PrimaryContinuation;
			open(sessionId: string): Promise<InterruptionAnswer>;
	  }
	| { readonly outcome: "unavailable"; readonly store: string };

/**
 * A serialisable DTO, not a branded object: the primary as the route built it, and what every completed requirement added
 * so far. Dates travel as epoch milliseconds, so a requirement can persist it in its own record (the MFA transaction) and
 * present it back from any replica; `resumePrimary` rehydrates and validates it (`checkPrimaryContinuation`: every field its
 * type admits, `recorded` well-formed, `done` entries each with a registered requirement's name) before composing from it.
 */
interface PrimaryContinuation {
	readonly primary: PrimaryAuthenticationDto;   // `PrimaryAuthentication` with `authTime` as epoch ms
	readonly done: readonly { readonly requirement: string; readonly adds: { readonly amr: readonly string[]; readonly mfaAtMs?: number } }[];
}

/** Branded and runtime-checked; built by `admitPrimary`, `resumePrimary` and `establishWithoutAsking` alone. `establishSession` requires one. */
type Establishment = { readonly [establishmentBrand]: true; readonly primary: PrimaryAuthentication };

interface Interruption {
	open(sessionId: string): Promise<InterruptionAnswer>;
}

interface InterruptionAnswer {
	readonly status: 403;
	readonly body: {
		readonly error: string;                         // held to the RFC 6749 error-text class
		readonly transaction?: string;
		readonly expires_in?: number;
		readonly hints?: Readonly<Record<string, string | number | boolean | readonly string[]>>;
	};
}
// Core wraps `open`: the answer is validated before it reaches the route, by a grammar core owns — `error` to the error-text
// class; `transaction` a base64url string; `expires_in` a positive integer; every `hints` key one the requirement declared in
// `hintKeys` AND of the form `^[a-z][a-z0-9_]{0,31}$` AND not one of core's reserved names (`user`, `sub`, `sid`, `subject`,
// `email`, `mail`, `address`, `phone`, `name`, `token`, `secret`, `password`, `claims`, `profile`); every hint value a boolean, a
// finite number, or an enum-like token `^[a-z][a-z0-9_-]{0,63}$` (or a list of such tokens). A snapshot, a URL, an IP address,
// an e-mail address or a name cannot pass that grammar, whoever wrote the requirement. A body that fails is the requirement's
// fault: a `RangeError`, which the route answers as an `open` failure (`503`, `abandonCookieSession`).

/**
 * After an interruption completes: appends what the completing requirement verified to the continuation,
 * composes the session's `recorded` from the primary and every completed requirement's additions (`composeAmr`,
 * refusing a reserved value or `mfaAt` under any name but `mfa`), and asks, in order, every requirement with
 * `admitPrimary` not already in `done` over the composed result — a requirement that completed is not asked again in
 * this login. There is no "after": one that has not completed may interrupt, with the updated continuation.
 */
resumePrimary(
	deps: AdmissionDeps,
	continuation: PrimaryContinuation,
	completed: { readonly requirement: string; readonly adds: { readonly amr: readonly string[]; readonly mfaAt?: Date } },
): Promise<PrimaryAdmission>
```

- Requirements with `admitPrimary` are asked in order; the first `Interruption` wins; a throw is `unavailable`, and the route answers `503` with nothing written — the MFA ADR's F1, step 1. As with `admit`, every answer is validated at the boundary: anything but the string `"establish"` or an object with an `open` function is `unavailable` (`store: <its name>`), logged once — never read as `establish`. Core wraps the winning requirement's `open`: the route calls `PrimaryAdmission.open(sessionId)`, and core calls the requirement's `open(sessionId, continuation)` with the continuation it built (the primary and `done` so far), which the requirement persists in its own record and presents back to `resumePrimary` — so a second interruption receives the first's additions without reconstructing core-owned state. Only when every requirement answered `establish` does `admitPrimary` return an `Establishment`, and `establishSession` (#713's: the two routes' create → index → regenerate → flags → save sequence in one function, the package's own and not exported today; A6 reshapes it to take the `Establishment` and exports it from `packages/session`, so the MFA package can finish a login with it — the MFA ADR's D2 amendment) takes it as its first argument and writes the session from `establishment.primary` alone, never from a `recorded` the caller passes beside it. A requirement that completes its interruption — MFA after a verified factor — presents the continuation it persisted in its own record and what it verified: `resumePrimary(deps, continuation, { requirement: "mfa", adds })`, and establishes only on `establish`; the review found that with two interrupting requirements, whichever is ordered first would otherwise complete the login and the other would never be asked, the order being decided by unrelated module dependencies. `resumePrimary` names no "after" — the reviews found that a name could be forged to skip the rest, and that a second interruption would drop the first's additions — so it asks, in order, every requirement with `admitPrimary` not already in `done` — a requirement that completed is not asked again in this login — over the composed result, and the continuation accumulates each completed requirement's additions: a second interruption resumes with the first's `amr` and `mfaAt` still in `recorded`. **Why by name, and what it rests on.** A requirement with an empty `reach` adds nothing, so it cannot see its own completion in `recorded`; asked again, it would interrupt again, and the login would loop. So a completed requirement is skipped by its name in `done`. `done` grows only by `resumePrimary` appending the continuation's `interruptedBy` — the completion must name that requirement — and a name twice, or one that is not a registered requirement with `admitPrimary`, is refused; the continuation's integrity therefore rests on the requirement's server-side record, and a requirement must never round-trip the continuation through the client. The `mfa` requirement's fail-closed guarantee — that a completion which verified nothing never establishes a password-only session — comes from the addition rule below, not from being asked again. The session's `amr` and `authentication` are composed by core (`composeAmr`, the MFA ADR's D14) from the primary the route built and the additions, never from a `recorded` a caller hands in; `completed.adds.amr` must be a subset of the completing requirement's snapshotted `reach`, and `mfaAt` is accepted under the name `mfa` alone — a value a requirement never declared it could add is refused (`RangeError`), so what a session vouches for is bounded by what was registered. Under the name `mfa`, a completion must be a verified second factor: at least one second-factor value of the factor's own (not `mfa`), `mfa` beside it unless the factor is the email code (whose `addsMfa` is off by default, the MFA ADR's D14 and O7), and `mfaAt` — refused otherwise (`RangeError`), whether presented to `resumePrimary` or read back from a continuation's `done`. *(Amended 2026-09-30: under the requirement that declares the second-factor authority, whatever its name — D3's closing note.)* `Establishment` is checked at runtime through a module-private `WeakSet`, like the resolver and the claims, and so is the interruption `admitPrimary` and `resumePrimary` answer (`InterruptAdmission`, `isInterruptAdmission`), which the session package's `answerInterruption` — the login's two phases, below, which a requirement's completion route calls too — requires. **The trust boundary is stated, not hidden**: a requirement's completion route is installed code, trusted as any module is (a module can just as well `provides` a fake store); what these checks refuse is a mistake — a wrong name, a forgotten addition, a primary rebuilt by hand — and what they keep honest is the contract. `tools/composition` pins the sequence with two interrupting fixture requirements: first interrupts, resumed, second interrupts, resumed with both additions present, established.
- **Two phases**, because the express session is regenerated between them (the MFA ADR's D8): the route regenerates, leaves the session unauthenticated, calls `open(req.sessionID)`, saves, and answers `status` with `body`. The exhaustive mapping in the route, each case pinned in A6: `unavailable`, a throw from `open` after the regeneration, and a `save` that fails after `open` → `503`, `abandonCookieSession`, no `UserSession`, never `establishSession`; a `save` failure leaves the requirement's record to its own expiry — the MFA transaction to its TTL — since the session id it is bound to will never be presented. The body's shape is closed and core validates it against the requirement's declared `hintKeys` before the route sees it, so a requirement cannot answer the `user` snapshot or an address to whoever holds the password; that a `403` reveals the password was right is what the MFA ADR's D23 already accepts.
- **The federation callback, in this release, does not call `admitPrimary`.** Its hook slot is the same shape (the user resolved, nothing written), and the MFA requirement would answer `establish` for a federated primary anyway (the baseline applies after `pwd` only, the MFA ADR's D13). But an interruption there would have to be answered as a navigation — a redirect chosen by the redirect policy, not a `403` body — and the upstream tokens the callback attaches after the session is written would have to travel in the requirement's record — the continuation the MFA transaction persists carries the primary and the additions, not those tokens. Both are the obligations of a later record ("Outside the first release"); until then, the callback calls `establishSession` with an `Establishment` that core builds for it without asking — `establishWithoutAsking(federated)`, which does not take a `PrimaryAuthentication` at all: it takes what a federated login legitimately produces (`subject`, `user`, the merged `claims`, the federation's name, the upstream `amr` as the IdP surfaced it, whether that federation is trusted, `authTime`, `request`) and composes `recorded` itself through #707's `federatedSessionAuthentication`, so a caller cannot mark an arbitrary `amr` or an `mfaAt` as a federated primary — the seam accepts only a federation's own facts, and a federated primary is outside the MFA baseline (the MFA ADR's D13), every requirement still applying at each use. A drift guard pins its callers to that one site; the shape of its input is what holds outside this repository, where the guard does not reach. Until the callback consults admission, a requirement's `admitPrimary` is never asked for a federated login — only its use-time `admit` applies to the session that results — and a requirement that needs the login hook for federated primaries is the later record's.

The interruption's body is a wire contract the MFA ADR's F1 and F3 wrote before this record: their `mfa_transaction`, `enrollable` and `email_proof` become `transaction`, `hints.enrollable` and `hints.email_proof` (§7), so every requirement's interruption reads the same way to a page.

### D6 — MFA becomes the first requirement; what leaves core and what stays

| Today (the MFA ADR's steps 3–5) | After this record |
| --- | --- |
| `mfaCoordinator` slot and `MFA_ABSENCE_POLICY` (`mfa/coordinator.mts`) | Removed. The MFA package contributes `sessionRequirements: { mfa }`; the coordinator is an internal of that package. |
| `decideMfaRequirement`, `MfaRequirementInput`, `MfaRequirementDecision`, `MfaRequirementSession` (`mfa/requirement.mts`) | The merge — its D16 rule — becomes D2's step 7, in core (`session-admission/admit.mts`); the baseline becomes the MFA requirement's `admit`, in the MFA package. The function and its two types are deleted, `MfaRequirementSession` is renamed `RequirementSession` (`session-admission/`), and the table-driven tests are split the same way (acceptance criterion 4). |
| `selectAcr`, `stepUpReach`, `readAcrTable`, `producibleAmr`, `vouchableAcrTable`, `AcrTable`, `AcrRequirement`, `UnsatisfiableAcrValue` (`mfa/requirement.mts`) | Stay in core, in `session-admission/acr.mts`: the provider's `acr` vocabulary. `producibleAmr` takes `reach` — the union over the resolver — where it took `secondFactorMethods`; `oauth/src/acrValues.mts` is its caller, so A2 touches that file. |
| `readMfaMode`, `MfaMode`, the `mfa` section of core's schema, `ratelimit/mfaSpec.mts` | Stay in core (D7). `readMfaMode`'s caller in `oauth/src/acrValues.mts` — the info-versus-warn rule of the MFA ADR's D15 — no longer reads the mode: a dropped entry is `info` when one alternative lacks only second-factor values and **no registered requirement reaches them**, `warn` otherwise. *(amended 2026-09-30: `readMfaMode`, `MfaMode` and the `mfa` section left core; `mfa.mode` is the MFA module's key — D7's closing note)* |
| `sessionAuthentication`, `vouchedAmr`, `requirementSession` (`user-sessions/authentication.mts`) | Stay; `requirementSession` answers the renamed type. |
| The `mfaFactors` kind, `mfaFactorResolver`, `MfaFactor`, the stores, `mail/`, the witness | Stay in core as step 3 put them: ports the MFA package and its adapters share. |
| `mfa-requires-user-session-store`, the boot refusal D16 planned for `oauthModule` and `deviceGrantModule` (never built) | Dropped from the plan. The MFA package's module `requires: ["userSessionStore"]`, so a composition without one is refused at the requires-closure, naming the slot. |

The MFA requirement, in `packages/mfa`: `name: "mfa"`; `reach` = the coordinator's `secondFactorMethods`; `stepUpPage` = `endpoints.mfa.url`; `admit` = the baseline under `mfa.mode`, by grade:

| `mfa.mode` | Grade | Session | Verdict |
| --- | --- | --- | --- |
| `required` | use, credential_change | `null`, or a primary the rule does not know | `reauthenticate` |
| `required` | use | primary `pwd`, no `mfaAt`, `reach` not empty | `step_up` to `endpoints.mfa.url`, `whenStillUnmet: "reauthenticate"` |
| `required` | use | primary `pwd`, no `mfaAt`, `reach` empty (no factor enabled) | `unmet` — nothing could finish the step-up |
| `required` | use | primary `fed`, or `mfaAt` set | `met` |
| `required` | use, named `device.lookup` or `device.deny` | any live session | `met` — refined by name: neither grants anything, and a user must be able to refuse a phished device request without a step-up (the MFA ADR's D16 gated `approve` alone). *(Amended 2026-09-30: by the `grants_nothing` grade, never a name — D4's closing note.)* |
| `required` | use, carrier `token` (the refresh grant, D9) | primary `pwd`, no second-factor value in the token's `amr` | `unmet` — the MFA ADR's O3: a password-only refresh token ends at its next refresh |
| `required` | use, carrier `token` | no `amr` at all (issued before #481) | `reauthenticate` — unknown, as O3 counts it |
| `required` | use, carrier `token` | `fed`, or a second-factor value present | `met` |
| any | credential_change | no recent MFA (the MFA ADR's D16, "recent MFA": `mfaAt` within `mfa.manage.maxAgeSeconds`; for a subject with no counting factor, a primary that recent) | `step_up`, or `reauthenticate` for a subject with no counting factor and a stale primary |
| any | credential_change | recent MFA | `met` |
| `optional` | use | any | `met` |

*Amended 2026-09-30: under `required`, `credential_change` is recent MFA on top of the baseline — the baseline is asked first and its answer stands unless it is met. The two "any | credential_change" rows read alone let a password session without a second factor, whose subject holds no counting factor, meet the grade on a recent primary while `use` stepped it up; the strictest grade (D4) is never looser than `use`, and every consumer applies the baseline (the MFA ADR's §7).*

`admitPrimary` = `decideAfterPrimary` and `openLoginTransaction` behind one `Interruption`, asked once per login — `resumePrimary` does not ask it again after its own completion (D5); the transaction persists the continuation, and the verified factor's completion calls `resumePrimary` with it and then `establishSession` (D5). `/authorize`'s D17 ask handling — the trips, the accumulating record, `prompt=none` → `interaction_required` — stays in `oauth`, driven by `Admission` instead of by `decideMfaRequirement`.

### D7 — A requirement installed is a requirement on; what a composition expects is declared; asking for one that is not installed is refused (re-decides the MFA ADR's O2)

Under the MFA ADR, "on by default" was to be expressed by removing core's default for `mfa.mode`, so that every composition states `required`, `optional` or `off` (O2), with `MFA_ABSENCE_POLICY` on the `session` and `oauth` manifests making an unfilled `mfaCoordinator` a refused boot. That followed the repository's rule for an **optional slot a module reads** with a security consequence.

The first draft of this record replaced that with a warning when no requirement is registered, by analogy with the token-binding mechanisms. Both reviews rejected the analogy, and this record agrees: a mechanism's absence is declared by a core config key, and a client that asked for it is refused rather than downgraded — whereas MFA's baseline has nobody asking, and its absence downgrades every password login silently. A warning also dies as soon as any other requirement is installed, and the repository's rule is that absence is a decision, not a default. So:

- **Core keeps the `mfa` section of its schema, `mfa.mode` among it, with the reference default `off`.** The review found the alternative — the key declared by the MFA package alone — does not work: core's schema is strip-mode, so `mfa.mode = "required"` without the package would be silently dropped rather than refused; the template parses through `AppConfigSchema` before `buildModules` reads the switch; core's `ratelimit/mfaSpec.mts` reads `mfa.rateLimit.*`; and the key-parity and reference-conf drift tests require core's schema to declare a bundled package's keys. The schema admits the three values from A2 (the step-3 lock to `"off"` is lifted); O2's "core removes its default" is dropped.
- **Installed ⇒ on.** The MFA package's module reads `mfa.mode`; `required` and `optional` are its two behaviours; `off` with the package installed is refused by the package ("remove the module, or set `mfa.mode`"), the MFA ADR's D20 row, kept.
- **What is expected is declared.** A new core key, `sessionRequirements.expected` — a list of requirement names, `[]` allowed, with **no default** in core's schema or `reference.conf` — is **required** whenever a consumer of admission is installed (a module lists `sessionRequirementResolver` in its `requires` or its `optional` — read from `plan.validated.modules[].normalised`, which every module has, as `checkDeclaredAbsence` reads it; `depsBlueprint` omits a requires-only module), and is compared with the registrations at the end of stage 4, where `applyContributions` holds the parsed config, the collector and the plan: the declared set and the registered set must be **equal** — a name declared and not registered, a requirement registered and not declared, or nothing declared at all, refuses the boot (`session-requirements-undeclared`, naming the key, the declared names and the registered names). An `expected: []` beside an installed requirement is therefore refused too: a composition cannot install an extension that changes admission without saying so. *(Amended 2026-09-30: a name declared and not registered is `session-requirement-missing`, and a written declaration is compared both ways with or without a consumer — this section's closing note.)* Core names no requirement; the template's `buildModules` writes `["mfa"]` or `[]` in TypeScript (HOCON has no conditional), and a hand-written composition writes what it means — `testing/fixtures/valid-config.mts` and every `createApp` test that installs a consumer gain `expected: []`. This is O2's substance — every composition states its posture — in the generic form the kind allows, with no absence policy and no module named in core's boot rules.
- **Asked for, not installed ⇒ refused.** `mfa.mode` present and not `off` while no requirement named `mfa` is registered refuses the boot (`session-requirement-missing`, naming the module to install and `mfa.mode = "off"` as the alternative) — the MFA ADR's step-3 guard ("refused at boot rather than left believing logins ask for a second factor"), kept. It puts the name `mfa` into one core check; the check reads a config key core already owns, so the coupling is no wider than the schema's. *(Amended 2026-09-30: core's check is generic — a declared name nothing registers — and the template declares `mfa` from the mode; this section's closing note.)*
- **The name `mfa` is reserved, and bound to core's MFA ports.** A requirement registered as `mfa` is accepted only from a module that lists core's `mfaFactorResolver`, `mfaFactorStore` and `mfaTransactionStore` in its `requires` (the plan's `depsBlueprint` says so), whose `reach` equals the set core recomputes from `mfaFactorResolver.entries()` — the union of each enabled factor's `amrValues`, and `mfa` when one of them `addsMfa` (`amrValues` is a static list A2 adds to the `MfaFactor` port beside the data-dependent `amrFor`, which the MFA ADR's D8 assumed the coordinator had; a factor-type test holds `amrFor`'s answers to it) — and whose `remediations` include `mfa.step_up`; anything else registered as `mfa` is refused at the end of stage 4 (`contribute-factory-failed`, naming the module). A module that meets all three is wired to the factor and transaction stores and the installed factors — it is an MFA implementation, whoever published it — and beyond that installed code is trusted, as D5 states; the boot line names the module for the operator.
- The template's and create-app's switch stays: `MFA_MODE` feeds `mfa.mode` through `application.conf`, and `buildModules` derives both what it installs and `sessionRequirements.expected` from the **parsed** `mfa.mode` — never from the raw environment variable, which would let `MFA_MODE=required` boot with `expected = []` and `mfa.mode = off` — `off` installing nothing and declaring `[]`, and the default becomes `required` at the flip — the MFA ADR's step 22, now template and create-app only. A template test pins each of the three values. `create-app --no-mfa` is unchanged. *(Amended 2026-09-30: the declaration is the configuration's own list with `mfa` added under a mode other than `off`, through the template's `expectedSessionRequirements`; this section's closing note.)*

Rejected: moving `mfa.mode` out of core (strip-mode, above); a warning in place of the declaration (the first draft; see above); an absence policy on the resolver (it would fire unconditionally, a synthetic key being never planned).

**Amended 2026-09-30 (config ownership, #728): core's checks act on `sessionRequirements.expected` alone; the template keeps declaring `mfa` from `mfa.mode`.** Stage 1 still validates `mfa.mode` (core's schema keeps declaring it until #728 moves it under the MFA module with `readMfaMode`), but boot's checks no longer act on it. The fourth bullet's refusal takes the generic form: a name in `sessionRequirements.expected` that no module registers refuses the boot as `session-requirement-missing` (naming the key, the missing names, what is declared and what is registered), checked first so a composition is told to install the module rather than to fix the list. Once the key is written it is compared both ways whether or not a consumer is installed — a registered requirement it leaves out is `session-requirements-undeclared` — and beside a consumer it must be written; with no consumer and no key, nothing is compared. The last bullet stands: the template's composition root turns its switch into the declaration — its `expectedSessionRequirements` adds `mfa` to the configuration's own list (`[]` in the shipped `application.conf`, an operator's names kept) when the parsed `mfa.mode` is not `off` — so `MFA_MODE=required` without the MFA module is refused (`session-requirement-missing`, `missing: ["mfa"]`) and the step-3 guard holds there; a hand-written composition declares `mfa` itself. Core's boot rules name no requirement. *(Amended 2026-09-30: `mfa.mode` is the MFA module's key. The module's section schema holds it to the three values and the MFA package's `reference.conf` carries its default `off` and `MFA_MODE`; core's schema and `reference.conf` name no `mfa` section, and `readMfaMode` is gone from core. The template reads the key itself — raw from its own layers, where its `application.conf` binds `MFA_MODE` with no default, held to the three values, absent read as `off` — and declares `mfa` from it as above, until the MFA ADR's build-order step 20 installs the MFA module and removes that reading. A hand-written composition that must require MFA declares `mfa` in `sessionRequirements.expected`, which boot refuses unmet; an `mfa` section it writes without the MFA module is one no module reads.)*

**Amended 2026-09-30 (#733): the binding is the declared authority's.** The fifth bullet's binding to core's MFA ports applies to the requirement that declares the second-factor authority (D3's closing note), whatever its name, and to no other; the name `mfa` is reserved to nothing. The template's composition root, under a parsed `mfa.mode` other than `off`, refuses the boot unless the requirement it declares for MFA, `mfa`, is registered as the declared authority, so a requirement merely named `mfa` cannot stand in for MFA there.

### D8 — The consumers, and what changes for each

Every cookie consumer in the inventory calls `admitSession` with its own slots and keeps its protocol's answers — what each answers per outcome is the site's, as the MFA ADR's D16 table listed. A consumer that re-checks a session before a write, as two do today on purpose, calls `admitSession` again with the same claim and maps `not_live` to its existing answer; no consumer reads the store by other means. The table below says what **changes** because the reading is now shared. Each change is breaking for a deployment that relied on the old behaviour, and each is pinned by a test named for it (acceptance criterion 3).

| Consumer | Changes in behaviour |
| --- | --- |
| `/authorize` | The cookie flag is still checked first, before the client is looked up and with no store read, so an unauthenticated request is sent to the login page as today; `admitSession` is called once, after the client lookup and the `redirect_uri` check, the request-object refusal, and the parsing of `prompt`, the single-valued parameters, `claims`, `max_age` and `acr_values`, and before the `response_type`, grant-type, first-party, email-verified, PKCE, nonce and scope checks (`acr_values` is parsed only then), and `evaluateReauthentication` is applied to `admitted`, `step_up` and `unmet` before the method verdict is acted on, so `prompt=none` with a stale `max_age` still answers `login_required`. Changes: (1) a cookie with `isAuthenticated` but no `sid`, while a store is wired, is `not_live` → the login redirect, instead of a code minted without `sid`; (2) a store outage is `temporarily_unavailable` on the validated redirect URI — not a redirect to the login page; (3) a cookie without `user.id`, or a record whose `sub` differs from it, is `not_live`; (4) the subject-revocation boundary applies when `subjectRevocation` is wired — the handler receives the slot `oauthModule` already declares; (5) a record past its `expiresAt` is `not_live`; (6) the cookie session is regenerated before a login redirect for `not_live` / `revoked` / `reauthenticate`, so the flag no longer survives the refusal — a regeneration that fails is a session-store write, answered `temporarily_unavailable`; (7) a cookie whose session is dead, sent with an invalid client, is answered the client's `400` after the lookup, where today it is redirected to the login page before the client is looked up. `readLiveSession` and `resolveAcr` are deleted; `evaluateReauthentication` and the ask stay until the MFA ADR's step 13 reshapes them, the ask's `mfaAskedAt` becoming per-requirement (§7). The log line `authorize_session_liveness_unavailable` becomes admission's (D10). |
| `/consent` | (1), (3), (4), (5). A store outage stays `503`; `consent_session_liveness_unavailable` becomes admission's. |
| `session` grant | (4), (5). `step_up` → `400 invalid_grant` with `step_up: "<requirement>"`, the MFA ADR's row — RFC 6749's vocabulary on the token endpoint, so no new code there. |
| `authorization_code` grant | (4), (5) on both reads; the first read's claim carries no subject (`codeClaimFirstRead`, D4), the second is built with `codeClaimRevalidation(code, sub)`, whose subject is required, so `session_invalidated` on a changed `sub` stands and cannot be skipped. |
| device verification | none in liveness or revocation, already fail-closed; `livenessOf` and the direct `revokedBefore` read are replaced. Changes: the body is parsed before admission (`400` before `401` / `503`); (5); `step_up` on `approve` → `403 { error: "step_up_required", requirement }` — one code, whichever requirement asked; `lookup` and `deny` are never stepped up by the MFA requirement (D6, by name), and a `step_up` another requirement answers for them is `403 step_up_required` all the same; the log lines `device_verification_session_liveness_unavailable` and `device_verification_session_subject_mismatch` become admission's (D10), with the runbook rows updated. |
| federation-grants connect / consent / callback | none in liveness or revocation; `judge` / `sessionHolds` keep the intent, binding and client checks and delegate the session part; the callback's re-read before activation is the second call; (6) does not apply — connect's only login redirect is for a cookie that is not authenticated, and a dead session keeps its plain `403`. The grants boundary (`grantsRevokedBefore`) is theirs and stays. A requirement's `step_up` is answered as the route answers a dead session (a plain 403 at connect, 403 reauthentication_required at consent, error=reauthentication_required at the callback) until the MFA ADR's step 14 designs the trip. |
| federation `?link=1` start and callback | the start reads the live session and decides the recent-MFA rule (today: the flag and `typeof sid` only), (3), (5); the start envelope records the subject beside the `sid`, and the callback's claim is `linkClaim` (D4), so a form_post callback on a fresh cookie is admitted as it is today; (4) once `sessionModule` gains an optional `subjectRevocation` slot — it has none today — attached to `SUBJECT_REVOCATION_ABSENCE_POLICY`, which it already attaches for `subjectSessionIndex`. |
| WebAuthn registration | `packages/webauthn` gains `webauthnSessionSubjectModule({ subjectFor })`: a module that `requires` `sessionRequirementResolver` **and `userSessionStore`** (the cookie path it serves is the store-backed one, so `admitted.session` is never `null` there), lists `subjectRevocation` optional, and contributes a route at the registration routes' mount path, `after: ["session-middleware"]` and `before:` the two registration routes, which calls `admitSession` with `webauthn.register` and, on `admitted`, sets `req.webauthnSubject` to `subjectFor(session)` — the deployment's mapper, because the README requires an opaque `userId`. `unavailable` → `503`; `step_up` → `403 step_up_required`; every other outcome → `next()` with no subject, and the routes answer `401` as today. The README's other bridge — a subject taken from a bearer token — is not a session consumer and stays the deployment's own middleware, as today; a cookie-only composition without a store keeps writing its own bridge too, and the README says both. The review found that a middleware core exports cannot set a field `packages/webauthn` types, and that a deployment-built session bridge is the resolver-less consumer D1 forbids. |
| refresh grant | through admission with `tokenClaim` (D9): the live read by the token's `sid` as today, the O3 rows once the MFA requirement exists; `unmet` / `reauthenticate` / `not_live` → `400 invalid_grant`; `step_up` → `400 invalid_grant` with `step_up: "<requirement>"`, as the `session` grant answers — a token has no browser to send anywhere, and the client re-authenticates the user interactively; the revocation boundary stays `verifyJwt`'s. No change beyond D2's reading of the record until a requirement is registered: a record past its `expiresAt`, with an `authTime` that is not a valid date, or whose `sub` is not the token's is `session_invalid` (D2, steps 2 and 3), where the grant asked only whether one existed. |
| `device_code` grant, introspection, userinfo, federation token, token exchange, logout | **not through admission in this release** (D9) |

`403` bodies and `303` redirects on the plain-text federation-grants pages keep their text. `step_up` on a `403` route always carries `requirement`, and on a browser-facing consumer the page.

**On change (4).** It applies where a store is wired beside `subjectRevocation` — the boundary is read against a live record (D2, step 4). `revokeAllForSubject` stamps the boundary at its own `now()`; a session established within `DEFAULT_SUBJECT_REVOCATION_SKEW_MS` (one second) of it — the user's own immediate re-login, or a login replica whose clock runs behind — is refused until the user logs in again. Device verification and federation grants accept this today, and so does this record: the skew is the price of the backstop, a login a second later is not, and only the Store or an operator can trigger a revocation. The token side compares in whole seconds (`verifyJwt`) where the session side compares in milliseconds; a session established in the sliver between the two passes admission and has its tokens refused at once — harmless, and unified when D9 moves the token side.

**Amended 2026-09-29 (review): the page a `403 step_up_required` carries.** Above, a `step_up` on a browser-facing consumer carries "the page" without saying in what form, and the consumers answered it two ways — device verification as an absolute URL it built on an issuer it was given, the WebAuthn session-subject module and the link start as the `StepUpPage` object, leaving every caller to resolve it. The member is a **string: one absolute URL — the page resolved at registration on the issuer**. Registration (`registeredRequirement`, D3) already holds a page to the issuer's origin; it now also resolves it there, once, on the issuer it was validated on (`oauth.jwt.issuer` at boot): its `url` against the issuer — a path against the issuer's origin, as a browser resolves a `Location`, an absolute URL as it is — and each of its `params` set on the query with `searchParams.set` (`stepUpPageUrl`, D2's rule for building one — never concatenation). The registered page carries it as `href` (`RegisteredStepUpPage`), and `Admission.step_up.page` is that page. Every consumer answers or navigates from `page.href` and none reads the issuer for it: the JSON consumers answer it as it is, so no caller resolves anything and none can resolve it against its own origin when that is another host; `/authorize`'s trip navigates to it with its own two parameters added — the `acr_values` hint of its request, and `redirect_to`, which D3 reserves as the consumer's return parameter — and keeps its own origin check as defence in depth. A JSON consumer answers no return parameter: its caller is the deployment's own page, which knows where it comes back to and adds its own when it navigates. A path page has nothing to be resolved on without an issuer, and its registration is refused (`resolverForTests` takes the issuer a test registers on). Device verification, `webauthnSessionSubjectModule` and the link start carry the page; the link callback answers a step-up `401 login_required` (it has nowhere to return to), the token endpoint `invalid_grant` with `step_up`, and the federation-grants browser half as it answers a dead session — none of them carries a page.

### D9 — Sessions read from a token: the refresh grant moves now, the rest later

The refresh grant, the `device_code` grant, introspection, userinfo, the federation-token route, token exchange and the logout routes read a session by a `sid` taken from a token or a record, with the subject-revocation boundary applied through `verifyJwt` where it applies. Their reads are already fail-closed and consistent (`session_invalid`, `503`), and they hold no cookie.

**The refresh grant moves in this release**, because the MFA ADR's O3 needs it: under `required`, a refresh token issued to a password-only session must stop minting at its next refresh, and no other place can apply that. Its claim is `tokenClaim(claims)` — the verified refresh token's `sid` (optional: without one the read is skipped, as today), `sub` and `amr` — and the MFA requirement's table gains the O3 rows (D6): carrier `token`, mode `required`, primary `pwd` and no second-factor value among the token's `amr` → `unmet`; no `amr` at all (a token issued before #481) → primary unknown → `reauthenticate`; `fed`, or a second-factor value → `met`. The grant maps both to `400 invalid_grant`, the MFA ADR's row, and a `step_up` — which the MFA requirement never answers for a token, but another may — to `400 invalid_grant` with `step_up: "<requirement>"`, as the `session` grant does. The subject-revocation boundary for a token stays `verifyJwt`'s (whole-second granularity) — admission's step 4 is skipped for a token carrier, so the two readings do not double up, and the granularity is unified when the rest move.

The others are out of this release's scope; `SessionClaim` names its carrier so a later record routes them through `admitSession` without changing the port.

### D10 — Outages, logs, audit, and the guards

- **Logs.** `admitSession` logs an outage once, at `error`, object-first: `session_admission_unavailable` with `store` (`user_session`, `revocation_boundary`, or the requirement's name), `action` (a bundled action's name, or an issued remediation action's — both core-validated vocabulary — else `custom`), and `loggableError`'s projection — never the `sid`. A subject mismatch is `session_admission_subject_mismatch` at `warn` with `action` and no identifier; a cookie without a subject is `session_admission_no_subject` at `warn`. Three lines are logged once per process per requirement name, at `warn`: `session_admission_remediation_undeclared` (D4), `session_admission_step_up_without_page` and `session_admission_step_up_without_session` (D2, step 5). The boot line is `session_requirements_registered` (D3). These replace the consumers' own lines (`authorize_session_liveness_unavailable`, `consent_session_liveness_unavailable`, `session_grant_store_unavailable`, `device_verification_session_liveness_unavailable`, `device_verification_session_subject_mismatch`), and the operator runbook's rows move with them. Nothing else is logged: a refusal is the consumer's line, as today. `/authorize` adds two error lines of its own: `authorize_cookie_session_unavailable` (`store: "cookie_session"`, `step: "regenerate"`) when the cookie session cannot be regenerated before a login redirect (D8, change 6), and `authorize_step_up_page_off_origin` (the requirement) when the step-up page it built is not on the issuer's origin, which it never follows.
- **Audit.** One new built-in event, `session.admission.subject_mismatch`, with the claim's `sid` — the cookie's, the code record's, the link transaction's or the token's, whichever carrier made the claim — the `carrier`, the subject the claim named and the record's. A subject mismatch is a security signal whichever carrier made the claim, and a session's `sid` is not a secret: it is the value the id_token carries as its `sid` claim. Emitted through the consumer's `auditSink` when wired. Everything else is unchanged: the consumers' events, and a requirement's own.
- **The boundary reading keeps its home.** `coveredByRevocationBoundary` stays in `federation-grants/effective-status.mts`, which core's grants boundary already uses; moving it under `session-admission/` would close a cycle `importBoundaries.drift.test.mts` forbids. It gets a design-vocabulary row of its own, and admission imports it.
- **Drift guards** (`packages/core/src/__tests__/`): a design-vocabulary row for admission, home `session-admission/admit.mts` (`admitSession`, `admitPrimary`, `resumePrimary`, the claim builders); the five rows homed at `mfa/requirement.mts` re-homed — `selectAcr`, `readAcrTable`, `vouchableAcrTable` to `session-admission/acr.mts`, `readMfaMode` and `MfaMode` to `mfa/mode.mts` (they stay in `mfa/`, the only thing left there of the rule), `decideMfaRequirement` withdrawn — and `REQUIREMENT_RULE_HOME` and `SESSION_RECORD_READERS` updated with them; the `requirementSession(` call-site guard retargeted to admission's own `selectAcr` call; a new **receiver-following AST guard**, in the style of #707's `amr` guard, that no shipped source outside `session-admission/` calls `get(` on a `UserSessionStore`-typed receiver, `revokedBefore(` on a `SubjectRevocation`, `selectAcr(`, or builds a `SessionClaim` literal — a literal grep would miss `/authorize`'s aliased store and federation grants' `options.sessionsBoundary()` — with a file-and-count allowlist: `jwt/verify.mts` (permanent, the token side), `federation-grants/src/module.mts` (the sessions boundary handed to the browser routes, until A4), and D9's list, each with a comment, shrunk as they move; the same guard limits `recordSecondFactor(` to `packages/mfa` and `establishWithoutAsking(` to the federation callback.
- **Inventories.** `docs/adapter-surface.md`: the synthetic key `sessionRequirementResolver`, the kind, the removed `mfaCoordinator` and its policy rows; the pins — `contributes-map.test.mts` (10 → 11 kinds), `synthetic-keys.test.mts` and `synthetic-keys-a5.test.mts` (7 → 8 keys), `factorResolver.test.mts`'s key list, `types.test.mts` (three more `BootErrorReason`s: `session-requirement-kind-guarded`, `session-requirements-undeclared`, `session-requirement-missing`), `check-registry.test.mts` (the new row); core's `reference.conf` and `reference-conf-drift` (a key with no default); `testing/fixtures/valid-config.mts` and the `createApp` tests that install a consumer (`expected: []`); the counts in `boot/README.md` and `manifest/README.md`; `src/README.md`'s directory table (a directory with behaviour, not a leaf); the audit inventory (`BUILT_IN_AUDIT_EVENT_TYPES`); `tools/composition` gains two fixture requirements (`ADDED`) — both interrupt a login, one steps a session up — so the composition test exercises both halves and D5's resumption without MFA; the template's all-modules test lists the MFA package's requirement once it exists, and the template's `documented-env-overrides` gains `sessionRequirements.expected`. Core's `mfa.mode` pins (`documented-env-overrides`, `mfa-schema.test.mts`, `testing/fixtures/valid-config.mts`, the template's smoke test) stay, the schema widening aside.

**Amended 2026-09-29 (module review): the resumption's callers are guarded too.** Beside `recordSecondFactor(` and `establishWithoutAsking(`, the receiver-following guard (`sessionAdmissionCallers.drift.test.mts`) keeps a call of `resumePrimary(` — and of `continuationOf(`, the one builder of a continuation, which is not on core's barrel — to `packages/mfa/src` outside `session-admission/`: in this repository only the MFA package completes an interruption. D5's contract stays generic, so this limits the tree, not the port: a second in-tree requirement that interrupts a login must widen the guard's list in the pull request that adds it. `tools/composition`'s two fixture requirements resume through `resumePrimary` and are outside what the guard scans.

## Acceptance criteria

1. Every cookie consumer in D8 reads its session through `admitSession` — once, or twice where D8 says so — with a claim core built, and the receiver-following guard proves no other read and no other claim exists.
2. The composition test, with the two fixture requirements, shows: a login interrupted by the first, resumed, interrupted by the second, and completed; `/authorize`, the `session` grant and device approval each answering `step_up` for an unmet session and admitting it after the fixture records the step-up; a `remediation` action admitted without asking; consent → `/authorize` deciding again; a revoked subject refused at `/authorize`, consent, both grants and the link start; a store outage `503` / `temporarily_unavailable` at every site; `sessionRequirements.expected` missing, or naming an unregistered requirement, and `mfa.mode = "required"` with no requirement, each refused at boot.
3. With no requirement registered and `sessionRequirements.expected = []`, every consumer behaves as at `db9c080e2` except D8's changes, each pinned by a test named for the change.
4. The MFA ADR's step-4 table (its D16 and D17 rows) passes unchanged, under D2's stated mapping, against D2's merge with a requirement whose `admit` is D6's table — the split of `decideMfaRequirement` loses no row.
5. Mutation over the merge table, the liveness steps and the claim builders: every row's mutant is killed by the directory's own tests, not by a consumer's.

## Build order

Each PR is RED → GREEN → REFACTOR, with the reviews the MFA slices had (a design and a security reviewer, Codex, Copilot). No PR touches `CHANGELOG.md` (release-policy R2); each PR's description says what an operator notices.

| PR | Delivers | Notes |
| --- | --- | --- |
| A1. `docs(core)`: this ADR, and the MFA ADR's amendments (§7) | — | the owner's decisions of 2026-09-28 (§9) recorded |
| A2. `feat(core,oauth)!`: session admission | the directory — `admitSession`, `admitPrimary`, `resumePrimary`, the claim builders, `Establishment`, the kind, the resolver, the three refusals, the declaration and the boot line, the contract suite, `acr.mts` (moved), the merge with step 4's tests re-homed; `mfaCoordinator`, `MFA_ABSENCE_POLICY`, `decideMfaRequirement` and its types removed; `mfa.mode` widened to three values, `sessionRequirements.expected`, `session-requirement-missing` and `session-requirements-undeclared`; the audit event; the vocabulary rows, the AST guard with the whole D8 list allowlisted; adapter-surface, the pins, the READMEs; `oauth/src/acrValues.mts` on the new `producibleAmr` and the mode-free info rule; the template's `buildModules` writes `sessionRequirements.expected` from the parsed `mfa.mode` (D7) — the umbrella E2E's `tests/abac/application.conf` is mounted over the template and goes through the same `buildModules`, so it needs no line of its own *(corrected 2026-09-30: on the umbrella's `develop` that file is mounted over the policy verifier's template, not the provider's; the provider there reads the template's own `application.conf`)* | BREAKING for exported types nobody consumes yet (unreleased), and for a hand-written composition with a consumer of admission, which must now declare |
| A3. `refactor(oauth)!`: `/authorize`, consent, the `session` grant, the `authorization_code` grant and the refresh grant on admission | D8's rows for `oauth`; `readLiveSession`, `refuseUnlessLive`, `resolveAcr` deleted; `subjectRevocation` handed to the authorize handler; the refresh grant's `tokenClaim` read; the ask per requirement; the allowlist shrinks | BREAKING: D8 (1)–(7) |
| A4. `refactor(device-grant,federation-grants)!`: on admission | `livenessOf` and the session half of `judge` / `sessionHolds` replaced; the three device actions and the body-first order; `step_up_required` on approve; the log lines and runbook rows | BREAKING: the device changes in D8 |
| A5. `refactor(session,webauthn)!`: the link flow and the WebAuthn subject module | `session.link` / `session.link_callback` through admission, the subject in the start envelope; `sessionModule` gains optional `subjectRevocation`; `webauthnSessionSubjectModule`; the README bridge | BREAKING: D8's link and WebAuthn rows |
| A6. `feat(session)!`: `establishSession` on the `Establishment`, `admitPrimary` | #713's `establishSession` reshaped to take the `Establishment` and exported from `packages/session`; the password route calls `admitPrimary`, the callback `establishWithoutAsking`; the regenerate-then-`open` sequence and its exhaustive failure mapping; the two fixture requirements' interruption-and-resumption test in `tools/composition` | replaces the MFA ADR's step 7 (the extraction itself landed in #713) |
| then MFA resumes at its step 6 | step 6 (Redis stores) unchanged; step 8 contributes `sessionRequirements: { mfa }`, reads `mfa.mode` through core's `readMfaMode`, and completes a login through `resumePrimary`; step 11's `POST /session/mfa/step-up` admits with the `remediation` action `mfa.step_up`; steps 13 and 14 shrink to `/authorize`'s ask handling over `Admission` and the MFA requirement's per-grade table (D6); step 22 is template and create-app only | |

A2 and A3 are separate PRs (§9), so the port's tests are reviewed on their own before a consumer moves.

## §7 — What this record amends in the MFA ADR

Recorded in that document as "Amended 2026-09-28 (session admission)" notes at each place.

- **D1 / D2 / D3**: the ports stay in core; the coordinator is no longer a slot, and D3's `MfaCoordinator` row is superseded. The dependency directions gain one arrow — the MFA package → `session-admission`, by contribution — and none from a consumer to MFA; MFA imports `session` for `establishSession` (exported by A6).
- **D7**: `MfaFactor` gains the static `amrValues` (D7 here).
- **D8**: "The coordinator slot" is replaced by the MFA requirement (D6 here), the login's completion goes through `resumePrimary` (D5), and `MfaTransaction` carries the continuation in place of `primary` and `user`.
- **§7 (migration)**: the upgrade checklist and the integrator list, where they named the coordinator wiring, `authenticatedSubject`, `mfa_step_up_required` or the removal of core's default.
- **"Outside the first release"**: MFA after a federated login reads against `admitPrimary` and the continuation.
- **F1 / F3**: the interruption's body is the closed shape of D5 — `transaction`, `expires_in`, `hints` — so `mfa_transaction`, `enrollable` and `email_proof` become `transaction`, `hints.enrollable` and `hints.email_proof`.
- **D16**: the rule is split — the merge is admission's (D2, step 7), the baseline the requirement's (D6's table, by grade); the per-consumer table is D8 here; "Conditional requirements are boot checks" is replaced by the MFA module's `requires: ["userSessionStore"]`; the `403` step-up code on device approval, F4's routes and step 12 is `step_up_required` with `requirement` in a field.
- **D17**: "D16's rule" reads "the admission", applied after freshness on the session the verdict carries; the ask's `mfaAskedAt` becomes `stepUpAskedAt`, keyed by requirement name, so a second requirement's trip is not refused as "already sent". `Admission.step_up.page` is where `endpoints.mfa.url` comes from, so `/authorize` no longer reads that key.
- **D19 / D20**: `mfa.mode` stays core's, widened to its three values from A2 with the reference default `off`; the "off is a statement" paragraph and `MFA_ABSENCE_POLICY` are withdrawn; `sessionRequirements.expected` is the declaration, `session-requirements-undeclared` and `session-requirement-missing` the refusals; the refusal table loses its `mfaCoordinator unfilled` and `mfa-requires-user-session-store` rows and gains those two.
- **Build order**: step 7 → A6 (the password route only; the federated interruption is deferred); steps 13 and 14 → as above; step 22 → template and create-app only.
- **O2**: re-decided by D7.

The MFA ADR's "today" (its "What exists today", written against `d3d9c8f2`) is left as the snapshot it is; its 2026-09-26 amendment already records that device verification reads the live session, and `FEDERATED_AMR` moved to core at its step 4.

## Consequences

- Adding an extension that changes what "logged in" means is one package contributing one requirement, and one name in a deployment's `sessionRequirements.expected`; no consumer changes. Adding a consumer is one `admitSession` call with a core-built claim, one graded action, and one outcome mapping.
- The disagreements the inventory found are gone, and the subject-revocation boundary protects every cookie consumer, not two of them — including the case the best-effort `subjectSessionIndex` write missed.
- The cost is one refactor of every consumer now (A3–A5): the cost the MFA ADR's steps 13 and 14 were going to pay, paid once and generically, and MFA ships later by that much.
- Consumers keep an outcome-to-answer mapping each; what leaves them is the decision, not the protocol.
- Two requirements that both step up cause two trips, and an `acr` entry only the union of two requirements' reach could meet is unmet. A combined trip is outside the first release.
- The generic contract is shaped by one real requirement (MFA) and two fixtures. D9's second campaign, and the second real requirement when it comes, are where it is tested against another shape.

## Rejected

- **A middleware before every consumer**: core cannot mount one that sees the cookie, and a route-level one makes every consumer route a mandatory `before:` target.
- **A module every composition must list**: the requires-closure would refuse hand-written compositions for nothing the function does not already get from the consumer's slots.
- **Admission as a planner-built synthetic component closing over the world's slots** (the security review's alternative, which would make D10's guard structural): the slots' absence policies are the consumers' declarations today, and a component that reads them globally would leave those declarations meaningless; revisited with D9, when the token side moves and the slots' ownership is looked at again.
- **A list-shaped kind**: no read-side projection exists for list kinds; name-keyed gives duplicate detection and a boot line with names.
- **Keeping `mfaCoordinator` as a slot with `MFA_ABSENCE_POLICY` on each consumer**: every consumer naming the extension — what this record removes.
- **Overridable or nullable requirements, or a host-supplied collector for the kind**: a security-relevant contribution nothing may switch off from behind the consumers.
- **A warning in place of a declaration when no requirement is registered**: the first draft, and O2's opposite; rejected in D7 with both reviews.
- **`mfa.mode` declared by the MFA package alone**: core's strip-mode schema would drop it silently, and the template's parse, `mfaSpec.mts` and the key-parity tests all read it from core (D7).
- **Moving `coveredByRevocationBoundary` under `session-admission/`**: an import cycle (D10).
- **Free-string actions decided by name**: a deployment's own credential-adding route, or a typo, would fall to a requirement's default (D4).

## 9. Owner decisions (2026-09-28)

First round, on the draft:

- **D7**: a requirement installed is on; O2 is re-decided. (The draft's "no requirement registered is a warning" — see the second round.)
- **Names**: `session-admission`, `admitSession`, `admitPrimary`, `sessionRequirements`, `sessionRequirementResolver`.
- **D8's changes**, the `/authorize` store-outage answer included.
- **One step-up code on `403` routes**: `step_up_required` with `requirement` in a field, in place of the MFA ADR's `mfa_step_up_required`; the token endpoint keeps `invalid_grant` with `step_up`.
- **A2 and A3 are separate PRs.**

Second round, after the two reviews — recorded here for the owner's confirmation, since two of them move a first-round answer:

- **D7, the declaration**: `sessionRequirements.expected` is required wherever a consumer of admission is installed, and a mismatch or a missing declaration refuses the boot — in place of the first round's warning. *(Amended 2026-09-30: a declared name nothing registers is `session-requirement-missing`, and a written declaration is compared both ways with or without a consumer — D7's closing note.)* The reviews' reasoning is in D7; the owner may keep the warning instead, in which case the declaration becomes optional and the boot line is `warn` when nothing is registered.
- **D7, `mfa.mode` stays in core**, widened, with `session-requirement-missing` when it asks for a requirement that is not installed. *(Amended 2026-09-30: core's checks act on `sessionRequirements.expected` alone; the template declares `mfa` from the mode, so asking for MFA without the module is still refused there — D7's closing note.)*
- **D4, graded actions**; **D5, the `Establishment` capability and `resumePrimary`**; **D8, the WebAuthn subject module in `packages/webauthn`** in place of a core middleware; **D8 (6)**, the cookie regenerated before a login redirect; **D10, the audit event**. None of these moves a first-round answer.

## Outside the first release

- Token-side session reads through admission (D9), and one boundary granularity on both sides.
- A generic, validated capability for a requirement other than the second-factor authority to record what it vouched for into a live session (leaving `mfaAt` alone), and with it a non-empty `reach` for such a requirement (D3).
- The federation callback calling `admitPrimary`: a navigation-shaped `InterruptionAnswer`, and the upstream tokens carried in the requirement's record (D5).
- A combined step-up trip when two requirements step up in one request, or when only their union reaches an `acr` entry.
- MFA after a federated login and per-client requirements (the MFA ADR's "not now"): each is one change in the MFA requirement's `admit` / `admitPrimary` once the callback consults admission.

## References

- The MFA ADR: `2026-09-25-multi-factor-authentication.md` (D8, D9, D13–D20, §8, O2), and #693, #695, #702, #706, #707 — its steps 1–5.
- Token binding as a contribution kind: `2026-05-20-token-binding-first-class-abstraction.md`.
- Readiness probes as a registrar slot: `2026-08-26-readiness-probes-registered-by-connection-owners.md`.
- Boot stages and their guarantees: `packages/core/src/boot/README.md`; the manifest vocabulary: `packages/core/src/modules/manifest/README.md`; declared absence: `docs/adapter-surface.md`.
- Module boundaries: o3co/auth.provider#626 (P3: core owns the decision, the packages own the protocol).
