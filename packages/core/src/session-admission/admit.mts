/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Session admission (the session-admission ADR's D1, D2, D4, D5, D10): the
 * one decision point every consumer of an authenticated browser session
 * calls, and the one the login route calls before a session is written.
 * `admitSession` reads the session — the claim, the live record, the
 * subject, the subject-revocation boundary — asks the registered
 * requirements by the action's grade, selects the `acr`, and merges the two
 * verdicts by D2's table. The claim builders (`cookieClaim`, `codeClaim`,
 * `linkClaim`, `tokenClaim`) are the one reading of each carrier;
 * `ADMISSION_ACTIONS` names the bundled actions with their grades.
 * `admitPrimary` asks the requirements that interrupt a login and answers
 * the `Establishment` `establishSession` requires; `resumePrimary` composes
 * what every completed requirement added and asks them all again;
 * `establishWithoutAsking` builds a federated login's establishment from
 * the federation's own facts; an interruption's `open` is wrapped, so its
 * answer is validated against the requirement's declared `hintKeys` before
 * the route sees it.
 *
 * Every step fails closed: a store that throws is `unavailable`, logged once
 * at error as `session_admission_unavailable` with the store, the action and
 * `loggableError`'s projection — never the `sid`; a subject mismatch is
 * `session_admission_subject_mismatch` at warn and the audit event
 * `session.admission.subject_mismatch`. A caller's fault — a claim no
 * builder made, a resolver the planner did not build, an action without a
 * grade — is a `RangeError` before anything is read. The three brands are
 * module-private `WeakSet`s: an `as` cast forges nothing.
 *
 * The one call of `selectAcr` in product code is here, over
 * `requirementSession(session)?.amr` — the vouched `amr` — so a value an
 * untrusted IdP asserted in a pre-upgrade session meets no `acr`.
 */

import { emitAuditEvent } from "../audit/factory.mjs";
import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import { coveredByRevocationBoundary } from "../federation-grants/effective-status.mjs";
import { composeAmr, MFA_AMR, wellFormedAmr } from "../grants/authenticationClaims.mjs";
import { DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import {
	copySessionAuthentication,
	federatedSessionAuthentication,
	passwordSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
} from "../user-sessions/authentication.mjs";
import type { UserSession } from "../user-sessions/types.mjs";
import { type AcrSelection, selectAcr, stepUpReach } from "./acr.mjs";
import {
	additionsFromDto,
	checkPrimaryAdditions,
	checkPrimaryAuthentication,
	checkPrimaryContinuation,
	continuationOf,
	primaryFromDto,
} from "./primary.mjs";
import {
	ADMISSION_ACTIONS,
	type Admission,
	type AdmissionAction,
	type AdmissionDeps,
	type AdmissionGrade,
	type AdmissionRequest,
	type CompletedRequirement,
	type Establishment,
	type Interruption,
	type InterruptionAnswer,
	isHintKey,
	isHintToken,
	type PrimaryAdmission,
	type PrimaryAuthentication,
	type PrimaryContinuation,
	type RequirementInput,
	type RequirementVerdict,
	type SessionClaim,
	type SessionRequirement,
	type SessionRequirementResolver,
	type SessionView,
	type StepUpPage,
} from "./requirement.mjs";

// ---------------------------------------------------------------------------
// The brands (D1, D2)
// ---------------------------------------------------------------------------

/** The claims the builders below made. */
const knownClaims = new WeakSet<object>();
/** The resolvers the boot planner and `resolverForTests` built. */
const knownResolvers = new WeakSet<object>();

/** What a resolver is built over: the collector's read side, or a test's list. */
export interface SessionRequirementSource {
	get(name: string): SessionRequirement | undefined;
	entries(): IterableIterator<readonly [string, SessionRequirement]>;
}

/**
 * Builds the branded resolver over `source` and records it, so `admitSession`
 * knows it (D1). `wrap` is the planner's: the read gate closed while the
 * `provides` factories run is applied to the object recorded, which is the
 * one a consumer is handed. For the boot planner and `resolverForTests`
 * alone; not on the package barrel.
 * @internal
 */
export function sessionRequirementResolverOver(
	source: SessionRequirementSource,
	wrap: <T extends object>(view: T) => T = (view) => view,
): SessionRequirementResolver {
	const view = wrap(
		Object.freeze({
			get: (name: string) => source.get(name),
			entries: () => source.entries(),
		}),
	);
	knownResolvers.add(view);
	return view as unknown as SessionRequirementResolver;
}

const isKnownResolver = (value: unknown): value is SessionRequirementResolver =>
	typeof value === "object" && value !== null && knownResolvers.has(value);

/** Refuses a resolver the planner or `resolverForTests` did not build: a home-made object or a copy forges nothing. */
export function checkResolver(value: unknown): SessionRequirementResolver {
	if (!isKnownResolver(value)) {
		throw new RangeError(
			"requirements must be the sessionRequirementResolver the boot planner built (or resolverForTests, in a test)",
		);
	}
	return value;
}

// ---------------------------------------------------------------------------
// The claim builders (D2)
// ---------------------------------------------------------------------------

const nonEmptyString = (value: unknown): string | undefined =>
	typeof value === "string" && value.length > 0 ? value : undefined;

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null;

const claim = (fields: Omit<SessionClaim, never>): SessionClaim => {
	const built = Object.freeze({ ...fields });
	knownClaims.add(built);
	return built;
};

/** What a cookie claim is built from: the express session, when the request has one. */
export interface CookieCarrier {
	readonly session?: {
		readonly isAuthenticated?: unknown;
		readonly sid?: unknown;
		readonly user?: unknown;
	} | null;
}

/**
 * The cookie's claim: `authenticated` is `isAuthenticated === true` — the
 * consumers did not agree on the flag's reading; this is the one — and `sid`
 * and `subject` (`user.id`) are copied when they are non-empty strings, else
 * `undefined`. A request without a session claims nothing.
 */
export function cookieClaim(req: CookieCarrier): SessionClaim {
	if (!isObject(req)) throw new RangeError("cookieClaim: the request must be an object");
	const session = isObject(req.session) ? req.session : undefined;
	const user = session !== undefined && isObject(session.user) ? session.user : undefined;
	return claim({
		authenticated: session?.isAuthenticated === true,
		sid: nonEmptyString(session?.sid),
		subject: nonEmptyString(user?.id),
		carrier: "cookie",
	} as SessionClaim);
}

/** What a code claim is built from: the code record, which carries a `sid` when a session minted it. */
export interface CodeCarrier {
	readonly sid?: unknown;
}

/**
 * A code record's claim: authenticated — a code is minted by a session — with
 * the code's `sid`, and no subject on the first read (`CodeData` carries no
 * `sub`); the `authorization_code` grant's second read hands the first
 * read's in `subject`, so the two reads are compared as today.
 */
export function codeClaim(code: CodeCarrier, opts?: { readonly subject: string }): SessionClaim {
	if (!isObject(code)) throw new RangeError("codeClaim: the code record must be an object");
	if (opts !== undefined && nonEmptyString(opts.subject) === undefined) {
		throw new RangeError("codeClaim: subject must be a non-empty string when given");
	}
	return claim({
		authenticated: true,
		sid: nonEmptyString(code.sid),
		subject: opts?.subject,
		carrier: "code",
	} as SessionClaim);
}

/** What a link claim is built from: the link transaction's envelope, which records the session and its subject at the start (D8). */
export interface LinkCarrier {
	readonly sid: unknown;
	readonly subject: unknown;
}

/**
 * A link transaction's claim: authenticated, its `sid` and the subject
 * recorded at the start — a form_post callback arrives on a fresh cookie
 * session and has no other binding. An envelope without either is not one.
 */
export function linkClaim(link: LinkCarrier): SessionClaim {
	if (!isObject(link)) throw new RangeError("linkClaim: the transaction must be an object");
	const sid = nonEmptyString(link.sid);
	const subject = nonEmptyString(link.subject);
	if (sid === undefined || subject === undefined) {
		throw new RangeError("linkClaim: the transaction must record a sid and a subject");
	}
	return claim({ authenticated: true, sid, subject, carrier: "link" } as SessionClaim);
}

/** What a token claim is built from: a verified token's claims (D9). */
export interface TokenCarrier {
	readonly sid?: unknown;
	readonly sub: unknown;
	readonly amr?: unknown;
}

/**
 * A verified token's claim (D9): authenticated, its `sid` when it carries
 * one — without one the live read is skipped, as the refresh grant does
 * today — its `sub`, and its `amr` for the requirements (`tokenAmr`, absent
 * when the token carries none or not a well-formed list: a token issued
 * before #481). A token without a `sub` is not one a session issued.
 */
export function tokenClaim(claims: TokenCarrier): SessionClaim {
	if (!isObject(claims)) throw new RangeError("tokenClaim: the claims must be an object");
	const subject = nonEmptyString(claims.sub);
	if (subject === undefined) throw new RangeError("tokenClaim: the token must carry a sub");
	const tokenAmr = wellFormedAmr(claims.amr);
	return claim({
		authenticated: true,
		sid: nonEmptyString(claims.sid),
		subject,
		carrier: "token",
		...(tokenAmr === undefined ? {} : { tokenAmr }),
	} as SessionClaim);
}

// ---------------------------------------------------------------------------
// The actions (D4): `ADMISSION_ACTIONS` is `requirement.mts`'s, beside the
// remediation rule that reads it.
// ---------------------------------------------------------------------------

const GRADES: ReadonlySet<string> = new Set<AdmissionGrade>([
	"use",
	"credential_change",
	"remediation",
]);

/** The `action` field of a log line: a bundled action's name, else `custom` (D10). */
const actionLabel = (name: string): string =>
	Object.hasOwn(ADMISSION_ACTIONS, name) ? name : "custom";

/** The `remediation` names already said to be undeclared, once per process each (D4). */
const undeclaredRemediations = new Set<string>();

/** The requirements already said to have stepped up without a page, once per process each (D2, step 5). */
const pagelessStepUps = new Set<string>();

/** The requirements already said to have stepped up over no session, once per process each (D2, step 5). */
const sessionlessStepUps = new Set<string>();

// ---------------------------------------------------------------------------
// admitSession (D2)
// ---------------------------------------------------------------------------

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);

/** A caller's fault is a `RangeError` before anything is read. */
function checkRequest(deps: AdmissionDeps, request: AdmissionRequest): void {
	if (!isObject(deps)) throw new RangeError("admitSession: deps must be an object");
	checkResolver(deps.requirements);
	if (!isObject(deps.acrTable)) throw new RangeError("admitSession: acrTable must be an object");
	if (!isObject(request)) throw new RangeError("admitSession: the request must be an object");
	if (!isObject(request.claim) || !knownClaims.has(request.claim)) {
		throw new RangeError(
			"admitSession: the claim must be one cookieClaim, codeClaim or linkClaim built",
		);
	}
	const { action: asked } = request;
	if (
		!isObject(asked) ||
		nonEmptyString(asked.name) === undefined ||
		typeof asked.grade !== "string" ||
		!GRADES.has(asked.grade)
	) {
		throw new RangeError("admitSession: the action must be a name with a grade");
	}
	if (request.asks !== undefined) {
		if (!isObject(request.asks)) throw new RangeError("admitSession: asks must be an object");
		if (request.asks.acrValues !== undefined && !isStringList(request.asks.acrValues)) {
			throw new RangeError("admitSession: asks.acrValues must be a list of non-empty strings");
		}
	}
}

const isValidDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

/** The view a requirement is handed: a copy of four fields, never the record (D2, step 5). */
const viewOf = (session: UserSession): SessionView =>
	Object.freeze({
		sid: session.sid,
		sub: session.sub,
		authTime: new Date(session.authTime.getTime()),
		expiresAt: new Date(session.expiresAt.getTime()),
	});

const VERDICTS: ReadonlySet<string> = new Set(["met", "reauthenticate", "step_up", "unmet"]);

/** Whether `value` is one of the four verdicts, its `step_up` with a `whenStillUnmet` (and no page: the registered one answers). */
const isVerdict = (value: unknown): value is RequirementVerdict =>
	isObject(value) &&
	typeof value.outcome === "string" &&
	VERDICTS.has(value.outcome) &&
	(value.outcome !== "step_up" ||
		value.whenStillUnmet === "reauthenticate" ||
		value.whenStillUnmet === "unmet");

/** Step 5's verdict, with the requirement that gave it. */
type RequirementOutcome =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate"; readonly requirement: string }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly page: StepUpPage;
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string }
	| { readonly outcome: "unavailable"; readonly store: string };

/**
 * `admitSession`: whether the session `request.claim` names may proceed with
 * `request.action` (D2). The steps, each fail-closed, in order:
 *
 * 1. the claim — not authenticated → `unauthenticated`; a cookie without a
 *    subject → `not_live` (`subject_mismatch`);
 * 2. the live read — with a store: no `sid` → `not_live` (`no_sid`), except
 *    for a token carrier, whose absent `sid` skips the read (D9); no record,
 *    a record without a `sub` or past its `expiresAt` → `not_live` (`gone`),
 *    a throw → `unavailable`; without a store the session is `null` and the
 *    requirements decide what that means;
 * 3. the subject — a claim's subject that is not the record's → `not_live`
 *    (`subject_mismatch`), logged and audited;
 * 4. the revocation boundary — with `subjectRevocation` and a live record;
 *    skipped for a token carrier, whose boundary `verifyJwt` reads (D9);
 * 5. the requirements — for `use` and `credential_change`, each `admit` in
 *    registration order, the first verdict that is not `met` taken; none for
 *    a declared `remediation`; a token carrier's `authentication` is built
 *    from the token's own `amr`, record or not (D9); a throw →
 *    `unavailable`; a `step_up` answers
 *    the requirement's registered page, and one from a requirement that
 *    registered none — nothing could finish the trip — is `unmet` by its
 *    name, said once per process (`session_admission_step_up_without_page`);
 * 6. `acr_values` — `selectAcr` over the vouched `amr`, with reach the union
 *    of every requirement's when the session is live;
 * 7. the merge of 5 and 6, D2's table.
 *
 * A `step_up` a requirement answers over no session is read as
 * `reauthenticate`: nothing can be stepped up onto no session, and a login
 * can.
 */
export async function admitSession(
	deps: AdmissionDeps,
	request: AdmissionRequest,
): Promise<Admission> {
	checkRequest(deps, request);
	const { claim: presented, asks } = request;
	const now = deps.now === undefined ? new Date() : deps.now();
	const label = actionLabel(request.action.name);
	const logger = deps.logger;
	const unavailable = (store: string, err: unknown): Admission => {
		logger?.error(
			{ store, action: label, err: loggableError(err) },
			"session_admission_unavailable",
		);
		return { outcome: "unavailable", store };
	};

	// Step 1: the claim.
	if (presented.authenticated !== true) return { outcome: "unauthenticated" };
	if (presented.carrier === "cookie" && presented.subject === undefined) {
		return { outcome: "not_live", reason: "subject_mismatch" };
	}

	// Step 2: the live read.
	let session: UserSession | null = null;
	if (deps.userSessionStore !== undefined && presented.sid === undefined) {
		if (presented.carrier !== "token") return { outcome: "not_live", reason: "no_sid" };
	} else if (deps.userSessionStore !== undefined && presented.sid !== undefined) {
		let record: UserSession | null | undefined;
		try {
			record = await deps.userSessionStore.get(presented.sid);
		} catch (err) {
			return unavailable("user_session", err);
		}
		// `== null`: the port answers `null`, and a store of the deployment's own
		// that answers `undefined` for a missing session is still no session.
		if (
			record == null ||
			nonEmptyString(record.sub) === undefined ||
			!isValidDate(record.expiresAt) ||
			!(record.expiresAt.getTime() > now.getTime())
		) {
			return { outcome: "not_live", reason: "gone" };
		}
		session = record;
	}

	// Step 3: the subject.
	if (session !== null && presented.subject !== undefined && presented.subject !== session.sub) {
		logger?.warn({ action: label }, "session_admission_subject_mismatch");
		void emitAuditEvent(deps.auditSink, {
			timestamp: now,
			type: "session.admission.subject_mismatch",
			subject: session.sub,
			details: {
				// The claim's sid, whichever carrier made the claim: the record was read by it.
				sid: presented.sid,
				carrier: presented.carrier,
				claimedSubject: presented.subject,
				recordSubject: session.sub,
			},
		});
		return { outcome: "not_live", reason: "subject_mismatch" };
	}

	// Step 4: the revocation boundary, against a live record; a token's is
	// verifyJwt's, so the two readings do not double up.
	if (session !== null && deps.subjectRevocation !== undefined && presented.carrier !== "token") {
		try {
			const boundary = await deps.subjectRevocation.revokedBefore(session.sub);
			if (boundary !== null && !isValidDate(boundary)) {
				throw new TypeError("the sessions boundary is neither a date nor null");
			}
			if (
				coveredByRevocationBoundary(session.authTime, boundary, DEFAULT_SUBJECT_REVOCATION_SKEW_MS)
			) {
				return { outcome: "revoked" };
			}
		} catch (err) {
			return unavailable("revocation_boundary", err);
		}
	}

	// Step 5: the requirements, by the action's effective grade — normalised
	// first (D4): only a declared remediation keeps its grade and skips them.
	const requirements = [...deps.requirements.entries()];
	const effective = effectiveAction(requirements, request.action, deps);
	// A token carrier's authentication is the token's own, whether or not a
	// record was read (D9): the record is only the view.
	const authentication =
		presented.carrier === "token"
			? requirementSessionFromAmr(presented.tokenAmr)
			: requirementSession(session);
	let verdict: RequirementOutcome = { outcome: "met" };
	if (effective.grade !== "remediation") {
		const input: RequirementInput = Object.freeze({
			session: session === null ? null : viewOf(session),
			authentication,
			carrier: presented.carrier,
			action: effective,
			asks,
			now,
		});
		for (const [name, requirement] of requirements) {
			let answer: unknown;
			try {
				answer = await requirement.admit(input);
			} catch (err) {
				return unavailable(name, err);
			}
			if (!isVerdict(answer)) {
				return unavailable(
					name,
					new TypeError("a requirement answered something that is not a verdict"),
				);
			}
			if (answer.outcome === "met") continue;
			verdict =
				answer.outcome === "step_up"
					? stepUpVerdict(name, requirement, answer.whenStillUnmet, session, deps)
					: { outcome: answer.outcome, requirement: name };
			break;
		}
	}

	// Step 6: acr_values.
	const requested = asks?.acrValues ?? [];
	const reach = session === null ? new Set<string>() : stepUpReach(requirements.map(([, r]) => r));
	const selection: AcrSelection | undefined =
		requested.length === 0
			? undefined
			: selectAcr(requested, requirementSession(session)?.amr ?? [], deps.acrTable, reach);
	const noneConfigured =
		requested.length > 0 && requested.every((acr) => !Object.hasOwn(deps.acrTable, acr));

	// Step 7: the merge.
	return merge(verdict, selection, {
		session,
		noneConfigured,
		requirements,
		held: requirementSession(session)?.amr ?? [],
		table: deps.acrTable,
	});
}

/**
 * A requirement's `step_up` as admission takes it: over no session (no
 * store, or a token carrier without a record) it is `reauthenticate` by its
 * name, said once per process — nothing can be stepped up onto no session,
 * and a login can — so `step_up` always carries a live session; from a
 * requirement that registered no page it is `unmet` by its name, fail
 * closed, said once per process — nothing could finish the trip; else the
 * registered page.
 */
function stepUpVerdict(
	name: string,
	requirement: SessionRequirement,
	whenStillUnmet: "reauthenticate" | "unmet",
	session: UserSession | null,
	deps: AdmissionDeps,
): RequirementOutcome {
	if (session === null) {
		if (!sessionlessStepUps.has(name)) {
			sessionlessStepUps.add(name);
			deps.logger?.warn({ requirement: name }, "session_admission_step_up_without_session");
		}
		return { outcome: "reauthenticate", requirement: name };
	}
	const page = requirement.stepUpPage;
	if (page === undefined) {
		if (!pagelessStepUps.has(name)) {
			pagelessStepUps.add(name);
			deps.logger?.warn({ requirement: name }, "session_admission_step_up_without_page");
		}
		return { outcome: "unmet", requirement: name };
	}
	return { outcome: "step_up", requirement: name, page, whenStillUnmet };
}

/**
 * The action as the requirements see it (D4): `use` and `credential_change`
 * as given; `remediation` only for a name some registered requirement
 * declared, else `credential_change` — the strictest grade — said once per
 * process per name.
 */
function effectiveAction(
	requirements: readonly (readonly [string, SessionRequirement])[],
	asked: AdmissionAction,
	deps: AdmissionDeps,
): AdmissionAction {
	if (asked.grade !== "remediation") return { name: asked.name, grade: asked.grade };
	if (requirements.some(([, r]) => r.remediations.includes(asked.name))) {
		return { name: asked.name, grade: "remediation" };
	}
	if (!undeclaredRemediations.has(asked.name)) {
		undeclaredRemediations.add(asked.name);
		deps.logger?.warn({ action: asked.name }, "session_admission_remediation_undeclared");
	}
	return { name: asked.name, grade: "credential_change" };
}

interface MergeContext {
	readonly session: UserSession | null;
	/** No requested value is in the table: no login can meet the request. */
	readonly noneConfigured: boolean;
	readonly requirements: readonly (readonly [string, SessionRequirement])[];
	/** The vouched `amr`. */
	readonly held: readonly string[];
	readonly table: AdmissionDeps["acrTable"];
}

/** D2's merge table: `R` the requirements' verdict, `A` the acr selection (`undefined` when nothing was asked). */
function merge(
	R: RequirementOutcome,
	A: AcrSelection | undefined,
	context: MergeContext,
): Admission {
	const { session } = context;
	const unmetAcr = (): Admission => ({ outcome: "unmet", requirement: "acr", session });
	switch (R.outcome) {
		case "unavailable":
			return { outcome: "unavailable", store: R.store };
		case "met":
			if (A === undefined || A.outcome === "met") {
				return { outcome: "admitted", session, acr: A?.acr };
			}
			if (A.outcome === "unmet") return unmetAcr();
			return stepUpThroughOne(A.acrValues, context) ?? unmetAcr();
		case "reauthenticate":
			return context.noneConfigured
				? unmetAcr()
				: { outcome: "reauthenticate", requirement: R.requirement, session };
		case "step_up": {
			if (session === null) {
				throw new Error("invariant violated: a step-up over no session");
			}
			if (A?.outcome === "unmet") return unmetAcr();
			return {
				outcome: "step_up",
				requirement: R.requirement,
				session,
				page: R.page,
				acrValues: A?.outcome === "step_up" ? A.acrValues : [],
				whenStillUnmet: A?.outcome === "step_up" ? "unmet" : R.whenStillUnmet,
			};
		}
		case "unmet":
			return A?.outcome === "unmet"
				? unmetAcr()
				: { outcome: "unmet", requirement: R.requirement, session };
	}
}

/**
 * The `met` + `step_up` row: the page of the first requirement whose own
 * reach covers everything one alternative of a reachable entry lacks —
 * `undefined` when no single requirement does, since no one trip can finish
 * it.
 */
function stepUpThroughOne(
	reachable: readonly string[],
	context: MergeContext,
): Admission | undefined {
	const { session } = context;
	if (session === null) throw new Error("invariant violated: a step-up over no session");
	const held = new Set(context.held);
	for (const [name, requirement] of context.requirements) {
		const covers = reachable.some((acr) =>
			(Object.hasOwn(context.table, acr) ? context.table[acr] : [])?.some(
				(alternative) =>
					alternative.length > 0 &&
					alternative.every((value) => held.has(value) || requirement.reach.has(value)),
			),
		);
		// A requirement whose reach covers the entry registered a page: boot
		// holds a non-empty reach to one. Without one nothing could finish it.
		if (covers && requirement.stepUpPage !== undefined) {
			return {
				outcome: "step_up",
				requirement: name,
				session,
				page: requirement.stepUpPage,
				acrValues: reachable,
				whenStillUnmet: "unmet",
			};
		}
	}
	return undefined;
}

// ---------------------------------------------------------------------------
// Establishment (D5)
// ---------------------------------------------------------------------------

/** The establishments `admitPrimary`, `resumePrimary` and `establishWithoutAsking` built. */
const knownEstablishments = new WeakSet<object>();

/**
 * The primaries core's builders made (`passwordPrimary`, and
 * `establishWithoutAsking`'s own): what `admitPrimary` accepts. A
 * continuation a requirement persisted and presents back is plain data a
 * store round-tripped, which no set can mark, so `resumePrimary` reads it
 * through `checkPrimaryContinuation` instead.
 */
const knownPrimaries = new WeakSet<object>();

/** What a password login produces (D5): the facts, never a `recorded`. */
export interface PasswordLoginFacts {
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	readonly authTime: Date;
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

/**
 * The one builder a password login has (D5): `recorded` is
 * `passwordSessionAuthentication()` — `amr` `["pwd"]`, primary `pwd`, no
 * second factor — so a route cannot hand in an `amr` or an `mfaAt`. A
 * frozen copy of the facts, checked (`checkPrimaryAuthentication`), which
 * `admitPrimary` alone accepts.
 */
export function passwordPrimary(facts: PasswordLoginFacts): PrimaryAuthentication {
	if (!isObject(facts)) throw new RangeError("passwordPrimary: the facts must be an object");
	const primary = checkPrimaryAuthentication({
		subject: facts.subject,
		user: facts.user,
		recorded: passwordSessionAuthentication(),
		authTime: facts.authTime,
		redirectTo: facts.redirectTo,
		request: facts.request,
	});
	knownPrimaries.add(primary);
	return primary;
}

/** Whether `value` is an `Establishment` one of the three built: a copy, or an object shaped like one, is not. */
export function isEstablishment(value: unknown): value is Establishment {
	return typeof value === "object" && value !== null && knownEstablishments.has(value);
}

const establish = (primary: PrimaryAuthentication): Establishment => {
	const built = Object.freeze({ primary });
	knownEstablishments.add(built);
	return built as unknown as Establishment;
};

const isInterruption = (value: unknown): value is Interruption =>
	isObject(value) && typeof value.open === "function";

/** The keys an interruption's body may carry (D5): closed, so a `user` snapshot, a `sub` or a `sid` cannot leave through it. */
const ANSWER_KEYS: ReadonlySet<string> = new Set(["error", "transaction", "expires_in", "hints"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * `value` as the closed body of D5, held to what the requirement named
 * `name` declared: `status` 403; `error` in the RFC 6749 error-text class;
 * `transaction` base64url when present; `expires_in` a positive integer
 * when present; `hints` an object whose every key is one of `hintKeys` — a
 * hint name by core's grammar and not a reserved one (`isHintKey`, held at
 * registration and here) — and every value a boolean, a finite number, or
 * an enum-like token (`isHintToken`, or a list of such); no other key. A
 * snapshot, a URL, an address or a name cannot pass. A frozen copy; a body
 * that fails is the requirement's fault, a `RangeError` the route answers
 * as an `open` failure.
 */
function checkInterruptionAnswer(
	value: unknown,
	name: string,
	hintKeys: readonly string[],
): InterruptionAnswer {
	const refuse = (what: string): never => {
		throw new RangeError(`requirement "${name}" answered an interruption ${what}`);
	};
	if (!isObject(value)) return refuse("that is not an object");
	if (value.status !== 403) refuse("whose status is not 403");
	const body = value.body;
	if (!isObject(body) || Array.isArray(body)) return refuse("without a body");
	for (const key of Object.keys(body)) {
		if (!ANSWER_KEYS.has(key)) {
			refuse(`whose body carries "${key}", which the body's shape does not admit`);
		}
	}
	if (!isWellFormedErrorCode(body.error)) refuse("whose error is not a well-formed error code");
	if (body.transaction !== undefined) {
		if (typeof body.transaction !== "string" || !BASE64URL.test(body.transaction)) {
			refuse("whose transaction is not a base64url string");
		}
	}
	if (body.expires_in !== undefined) {
		if (!Number.isSafeInteger(body.expires_in) || (body.expires_in as number) <= 0) {
			refuse("whose expires_in is not a positive integer");
		}
	}
	let hints: Record<string, string | number | boolean | readonly string[]> | undefined;
	if (body.hints !== undefined) {
		if (!isObject(body.hints) || Array.isArray(body.hints)) {
			return refuse("whose hints are not an object");
		}
		hints = {};
		for (const [key, hint] of Object.entries(body.hints)) {
			if (!hintKeys.includes(key) || !isHintKey(key)) {
				refuse(`with a hint "${key}" it did not declare, or that is not a hint name`);
			}
			if (typeof hint === "boolean" || (typeof hint === "number" && Number.isFinite(hint))) {
				hints[key] = hint;
			} else if (isHintToken(hint)) {
				hints[key] = hint;
			} else if (Array.isArray(hint) && hint.every(isHintToken)) {
				hints[key] = Object.freeze([...hint]);
			} else {
				refuse(
					`with a hint "${key}" that is not a boolean, a finite number, or an enum-like token`,
				);
			}
		}
	}
	return Object.freeze({
		status: 403,
		body: Object.freeze({
			error: body.error as string,
			...(body.transaction === undefined ? {} : { transaction: body.transaction as string }),
			...(body.expires_in === undefined ? {} : { expires_in: body.expires_in as number }),
			...(hints === undefined ? {} : { hints: Object.freeze(hints) }),
		}),
	});
}

/** An outage at establishment: logged once, at error, object-first, with the requirement's name and the projection. */
const unavailableAtEstablishment = (
	deps: AdmissionDeps,
	store: string,
	err: unknown,
): PrimaryAdmission => {
	deps.logger?.error(
		{ store, phase: "establishment", err: loggableError(err) },
		"session_admission_unavailable",
	);
	return { outcome: "unavailable", store };
};

/**
 * Asks every requirement with `admitPrimary`, in registration order, about
 * `composed`: the first interruption wins, carrying `continuation` and an
 * `open` that validates the answer; a throw, or an answer that is neither
 * `establish` nor an interruption, is `unavailable`; when every one answered
 * `establish`, the establishment over `composed`.
 */
async function askEvery(
	deps: AdmissionDeps,
	composed: PrimaryAuthentication,
	continuation: PrimaryContinuation,
): Promise<PrimaryAdmission> {
	for (const [name, requirement] of deps.requirements.entries()) {
		if (requirement.admitPrimary === undefined) continue;
		let answer: unknown;
		try {
			answer = await requirement.admitPrimary(composed);
		} catch (err) {
			return unavailableAtEstablishment(deps, name, err);
		}
		if (answer === "establish") continue;
		if (isInterruption(answer)) {
			const interruption = answer;
			return {
				outcome: "interrupt",
				requirement: name,
				continuation,
				open: async (sessionId: string) => {
					if (nonEmptyString(sessionId) === undefined) {
						throw new RangeError("open: the session id must be a non-empty string");
					}
					return checkInterruptionAnswer(
						await interruption.open(sessionId),
						name,
						requirement.hintKeys,
					);
				},
			};
		}
		return unavailableAtEstablishment(
			deps,
			name,
			new TypeError(
				"a requirement answered something that is neither establish nor an interruption",
			),
		);
	}
	return { outcome: "establish", establishment: establish(composed) };
}

/**
 * `admitPrimary` (D5): what `POST /session/login` calls once the user is
 * verified and nothing is written. The primary must be one a core builder
 * made (`passwordPrimary`; a caller's fault is a `RangeError` before any
 * requirement is asked), then every requirement with `admitPrimary` is
 * asked in order over it; the first interruption wins, with a continuation
 * holding the primary and nothing done yet; only when every one answered
 * `establish` is an `Establishment` answered.
 */
export async function admitPrimary(
	deps: AdmissionDeps,
	primary: PrimaryAuthentication,
): Promise<PrimaryAdmission> {
	if (!isObject(deps)) throw new RangeError("admitPrimary: deps must be an object");
	checkResolver(deps.requirements);
	if (!isObject(primary) || !knownPrimaries.has(primary)) {
		throw new RangeError("admitPrimary: the primary must be one passwordPrimary built");
	}
	return askEvery(deps, primary, continuationOf(primary, []));
}

/**
 * The session's `recorded` composed from the primary the route built and
 * what every completed requirement added, in order (`composeAmr`, the MFA
 * ADR's D14: a requirement's `mfa` comes through `addsMfa`); `mfaAt` what
 * the one completion that may carry one — the requirement named `mfa`,
 * which completes once — verified at.
 */
function composeRecorded(
	primary: PrimaryAuthentication,
	done: readonly CompletedRequirement[],
): PrimaryAuthentication {
	let amr = primary.recorded.amr;
	let mfaAt: Date | undefined;
	for (const entry of done) {
		const added = entry.adds.amr;
		amr = composeAmr(amr, {
			amr: added.filter((value) => value !== MFA_AMR),
			addsMfa: added.includes(MFA_AMR),
		});
		if (entry.adds.mfaAt !== undefined) mfaAt = new Date(entry.adds.mfaAt.getTime());
	}
	return Object.freeze({
		...primary,
		recorded: Object.freeze({
			amr: Object.freeze([...amr]),
			authentication: Object.freeze({
				...copySessionAuthentication(primary.recorded.authentication),
				mfaAt,
			}),
		}),
	});
}

/**
 * `resumePrimary` (D5): after a requirement's ceremony completes. Refuses,
 * before asking anything, a continuation it cannot read — the serialisable
 * DTO the requirement persisted, every field its type admits, every instant
 * epoch milliseconds (`checkPrimaryContinuation`), rehydrated here — a
 * completion by a name that is not a registered requirement with
 * `admitPrimary` — or one already in `done` — and what the name may not add
 * (`checkPrimaryAdditions`); then appends the completion, composes the
 * session's `recorded` from the primary and every completed requirement's
 * additions, and asks every requirement with `admitPrimary` again, in order,
 * over the composed result: a requirement that already completed sees its
 * own additions and answers `establish`; one that has not may interrupt,
 * with the updated continuation.
 */
export async function resumePrimary(
	deps: AdmissionDeps,
	continuation: PrimaryContinuation,
	completed: CompletedRequirement,
): Promise<PrimaryAdmission> {
	if (!isObject(deps)) throw new RangeError("resumePrimary: deps must be an object");
	checkResolver(deps.requirements);
	const read = checkPrimaryContinuation(continuation);
	if (!isObject(completed) || nonEmptyString(completed.requirement) === undefined) {
		throw new RangeError("resumePrimary: the completion must name a requirement");
	}
	const registeredWithAdmitPrimary = (name: string): boolean =>
		deps.requirements.get(name)?.admitPrimary !== undefined;
	for (const entry of [...read.done.map((d) => d.requirement), completed.requirement]) {
		if (!registeredWithAdmitPrimary(entry)) {
			throw new RangeError(
				`resumePrimary: "${entry}" is not a registered requirement that interrupts a login`,
			);
		}
	}
	if (read.done.some((entry) => entry.requirement === completed.requirement)) {
		throw new RangeError(`resumePrimary: "${completed.requirement}" already completed`);
	}
	const adds = checkPrimaryAdditions(completed.requirement, completed.adds);
	// Rehydrated: the continuation carries epoch milliseconds.
	const primary = primaryFromDto(read.primary);
	const done: readonly CompletedRequirement[] = Object.freeze([
		...read.done.map((entry) =>
			Object.freeze({ requirement: entry.requirement, adds: additionsFromDto(entry.adds) }),
		),
		Object.freeze({ requirement: completed.requirement, adds }),
	]);
	return askEvery(deps, composeRecorded(primary, done), continuationOf(primary, done));
}

/** What a federated login legitimately produces (D5): the federation's own facts, never a `recorded`. */
export interface FederatedLogin {
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	/** The federation's name (`federations.<name>`). */
	readonly federation: string;
	/** The upstream IdP's `amr`, as it surfaced it. */
	readonly upstreamAmr: readonly string[];
	/** Whether that federation's upstream `amr` counts (`federationTrustsUpstreamAmr`, D13). */
	readonly trusted: boolean;
	readonly authTime: Date;
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

/**
 * `establishWithoutAsking` (D5): the federation callback's establishment,
 * built from the federation's own facts and no requirement asked — the
 * callback consults admission in a later record. `recorded` is composed
 * here through `federatedSessionAuthentication` (#707), so a caller cannot
 * mark an arbitrary `amr` or an `mfaAt` as a federated primary; the seam
 * accepts only what a federation produces. A drift guard pins its callers
 * to the callback.
 */
export function establishWithoutAsking(login: FederatedLogin): Establishment {
	if (!isObject(login)) throw new RangeError("establishWithoutAsking: the login must be an object");
	if (nonEmptyString(login.federation) === undefined) {
		throw new RangeError(
			"establishWithoutAsking: the federation's name must be a non-empty string",
		);
	}
	if (!Array.isArray(login.upstreamAmr) || !login.upstreamAmr.every((v) => typeof v === "string")) {
		throw new RangeError("establishWithoutAsking: upstreamAmr must be a list of strings");
	}
	if (typeof login.trusted !== "boolean") {
		throw new RangeError("establishWithoutAsking: trusted must be true or false");
	}
	const recorded = federatedSessionAuthentication({
		federation: login.federation,
		upstreamAmr: login.upstreamAmr,
		trusted: login.trusted,
	});
	const primary = checkPrimaryAuthentication({
		subject: login.subject,
		user: login.user,
		recorded,
		authTime: login.authTime,
		redirectTo: login.redirectTo,
		request: login.request,
	});
	knownPrimaries.add(primary);
	return establish(primary);
}
