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
 * Session admission (the session-admission ADR's D1, D2, D4, D10): the one
 * decision point every consumer of an authenticated browser session calls.
 * `admitSession` reads the session — the claim, the live record, the
 * subject, the subject-revocation boundary — asks the registered
 * requirements by the action's grade, selects the `acr`, and merges the two
 * verdicts by D2's table. The claim builders (`cookieClaim`, `codeClaim`,
 * `linkClaim`) are the one reading of each carrier; `ADMISSION_ACTIONS`
 * names the bundled actions with their grades.
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
import { coveredByRevocationBoundary } from "../federation-grants/effective-status.mjs";
import { wellFormedAmr } from "../grants/authenticationClaims.mjs";
import { DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import { requirementSession, requirementSessionFromAmr } from "../user-sessions/authentication.mjs";
import type { UserSession } from "../user-sessions/types.mjs";
import { type AcrSelection, selectAcr, stepUpReach } from "./acr.mjs";
import type {
	Admission,
	AdmissionAction,
	AdmissionDeps,
	AdmissionGrade,
	AdmissionRequest,
	RequirementInput,
	RequirementVerdict,
	SessionClaim,
	SessionRequirement,
	SessionRequirementResolver,
	SessionView,
	StepUpPage,
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
// The actions (D4)
// ---------------------------------------------------------------------------

const action = <N extends string, G extends AdmissionGrade>(
	name: N,
	grade: G,
): { readonly name: N; readonly grade: G } => Object.freeze({ name, grade });

/**
 * The bundled consumers' actions, each with its grade (D4). A deployment's
 * own route builds `{ name, grade }` for what it does and is treated by its
 * grade; `remediation` is accepted only for a name a registered requirement
 * declared, else treated as `credential_change`.
 */
export const ADMISSION_ACTIONS = Object.freeze({
	"oauth.authorize": action("oauth.authorize", "use"),
	"oauth.consent": action("oauth.consent", "use"),
	"oauth.session_grant": action("oauth.session_grant", "use"),
	"oauth.code_exchange": action("oauth.code_exchange", "use"),
	"device.lookup": action("device.lookup", "use"),
	"device.approve": action("device.approve", "use"),
	"device.deny": action("device.deny", "use"),
	"federation_grants.connect": action("federation_grants.connect", "use"),
	"federation_grants.consent": action("federation_grants.consent", "use"),
	"federation_grants.callback": action("federation_grants.callback", "use"),
	"session.link": action("session.link", "credential_change"),
	"session.link_callback": action("session.link_callback", "use"),
	"webauthn.register": action("webauthn.register", "credential_change"),
	"mfa.manage": action("mfa.manage", "credential_change"),
	"mfa.step_up": action("mfa.step_up", "remediation"),
});

/** A bundled action's name. */
export type AdmissionActionName = keyof typeof ADMISSION_ACTIONS;

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

/** The page a requirement with a non-empty reach declares; boot and `resolverForTests` hold it to that. */
const pageOf = (requirement: SessionRequirement) => {
	if (requirement.stepUpPage === undefined) {
		throw new Error(
			`invariant violated: requirement "${requirement.name}" reaches but has no page`,
		);
	}
	return requirement.stepUpPage;
};

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
 *    a declared `remediation`; a throw → `unavailable`; a `step_up` answers
 *    the requirement's registered page;
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
			details: { sid: session.sid, claimedSubject: presented.subject, action: label },
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

	// Step 5: the requirements, by the action's effective grade.
	const requirements = [...deps.requirements.entries()];
	const effective = effectiveAction(requirements, request.action, deps);
	const authentication =
		session !== null
			? requirementSession(session)
			: presented.carrier === "token"
				? requirementSessionFromAmr(presented.tokenAmr)
				: null;
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
					? session === null
						? { outcome: "reauthenticate", requirement: name }
						: {
								outcome: "step_up",
								requirement: name,
								page: pageOf(requirement),
								whenStillUnmet: answer.whenStillUnmet,
							}
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
		if (covers) {
			return {
				outcome: "step_up",
				requirement: name,
				session,
				page: pageOf(requirement),
				acrValues: reachable,
				whenStillUnmet: "unmet",
			};
		}
	}
	return undefined;
}
