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
 * verdicts by D2's table. The claim builders (`cookieClaim`, `codeClaimFirstRead`, `codeClaimRevalidation`,
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
import type { AuditSink } from "../audit/types.mjs";
import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import { coveredByRevocationBoundary } from "../federation-grants/effective-status.mjs";
import {
	composeAmr,
	MFA_AMR,
	PASSWORD_AMR,
	wellFormedAmr,
} from "../grants/authenticationClaims.mjs";
import { DEFAULT_SUBJECT_REVOCATION_SKEW_MS } from "../jwt/verify.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import {
	copySessionAuthentication,
	federatedSessionAuthentication,
	passwordSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
} from "../user-sessions/authentication.mjs";
import type {
	SubjectRevocation,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "../user-sessions/types.mjs";
import { type AcrSelection, type AcrTable, selectAcr, stepUpReach } from "./acr.mjs";
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
	type AdmissionAsks,
	type AdmissionDeps,
	type AdmissionGrade,
	type AdmissionRequest,
	type CompletedRequirement,
	type Establishment,
	type InterruptionAnswer,
	isHintKey,
	isHintToken,
	isIssuedAction,
	issuedActionsOf,
	type PrimaryAdmission,
	type PrimaryAuthentication,
	type PrimaryContinuation,
	type RegisteredRequirement,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementVerdict,
	type SessionClaim,
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
	get(name: string): RegisteredRequirement | undefined;
	entries(): IterableIterator<readonly [string, RegisteredRequirement]>;
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
 * A code record's claim on its first read: authenticated — a code is minted
 * by a session — with the code's `sid`, and no subject (`CodeData` carries
 * no `sub`): the one claim that reaches a record without one (D2, step 3).
 */
export function codeClaimFirstRead(code: CodeCarrier): SessionClaim {
	if (!isObject(code)) {
		throw new RangeError("codeClaimFirstRead: the code record must be an object");
	}
	return claim({
		authenticated: true,
		sid: nonEmptyString(code.sid),
		subject: undefined,
		carrier: "code",
	} as SessionClaim);
}

/**
 * A code record's claim on the `authorization_code` grant's second read:
 * the first read's `subject`, required, so the two reads are compared as
 * today and the comparison cannot be left out by omitting an option.
 */
export function codeClaimRevalidation(code: CodeCarrier, subject: string): SessionClaim {
	if (!isObject(code)) {
		throw new RangeError("codeClaimRevalidation: the code record must be an object");
	}
	if (nonEmptyString(subject) === undefined) {
		throw new RangeError(
			"codeClaimRevalidation: the first read's subject must be a non-empty string",
		);
	}
	return claim({
		authenticated: true,
		sid: nonEmptyString(code.sid),
		subject,
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

/** The `action` field of a log line: a bundled action's name, or an issued remediation's, else `custom` (D10). */
const actionLabel = (action: AdmissionAction): string =>
	Object.hasOwn(ADMISSION_ACTIONS, action.name) || isIssuedAction(action) ? action.name : "custom";

/** The `remediation` names already said to be undeclared, once per process each (D4), up to the cap; past it, once for all. */
const undeclaredRemediations = new Set<string>();
const UNDECLARED_REMEDIATION_CAP = 256;
let undeclaredRemediationsOverflowed = false;

/** The requirements already said to have stepped up without a page, once per process each (D2, step 5). */
const pagelessStepUps = new Set<string>();

/** The requirements already said to have stepped up over no session, once per process each (D2, step 5). */
const sessionlessStepUps = new Set<string>();

// ---------------------------------------------------------------------------
// admitSession (D2)
// ---------------------------------------------------------------------------

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);

/**
 * What `checkRequest` answers: every untrusted input read once and copied —
 * the claim's fields, the action (the bundled entry or the issued object
 * itself, else a plain copy of name and grade), the caller's `asks`, and
 * each dependency read once off `deps` — so a getter answering one thing to
 * the check and another to the steps changes nothing, and a requirement
 * cannot reach the caller's objects.
 */
interface CheckedRequest {
	readonly claim: SessionClaim;
	readonly action: AdmissionAction;
	readonly asks: AdmissionAsks | undefined;
	readonly requirements: SessionRequirementResolver;
	readonly userSessionStore: UserSessionStore | undefined;
	readonly subjectRevocation: SubjectRevocation | undefined;
	readonly acrTable: AcrTable;
	readonly logger: Logger | undefined;
	readonly auditSink: AuditSink | undefined;
	readonly now: Date;
}

/** A caller's fault is a `RangeError` before anything is read. Answers core's copy of what it read, each input read once. */
function checkRequest(deps: AdmissionDeps, request: AdmissionRequest): CheckedRequest {
	if (!isObject(deps)) throw new RangeError("admitSession: deps must be an object");
	const requirements = checkResolver(deps.requirements);
	const acrTable = deps.acrTable;
	if (!isObject(acrTable)) throw new RangeError("admitSession: acrTable must be an object");
	const userSessionStore = deps.userSessionStore;
	const subjectRevocation = deps.subjectRevocation;
	const logger = deps.logger;
	const auditSink = deps.auditSink;
	const clock = deps.now;
	const now = clock === undefined ? new Date() : clock();
	if (!isObject(request)) throw new RangeError("admitSession: the request must be an object");
	const presented = request.claim;
	if (!isObject(presented) || !knownClaims.has(presented)) {
		throw new RangeError(
			"admitSession: the claim must be one a claim builder made — cookieClaim, codeClaimFirstRead, codeClaimRevalidation, linkClaim or tokenClaim",
		);
	}
	// A branded claim is frozen and core's own; the copy is still taken, so
	// nothing downstream reads the caller's object twice.
	const claim = Object.freeze({
		authenticated: presented.authenticated === true,
		sid: nonEmptyString(presented.sid),
		subject: nonEmptyString(presented.subject),
		carrier: presented.carrier,
		...(Array.isArray(presented.tokenAmr)
			? { tokenAmr: Object.freeze([...(presented.tokenAmr as readonly string[])]) }
			: {}),
	}) as SessionClaim;
	const asked = request.action;
	if (!isObject(asked))
		throw new RangeError("admitSession: the action must be a name with a grade");
	const name = asked.name;
	const grade = asked.grade;
	if (nonEmptyString(name) === undefined || typeof grade !== "string" || !GRADES.has(grade)) {
		throw new RangeError("admitSession: the action must be a name with a grade");
	}
	// A bundled name is accepted as the bundled entry itself alone: the grade
	// is not the caller's to restate (D4).
	if (Object.hasOwn(ADMISSION_ACTIONS, name)) {
		if (asked !== (ADMISSION_ACTIONS as Record<string, AdmissionAction>)[name]) {
			throw new RangeError(
				`admitSession: "${name}" is a bundled action: pass ADMISSION_ACTIONS["${name}"] itself, not a copy or a literal`,
			);
		}
	}
	// The issued object keeps its identity — that is what step 5 checks — and
	// so does the bundled entry; anything else is copied.
	const action: AdmissionAction =
		isIssuedAction(asked) || Object.hasOwn(ADMISSION_ACTIONS, name)
			? (asked as AdmissionAction)
			: Object.freeze({ name, grade: grade as AdmissionGrade });
	const asksRead = request.asks;
	let asks: AdmissionAsks | undefined;
	if (asksRead !== undefined) {
		if (!isObject(asksRead)) throw new RangeError("admitSession: asks must be an object");
		const acrValues = asksRead.acrValues;
		if (acrValues !== undefined && !isStringList(acrValues)) {
			throw new RangeError("admitSession: asks.acrValues must be a list of non-empty strings");
		}
		asks = Object.freeze({
			...(acrValues === undefined ? {} : { acrValues: Object.freeze([...acrValues]) }),
		});
	}
	return {
		claim,
		action,
		asks,
		requirements,
		userSessionStore,
		subjectRevocation,
		acrTable,
		logger,
		auditSink,
		now,
	};
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

/** A requirement's answer read once — `outcome` and `whenStillUnmet` — into a plain object; anything that is not an object as it is. */
const copyVerdict = (answer: unknown): unknown =>
	isObject(answer) ? { outcome: answer.outcome, whenStillUnmet: answer.whenStillUnmet } : answer;

/** Whether `value` is one of the four verdicts, its `step_up` with a `whenStillUnmet` (and no page: the registered one answers). */
const isVerdict = (value: unknown): value is RequirementVerdict =>
	isObject(value) &&
	typeof value.outcome === "string" &&
	VERDICTS.has(value.outcome) &&
	(value.outcome !== "step_up" ||
		value.whenStillUnmet === "reauthenticate" ||
		value.whenStillUnmet === "unmet");

/**
 * Step 5's verdict, with the requirement that gave it. An outage never gets
 * here — step 5 answers `unavailable` itself — and a `step_up` carries the
 * live session it was taken over and the requirement whose reach bounds its
 * hint: `stepUpVerdict` makes one over no session `reauthenticate`.
 */
type RequirementOutcome =
	| { readonly outcome: "met" }
	| { readonly outcome: "reauthenticate"; readonly requirement: string }
	| {
			readonly outcome: "step_up";
			readonly requirement: string;
			readonly stepping: RegisteredRequirement;
			readonly session: UserSession;
			readonly page: StepUpPage;
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string };

/**
 * `admitSession`: whether the session `request.claim` names may proceed with
 * `request.action` (D2). The steps, each fail-closed, in order:
 *
 * 1. the claim — not authenticated → `unauthenticated`; a cookie without a
 *    subject → `not_live` (`no_subject`), logged at warn;
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
	const checked = checkRequest(deps, request);
	const {
		claim: presented,
		asks,
		requirements: resolver,
		userSessionStore,
		subjectRevocation,
		now,
		logger,
	} = checked;
	const label = actionLabel(checked.action);
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
		// A cookie that says authenticated without a user: not a session this
		// provider wrote. Said at warn with the action alone; nothing to audit.
		logger?.warn({ action: label }, "session_admission_no_subject");
		return { outcome: "not_live", reason: "no_subject" };
	}

	// Step 2: the live read.
	let session: UserSession | null = null;
	if (userSessionStore !== undefined && presented.sid === undefined) {
		if (presented.carrier !== "token") return { outcome: "not_live", reason: "no_sid" };
	} else if (userSessionStore !== undefined && presented.sid !== undefined) {
		let record: UserSession | null | undefined;
		try {
			record = await userSessionStore.get(presented.sid);
		} catch (err) {
			return unavailable("user_session", err);
		}
		// `== null`: the port answers `null`, and a store of the deployment's own
		// that answers `undefined` for a missing session is still no session.
		if (
			record == null ||
			nonEmptyString(record.sub) === undefined ||
			!isValidDate(record.authTime) ||
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
		void emitAuditEvent(checked.auditSink, {
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
	if (session !== null && subjectRevocation !== undefined && presented.carrier !== "token") {
		try {
			const boundary = await subjectRevocation.revokedBefore(session.sub);
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
	// first (D4): only the issued remediation keeps its grade and skips them.
	const requirements = [...resolver.entries()];
	const effective = effectiveAction(requirements, checked.action, logger);
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
			// The record's sub when read — step 3 made it the claim's — else the claim's.
			subject: session === null ? presented.subject : session.sub,
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
			// Copied before it is checked: a getter cannot answer one outcome
			// to the check and another to the merge.
			answer = copyVerdict(answer);
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
			: // The amr a carrier is judged on (D2, step 5): a token's own — the
				// record is only the live view — else the D9 reading of the record.
				selectAcr(
					requested,
					(presented.carrier === "token"
						? requirementSessionFromAmr(presented.tokenAmr)
						: requirementSession(session)
					)?.amr ?? [],
					checked.acrTable,
					reach,
				);
	const noneConfigured =
		requested.length > 0 && requested.every((acr: string) => !Object.hasOwn(checked.acrTable, acr));

	// Step 7: the merge.
	return merge(verdict, selection, {
		session,
		noneConfigured,
		requirements,
		// What step 5 handed the requirements, the same reading the selection took.
		held: authentication?.amr ?? [],
		table: checked.acrTable,
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
	requirement: RegisteredRequirement,
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
	return {
		outcome: "step_up",
		requirement: name,
		stepping: requirement,
		session,
		page,
		whenStillUnmet,
	};
}

/**
 * The action as the requirements see it (D4): `use` and `credential_change`
 * as given; `remediation` only for the object core issued to one of these
 * requirements at registration — a literal, a copy, or `ADMISSION_ACTIONS`'
 * own entry carries no brand — else `credential_change`, the strictest
 * grade, said once per process per name.
 */
function effectiveAction(
	requirements: readonly (readonly [string, RegisteredRequirement])[],
	asked: AdmissionAction,
	logger: Logger | undefined,
): AdmissionAction {
	if (asked.grade !== "remediation") return { name: asked.name, grade: asked.grade };
	if (
		isIssuedAction(asked) &&
		// Every registered copy was issued its actions ({} when it declared none).
		requirements.some(([, r]) => Object.values(issuedActionsOf(r) as object).includes(asked))
	) {
		return asked;
	}
	// The name is the consumer's own, so the line says `custom`; once per
	// name, and once for all past the cap, so a route cannot fill the log.
	if (undeclaredRemediations.size < UNDECLARED_REMEDIATION_CAP) {
		if (!undeclaredRemediations.has(asked.name)) {
			undeclaredRemediations.add(asked.name);
			logger?.warn({ action: "custom" }, "session_admission_remediation_undeclared");
		}
	} else if (!undeclaredRemediations.has(asked.name) && !undeclaredRemediationsOverflowed) {
		undeclaredRemediationsOverflowed = true;
		logger?.warn({ action: "custom", overflow: true }, "session_admission_remediation_undeclared");
	}
	return { name: asked.name, grade: "credential_change" };
}

interface MergeContext {
	readonly session: UserSession | null;
	/** No requested value is in the table: no login can meet the request. */
	readonly noneConfigured: boolean;
	readonly requirements: readonly (readonly [string, RegisteredRequirement])[];
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
		case "met":
			if (A === undefined || A.outcome === "met") {
				return { outcome: "admitted", session, acr: A?.acr };
			}
			// A selection steps up only over a live session: step 6 hands it an
			// empty reach otherwise.
			if (A.outcome === "unmet" || session === null) return unmetAcr();
			return stepUpThroughOne(A.acrValues, context, session) ?? unmetAcr();
		case "reauthenticate":
			return context.noneConfigured
				? unmetAcr()
				: { outcome: "reauthenticate", requirement: R.requirement, session };
		case "step_up": {
			if (A?.outcome === "unmet") return unmetAcr();
			// The hint: what the stepping requirement's own trip can finish, as
			// in the met + step_up row — never an entry only another reaches.
			return {
				outcome: "step_up",
				requirement: R.requirement,
				session: R.session,
				page: R.page,
				acrValues:
					A?.outcome === "step_up"
						? A.acrValues.filter((acr: string) => finishes(context, R.stepping, acr))
						: [],
				whenStillUnmet: A?.outcome === "step_up" ? "unmet" : R.whenStillUnmet,
			};
		}
		case "unmet":
			return A?.outcome === "unmet"
				? unmetAcr()
				: { outcome: "unmet", requirement: R.requirement, session };
	}
}

/** Whether `requirement`'s reach, beside what is held, covers one alternative of the entry `acr`. */
const finishes = (
	context: MergeContext,
	requirement: RegisteredRequirement,
	acr: string,
): boolean =>
	// `acr` is one the selection answered reachable: a key of the table.
	(context.table[acr] as readonly (readonly string[])[]).some(
		(alternative) =>
			alternative.length > 0 &&
			alternative.every((value) => context.held.includes(value) || requirement.reach.has(value)),
	);

/**
 * The `met` + `step_up` row: the page of the first requirement whose own
 * reach covers everything one alternative of a reachable entry lacks, with
 * the entries that requirement alone can finish as the hint — `undefined`
 * when no single requirement covers any, since no one trip can finish it.
 */
function stepUpThroughOne(
	reachable: readonly string[],
	context: MergeContext,
	session: UserSession,
): Admission | undefined {
	for (const [name, requirement] of context.requirements) {
		// What this requirement's reach alone can finish, beside what is held.
		const finishable = reachable.filter((acr: string) => finishes(context, requirement, acr));
		// A requirement whose reach covers an entry registered a page: boot
		// holds a non-empty reach to one. Without one nothing could finish it.
		if (finishable.length > 0 && requirement.stepUpPage !== undefined) {
			return {
				outcome: "step_up",
				requirement: name,
				session,
				page: requirement.stepUpPage,
				// The hint: the entries this one trip can finish, in the request's order.
				acrValues: finishable,
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
	/** The route's `extractUserClaims(user)`: what the session record's `claims` will hold. */
	readonly claims: UserSessionClaims;
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
		claims: facts.claims,
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

/** The keys an interruption's body may carry (D5): closed, so a `user` snapshot, a `sub` or a `sid` cannot leave through it. */
const ANSWER_KEYS: ReadonlySet<string> = new Set(["error", "transaction", "expires_in", "hints"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** The hint grammar's caps (D5): an integer's range, a list's length, a transaction's length. */
const HINT_NUMBER_MAX = 86_400;
const HINT_LIST_MAX = 16;
const TRANSACTION_MAX_LENGTH = 128;

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
	// The body: read once, its own keys copied into a plain object that is
	// what gets validated and answered.
	const bodyRead = value.body;
	if (!isObject(bodyRead) || Array.isArray(bodyRead)) return refuse("without a body");
	const body: Record<string, unknown> = {};
	for (const key of Object.keys(bodyRead)) body[key] = bodyRead[key];
	for (const key of Object.keys(body)) {
		if (!ANSWER_KEYS.has(key)) {
			refuse(`whose body carries "${key}", which the body's shape does not admit`);
		}
	}
	const error = body.error;
	if (!isWellFormedErrorCode(error)) refuse("whose error is not a well-formed error code");
	const transaction = body.transaction;
	if (transaction !== undefined) {
		if (
			typeof transaction !== "string" ||
			transaction.length > TRANSACTION_MAX_LENGTH ||
			!BASE64URL.test(transaction)
		) {
			refuse(`whose transaction is not a base64url string of at most ${TRANSACTION_MAX_LENGTH}`);
		}
	}
	const expiresIn = body.expires_in;
	if (expiresIn !== undefined) {
		if (!Number.isSafeInteger(expiresIn) || (expiresIn as number) <= 0) {
			refuse("whose expires_in is not a positive integer");
		}
	}
	let hints: Record<string, string | number | boolean | readonly string[]> | undefined;
	const hintsRead = body.hints;
	if (hintsRead !== undefined) {
		if (!isObject(hintsRead) || Array.isArray(hintsRead)) {
			return refuse("whose hints are not an object");
		}
		hints = {};
		for (const key of Object.keys(hintsRead)) {
			const hint = hintsRead[key];
			if (!hintKeys.includes(key) || !isHintKey(key)) {
				refuse(`with a hint "${key}" it did not declare, or that is not a hint name`);
			}
			if (typeof hint === "boolean") {
				hints[key] = hint;
			} else if (typeof hint === "number") {
				if (!Number.isSafeInteger(hint) || hint < 0 || hint > HINT_NUMBER_MAX) {
					refuse(`with a hint "${key}" that is not an integer in [0, ${HINT_NUMBER_MAX}]`);
				}
				hints[key] = hint;
			} else if (isHintToken(hint)) {
				hints[key] = hint;
			} else if (Array.isArray(hint) && hint.every(isHintToken)) {
				if (hint.length > HINT_LIST_MAX) {
					refuse(`with a hint "${key}" that lists more than ${HINT_LIST_MAX} tokens`);
				}
				hints[key] = Object.freeze([...hint]);
			} else {
				refuse(`with a hint "${key}" that is not a boolean, an integer, or an enum-like token`);
			}
		}
	}
	return Object.freeze({
		status: 403,
		body: Object.freeze({
			error: error as string,
			...(transaction === undefined ? {} : { transaction: transaction as string }),
			...(expiresIn === undefined ? {} : { expires_in: expiresIn as number }),
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
	requirements: SessionRequirementResolver,
	composed: PrimaryAuthentication,
	primary: PrimaryAuthentication,
	done: readonly CompletedRequirement[],
): Promise<PrimaryAdmission> {
	for (const [name, requirement] of requirements.entries()) {
		const ask = requirement.admitPrimary;
		if (ask === undefined) continue;
		let answer: unknown;
		try {
			answer = await ask.call(requirement, composed);
		} catch (err) {
			return unavailableAtEstablishment(deps, name, err);
		}
		if (answer === "establish") continue;
		// The answer's `open` is read once, here.
		const open = isObject(answer) ? answer.open : undefined;
		if (typeof open === "function") {
			// The continuation names who interrupted: `resumePrimary` accepts
			// that requirement's completion alone (D5).
			const continuation = continuationOf(primary, done, name);
			return {
				outcome: "interrupt",
				requirement: name,
				continuation,
				open: async (sessionId: string) => {
					if (nonEmptyString(sessionId) === undefined) {
						throw new RangeError("open: the session id must be a non-empty string");
					}
					// The requirement persists what core built (D5).
					return checkInterruptionAnswer(
						await (open as RequirementInterruption["open"]).call(answer, sessionId, continuation),
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
	const requirements = checkResolver(deps.requirements);
	if (!isObject(primary) || !knownPrimaries.has(primary)) {
		throw new RangeError(
			"admitPrimary: the primary must be one passwordPrimary or establishWithoutAsking built",
		);
	}
	return askEvery(deps, requirements, primary, primary, []);
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
	const requirements = checkResolver(deps.requirements);
	const read = checkPrimaryContinuation(continuation);
	if (!isObject(completed) || nonEmptyString(completed.requirement) === undefined) {
		throw new RangeError("resumePrimary: the completion must name a requirement");
	}
	// The continuation waits on one requirement's ceremony: its completion,
	// no other's (D5).
	if (completed.requirement !== read.interruptedBy) {
		throw new RangeError(
			`resumePrimary: the continuation waits on "${read.interruptedBy}", not "${completed.requirement}"`,
		);
	}
	// This release interrupts a password login alone: `recorded` is recomposed
	// from that kind, never taken from the persisted DTO.
	const kind = read.primary.recorded.authentication.primary;
	if (kind !== PASSWORD_AMR) {
		throw new RangeError(
			`resumePrimary: a continuation's primary is a password login in this release, not "${kind}"`,
		);
	}
	const registeredWithAdmitPrimary = (name: string): boolean =>
		requirements.get(name)?.admitPrimary !== undefined;
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
	// Rehydrated: the continuation carries epoch milliseconds; `recorded` is
	// the password kind's, not the DTO's.
	const primary: PrimaryAuthentication = Object.freeze({
		...primaryFromDto(read.primary),
		recorded: passwordSessionAuthentication(),
	});
	const done: readonly CompletedRequirement[] = Object.freeze([
		...read.done.map((entry) =>
			Object.freeze({ requirement: entry.requirement, adds: additionsFromDto(entry.adds) }),
		),
		Object.freeze({ requirement: completed.requirement, adds }),
	]);
	// Every addition — the earlier completions' as read back, and this one —
	// is within its requirement's sealed reach (D5): a ceremony adds what its
	// requirement said it could, and a record from before a reach shrank is
	// refused rather than composed.
	for (const entry of done) {
		const reach = requirements.get(entry.requirement)?.reach;
		const outside = entry.adds.amr.filter((value) => !reach?.has(value));
		if (outside.length > 0) {
			throw new RangeError(
				`resumePrimary: "${entry.requirement}" adds ${outside.map((value) => `"${value}"`).join(", ")}, which its reach does not name`,
			);
		}
	}
	return askEvery(deps, requirements, composeRecorded(primary, done), primary, done);
}

/** What a federated login legitimately produces (D5): the federation's own facts, never a `recorded`. */
export interface FederatedLogin {
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	/** The merged claims envelope the callback composed: what the session record's `claims` will hold. */
	readonly claims: UserSessionClaims;
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
		claims: login.claims,
		recorded,
		authTime: login.authTime,
		redirectTo: login.redirectTo,
		request: login.request,
	});
	knownPrimaries.add(primary);
	return establish(primary);
}
