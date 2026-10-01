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
 * Session admission: the one decision point every consumer of an
 * authenticated browser session calls, and the one the login route calls
 * before a session is written. See ADR 2026-09-28-session-admission.
 *
 * `admitSession` judges a session for an action; the claim builders are the
 * one reading of each carrier, and `cookieSessionUser` the one reading of the
 * cookie session's user. `admitPrimary` and `resumePrimary` ask the
 * requirements that interrupt a login and answer the `Establishment`
 * `establishSession` requires; `establishWithoutAsking` builds a federated
 * login's.
 *
 * Every step fails closed: a store that throws is `unavailable`, logged once
 * at error with `loggableError`'s projection, never the `sid`. A caller's
 * fault is a `RangeError` before anything is read. The brands are
 * module-private `WeakSet`s, so an `as` cast forges nothing.
 *
 * `selectAcr` is called only here in product code, over the vouched `amr`,
 * so a value an untrusted IdP asserted in a pre-upgrade session meets no
 * `acr`.
 */

import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import {
	composeAmr,
	MFA_AMR,
	PASSWORD_AMR,
	wellFormedAmr,
} from "../grants/authenticationClaims.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import {
	copySessionAuthentication,
	federatedSessionAuthentication,
	passwordSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
} from "../user-sessions/authentication.mjs";
import { readEnrollmentFacts } from "../user-sessions/enrollmentFacts.mjs";
import type { UserSession, UserSessionClaims } from "../user-sessions/types.mjs";
import { type AcrSelection, selectAcr, stepUpReach } from "./acr.mjs";
import type { AdmissionAction } from "./actions.mjs";
import { isObject, nonEmptyString } from "./input-values.mjs";
import { readLiveSession } from "./live-session.mjs";
import {
	additionsFromDto,
	checkPrimaryAdditions,
	checkPrimaryAuthentication,
	checkPrimaryContinuation,
	continuationOf,
	frozenUserCopy,
	primaryFromDto,
} from "./primary.mjs";
import { checkRequest, claim } from "./request-check.mjs";
import {
	type Admission,
	type AdmissionDeps,
	type AdmissionRequest,
	type CompletedRequirement,
	type Establishment,
	type InterruptAdmission,
	type InterruptionAnswer,
	isHintKey,
	isHintToken,
	isIssuedAction,
	issuedActionsOf,
	type PrimaryAdmission,
	type PrimaryAuthentication,
	type PrimaryContinuation,
	type RegisteredRequirement,
	type RegisteredStepUpPage,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementVerdict,
	type SessionClaim,
	type SessionRequirementResolver,
	type SessionView,
} from "./requirement.mjs";
import { checkResolver } from "./requirement-resolver.mjs";

export {
	checkResolver,
	type SessionRequirementSource,
	sessionRequirementResolverOver,
} from "./requirement-resolver.mjs";

// ---------------------------------------------------------------------------
// The claim builders
// ---------------------------------------------------------------------------

/** What a cookie claim is built from: the express session, when the request has one. */
export interface CookieCarrier {
	readonly session?: {
		readonly isAuthenticated?: unknown;
		readonly sid?: unknown;
		readonly user?: unknown;
	} | null;
}

/**
 * The cookie's claim: `authenticated` is `isAuthenticated === true`, the one
 * reading of the flag; `sid` and `subject` (`user.id`) are copied when they
 * are non-empty strings. A request without a session claims nothing.
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

/**
 * The `User` the cookie session holds — its login's — copied as plain data,
 * frozen at every depth and sharing nothing with it (`frozenUserCopy`), when
 * the session is authenticated (`isAuthenticated === true`, as `cookieClaim`
 * reads it) and the copy's `id` is `subject`; else `undefined`, a user that
 * is not plain data included. For a route that admitted `subject` over the
 * cookie's claim. A request that is not an object, or a `subject` that is
 * not a non-empty string, is a `RangeError`.
 */
export function cookieSessionUser(
	req: CookieCarrier,
	subject: string,
): Readonly<Record<string, unknown>> | undefined {
	if (!isObject(req)) throw new RangeError("cookieSessionUser: the request must be an object");
	if (nonEmptyString(subject) === undefined) {
		throw new RangeError("cookieSessionUser: the subject must be a non-empty string");
	}
	const session = isObject(req.session) ? req.session : undefined;
	if (session?.isAuthenticated !== true) return undefined;
	// Judged on the copy it answers: the session's user is read once.
	const user = frozenUserCopy(session.user);
	return user?.id === subject ? user : undefined;
}

/** What a code claim is built from: the code record, which carries a `sid` when a session minted it. */
export interface CodeCarrier {
	readonly sid?: unknown;
}

/**
 * A code record's claim on its first read: authenticated (a session minted
 * the code), with the code's `sid` and no subject, since `CodeData` carries
 * no `sub`; `admitSession`'s subject check has nothing to compare.
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
 * the first read's `subject`, required, so the two reads are compared and
 * the comparison cannot be left out by omitting an option.
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

/** What a link claim is built from: the link transaction's envelope, which records the session and its subject at the start. */
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

/** What a token claim is built from: a verified token's claims. */
export interface TokenCarrier {
	readonly sid?: unknown;
	readonly sub: unknown;
	readonly amr?: unknown;
}

/**
 * A verified token's claim: authenticated, its `sid` when it carries one
 * (without one the live read is skipped), its `sub`, and its `amr` for the
 * requirements (`tokenAmr`, absent unless a well-formed list). A token
 * without a `sub` is not one a session issued.
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
// The actions: each a consumer's registration (`actions.mts`) or a
// remediation core issued to a requirement (`requirement.mts`).
// ---------------------------------------------------------------------------

/** The `remediation` names already said to be undeclared, once per process each, up to the cap; past it, once for all. */
const undeclaredRemediations = new Set<string>();
const UNDECLARED_REMEDIATION_CAP = 256;
let undeclaredRemediationsOverflowed = false;

/** The requirements already said to have stepped up without a page, once per process each. */
const pagelessStepUps = new Set<string>();

/** The requirements already said to have stepped up over no session, once per process each. */
const sessionlessStepUps = new Set<string>();

// ---------------------------------------------------------------------------
// admitSession
// ---------------------------------------------------------------------------

/**
 * The view a requirement is handed: a copy of four fields, and of the
 * record's `enrollmentFacts` when it holds ones the type admits — never the
 * record.
 */
const viewOf = (session: UserSession): SessionView => {
	const enrollmentFacts = readEnrollmentFacts(session.enrollmentFacts);
	return Object.freeze({
		sid: session.sid,
		sub: session.sub,
		authTime: new Date(session.authTime.getTime()),
		expiresAt: new Date(session.expiresAt.getTime()),
		...(enrollmentFacts === undefined ? {} : { enrollmentFacts: Object.freeze(enrollmentFacts) }),
	});
};

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
			readonly page: RegisteredStepUpPage;
			readonly whenStillUnmet: "reauthenticate" | "unmet";
	  }
	| { readonly outcome: "unmet"; readonly requirement: string };

/**
 * Whether the session `request.claim` names may proceed with
 * `request.action`. The steps, in order, each failing closed:
 *
 * 1. claim: not authenticated → `unauthenticated`; a cookie without a
 *    subject → `not_live` (`no_subject`).
 * 2. live read, with a store: no `sid` → `not_live` (`no_sid`), except a
 *    token carrier, which skips the read; no record, no `sub` or expired →
 *    `not_live` (`gone`). Without a store the session is `null` and the
 *    requirements decide what that means.
 * 3. subject: a claim's subject that is not the record's → `not_live`
 *    (`subject_mismatch`), logged and audited.
 * 4. revocation boundary, for a live record; skipped for a token carrier,
 *    whose boundary `verifyJwt` reads.
 * 5. requirements, for `use` and `credential_change`: each `admit` in
 *    registration order, the first verdict that is not `met` taken (see
 *    `stepUpVerdict` for `step_up`). A token carrier is judged on the
 *    token's own `amr`, record or not.
 * 6. `acr_values`: `selectAcr` over the vouched `amr`, with reach the union
 *    of every requirement's when the session is live.
 * 7. `merge` of 5 and 6.
 */
export async function admitSession(
	deps: AdmissionDeps,
	request: AdmissionRequest,
): Promise<Admission> {
	const checked = checkRequest(deps, request);
	const { claim: presented, asks, requirements: resolver, now, logger } = checked;
	const label = checked.action.name;
	const unavailable = (store: string, err: unknown): Admission => {
		logger?.error(
			{ store, action: label, err: loggableError(err) },
			"session_admission_unavailable",
		);
		return { outcome: "unavailable", store };
	};

	// Steps 1 to 4: the claim, the live read, the subject, the revocation boundary.
	const live = await readLiveSession(checked, unavailable);
	if ("answer" in live) return live.answer;
	const { session } = live;

	// Step 5: the requirements, by the action's effective grade: only the
	// issued remediation keeps its grade and skips them.
	const requirements = [...resolver.entries()];
	const effective = effectiveAction(requirements, checked.action, logger);
	// A token carrier's authentication is the token's own, whether or not a
	// record was read: the record is only the view.
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
			: // The amr step 5 judged on: a token's own, else the record's.
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
 * store, or a token carrier without a record) it is `reauthenticate`, since
 * nothing can be stepped up onto no session and a login can; from a
 * requirement that registered no page it is `unmet`, since nothing could
 * finish the trip. Each is logged once per process per name. So a `step_up`
 * always carries a live session and a page.
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
 * The action as the requirements see it: a registered action as registered;
 * `remediation` only for an object core issued to one of these requirements —
 * else, one issued to a requirement another composition registered, as
 * `credential_change`, the strictest grade, said once per process per name.
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
	// Once per name, and once for all past the cap, so the log stays bounded.
	if (undeclaredRemediations.size < UNDECLARED_REMEDIATION_CAP) {
		if (!undeclaredRemediations.has(asked.name)) {
			undeclaredRemediations.add(asked.name);
			logger?.warn({ action: asked.name }, "session_admission_remediation_undeclared");
		}
	} else if (!undeclaredRemediations.has(asked.name) && !undeclaredRemediationsOverflowed) {
		undeclaredRemediationsOverflowed = true;
		logger?.warn(
			{ action: asked.name, overflow: true },
			"session_admission_remediation_undeclared",
		);
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

/** The merge table of ADR 2026-09-28-session-admission: `R` the requirements' verdict, `A` the acr selection (`undefined` when nothing was asked). */
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
// Establishment
// ---------------------------------------------------------------------------

/** The establishments `admitPrimary`, `resumePrimary` and `establishWithoutAsking` built. */
const knownEstablishments = new WeakSet<object>();

/** The interruptions `admitPrimary` and `resumePrimary` answered. */
const knownInterruptions = new WeakSet<object>();

/**
 * The primaries core's builders made (`passwordPrimary`, and
 * `establishWithoutAsking`'s own): what `admitPrimary` accepts. A
 * continuation a requirement persisted and presents back is plain data a
 * store round-tripped, which no set can mark, so `resumePrimary` reads it
 * through `checkPrimaryContinuation` instead.
 */
const knownPrimaries = new WeakSet<object>();

/** What a password login produces: the facts, never a `recorded`. */
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
 * The one builder a password login has: `recorded` is
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

/** Whether `value` is an interruption `admitPrimary` or `resumePrimary` answered: a copy, or an object shaped like one, is not. */
export function isInterruptAdmission(value: unknown): value is InterruptAdmission {
	return typeof value === "object" && value !== null && knownInterruptions.has(value);
}

const establish = (primary: PrimaryAuthentication): Establishment => {
	const built = Object.freeze({ primary });
	knownEstablishments.add(built);
	return built as unknown as Establishment;
};

/** The keys an interruption's body may carry: closed, so a `user` snapshot, a `sub` or a `sid` cannot leave through it. */
const ANSWER_KEYS: ReadonlySet<string> = new Set(["error", "transaction", "expires_in", "hints"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** The hint grammar's caps: an integer's range, a list's length, a transaction's length. */
const HINT_NUMBER_MAX = 86_400;
const HINT_LIST_MAX = 16;
const TRANSACTION_MAX_LENGTH = 128;

/**
 * Holds an interruption's answer to the closed body (`ANSWER_KEYS`, `error`
 * in the RFC 6749 error-text class) and to the `hintKeys` the requirement
 * named `name` declared, each hint a boolean, a bounded integer or
 * enum-like tokens, so a snapshot, a URL, an address or a name cannot pass.
 * Answers a frozen copy; a body that fails is the requirement's fault, a
 * `RangeError` the route answers as an `open` failure.
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
	// The body is read once into a null-prototype object, which is what gets
	// validated and answered: an own "__proto__" key is then an ordinary key,
	// not the prototype's setter.
	const bodyRead = value.body;
	if (!isObject(bodyRead) || Array.isArray(bodyRead)) return refuse("without a body");
	const body: Record<string, unknown> = Object.create(null);
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
 * Asks every requirement with `admitPrimary` not in `done`, in registration
 * order, about `composed`; one that completed is not asked again in this
 * login, whatever it added. The first interruption wins, carrying the
 * continuation and an `open` that validates the answer. A throw, or an
 * answer that is neither `establish` nor an interruption, is `unavailable`.
 */
async function askEvery(
	deps: AdmissionDeps,
	requirements: SessionRequirementResolver,
	composed: PrimaryAuthentication,
	primary: PrimaryAuthentication,
	done: readonly CompletedRequirement[],
): Promise<PrimaryAdmission> {
	const completed = new Set(done.map((entry) => entry.requirement));
	for (const [name, requirement] of requirements.entries()) {
		const ask = requirement.admitPrimary;
		if (ask === undefined || completed.has(name)) continue;
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
			// that requirement's completion alone.
			const continuation = continuationOf(primary, done, name);
			const interruption = Object.freeze({
				outcome: "interrupt" as const,
				requirement: name,
				continuation,
				open: async (sessionId: string) => {
					if (nonEmptyString(sessionId) === undefined) {
						throw new RangeError("open: the session id must be a non-empty string");
					}
					// The requirement persists what core built.
					return checkInterruptionAnswer(
						await (open as RequirementInterruption["open"]).call(answer, sessionId, continuation),
						name,
						requirement.hintKeys,
					);
				},
			});
			knownInterruptions.add(interruption);
			return interruption as unknown as InterruptAdmission;
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
 * What `POST /session/login` calls once the user is verified and before
 * anything is written. The primary must be one a core builder made, else a
 * `RangeError`; then every requirement with `admitPrimary` is asked in
 * order. The first interruption wins; only when every one answers
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
 * what every completed requirement added, in order (`composeAmr`: a
 * requirement's `mfa` comes through `addsMfa`); `mfaAt` is what the one
 * completion that may carry one, the second-factor authority's, verified at.
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
 * Continues a login after a requirement's ceremony completes. Refuses,
 * before asking anything, a continuation `checkPrimaryContinuation` cannot
 * read, a completion by any requirement but the one that interrupted (or
 * one not registered with `admitPrimary`, or already done), and additions —
 * this completion's and each read back from `done` — their requirement may
 * not make as registered (`checkPrimaryAdditions`). Then composes `recorded`
 * from the primary and every completion and asks each requirement not yet
 * done; any may interrupt again with the updated continuation.
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
	// no other's.
	if (completed.requirement !== read.interruptedBy) {
		throw new RangeError(
			`resumePrimary: the continuation waits on "${read.interruptedBy}", not "${completed.requirement}"`,
		);
	}
	// Only a password login is interrupted: `recorded` is recomposed from that
	// kind, never taken from the persisted DTO.
	const kind = read.primary.recorded.authentication.primary;
	if (kind !== PASSWORD_AMR) {
		throw new RangeError(
			`resumePrimary: a continuation's primary is a password login in this release, not "${kind}"`,
		);
	}
	/** The registered requirement of `name` that interrupts a login, else a `RangeError`. */
	const interrupting = (name: string): RegisteredRequirement => {
		const requirement = requirements.get(name);
		if (requirement?.admitPrimary === undefined) {
			throw new RangeError(
				`resumePrimary: "${name}" is not a registered requirement that interrupts a login`,
			);
		}
		return requirement;
	};
	const earlier = read.done.map((entry) => ({
		entry,
		registered: interrupting(entry.requirement),
	}));
	const completing = interrupting(completed.requirement);
	if (read.done.some((entry) => entry.requirement === completed.requirement)) {
		throw new RangeError(`resumePrimary: "${completed.requirement}" already completed`);
	}
	const adds = checkPrimaryAdditions(completing, completed.adds);
	// Rehydrated: the continuation carries epoch milliseconds; `recorded` is
	// the password kind's, not the DTO's.
	const primary: PrimaryAuthentication = Object.freeze({
		...primaryFromDto(read.primary),
		recorded: passwordSessionAuthentication(),
	});
	const done: readonly CompletedRequirement[] = Object.freeze([
		// Held again to its requirement's declaration as registered, not as the
		// record says.
		...earlier.map(({ entry, registered }) =>
			Object.freeze({
				requirement: entry.requirement,
				adds: checkPrimaryAdditions(registered, additionsFromDto(entry.adds)),
			}),
		),
		Object.freeze({ requirement: completed.requirement, adds }),
	]);
	// Every addition, the earlier completions' as read back and this one, is
	// within its requirement's sealed reach: a record from before a reach
	// shrank is refused rather than composed.
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

/** What a federated login legitimately produces: the federation's own facts, never a `recorded`. */
export interface FederatedLogin {
	readonly subject: string;
	readonly user: Readonly<Record<string, unknown>>;
	/** The merged claims envelope the callback composed: what the session record's `claims` will hold. */
	readonly claims: UserSessionClaims;
	/** The federation's name (`federations.<name>`). */
	readonly federation: string;
	/** The upstream IdP's `amr`, as it surfaced it. */
	readonly upstreamAmr: readonly string[];
	/** Whether that federation's upstream `amr` counts (`federationTrustsUpstreamAmr`). */
	readonly trusted: boolean;
	readonly authTime: Date;
	readonly redirectTo: string | undefined;
	readonly request: { readonly ip?: string; readonly userAgent?: string };
}

/**
 * The federation callback's establishment, built from the federation's own
 * facts with no requirement asked. `recorded` is composed here through
 * `federatedSessionAuthentication`, so a caller cannot mark an arbitrary
 * `amr` or an `mfaAt` as a federated primary. A drift guard pins its
 * callers to the callback.
 *
 * A federated login asks no requirement's `admitPrimary`: the requirements
 * judge the resulting session only through `admit`, when a consumer admits it
 * (ADR 2026-09-28-session-admission, D5).
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
