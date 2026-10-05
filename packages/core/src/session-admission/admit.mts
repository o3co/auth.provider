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
 * Session admission's entry point: the claim builders, `admitSession` running
 * its steps in order, and a login's decisions. Product code calls `selectAcr`
 * here alone, over the vouched `amr`, so a value an untrusted IdP asserted in
 * a pre-upgrade session meets no `acr`.
 */

import {
	composeAmr,
	MFA_AMR,
	PASSWORD_AMR,
	wellFormedAmr,
} from "../grants/authenticationClaims.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import { readUserSnapshot } from "../repositories/userSnapshot.mjs";
import {
	canRecordSecondFactor,
	copySessionAuthentication,
	federatedSessionAuthentication,
	passwordSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
} from "../user-sessions/authentication.mjs";
import { readEnrollmentFacts } from "../user-sessions/enrollmentFacts.mjs";
import type { UserSession, UserSessionClaims, UserSessionStore } from "../user-sessions/types.mjs";
import { type AcrSelection, selectAcr, stepUpReach } from "./acr.mjs";
import { askEvery, establish } from "./establishment.mjs";
import { isObject, nonEmptyString } from "./input-values.mjs";
import { readLiveSession, readRecord, renewedAway } from "./live-session.mjs";
import { warnDroppedClaims } from "./login-claims.mjs";
import {
	additionsFromDto,
	checkPrimaryAdditions,
	checkPrimaryAuthentication,
	checkPrimaryContinuation,
	primaryFromDto,
} from "./primary.mjs";
import { brandClaim, checkRequest } from "./request-check.mjs";
import type {
	Admission,
	AdmissionDeps,
	AdmissionRequest,
	CompletedRequirement,
	Establishment,
	PrimaryAdmission,
	PrimaryAuthentication,
	PrimaryContinuation,
	RegisteredRequirement,
	RequirementInput,
	SessionClaim,
	SessionView,
} from "./requirement.mjs";
import { checkResolver } from "./requirement-resolver.mjs";
import {
	copyVerdict,
	effectiveAction,
	isVerdict,
	type LiveRecord,
	type RequirementOutcome,
	stepUpVerdict,
} from "./requirement-verdict.mjs";
import { merge } from "./verdict-merge.mjs";

export { isEstablishment, isInterruptAdmission } from "./establishment.mjs";
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
		readonly renewalNonce?: unknown;
	} | null;
}

/**
 * The cookie's claim: `authenticated` is `isAuthenticated === true`, the one
 * reading of the flag; `sid`, `subject` (`user.id`) and the renewal nonce a
 * renewal wrote (`renewalNonce`) are copied when they are non-empty strings.
 * A request without a session claims nothing.
 */
export function cookieClaim(req: CookieCarrier): SessionClaim {
	if (!isObject(req)) throw new RangeError("cookieClaim: the request must be an object");
	const session = isObject(req.session) ? req.session : undefined;
	const user = session !== undefined && isObject(session.user) ? session.user : undefined;
	const renewalNonce = nonEmptyString(session?.renewalNonce);
	return brandClaim({
		authenticated: session?.isAuthenticated === true,
		sid: nonEmptyString(session?.sid),
		subject: nonEmptyString(user?.id),
		carrier: "cookie",
		...(renewalNonce === undefined ? {} : { renewalNonce }),
	} as SessionClaim);
}

/**
 * The `User` the cookie session holds — its login's snapshot — read back as
 * a login reads one (`readUserSnapshot`: the fields `User` declares, each by
 * name once, frozen at every depth and sharing nothing with it), when the
 * session is authenticated (`isAuthenticated === true`, as `cookieClaim`
 * reads it) and the copy's `id` is `subject`; else `undefined`, a user the
 * snapshot refuses included. For a route that admitted `subject` over the
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
	const reading = readUserSnapshot(session.user);
	return reading.ok && reading.snapshot.id === subject ? reading.snapshot : undefined;
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
	return brandClaim({
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
	return brandClaim({
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
	return brandClaim({ authenticated: true, sid, subject, carrier: "link" } as SessionClaim);
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
	return brandClaim({
		authenticated: true,
		sid: nonEmptyString(claims.sid),
		subject,
		carrier: "token",
		...(tokenAmr === undefined ? {} : { tokenAmr }),
	} as SessionClaim);
}

// ---------------------------------------------------------------------------
// admitSession
// ---------------------------------------------------------------------------

/**
 * The view a requirement is handed, and an admitted or `step_up` admission
 * carries: a copy of four fields, and of the record's `enrollmentFacts` when
 * it holds ones the type admits — never the record — with whether a second
 * factor can be recorded on the session: `storeRecords`, whether the store
 * it was read from has the step-up capability (`readLiveSession` reads it),
 * and `canRecordSecondFactor` over the record. The one place admission
 * decides it. Each call is a fresh copy.
 * @internal
 */
export const viewOf = (session: UserSession, storeRecords: boolean): SessionView => {
	const enrollmentFacts = readEnrollmentFacts(session.enrollmentFacts);
	return Object.freeze({
		sid: session.sid,
		sub: session.sub,
		authTime: new Date(session.authTime.getTime()),
		expiresAt: new Date(session.expiresAt.getTime()),
		...(enrollmentFacts === undefined ? {} : { enrollmentFacts: Object.freeze(enrollmentFacts) }),
		secondFactorRecordable: storeRecords && canRecordSecondFactor(session),
	});
};

/**
 * Whether the record a cookie claim names is bound to another cookie
 * session: it carries a renewal nonce the cookie session does not hold, or
 * one that is not a nonce (the record's nonce read once). `false` for a
 * claim that is not a cookie's, one without a `sid`, and a record that is
 * gone or bound to none. For a route that acts on the record without
 * admitting the session — a logout — so a copy the record was renewed away
 * from cannot end it. Rejects with the store's own error, never answering
 * `unavailable`: the one exception to admission's promise that a store that
 * throws is `unavailable`, and its caller handles the rejection.
 */
export async function cookieRenewedAway(
	store: UserSessionStore,
	claim: SessionClaim,
): Promise<boolean> {
	if (!isObject(claim) || claim.carrier !== "cookie") return false;
	const sid = nonEmptyString(claim.sid);
	if (sid === undefined) return false;
	const record = await readRecord(store, sid);
	if (record == null) return false;
	return renewedAway(record.renewalNonce, nonEmptyString(claim.renewalNonce));
}

/** A copy of `view` with Dates of its own; the facts are frozen and shared. */
const copyView = (view: SessionView): SessionView =>
	Object.freeze({
		...view,
		authTime: new Date(view.authTime.getTime()),
		expiresAt: new Date(view.expiresAt.getTime()),
	});

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
 *    (`subject_mismatch`), logged and audited. Then, for a cookie claim, a
 *    record that carries a renewal nonce the cookie session does not hold →
 *    `not_live` (`renewed`).
 * 4. revocation boundary, for a live record; skipped for a token carrier,
 *    whose boundary `verifyJwt` reads.
 * 5. requirements, for `use` and `credential_change`: each `admit` in
 *    registration order, the first verdict that is not `met` taken (see
 *    `stepUpVerdict` for `step_up`). A token carrier is judged on the
 *    token's own `amr`, record or not.
 * 6. `acr_values`: `selectAcr` over the vouched `amr`, with reach the union
 *    of every requirement's when the session is live.
 * 7. `merge` of 5 and 6. In the met + step_up row, a step-up through the
 *    second-factor authority is never offered for `acr_values` onto a
 *    session the view says no second factor can be recorded on
 *    (`secondFactorRecordable`: a store without `recordSecondFactor`, or a
 *    record `canRecordSecondFactor` refuses): the answer is a new login
 *    (`reauthenticate`, `acr`). The requirements of step 5 were handed the
 *    same answer, on their copy of the view.
 * 8. the last reading, once a requirement was asked about a live record:
 *    steps 1 to 4 again, on a fresh clock reading and with the claim's
 *    subject held to the first reading's, whatever step 7 answered. An
 *    answer they give is the admission's; else step 7's stands, carrying the
 *    first reading's session and view. A requirement that throws has already
 *    answered `unavailable`.
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

	// Steps 1 to 4: the claim, the live read, the subject and the renewal nonce, the revocation boundary.
	const read = await readLiveSession(checked, unavailable);
	if ("answer" in read) return read.answer;
	const { session, storeRecords } = read;
	// The record is read into one view; each requirement is handed its own
	// copy of it, so what one does to its Dates reaches neither the next nor
	// the consumer. Whether a second factor can be recorded on the session is
	// decided here, in the view, once: the requirements, the merge and the
	// consumer all read it there.
	const live: LiveRecord | null =
		session === null ? null : { session, view: viewOf(session, storeRecords) };

	// Step 5: the requirements, by the action's effective grade: only the
	// issued remediation keeps its grade and skips them.
	const requirements = [...resolver.entries()];
	const effective = effectiveAction(checked.action);
	// A token carrier's authentication is the token's own, whether or not a
	// record was read: the record is only the view. Each reading is a frozen
	// copy of its own: the merge's here, and each requirement's below, so what
	// one does to its copy reaches no other.
	const authentication =
		presented.carrier === "token"
			? requirementSessionFromAmr(presented.tokenAmr)
			: requirementSession(session);
	let verdict: RequirementOutcome = { outcome: "met" };
	let asked = false;
	if (effective.grade !== "remediation") {
		const shared = {
			carrier: presented.carrier,
			// The record's sub when read — step 3 made it the claim's — else the claim's.
			subject: session === null ? presented.subject : session.sub,
			action: effective,
			asks,
			now,
		};
		for (const [name, requirement] of requirements) {
			const input: RequirementInput = Object.freeze({
				...shared,
				authentication:
					presented.carrier === "token"
						? requirementSessionFromAmr(presented.tokenAmr)
						: requirementSession(session),
				session: live === null ? null : copyView(live.view),
			});
			let answer: unknown;
			asked = true;
			try {
				// Copied before it is checked, in the guarded step: a getter cannot
				// answer one outcome to the check and another to the merge, and one
				// that throws is the requirement's outage.
				answer = copyVerdict(await requirement.admit(input));
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
					? stepUpVerdict(name, requirement, answer.whenStillUnmet, live, deps)
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
	const answer = merge(verdict, selection, {
		live,
		noneConfigured,
		requirements,
		// What step 5 handed the requirements, from a reading no requirement was handed.
		held: authentication?.amr ?? [],
		table: checked.acrTable,
	});

	// Step 8: the last reading. Nothing is awaited after it, so the record and
	// the boundary the answer stands on are the ones read last.
	if (asked && session !== null) {
		const last = await readLiveSession(
			{
				...checked,
				claim: Object.freeze({ ...presented, subject: session.sub }),
				now: checked.clock(),
			},
			unavailable,
		);
		if ("answer" in last) return last.answer;
	}
	return answer;
}

// ---------------------------------------------------------------------------
// Establishment
// ---------------------------------------------------------------------------

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
	/**
	 * The route's `extractUserClaims(user)`: what the session record's `claims` will hold.
	 *
	 * Core reads it by name, each claim once, into a plain frozen copy. It
	 * must be an object; a class instance is read by the declared claims'
	 * names and its own enumerable keys, nothing else of it. A claim
	 * `UserSessionClaims` declares must, when present, be of its declared
	 * type: `email`, `name` and `picture` a string, `emailVerified` a
	 * boolean, `groups` a list of strings (an ORM's list or an Array
	 * subclass is copied by index into a plain array). `null`, or any other
	 * value, is refused with a `RangeError`. A claim read as `undefined` is
	 * left out.
	 *
	 * A custom claim is stored as its JSON form — `JSON.stringify`, parsed
	 * back — so it should be JSON data: a string, a finite number, a
	 * boolean, `null`, or a list or plain object of those. Anything else is
	 * stored as JSON stores it, as a Redis-backed session store already read
	 * it back: a `Date` as its ISO string, an object with `toJSON` as what it
	 * answers, NaN or Infinity as `null`, and one whose JSON form is nothing
	 * (`undefined`, a function, a symbol) left out. One whose JSON form
	 * cannot be taken — a bigint, a cycle, a `toJSON` or a getter that
	 * throws — is dropped, and the login goes on; `admitPrimary` logs
	 * `login_claim_dropped` (warn) with its key, never its value.
	 */
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
	// A custom claim the builder dropped is said here, where the logger is.
	warnDroppedClaims(deps.logger, primary.claims);
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
	// A custom claim the continuation's check dropped — one a store answered
	// that JSON cannot hold — is said once the resumption is admissible.
	warnDroppedClaims(deps.logger, read.primary.claims);
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
	/**
	 * The merged claims envelope the callback composed: what the session
	 * record's `claims` will hold. Read as {@link PasswordLoginFacts.claims}
	 * is: declared claims of their declared types, `null` refused; custom
	 * claims stored as their JSON form, one that cannot be taken dropped —
	 * said as `login_claim_dropped` only when `establishWithoutAsking` is
	 * handed a logger.
	 */
	readonly claims: UserSessionClaims;
	/** The federation's name (`core.federations.<name>`). */
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
 *
 * `options.logger`, when given, is told of each custom claim the envelope
 * dropped (`login_claim_dropped`); without one, a dropped claim is silent.
 */
export function establishWithoutAsking(
	login: FederatedLogin,
	options: { readonly logger?: Logger } = {},
): Establishment {
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
	warnDroppedClaims(options.logger, primary.claims);
	return establish(primary);
}
