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

import {
	classifyFederationRefreshError,
	isKnownFederationRefreshErrorCode,
} from "../federation-tokens/refresh-error.mjs";
import { isFederationUpstreamOutage } from "../federation-tokens/upstreamOutage.mjs";
import { instantOf, judgeHeldUpstreamToken } from "../federations/token-lifetime.mjs";
import type { DelegatedTokens } from "../federations/types.mjs";
import { federationGrantAuditMetadata } from "./auditMetadata.mjs";
import { carryingFailure } from "./carry.mjs";
import { effectiveFederationGrantStatus } from "./effective-status.mjs";
import {
	federationGrantIneligibilityRetry,
	federationGrantRefreshFailureStamp,
	federationGrantRefreshFailureStands,
	isFederationGrantInteractionCode,
	isUsableMaxUpstreamAccessTokenLifetime,
	judgeUpstreamAccessToken,
	scopesWithin,
} from "./eligibility.mjs";
import {
	federationGrantHeldToken,
	federationGrantKeptAccessToken,
	type StoredAccessToken,
	type WrittenAccessToken,
} from "./held-token.mjs";
import { federationGrantEffectiveExpiry } from "./lifetime.mjs";
import type { FederationGrantStore } from "./store.mjs";
import {
	type AuthorizedFederationGrant,
	type FederationGrant,
	type FederationGrantConnection,
	type FederationGrantCredentials,
	type FederationGrantCredentialsInput,
	type FederationGrantDenial,
	type FederationGrantIneligibilityMarker,
	type FederationGrantRefreshFailureInput,
	type FederationGrantRetrievalFailure,
	type FederationGrantTokenResult,
	type FederationGrantUnavailableReason,
	hasFederationGrantAuthorization,
} from "./types.mjs";
import { readFederationGrantUpstreamAnswer } from "./upstream-answer.mjs";

export type { FederationGrantRetrievalFailure } from "./types.mjs";

export interface FederationGrantRefresher {
	refreshDelegatedToken(params: {
		readonly refreshToken: string;
		readonly scopes?: readonly string[];
		readonly resource?: string;
		readonly signal?: AbortSignal;
	}): Promise<DelegatedTokens>;
}

/** Token-free, always: no event carries an access token, a refresh token, or any other secret. */
export interface FederationGrantAuditEvent {
	readonly type:
		| "federation.grant.token.success"
		| "federation.grant.token.denied"
		| "federation.grant.refreshed"
		| "federation.grant.refresh_failed"
		| "federation.grant.refresh_persist_failed"
		| "federation.grant.reauthorization_required"
		| "federation.grant.revoked"
		/**
		 * A withdrawal that did not happen. Its own type, not a `.token.denied`:
		 * a refused withdrawal leaves a credential live, the opposite of a
		 * refused disclosure, and dashboards must not count them together.
		 */
		| "federation.grant.revoke.denied"
		/** A client lodged an intent — a first grant, or a renewal. */
		| "federation.grant.requested"
		/**
		 * A lodging that did not happen. Its own type, for the reason
		 * `.revoke.denied` is: a refused request to CREATE access is not a
		 * refused disclosure of access that exists.
		 */
		| "federation.grant.request.denied"
		/**
		 * A connect flow that ended without a grant — the user declined, the
		 * session was not the right one, the flow went stale. Only facts
		 * established by then are carried: an early failure may have no grant
		 * id to name.
		 */
		| "federation.grant.authorization_failed"
		/** A connect flow created a grant. */
		| "federation.grant.authorized"
		/** A renewal replaced a grant's authorization in place. */
		| "federation.grant.reauthorized";
	readonly correlationId: string;
	readonly grantId: string;
	/** The caller. */
	readonly clientId: string;
	/** The owner the caller asserted; for a grant that is the caller's, the grant's. */
	readonly subject: string;
	/** Absent for a grant that is unknown to the caller, and for one never authorized. */
	readonly upstream?: { readonly issuer: string; readonly subject: string };
	readonly connection?: string;
	readonly resource?: string;
	readonly scopes?: readonly string[];
	/** `success`, a denial's `code` or `code/reason`, or what a refresh ended with. */
	readonly outcome: string;
}

export interface FederationGrantRetrievalLimits {
	/** `federation-grants.maxExpiresIn`, as it is configured now. */
	readonly maxExpiresInMs: number;
	/**
	 * How far replicas' clocks may differ. It is the backstop's allowance,
	 * and how far ahead of `now` a stored token may be dated and still be
	 * believed.
	 */
	readonly revocationSkewMs: number;
	/**
	 * A stored token with no more life left than this is refreshed (30 s) —
	 * unless it is not yet half spent, which a token issued with less than twice
	 * this may be, or the grant's marker says the upstream is not to be asked
	 * yet: then it is answered with the life it has.
	 */
	readonly refreshBufferMs: number;
	readonly ineligibleRetryAfterMs: number;
	/**
	 * How long the upstream is not asked again after it failed twice in a row
	 * (30 s), and the least a rate limit is honoured for. The first
	 * failure of a row is retried promptly. `ineligibleRetryAfterMs` is the
	 * ceiling, and what a refusal with a code this provider knows waits.
	 */
	readonly refreshFailureBackoffMs: number;
	/** The SOFT deadline: how long a caller waits for the upstream. */
	readonly upstreamTimeoutMs: number;
	/** The HARD deadline: where the upstream request is aborted. */
	readonly upstreamHardTimeoutMs: number;
	readonly refreshLockTtlMs: number;
	/**
	 * How long a call waits for another replica's refresh before it looks again
	 * and answers. Nothing relates it to `refreshLockTtlMs`: after an outcome
	 * that is unknown the lock is left to run out, and until it has, every call
	 * that needs a refresh answers `lock_timeout` after waiting this long.
	 */
	readonly lockWaitMs: number;
	readonly persistRetryBudgetMs: number;
}

/**
 * What a refresh that keeps to its deadlines must still leave of its lock. The
 * lease is counted from when the lock was asked for plus what the store says
 * it waited — a lower bound on when the TTL began, since the store took the
 * lock some time after the caller asked — and timers fire late. Without a
 * margin, a configuration that fits by a millisecond does not fit.
 */
export const FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS = 1_000;

export interface RetrieveFederationGrantTokenDeps {
	readonly store: FederationGrantStore;
	/** The connection as it is configured now; `undefined` when the operator removed it. */
	connection(name: string): FederationGrantConnection | undefined;
	refresher(connection: FederationGrantConnection): FederationGrantRefresher | undefined;
	/**
	 * The subject's grants boundary. A failure fails closed: 503. Neither
	 * this read nor the store's `open` is bounded by the retrieval: a reader
	 * that can hang carries its own timeout. What the retrieval bounds is the
	 * wait for the refresh lock, and everything that holds it.
	 */
	grantsBoundary(subject: string): Promise<Date | null>;
	/** Sampled at every write and before every disclosure, never once per request. */
	now(): Date;
	readonly limits: FederationGrantRetrievalLimits;
	/**
	 * The one seam for work that may outlive a call's answer, so that a shutdown
	 * can drain it and a test can await it; nothing is detached any other way.
	 * That is the tail of every refresh — letting go of the lock, then telling
	 * the audit sink — and, when the caller stopped waiting at the soft
	 * deadline, the refresh itself, which goes on holding the lock until its
	 * result is persisted; and the record of a use and the audit of an
	 * answer, neither of which an answer waits for. The promise never rejects.
	 */
	background(work: Promise<void>): void;
	/**
	 * A sink that throws, rejects or never answers skips no write, holds no
	 * lock and delays no answer: it is told after the lock is let go of, and
	 * nothing waits for it.
	 */
	audit?(event: FederationGrantAuditEvent): void | Promise<void>;
	/**
	 * Told the cause whenever a failure becomes a typed answer or is dropped,
	 * so an operator can see what a 503 hides. The error may echo upstream
	 * content: it is for a projecting logger (`loggableError`), never for a
	 * response. A 503 carries the same object as its `failure`. Retried
	 * writes are told once per distinct kind (name and code) with the last
	 * error and `attempts`; a call that did not answer in time is told too.
	 */
	report?(failure: FederationGrantRetrievalFailure): void;
}

export interface RetrieveFederationGrantTokenRequest {
	readonly grantId: string;
	/** The authenticated client. */
	readonly clientId: string;
	/** `sub`, required on every grant-addressed route. */
	readonly subject: string;
	/** The client's `allowedFederationGrantConnections`. */
	readonly allowedConnections: readonly string[];
	readonly correlationId: string;
	// Assertions the provider checks. None of them widens anything.
	readonly connection?: string;
	readonly scope?: readonly string[];
	readonly resource?: string;
	readonly minTtlSeconds?: number;
}

/** `setTimeout` takes a signed 32-bit number of milliseconds; beyond it, it fires at once. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * Refuses limits the retrieval cannot keep its promises under. Call at boot:
 * a hand-built config bypasses the schema.
 *
 * - Every limit is finite and non-negative; those given to a timer or a lock
 *   are positive and fit a timer. (NaN would silently disable early refresh
 *   and the marker's limit.)
 * - `refreshFailureBackoffMs <= ineligibleRetryAfterMs`: the marker's
 *   interval is the ceiling on how long a failing upstream is not asked.
 * - `upstreamTimeoutMs <= upstreamHardTimeoutMs`: the soft deadline answers
 *   the caller; the hard one aborts the request.
 * - `upstreamHardTimeoutMs + persistRetryBudgetMs + margin <= refreshLockTtlMs`:
 *   the lock has no renewal, and one that expires mid-refresh lets two
 *   replicas present the same refresh token.
 *
 * Only configured durations are compared; every deadline counts from lock
 * acquisition (see `refresh`).
 */
export function assertFederationGrantRetrievalLimits(limits: FederationGrantRetrievalLimits): void {
	const timed = [
		"upstreamTimeoutMs",
		"upstreamHardTimeoutMs",
		"refreshLockTtlMs",
		"persistRetryBudgetMs",
		"ineligibleRetryAfterMs",
		"maxExpiresInMs",
	] as const;
	const allowances = [
		"revocationSkewMs",
		"refreshBufferMs",
		"lockWaitMs",
		"refreshFailureBackoffMs",
	] as const;
	for (const name of timed) {
		const value = limits[name];
		if (!Number.isFinite(value) || value <= 0) {
			throw new RangeError(`federation-grants: ${name} must be a positive finite number`);
		}
	}
	for (const name of allowances) {
		const value = limits[name];
		if (!Number.isFinite(value) || value < 0) {
			throw new RangeError(`federation-grants: ${name} must be a non-negative finite number`);
		}
	}
	for (const name of [
		"upstreamTimeoutMs",
		"upstreamHardTimeoutMs",
		"refreshLockTtlMs",
		"persistRetryBudgetMs",
		"lockWaitMs",
	] as const) {
		if (limits[name] > MAX_TIMER_MS) {
			throw new RangeError(`federation-grants: ${name} does not fit a timer`);
		}
	}
	// The store is given `SIDE_EFFECT_WAIT_MS` over the lock wait (`refresh`).
	if (limits.lockWaitMs + SIDE_EFFECT_WAIT_MS > MAX_TIMER_MS) {
		throw new RangeError("federation-grants: lockWaitMs does not fit a timer");
	}
	if (!(limits.refreshFailureBackoffMs <= limits.ineligibleRetryAfterMs)) {
		throw new RangeError(
			"federation-grants: refreshFailureBackoffMs must not exceed ineligibleRetryAfterMs — the marker's interval is the ceiling on how long a failing upstream is not asked",
		);
	}
	if (!(limits.upstreamTimeoutMs <= limits.upstreamHardTimeoutMs)) {
		throw new RangeError(
			"federation-grants: upstreamTimeoutMs must not exceed upstreamHardTimeoutMs — the soft deadline only answers the caller, and the hard one is where the request is aborted",
		);
	}
	if (
		!(
			limits.upstreamHardTimeoutMs +
				limits.persistRetryBudgetMs +
				FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS <=
			limits.refreshLockTtlMs
		)
	) {
		throw new RangeError(
			"federation-grants: upstreamHardTimeoutMs + persistRetryBudgetMs must leave a second of refreshLockTtlMs — the refresh lock has no renewal, and one that expires mid-refresh lets two replicas present the same refresh token",
		);
	}
}

// ---------------------------------------------------------------------------
// Small things everything below leans on
// ---------------------------------------------------------------------------

type Settled<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly error: unknown };

/**
 * A dependency's answer as a value, whichever way it failed. `start` runs
 * inside the chain, so one that THROWS where it should have rejected is caught
 * like any other: a composer's bug must not leave a lock behind, nor turn a
 * typed answer into an exception.
 */
function settle<T>(start: () => T | Promise<T>): Promise<Settled<T>> {
	return Promise.resolve()
		.then(start)
		.then(
			(value) => ({ ok: true as const, value }),
			(error: unknown) => ({ ok: false as const, error }),
		);
}

interface Cancellable {
	readonly elapsed: Promise<"elapsed">;
	cancel(): void;
}

function after(ms: number): Cancellable {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const elapsed = new Promise<"elapsed">((resolve) => {
		timer = setTimeout(() => resolve("elapsed"), Math.max(0, ms));
	});
	return { elapsed, cancel: () => clearTimeout(timer) };
}

/**
 * How long a sink, a `touch` or the release of a lock is waited for by the
 * work that was handed over. Nothing a caller is answered with waits for any
 * of them; this only keeps what was handed to `background` from never
 * settling, which a registry would hold for ever and a shutdown never drain.
 */
const SIDE_EFFECT_WAIT_MS = 3_000;

const NOT_ANSWERED = new Error("not answered in time; no longer waited for");

/**
 * What kind of failure `error` is, to tell one from another: its name and its
 * code, read so that nothing throws. Two attempts that failed the same way
 * are one kind, whatever their messages say.
 */
function kindOf(error: unknown): string {
	if (error === null || (typeof error !== "object" && typeof error !== "function")) {
		return `thrown:${typeof error}`;
	}
	const read = (key: string): unknown => {
		try {
			return (error as Record<string, unknown>)[key];
		} catch {
			return undefined;
		}
	};
	const name = read("name");
	const code = read("code");
	return `${typeof name === "string" ? name : ""}\u0000${
		typeof code === "string" || typeof code === "number" ? String(code) : ""
	}`;
}

/** `work`, or `"elapsed"` when it has not settled within `ms`. No timer is left behind. */
async function within<T>(work: Promise<T>, ms: number): Promise<T | "elapsed"> {
	const limit = after(ms);
	try {
		return await Promise.race([work, limit.elapsed]);
	} finally {
		limit.cancel();
	}
}

/**
 * Tells the composer's logger what was swallowed, and answers with what it
 * told it: a 503 turned from this failure carries the same object. A reporter
 * that throws is not worth an answer.
 */
function report(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	during: FederationGrantRetrievalFailure["during"],
	error: unknown,
	attempts = 1,
): FederationGrantRetrievalFailure {
	const failure: FederationGrantRetrievalFailure = {
		during,
		error,
		grantId: request.grantId,
		correlationId: request.correlationId,
		...(attempts > 1 ? { attempts } : {}),
	};
	try {
		deps.report?.(failure);
	} catch {
		// See above.
	}
	return failure;
}

/**
 * Hands `work`, which never rejects, to the composer's registry. Nothing a
 * caller is waiting for goes through here: only what may outlive its answer.
 * A registry that throws loses the ability to drain the work, and nothing
 * else — whatever the work owns, it still does.
 */
function handOver(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	work: Promise<unknown>,
): void {
	try {
		deps.background(work.then(() => undefined));
	} catch (error) {
		report(deps, request, "background", error);
	}
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/**
 * What a look is told about the call it is made for. Every look judges the
 * grant the same way; they differ in what becomes of a stored token that
 * would be refreshed.
 *
 * - Default (the first look, and again under the lock): sends the call to
 *   the refresh.
 * - `attempted` — the last look, after a refresh was tried, whatever came of
 *   it. A good stored token carrying what was asked is answered with the
 *   life it has: a refresh improves on it, never conditions it, and runs at
 *   most once per call. The look's own verdicts (an expiry or revocation
 *   meanwhile) come first; what would have been a refresh answers with what
 *   the attempt came to.
 * - `fetched` — with `attempted`, the token this call wrote. While it is
 *   stored it is never refreshed again, and lacking the asserted scope it
 *   answers `invalid_scope`. Anything else stored by then is somebody else's
 *   (a reauthorization does not take the refresh lock).
 */
interface Look {
	readonly attempted?: true;
	/** With `attempted`: the access token this call wrote. */
	readonly fetched?: string;
}

type Evaluation =
	| {
			readonly kind: "deny";
			readonly denial: FederationGrantDenial;
			readonly grant?: FederationGrant;
	  }
	| {
			readonly kind: "token";
			readonly grant: AuthorizedFederationGrant;
			readonly token: StoredAccessToken;
			readonly expiresIn: number;
	  }
	| {
			readonly kind: "refresh";
			readonly grant: AuthorizedFederationGrant;
			/** What every write of the refresh is guarded by, read before the upstream is asked. */
			readonly guard: WriteGuard;
			readonly connection: FederationGrantConnection;
			readonly refreshToken: string;
			/**
			 * The stored access token, when it is one that could still be disclosed:
			 * eligible under the current maximum, alive, and dated believably. A
			 * refresh that brings nothing usable keeps it.
			 */
			readonly keep?: WrittenAccessToken;
			/** The access token that is stored, whether or not it could be disclosed. */
			readonly stored?: string;
	  };

/** `value`, carrying the failure it was turned from where nothing enumerates it (`carry.mts`). */
const carrying = <T extends object>(
	value: T,
	failure: FederationGrantRetrievalFailure | undefined,
): T => carryingFailure(value, failure);

/** The failure a denial was turned from, when it is a 503 that carries one. */
const failureOf = (denial: FederationGrantDenial): FederationGrantRetrievalFailure | undefined =>
	denial.code === "temporarily_unavailable" ? denial.failure : undefined;

const unavailable = (
	reason: FederationGrantUnavailableReason,
	failure?: FederationGrantRetrievalFailure,
): FederationGrantDenial => carrying({ code: "temporarily_unavailable", reason }, failure);

/** How far ahead of `now` a stored date is believed: what the refresh buffer absorbs, or replicas' clocks may differ by. */
const dateAllowanceMs = (limits: FederationGrantRetrievalLimits): number =>
	Math.max(limits.refreshBufferMs, limits.revocationSkewMs);

/** RFC 6749 §4.1.2.1's names for an outage: not refusals, whatever status they came with. */
const UPSTREAM_OUTAGE_CODES: ReadonlySet<string> = new Set([
	"server_error",
	"temporarily_unavailable",
]);

/**
 * What `count` the store will give a failure at `at`: one more than a stamp no
 * older than `rowMs`, else one — and `undefined` for one dated before the
 * stamp on the record, which the store refuses: a caller must not be
 * told a wait the record will not carry. A stamp whose date holds no instant
 * starts no row.
 */
const rowCount = (
	grant: AuthorizedFederationGrant,
	at: Date,
	rowMs: number,
): number | undefined => {
	const previous = grant.refreshFailure;
	if (previous === undefined) return 1;
	const sinceMs = at.getTime() - (instantOf(previous.at) ?? Number.NaN);
	if (sinceMs < 0) return undefined;
	return sinceMs <= rowMs ? previous.count + 1 : 1;
};

/** The grant's id and version, as a guarded write names them. */
interface WriteGuard {
	readonly grantId: string;
	readonly expectedVersion: number;
}

/**
 * The guard for the writes of a refresh of `grant`, read once. Throws when
 * the store's answer cannot guard one: an id other than the one the lock is
 * taken for, or a version that is not a safe integer, which no store's guard
 * matches. No refresh starts then: its rotated refresh token would be lost.
 */
function writeGuard(grant: AuthorizedFederationGrant, grantId: string): WriteGuard {
	const id: unknown = grant.id;
	const version: unknown = grant.version;
	if (id !== grantId) throw new TypeError("the store answered a grant under another id");
	if (typeof version !== "number" || !Number.isSafeInteger(version)) {
		throw new TypeError("the store answered a grant version that is not a safe integer");
	}
	return { grantId, expectedVersion: version };
}

const NOT_PERMITTED: FederationGrantDenial = {
	code: "access_denied",
	reason: "connection_not_permitted",
};

async function evaluate(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	look: Look = {},
): Promise<Evaluation> {
	// The boundary first and the record last, so that the record — the thing a
	// revocation changes — is the freshest thing evaluated. A boundary that
	// cannot be read is held, not thrown: it must not turn "not yours" or a
	// stored revocation into a 503.
	//
	// Neither read is bounded here. A store or a boundary reader that can hang
	// carries its own timeout; what this function bounds is what holds the lock.
	const boundary = await settle(() => deps.grantsBoundary(request.subject));
	const boundaryFailure = boundary.ok
		? undefined
		: report(deps, request, "boundary", boundary.error);
	const read = await settle(() => deps.store.open(request.grantId, deps.now()));
	if (!read.ok) {
		return {
			kind: "deny",
			denial: unavailable("storage", report(deps, request, "open", read.error)),
		};
	}
	const opened = read.value;
	// After the awaited reads, not before them.
	const now = deps.now();

	// One answer for an unknown ID, another client's grant and another
	// subject's, so that a known ID tells a stranger nothing.
	if (
		opened === null ||
		opened.grant.clientId !== request.clientId ||
		opened.grant.subject !== request.subject
	) {
		return { kind: "deny", denial: { code: "grant_not_found" } };
	}
	const grant = opened.grant;

	// What is stored as over is reported before anything that could be an outage.
	if (grant.status === "revoked") {
		return { kind: "deny", denial: { code: "grant_revoked", reason: grant.revocation.by }, grant };
	}
	if (grant.status === "pending") {
		return { kind: "deny", denial: { code: "authorization_pending" }, grant };
	}
	if (!boundary.ok) return { kind: "deny", denial: unavailable("storage", boundaryFailure), grant };

	const connection = deps.connection(grant.connection);
	let status: ReturnType<typeof effectiveFederationGrantStatus>;
	try {
		status = effectiveFederationGrantStatus(grant, {
			now,
			connection,
			maxExpiresInMs: deps.limits.maxExpiresInMs,
			grantsBoundary: boundary.value,
			revocationSkewMs: deps.limits.revocationSkewMs,
			credentials: opened.credentials.state === "ok" ? "ok" : "unreadable",
		});
	} catch (error) {
		// A boundary or an allowance that cannot be compared: answered neither
		// way. Anything else that is thrown here is a bug, and is not dressed up
		// as an outage.
		if (!(error instanceof RangeError)) throw error;
		return {
			kind: "deny",
			denial: unavailable("storage", report(deps, request, "status", error)),
			grant,
		};
	}

	if (status.status === "revoked") {
		// The backstop: a subject-wide revocation that never reached this record.
		// Made durable on the first touch. A write that FAILS is a revocation
		// outage and surfaces as one; one that changes nothing means somebody
		// else got there, and the answer stands.
		const revoked = await settle(() => deps.store.revoke(grant.id, "backstop", now));
		if (!revoked.ok) {
			return {
				kind: "deny",
				denial: unavailable("storage", report(deps, request, "backstop_revoke", revoked.error)),
				grant,
			};
		}
		if (revoked.value.ok) {
			// Not awaited: this look may be the one under the lock.
			handOver(deps, request, audit(deps, request, "federation.grant.revoked", "backstop", grant));
		}
		return { kind: "deny", denial: { code: "grant_revoked", reason: status.reason }, grant };
	}
	if (status.status === "expired") {
		return { kind: "deny", denial: { code: "grant_expired", reason: status.reason }, grant };
	}
	if (status.status === "pending") {
		return { kind: "deny", denial: { code: "authorization_pending" }, grant };
	}
	// Configuration remedies come after every terminal fact: a client must not
	// be sent to its operator about a grant that is over.
	if (
		status.status === "connection_not_configured" ||
		connection === undefined ||
		!request.allowedConnections.includes(grant.connection)
	) {
		return { kind: "deny", denial: NOT_PERMITTED, grant };
	}
	if (status.status === "connection_identity_changed") {
		return { kind: "deny", denial: { code: "connection_identity_changed" }, grant };
	}
	if (status.status === "reauthorization_required") {
		// A key that is missing from the ring is an outage, and not a status:
		// the credential may be perfectly good. It is answered here, where
		// the credential is first needed, and not earlier — everything reported
		// ahead of it is decided without one, and an outage must mask none of it.
		if (
			status.reason === "credential_unreadable" &&
			opened.credentials.state === "key_unavailable"
		) {
			return { kind: "deny", denial: unavailable("key_unavailable"), grant };
		}
		return {
			kind: "deny",
			denial: { code: "reauthorization_required", reason: status.reason },
			grant,
		};
	}
	// What is answered where the upstream may not be asked: `undefined` when it
	// may be.
	let notAsked: FederationGrantDenial | undefined;
	if (status.status === "upstream_token_ineligible") {
		// For the status route this is where it ends. Here the marker only limits
		// how often the upstream is asked. It does not withhold a stored token
		// that is good — the last refresh brought nothing usable, and that token
		// was kept — and once its interval has passed the grant is refreshed
		// again, or no starved grant would ever recover.
		const usable = isUsableMaxUpstreamAccessTokenLifetime(connection.maxAccessTokenLifetime);
		const retry = federationGrantIneligibilityRetry(grant.ineligible, {
			now,
			retryAfterMs: deps.limits.ineligibleRetryAfterMs,
			allowanceMs: dateAllowanceMs(deps.limits),
		});
		const denial: FederationGrantDenial = {
			code: "upstream_token_ineligible",
			reason: status.reason,
			...(usable && !retry.due ? { retryAfterSeconds: retry.retryAfterSeconds } : {}),
		};
		// Under a maximum no token can satisfy nothing is disclosed, and nothing
		// below can be judged: `min_ttl` is held against that maximum.
		if (!usable) return { kind: "deny", denial, grant };
		if (!retry.due) notAsked = denial;
	} else if (status.status !== "active") {
		// Unreachable today, and refused by the compiler the day a status is
		// added and not handled above: nothing unknown falls through to a token.
		const unhandled: never = status;
		void unhandled;
		return { kind: "deny", denial: unavailable("storage"), grant };
	}
	// The stamp of a failed refresh: while it stands the upstream is not
	// asked either. The marker's denial comes first: an ineligible answer is the
	// more specific fault.
	const failure = federationGrantRefreshFailureStands(grant.refreshFailure, {
		now,
		allowanceMs: dateAllowanceMs(deps.limits),
		backoffMs: deps.limits.refreshFailureBackoffMs,
		ceilingMs: deps.limits.ineligibleRetryAfterMs,
	});
	if (notAsked === undefined && failure.stands) {
		const { retryAfterSeconds } = failure;
		notAsked =
			failure.kind === "rate_limited"
				? { code: "rate_limited", reason: "upstream", retryAfterSeconds }
				: failure.kind === "rejected"
					? {
							code: "upstream_rejected",
							// Asked again on the way out: the allow-list was applied
							// when the stamp was written, and this reads one back.
							reason: isKnownFederationRefreshErrorCode(grant.refreshFailure?.upstreamCode)
								? grant.refreshFailure.upstreamCode
								: "unknown",
							retryAfterSeconds,
						}
					: { code: "temporarily_unavailable", reason: "upstream", retryAfterSeconds };
	}

	// What the request asserts is checked here, so that a request that can
	// never succeed does not cost an upstream call.
	if (request.connection !== undefined && request.connection !== grant.connection) {
		return {
			kind: "deny",
			denial: { code: "invalid_request", reason: "connection_mismatch" },
			grant,
		};
	}
	if (request.resource !== undefined && request.resource !== grant.resource) {
		return { kind: "deny", denial: { code: "invalid_target" }, grant };
	}
	if (request.scope !== undefined && !scopesWithin(request.scope, grant.consent.scopes)) {
		return { kind: "deny", denial: { code: "invalid_scope" }, grant };
	}
	const minTtlSeconds = request.minTtlSeconds ?? 0;
	if (
		typeof minTtlSeconds !== "number" ||
		!Number.isFinite(minTtlSeconds) ||
		minTtlSeconds < 0 ||
		!(minTtlSeconds <= connection.maxAccessTokenLifetime)
	) {
		return {
			kind: "deny",
			denial: { code: "invalid_request", reason: "min_ttl_out_of_range" },
			grant,
		};
	}

	if (opened.credentials.state !== "ok") {
		// Unreachable while the status rules hold: an `active` grant whose
		// credential does not open reads as `credential_unreadable` above.
		return {
			kind: "deny",
			denial: { code: "reauthorization_required", reason: "credential_unreadable" },
			grant,
		};
	}
	const credentials = opened.credentials.value;
	// Read once, here: what is judged is what a refresh keeps, and nothing of a
	// store's answer is read again once the upstream has been asked.
	const stored = credentials.accessToken;
	const token = stored === undefined ? undefined : federationGrantKeptAccessToken(stored);
	let keep: WrittenAccessToken | undefined;
	if (token !== undefined) {
		// The same predicate guards every disclosure, cached or fresh, against
		// the CURRENT maximum.
		const eligible = judgeUpstreamAccessToken({
			issuedLifetime: token.issuedLifetime,
			scopes: token.scopes,
			consentedScopes: grant.consent.scopes,
			maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
			tokenType: token.tokenType,
		}).eligible;
		// A token dated further ahead than the refresh buffer absorbs, or than
		// replicas' clocks may differ where the buffer is set to less, is not
		// believed; none has more left than its own life (`expiresAt − obtainedAt`).
		const { believed, remainingMs, halfSpent } = judgeHeldUpstreamToken(
			federationGrantHeldToken(token),
			{ now: now.getTime(), allowanceMs: dateAllowanceMs(deps.limits) },
		);
		const tokenEndsAt = now.getTime() + remainingMs;
		if (eligible && believed && remainingMs > 0) {
			keep = token;
			// Against the scopes THIS token carries, not what the grant once got.
			const carries = request.scope === undefined || scopesWithin(request.scope, token.scopes);
			// Never refreshed before it is half spent: an earlier refresh gains
			// little and rotates the refresh token at a rotating IdP. Without this
			// bound a client could force a rotation on every request (a `min_ttl`
			// near the lifetime, a scope the upstream never grants, a lifetime
			// below the buffer), a path the ineligibility marker does not cover.
			// With it, at most two rotations per token lifetime while the
			// upstream answers. A FAILING upstream is bounded by the stamp.
			const ranDown = remainingMs <= deps.limits.refreshBufferMs;
			const wantsMore = !carries || remainingMs <= minTtlSeconds * 1000;
			// The call's own token, at the last look: what the upstream just gave is
			// not refreshed again, and one that lacks the asserted scope answers
			// `invalid_scope`, half spent or not — the upstream was asked.
			const own = look.fetched !== undefined && token.value === look.fetched;
			const refreshIt = !own && halfSpent && (ranDown || wantsMore);
			if (carries && (!refreshIt || notAsked !== undefined || look.attempted === true)) {
				const grantEndsAt = federationGrantEffectiveExpiry(grant, deps.limits.maxExpiresInMs);
				return {
					kind: "token",
					grant,
					token,
					// A cache hint for a cooperating worker, never enforcement.
					expiresIn: Math.floor(
						Math.max(0, Math.min(tokenEndsAt, grantEndsAt.getTime()) - now.getTime()) / 1000,
					),
				};
			}
			if (!carries && !refreshIt) {
				// A token that is good, does not carry what was asked for, and is not
				// one to ask the upstream again about yet. That is not
				// `scope_exceeded`: nothing exceeded the consent.
				return { kind: "deny", denial: { code: "invalid_scope" }, grant };
			}
		}
	}
	if (notAsked !== undefined) return { kind: "deny", denial: notAsked, grant };
	let guard: WriteGuard;
	try {
		guard = writeGuard(grant, request.grantId);
	} catch (error) {
		return {
			kind: "deny",
			denial: unavailable("storage", report(deps, request, "open", error)),
			grant,
		};
	}
	return {
		kind: "refresh",
		grant,
		guard,
		connection,
		refreshToken: credentials.refreshToken,
		...(keep !== undefined ? { keep } : {}),
		...(token !== undefined ? { stored: token.value } : {}),
	};
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** Never rejects: a sink that fails must not skip a write or a release, nor turn an answer into an error. */
async function audit(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	type: FederationGrantAuditEvent["type"],
	outcome: string,
	grant?: FederationGrant,
): Promise<void> {
	const sink = deps.audit;
	if (sink === undefined) return;
	// A grant that was never authorized has no upstream account and no scopes.
	const told = await within(
		settle(() =>
			sink({
				type,
				correlationId: request.correlationId,
				grantId: request.grantId,
				clientId: request.clientId,
				subject: request.subject,
				// Through the shared helper, so this emitter and the two
				// revocation ones cannot disagree about what a pending grant
				// carries or about copying the record's own fields. An unknown
				// grant carries none of it: there is nothing established, and a
				// read would answer the question the identical 404 refuses.
				...(grant === undefined ? {} : federationGrantAuditMetadata(grant)),
				outcome,
			}),
		),
		SIDE_EFFECT_WAIT_MS,
	);
	if (told === "elapsed") report(deps, request, "audit", NOT_ANSWERED);
	else if (!told.ok) report(deps, request, "audit", told.error);
}

const outcomeOf = (denial: FederationGrantDenial): string =>
	"reason" in denial && denial.reason !== undefined
		? `${denial.code}/${denial.reason}`
		: denial.code;

/**
 * The answer. Neither the record of the use nor the audit is waited for: a
 * store or a sink that hangs must not hang an answer that is already decided.
 */
function conclude(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	evaluation: Evaluation,
	refreshed: boolean,
	otherwise: FederationGrantDenial,
): FederationGrantTokenResult {
	if (evaluation.kind === "token") {
		// Best effort: a use that could not be recorded is still a use.
		handOver(
			deps,
			request,
			within(
				settle(() => deps.store.touch(evaluation.grant.id, deps.now())),
				SIDE_EFFECT_WAIT_MS,
			).then((touched) => {
				if (touched === "elapsed") report(deps, request, "touch", NOT_ANSWERED);
				else if (!touched.ok) report(deps, request, "touch", touched.error);
			}),
		);
		handOver(
			deps,
			request,
			audit(deps, request, "federation.grant.token.success", "success", evaluation.grant),
		);
		return {
			ok: true,
			accessToken: evaluation.token.value,
			tokenType: evaluation.token.tokenType,
			expiresIn: evaluation.expiresIn,
			scopes: [...evaluation.token.scopes],
			refreshed,
		};
	}
	// A look that would refresh, where no refresh is to be had, is answered as
	// the outage that brought the call there.
	const denial = evaluation.kind === "deny" ? evaluation.denial : otherwise;
	handOver(
		deps,
		request,
		audit(deps, request, "federation.grant.token.denied", outcomeOf(denial), evaluation.grant),
	);
	// The spread leaves the failure behind: it is carried on again, as it was.
	return carrying<FederationGrantTokenResult>({ ok: false, ...denial }, failureOf(denial));
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

type PendingAudit = readonly [type: FederationGrantAuditEvent["type"], outcome: string];

/**
 * What the one worker that owns a refresh ended with, and what it has to say
 * to the audit sink — said once the lock is let go of, never while it is
 * held. It never rejects.
 */
type RefreshOutcome =
	/** `fetched`: the access token that came with it. Without one, what is stored is what the grant had. */
	(
		| { readonly kind: "written"; readonly fetched?: string }
		/** A guarded write lost. Never the fetched token: the last look answers with what is there. */
		| { readonly kind: "lost" }
		| { readonly kind: "denied"; readonly denial: FederationGrantDenial }
	) & {
		readonly audits: readonly PendingAudit[];
		/**
		 * Something of this call's is still IN FLIGHT (an aborted upstream
		 * request may still rotate the refresh token; a write past its budget may
		 * still land), so the lock is left to run out rather than released: the
		 * next holder would present the old refresh token, and a reuse-detecting
		 * IdP revokes the whole family. A failure that arrived leaves nothing in
		 * flight.
		 */
		readonly keepLock?: true;
	};

const PERSIST_RETRY_DELAY_MS = 100;

/** A marker's date, `undefined` for none, and NaN, equal to nothing, for a date that holds no instant. */
const markerInstant = (
	marker: FederationGrantIneligibilityMarker | undefined,
): number | undefined => (marker === undefined ? undefined : (instantOf(marker.at) ?? Number.NaN));

/**
 * Tells the logger, once per call and by the field's name alone, of a stored
 * marker or failed-refresh stamp whose date holds no instant. Each reads as a
 * retry that is due, so a store that answers them so would have every request
 * ask the upstream with nothing else to say why.
 */
function reportUndatedStamps(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	grant: FederationGrant | undefined,
): void {
	if (grant === undefined || !hasFederationGrantAuthorization(grant)) return;
	const stamps = [
		["ineligible.at", grant.ineligible],
		["refreshFailure.at", grant.refreshFailure],
	] as const;
	for (const [field, stamp] of stamps) {
		if (stamp !== undefined && instantOf(stamp.at) === undefined) {
			report(deps, request, "open", new TypeError(`the stored ${field} holds no instant`));
		}
	}
}

/**
 * Whether the record holds what this call tried to store: the credentials,
 * and the marker beside them. Two replicas can come to store the very same
 * credentials — an IdP that does not rotate, an answer that brought no access
 * token — and the marker, which is dated, is what tells theirs from this
 * call's. Waited for no longer than `budgetMs`: the lock is sized for ONE
 * persist budget after the hard deadline, and this look is spent of the same
 * one.
 */
async function isStored(
	deps: RetrieveFederationGrantTokenDeps,
	grantId: string,
	credentials: FederationGrantCredentials,
	ineligible: FederationGrantIneligibilityMarker | null,
	budgetMs: number,
): Promise<boolean> {
	const read = await within(
		settle(() => deps.store.open(grantId, deps.now())),
		budgetMs,
	);
	if (read === "elapsed" || !read.ok || read.value === null) return false;
	const { grant: current, credentials: held } = read.value;
	const marker = hasFederationGrantAuthorization(current) ? current.ineligible : undefined;
	return (
		held.state === "ok" &&
		held.value.refreshToken === credentials.refreshToken &&
		held.value.accessToken?.value === credentials.accessToken?.value &&
		markerInstant(marker) === markerInstant(ineligible ?? undefined)
	);
}

async function refreshUnderLock(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	held: Extract<Evaluation, { kind: "refresh" }>,
	refresher: FederationGrantRefresher,
	hardDeadline: number,
): Promise<RefreshOutcome> {
	const { grant, guard, connection } = held;
	const { limits } = deps;
	const failed = (
		during: FederationGrantRetrievalFailure["during"],
		error: unknown,
		attempts?: number,
	): FederationGrantRetrievalFailure => report(deps, request, during, error, attempts);

	const controller = new AbortController();
	const calledAt = deps.now().getTime();
	// Settled into a value either way: once the hard deadline has passed nobody
	// looks at this again, and a late rejection must not go unhandled.
	const call = settle(() =>
		refresher.refreshDelegatedToken({
			refreshToken: held.refreshToken,
			// The grant's scopes: RFC 6749 §6 lets a refresh ask for no more, and an
			// IdP that honours it never starves a narrow grant.
			scopes: [...grant.scopes],
			...(grant.resource !== undefined ? { resource: grant.resource } : {}),
			signal: controller.signal,
		}),
	);
	const settled = await within(call, hardDeadline - calledAt);

	if (settled === "elapsed") {
		// Aborting does not undo a rotation at the IdP; past this point the
		// outcome is unknown, and a result that arrives later is not accepted,
		// whether or not the abort ever settles. The stored refresh credential is
		// not assumed to be still good: the next refresh decides.
		controller.abort();
		// Reported: the caller has usually been answered already, at the soft
		// deadline, and this is what became of the call it was answered about.
		return {
			kind: "denied",
			denial: unavailable("upstream", failed("upstream", NOT_ANSWERED)),
			audits: [["federation.grant.refresh_persist_failed", "hard_timeout"]],
			keepLock: true,
		};
	}

	if (!settled.ok) {
		const upstreamFailure = failed("upstream", settled.error);
		const classified = classifyFederationRefreshError(settled.error);
		// An outage, read before anything the body said: unreachable, timed out
		// or 5xx, on the error, its causes or its Response
		// (`isFederationUpstreamOutage`), or a structural 5xx status or
		// connection code the classifier finds on a non-Error. Neither reads
		// the IdP's parsed body. A 5xx is never a verdict on the credential,
		// whatever OAuth code its body names. A 429 is not an outage, and the
		// classifier's message-only `network` is a guess, not an outage.
		const outage =
			isFederationUpstreamOutage(settled.error) ||
			(classified.reason === "network" && classified.structured);
		// Only the upstream's structured rejection ends the credentials, which is
		// all the classifier's `invalid_grant` ever is: it is never read during
		// an outage — a 503 saying `invalid_grant` must not send the user through
		// consent again — nor off a message, where a wrong guess would do the
		// same for nothing.
		if (classified.reason === "invalid_grant") {
			const marked = await within(
				settle(() =>
					deps.store.requireReauthorization({
						...guard,
						now: deps.now(),
					}),
				),
				limits.persistRetryBudgetMs,
			);
			if (marked === "elapsed" || !marked.ok) {
				return {
					kind: "denied",
					denial: unavailable(
						"storage",
						failed("mark", marked === "elapsed" ? NOT_ANSWERED : marked.error),
					),
					audits: [["federation.grant.refresh_failed", "mark_not_written"]],
				};
			}
			// Refused on the version: the grant changed while the upstream was
			// answering — renewed, perhaps, and then this rejection was for a
			// refresh token that is no longer the grant's. It is not forced through.
			if (!marked.value.ok) {
				return { kind: "lost", audits: [["federation.grant.refresh_failed", "mark_lost"]] };
			}
			return {
				kind: "denied",
				denial: { code: "reauthorization_required", reason: "upstream_invalid_grant" },
				audits: [["federation.grant.reauthorization_required", "upstream_invalid_grant"]],
			};
		}
		// The upstream asked for the user: an interaction code read off the
		// error's own field, ahead of a 429 it came with. Never beside an
		// outage: a 5xx is no verdict. The refresh token is not known bad, so
		// the credentials are kept; waiting mends nothing, so no wait is told.
		// The answer comes from the record at the last look, never the code in
		// hand, which a renewal or revocation may have overtaken.
		if (!outage && isFederationGrantInteractionCode(classified.upstreamCode)) {
			const reason = `upstream_${classified.upstreamCode}` as const;
			const noted = await stamp(
				deps,
				request,
				guard,
				{ at: deps.now(), kind: "rejected", upstreamCode: classified.upstreamCode },
				limits.persistRetryBudgetMs,
			);
			switch (noted.outcome) {
				case "written":
					// The last look reads it back as `reauthorization_required`. The
					// fallback is for a record that no longer carries it.
					return {
						kind: "denied",
						denial: unavailable("concurrent_update"),
						audits: [["federation.grant.reauthorization_required", reason]],
					};
				case "refused":
					// Refused on the version: renewed or ended while the upstream was
					// answering. What it is now is the answer.
					return { kind: "lost", audits: [["federation.grant.refresh_failed", "mark_lost"]] };
				case "failed":
					return {
						kind: "denied",
						denial: unavailable("storage", noted.failure),
						audits: [["federation.grant.refresh_failed", "mark_not_written"]],
					};
				case "elapsed":
					// The write may still land. The lease is kept so that it does not
					// land under the next holder's refresh.
					return {
						kind: "denied",
						denial: unavailable("storage", noted.failure),
						audits: [["federation.grant.refresh_failed", "mark_not_written"]],
						keepLock: true,
					};
			}
		}
		// None of the rest changes the credentials. The failure is stamped on the
		// record, so that the next request does not ask a failing upstream
		// again at once — a refusal, and an outage from the second time on.
		let denial: FederationGrantDenial;
		let failure: FederationGrantRefreshFailureInput;
		const at = deps.now();
		if (classified.reason === "rate_limited") {
			const advice = classified.retryAfterSeconds;
			denial = { code: "rate_limited", reason: "upstream" };
			failure = {
				at,
				kind: "rate_limited",
				...(advice !== undefined ? { retryAfterSeconds: advice } : {}),
			};
		} else if (outage || classified.reason === "network") {
			// The upstream could not be reached, did not answer in time, or said
			// it is down: the outage this answer is (`outage`, above), or what the
			// refresh-error classifier alone reads as one. Stamped `unavailable`
			// either way, so the backoff is unchanged.
			denial = unavailable("upstream", upstreamFailure);
			failure = { at, kind: "unavailable" };
		} else if (
			classified.upstreamCode !== undefined &&
			!UPSTREAM_OUTAGE_CODES.has(classified.upstreamCode)
		) {
			// The upstream's error code when it is one this provider knows, and
			// never its message: this goes into a response. The IdP answered and
			// said no: nothing was processed, and a refusal is remembered at once.
			denial = { code: "upstream_rejected", reason: classified.upstreamCode };
			failure = { at, kind: "rejected", upstreamCode: classified.upstreamCode };
		} else {
			// An error nobody can read, or an outage the IdP named in its body
			// (RFC 6749 §4.1.2.1) with some status other than a 5xx: it may have
			// been processed, and its answer lost, so it is retried promptly like
			// an outage.
			denial = { code: "upstream_rejected", reason: classified.upstreamCode ?? "unknown" };
			failure = { at, kind: "unavailable" };
		}
		// What the failing caller is told is what the stamp will tell the next
		// one, computed the same way — and told even when the stamp does not land.
		const count = rowCount(grant, failure.at, limits.ineligibleRetryAfterMs);
		const wouldStand =
			count === undefined
				? { stands: false as const }
				: federationGrantRefreshFailureStands(federationGrantRefreshFailureStamp(failure, count), {
						now: at,
						allowanceMs: dateAllowanceMs(limits),
						backoffMs: limits.refreshFailureBackoffMs,
						ceilingMs: limits.ineligibleRetryAfterMs,
					});
		if (
			wouldStand.stands &&
			(denial.code === "rate_limited" ||
				denial.code === "upstream_rejected" ||
				denial.code === "temporarily_unavailable")
		) {
			denial = carrying(
				{ ...denial, retryAfterSeconds: wouldStand.retryAfterSeconds },
				failureOf(denial),
			);
		}
		await stamp(deps, request, guard, failure, limits.persistRetryBudgetMs);
		// The lock is let go of, whatever the failure was. A failure that ARRIVED
		// leaves nothing of this call's in flight, which is what keeping the lock
		// is for. If the IdP rotated before its answer was lost, the old refresh
		// token is presented again whenever the next refresh comes, and waiting
		// out the lock changes nothing about that — except that an IdP with a
		// grace window for exactly this takes a prompt retry, and not a late one.
		return {
			kind: "denied",
			denial,
			audits: [["federation.grant.refresh_failed", outcomeOf(denial)]],
		};
	}

	// --- the upstream answered ------------------------------------------------
	const receivedAt = deps.now().getTime();
	const answered = readFederationGrantUpstreamAnswer(settled.value, {
		calledAt,
		receivedAt,
		// A refresh asks for the grant's scopes, so an answer that names none carries them (RFC 6749 §6).
		requestedScopes: grant.scopes,
		consentedScopes: grant.consent.scopes,
		maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
	});
	// The rotated refresh token, or the stored one when the upstream sent none that is usable.
	const refreshToken = answered.refreshToken ?? held.refreshToken;
	// A rotated refresh token is ALWAYS persisted, even beside an access token
	// that cannot be disclosed. The access token that cannot be is never
	// written — and the stored one that still can be is kept: a refresh that
	// brought nothing usable must not cost the grant the token that worked. It
	// is judged again, against the maximum and the clock, at every disclosure.
	let credentials: FederationGrantCredentialsInput = { refreshToken, accessToken: held.keep };
	let ineligible: FederationGrantIneligibilityMarker | null = null;
	if (answered.accessToken.eligible) {
		credentials = { refreshToken, accessToken: answered.accessToken.token };
	} else {
		ineligible = {
			reason: answered.accessToken.reason,
			at: new Date(receivedAt),
			judgedAgainst: connection.maxAccessTokenLifetime,
		};
	}

	// --- the guarded write, retried only when it THROWS -------------------------
	// Bounded twice: by the clock, and by a count, for a clock that does not move.
	const persistDeadline = receivedAt + limits.persistRetryBudgetMs;
	const attempts = Math.max(1, Math.ceil(limits.persistRetryBudgetMs / PERSIST_RETRY_DELAY_MS));
	const fetched = ineligible === null ? credentials.accessToken?.value : undefined;
	const refreshedAudit: PendingAudit = [
		"federation.grant.refreshed",
		ineligible === null ? "success" : `upstream_token_ineligible/${ineligible.reason}`,
	];
	let threwBefore = false;
	// What every attempt that threw threw. Told once the loop is done with
	// them, and not once per attempt: the retries are one write. Each distinct
	// kind of failure is told once, with how many attempts failed so; what is
	// returned — for the answer to carry — is the kind the LAST attempt threw.
	const thrown: unknown[] = [];
	const reportWrite = (): FederationGrantRetrievalFailure | undefined => {
		const last = thrown.at(-1);
		if (thrown.length === 0) return undefined;
		const kinds = new Map<string, { last: unknown; count: number }>();
		for (const error of thrown.splice(0)) {
			const kind = kindOf(error);
			kinds.set(kind, { last: error, count: (kinds.get(kind)?.count ?? 0) + 1 });
		}
		const lastKind = kindOf(last);
		for (const [kind, { last: error, count }] of kinds) {
			if (kind !== lastKind) failed("write", error, count);
		}
		const carried = kinds.get(lastKind) as { last: unknown; count: number };
		return failed("write", carried.last, carried.count);
	};
	for (let attempt = 0; attempt < attempts; attempt++) {
		const remaining = persistDeadline - deps.now().getTime();
		if (remaining <= 0) break;
		const result = await within(
			settle(() =>
				deps.store.replaceCredentials({
					...guard,
					credentials,
					ineligible,
					// Sampled at the write: a refresh that straddles the expiry must fail.
					now: deps.now(),
				}),
			),
			remaining,
		);
		// A write that hangs is not waited for past the budget. If it lands
		// later it is still guarded by the version — and until it has had the
		// time to, nobody else is let at the refresh token it replaces.
		if (result === "elapsed") {
			// The answer is the write that did not answer; what attempts before
			// it threw is told beside it, and not carried.
			reportWrite();
			return {
				kind: "denied",
				denial: unavailable("storage", failed("write", NOT_ANSWERED)),
				audits: [["federation.grant.refresh_persist_failed", "write_in_flight"]],
				keepLock: true,
			};
		}
		if (result.ok) {
			// An attempt that threw before this one answered is told all the same.
			reportWrite();
			// A writer whose precondition fails does not use what it fetched.
			// That includes this call's own earlier attempt having landed with its
			// acknowledgement lost: the last look then finds its token stored. The
			// upstream was asked, and may have rotated: that leaves a trail.
			if (!result.value.ok) {
				// Refused on the version — which this call's own earlier attempt
				// bumped, if that one landed and only its acknowledgement was lost.
				// One look, still under the lock, tells the two apart: it is this
				// call's write exactly when what is stored is what it tried to store.
				const left = persistDeadline - deps.now().getTime();
				if (threwBefore && (await isStored(deps, guard.grantId, credentials, ineligible, left))) {
					return {
						kind: "written",
						...(fetched !== undefined ? { fetched } : {}),
						audits: [refreshedAudit],
					};
				}
				return { kind: "lost", audits: [["federation.grant.refresh_failed", "write_lost"]] };
			}
			return {
				kind: "written",
				...(fetched !== undefined ? { fetched } : {}),
				audits: [refreshedAudit],
			};
		}
		threwBefore = true;
		thrown.push(result.error);
		await after(Math.min(PERSIST_RETRY_DELAY_MS, remaining)).elapsed;
	}
	// No attempt that threw means none was made in time: nothing answered.
	const writeFailure = reportWrite() ?? failed("write", NOT_ANSWERED);
	// The new credentials are dropped. The stored refresh credential is not
	// assumed to be still good: the next refresh decides. The failure is
	// stamped all the same, best effort, with what is left of the persist
	// budget — the store is what failed, and one more write to it may fail too
	// — and not a millisecond past it: the lock is sized for the budget, and a
	// stamp written past the lease could land under the next holder.
	const left = persistDeadline - deps.now().getTime();
	if (left > 0) await stamp(deps, request, guard, { at: deps.now(), kind: "unavailable" }, left);
	return {
		kind: "denied",
		denial: unavailable("storage", writeFailure),
		audits: [["federation.grant.refresh_persist_failed", "storage"]],
	};
}

/**
 * Stamps a failed refresh on the record: one bounded attempt under the lock,
 * so every waiter finds it. For the timed backoff it never changes the
 * answer, and a store that refuses it is only reported. For the user's
 * absence the stamp IS the answer, so the outcome is returned: `written`,
 * `refused` (guard), `failed` (throw) or `elapsed` (may still land), the
 * last two with the failure they were reported as.
 */
async function stamp(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	guard: WriteGuard,
	failure: FederationGrantRefreshFailureInput,
	budgetMs: number,
): Promise<
	| { readonly outcome: "written" | "refused" }
	| { readonly outcome: "failed" | "elapsed"; readonly failure: FederationGrantRetrievalFailure }
> {
	const noted = await within(
		settle(() =>
			deps.store.noteRefreshFailure({
				...guard,
				failure,
				rowMs: deps.limits.ineligibleRetryAfterMs,
				now: deps.now(),
			}),
		),
		budgetMs,
	);
	if (noted === "elapsed") {
		return { outcome: "elapsed", failure: report(deps, request, "mark", NOT_ANSWERED) };
	}
	if (!noted.ok) {
		return { outcome: "failed", failure: report(deps, request, "mark", noted.error) };
	}
	// Refused on the version, the stamp says nothing about the credentials the
	// grant has now: nothing to report.
	return { outcome: noted.value.ok ? "written" : "refused" };
}

/** Lets go of a lock, waiting so long and no longer, and tells the logger when it could not. Never rejects. */
async function letGo(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	lock: { release(): Promise<void> },
): Promise<void> {
	const released = await within(
		settle(() => lock.release()),
		SIDE_EFFECT_WAIT_MS,
	);
	// The lock has a TTL: one that could not be let go of runs out.
	if (released === "elapsed") report(deps, request, "release", NOT_ANSWERED);
	else if (!released.ok) report(deps, request, "release", released.error);
}

/**
 * The last look of a call that went for a refresh: what is stored NOW, judged
 * with `attempted`. A token that serves the request is answered; otherwise the
 * look's own verdict when it has one, and `fallback` — what the attempt came
 * to — when the look would have refreshed. With `fetched`, the token this call
 * wrote: answered as `refreshed` only while that is what is stored, and
 * overtaken — `concurrent_update`, whatever `fallback` says — when something
 * else is.
 */
async function lastLook(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	fallback: FederationGrantDenial,
	wrote: { readonly fetched?: string } = {},
): Promise<FederationGrantTokenResult> {
	const { fetched } = wrote;
	const stored = await evaluate(deps, request, {
		attempted: true,
		...(fetched !== undefined ? { fetched } : {}),
	});
	// A write that was replaced before this look was overtaken, whatever the
	// caller says the attempt came to.
	const replaced = fetched !== undefined && stored.kind === "refresh" && stored.stored !== fetched;
	return conclude(
		deps,
		request,
		stored,
		// `refreshed` says that what is answered is what this call fetched. It is
		// not when the write brought no access token and kept the one the grant
		// had, nor when something else was stored before this look.
		fetched !== undefined && stored.kind === "token" && stored.token.value === fetched,
		replaced ? unavailable("concurrent_update") : fallback,
	);
}

async function refresh(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
): Promise<FederationGrantTokenResult> {
	const askedAt = deps.now().getTime();
	const asking = settle(() =>
		deps.store.acquireRefreshLock(request.grantId, {
			ttlMs: deps.limits.refreshLockTtlMs,
			waitForMs: deps.limits.lockWaitMs,
		}),
	);
	// The store is told how long to wait, and is not trusted to keep to it.
	const asked = await within(asking, deps.limits.lockWaitMs + SIDE_EFFECT_WAIT_MS);
	if (asked === "elapsed" || !asked.ok) {
		if (asked === "elapsed") {
			// A lock that arrives for nobody is let go of, not left to run out
			// against every replica that needs it. The WAIT for it is not handed to
			// `background` — it may never arrive, and what is handed over has to
			// settle — but letting go of it, once it has, is.
			void asking.then((late) => {
				if (!late.ok || !late.value.acquired) return;
				handOver(deps, request, letGo(deps, request, late.value));
			});
		}
		const lockFailure = report(
			deps,
			request,
			"lock",
			asked === "elapsed" ? NOT_ANSWERED : asked.error,
		);
		return lastLook(deps, request, unavailable("storage", lockFailure));
	}
	const lock = asked.value;
	if (!lock.acquired) {
		// Whoever held it may have refreshed. One look, which never refreshes.
		return lastLook(deps, request, unavailable("lock_timeout"));
	}

	// One owner of the release, whichever way this ends. Never waited for by the
	// caller: a lock that is slow to let go of must not turn a refresh that was
	// persisted into an outage.
	const release = (): Promise<void> => letGo(deps, request, lock);

	let held: Extract<Evaluation, { kind: "refresh" }>;
	let refresher: FederationGrantRefresher;
	let leaseStartedAt: number;
	let startedAt: number;
	try {
		// The lease has one clock. It starts when the store TOOK the lock — when it
		// was asked for, plus what the store waited — which is before the store
		// answered. Every deadline counts from there: what this call spends under
		// the lock before it asks the upstream is spent of the same lease, and
		// so is however long the acknowledgement took. A store that cannot say how
		// long it waited, or says it waited longer than the whole round trip, is not
		// one to run a refresh on: the lock is let go of, and the caller is told the
		// store failed.
		const acknowledgedAt = deps.now().getTime();
		const waitedMs: unknown = lock.waitedMs;
		if (
			typeof waitedMs !== "number" ||
			!(waitedMs >= 0) ||
			!(askedAt + waitedMs <= acknowledgedAt + FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS)
		) {
			handOver(deps, request, release());
			const unmeasured = report(
				deps,
				request,
				"lock",
				new Error("the store did not say how long it waited for the lock"),
			);
			return lastLook(deps, request, unavailable("storage", unmeasured));
		}
		leaseStartedAt = askedAt + waitedMs;
		const again = await evaluate(deps, request);
		if (again.kind !== "refresh") {
			// Another replica refreshed already, or the grant ended meanwhile.
			handOver(deps, request, release());
			return conclude(deps, request, again, false, unavailable("lock_timeout"));
		}
		const found = deps.refresher(again.connection);
		if (found === undefined) {
			handOver(deps, request, release());
			return conclude(
				deps,
				request,
				{ kind: "deny", denial: NOT_PERMITTED, grant: again.grant },
				false,
				NOT_PERMITTED,
			);
		}
		startedAt = deps.now().getTime();
		if (!(startedAt < leaseStartedAt + deps.limits.upstreamTimeoutMs)) {
			// The look under the lock used up the time a caller waits — or more:
			// the whole lease, when a read hung. A rotation started now would be
			// one nobody waits for, run toward a deadline it no longer has the time
			// to meet, perhaps under a lock that has already run out while another
			// replica presents the same refresh token. The upstream is not asked —
			// and what was slow is the look under the lock, so that is what the
			// answer names, and the logger is told.
			handOver(deps, request, release());
			const spent = report(
				deps,
				request,
				"refresh",
				new Error("the look under the refresh lock used up the lease; the upstream was not asked"),
			);
			return lastLook(deps, request, unavailable("storage", spent));
		}
		held = again;
		refresher = found;
	} catch (error) {
		// A dependency threw where it should not have. The bug is the
		// composer's to see; the lock is not left behind for it.
		handOver(deps, request, release());
		throw error;
	}

	// ONE worker owns the upstream call and the guarded write. Its tail — the
	// release, and then what it has to tell the audit sink, in that order —
	// is handed over at once: it may outlive the answer, and when the caller
	// stops waiting at the soft deadline the whole of it does.
	const work = refreshUnderLock(
		deps,
		request,
		held,
		refresher,
		leaseStartedAt + deps.limits.upstreamHardTimeoutMs,
	).catch((error: unknown): RefreshOutcome => {
		// Nothing in there is expected to reject. If something did, the upstream
		// may have been asked, and nothing is known about what it did.
		return {
			kind: "denied",
			denial: unavailable("upstream", report(deps, request, "refresh", error)),
			audits: [["federation.grant.refresh_failed", "internal_error"]],
			keepLock: true,
		};
	});
	handOver(
		deps,
		request,
		work.then(async (outcome) => {
			if (outcome.keepLock !== true) await release();
			for (const [type, result] of outcome.audits) {
				await audit(deps, request, type, result, held.grant);
			}
		}),
	);

	const first = await within(work, leaseStartedAt + deps.limits.upstreamTimeoutMs - startedAt);
	if (first === "elapsed") {
		// A slow upstream must not cost users their grants: the request goes on,
		// holding the lock, and its result is persisted whenever it arrives. Only
		// the caller is answered now — with what is stored, when that serves it.
		return lastLook(deps, request, unavailable("upstream"));
	}
	if (first.kind === "denied") return lastLook(deps, request, first.denial);
	// Written or lost, the last look is the same: the record as it is NOW, the
	// boundary as it is now, and the token that is stored — never the one this
	// call fetched and holds in a variable.
	// A write that landed and is still what is stored was overtaken by nothing:
	// if its token cannot be answered, the upstream's token is what failed the
	// call. Lost, it was overtaken.
	return lastLook(
		deps,
		request,
		unavailable(first.kind === "written" ? "upstream" : "concurrent_update"),
		first.kind === "written" ? first : {},
	);
}

/**
 * An upstream access token for a federation grant: every retrieval
 * re-evaluates the grant, a call refreshes at most once, and a writer that
 * loses never returns the token it fetched. The routes package only maps the
 * typed result to HTTP. See ADR 2026-09-17-federation-grants-offline-delegation,
 * D10–D12.
 *
 * Any run-time misbehaviour of a dependency becomes a typed result. It
 * rejects only for a composition bug (a throwing `connection`, `refresher` or
 * `now`), and even then leaves no lock behind.
 */
export async function retrieveFederationGrantToken(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
): Promise<FederationGrantTokenResult> {
	const first = await evaluate(deps, request);
	reportUndatedStamps(deps, request, first.grant);
	if (first.kind !== "refresh") {
		return conclude(deps, request, first, false, unavailable("upstream"));
	}
	return refresh(deps, request);
}
