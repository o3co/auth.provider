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

import { classifyFederationRefreshError } from "../federation-tokens/refresh-error.mjs";
import { effectiveFederationGrantStatus } from "./effective-status.mjs";
import {
	federationGrantIneligibilityRetry,
	isUsableMaxUpstreamAccessTokenLifetime,
	judgeUpstreamAccessToken,
	scopesWithin,
} from "./eligibility.mjs";
import { federationGrantEffectiveExpiry } from "./lifetime.mjs";
import type { FederationGrantStore } from "./store.mjs";
import {
	type AuthorizedFederationGrant,
	type FederationGrant,
	type FederationGrantConnection,
	type FederationGrantCredentials,
	type FederationGrantDenial,
	type FederationGrantIneligibilityMarker,
	type FederationGrantTokenResult,
	type FederationGrantUnavailableReason,
	hasFederationGrantAuthorization,
} from "./types.mjs";

/**
 * What a delegated refresh answers (#593, D17), as far as the retrieval needs
 * it. Structural, as the session-bound route's refresh shape is, so that core
 * does not depend on the package the adapters live in.
 *
 * Every field is optional, as the adapters' own token snapshot has them, and
 * none is trusted: the retrieval reads an answer field by field, keeps the
 * refresh token it came with whatever else is wrong, and treats an answer it
 * cannot use as `malformed_token_response`.
 */
export interface FederationGrantRefreshedToken {
	readonly accessToken?: string;
	/** Absent when the upstream did not rotate it (RFC 6749 §6): the stored one is kept. */
	readonly refreshToken?: string;
	/**
	 * Seconds, exactly as the upstream issued them; `null` when it named none.
	 * This is what eligibility judges. It cannot be recovered from `expiresAt`:
	 * one step of the clock between the adapter and here turns 3600 into 3601,
	 * and starves every grant on a connection whose maximum is 3600.
	 */
	readonly expiresIn?: number | null;
	/**
	 * The adapter's own `now + expiresIn`. With `expiresIn` it anchors when the
	 * token was obtained on the ADAPTER's reading of the clock; pairing
	 * `expiresIn` with a later reading taken here would extend the expiry.
	 */
	readonly expiresAt?: Date | null;
	/** Space-delimited, as in the token response. Absent means "as the grant's" (RFC 6749 §6). */
	readonly scope?: string;
	readonly tokenType?: string;
}

export interface FederationGrantRefresher {
	refreshDelegatedToken(params: {
		readonly refreshToken: string;
		readonly scopes?: readonly string[];
		readonly resource?: string;
		readonly signal?: AbortSignal;
	}): Promise<FederationGrantRefreshedToken>;
}

/** Token-free, always: no event carries an access token, a refresh token, or any other secret (D18). */
export interface FederationGrantAuditEvent {
	readonly type:
		| "federation.grant.token.success"
		| "federation.grant.token.denied"
		| "federation.grant.refreshed"
		| "federation.grant.refresh_failed"
		| "federation.grant.refresh_persist_failed"
		| "federation.grant.reauthorization_required"
		| "federation.grant.revoked";
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
	/** `federationGrants.maxExpiresIn`, as it is configured now. */
	readonly maxExpiresInMs: number;
	/**
	 * How far replicas' clocks may differ. It is the backstop's allowance (D13),
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
	/** The SOFT deadline: how long a caller waits for the upstream (D12). */
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
 * lease is counted from when the acquisition was ACKNOWLEDGED, which is after
 * the store started the lock's TTL; and timers fire late. Without a margin, a
 * configuration that fits by a millisecond does not fit.
 */
export const FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS = 1_000;

/** What went wrong where a cause is otherwise swallowed into a typed answer. For a logger; never for a response. */
export interface FederationGrantRetrievalFailure {
	readonly during:
		| "boundary"
		| "open"
		| "status"
		| "backstop_revoke"
		| "lock"
		| "release"
		| "upstream"
		| "mark"
		| "write"
		| "touch"
		| "audit"
		| "background"
		| "refresh";
	readonly error: unknown;
	readonly grantId: string;
	readonly correlationId: string;
}

export interface RetrieveFederationGrantTokenDeps {
	readonly store: FederationGrantStore;
	/** The connection as it is configured now; `undefined` when the operator removed it. */
	connection(name: string): FederationGrantConnection | undefined;
	refresher(connection: FederationGrantConnection): FederationGrantRefresher | undefined;
	/**
	 * The subject's grants boundary (D13). A failure fails closed: 503. Neither
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
	 * result is persisted (D12); and the record of a use and the audit of an
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
	 * Told the cause wherever one is turned into a typed answer, or dropped:
	 * a 503 says that something failed, and an operator needs to know what. The
	 * error may be an upstream's, and may carry what the upstream echoed: it is
	 * for a logger that redacts, and never for a response.
	 */
	report?(failure: FederationGrantRetrievalFailure): void;
}

export interface RetrieveFederationGrantTokenRequest {
	readonly grantId: string;
	/** The authenticated client. */
	readonly clientId: string;
	/** `sub`, required on every grant-addressed route (D9). */
	readonly subject: string;
	/** The client's `allowedFederationGrantConnections`. */
	readonly allowedConnections: readonly string[];
	readonly correlationId: string;
	// Assertions the provider checks (D10). None of them widens anything.
	readonly connection?: string;
	readonly scope?: readonly string[];
	readonly resource?: string;
	readonly minTtlSeconds?: number;
}

/** `setTimeout` takes a signed 32-bit number of milliseconds; beyond it, it fires at once. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * Refuses limits the retrieval cannot keep its promises under. For whoever
 * composes it to call at boot: a schema guarantees these, and a hand-built
 * config bypasses a schema (#448).
 *
 * - Every limit is a finite number, and none is negative; the ones a timer or
 *   a lock is given are positive, and fit a timer. NaN compares as fine
 *   everywhere: under a NaN refresh buffer no token is refreshed before it
 *   has died, and a NaN retry interval switches the marker's limit off.
 * - `upstreamTimeoutMs <= upstreamHardTimeoutMs`: the soft deadline only
 *   answers the caller, and the hard one is where the request is aborted.
 * - `upstreamHardTimeoutMs + persistRetryBudgetMs + margin <= refreshLockTtlMs`
 *   (D12). The lock has no renewal, and one that expires mid-refresh lets two
 *   replicas present the same refresh token.
 *
 * This compares configured durations and nothing else. What makes them mean
 * something is in the retrieval: every deadline counts from the moment the
 * lock was acquired, and the upstream is not asked at all once the look under
 * the lock has used up the time a caller waits.
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
	const allowances = ["revocationSkewMs", "refreshBufferMs", "lockWaitMs"] as const;
	for (const name of timed) {
		const value = limits[name];
		if (!Number.isFinite(value) || value <= 0) {
			throw new RangeError(`federationGrants: ${name} must be a positive finite number`);
		}
	}
	for (const name of allowances) {
		const value = limits[name];
		if (!Number.isFinite(value) || value < 0) {
			throw new RangeError(`federationGrants: ${name} must be a non-negative finite number`);
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
			throw new RangeError(`federationGrants: ${name} does not fit a timer`);
		}
	}
	// The store is given `SIDE_EFFECT_WAIT_MS` over the lock wait (`refresh`).
	if (limits.lockWaitMs + SIDE_EFFECT_WAIT_MS > MAX_TIMER_MS) {
		throw new RangeError("federationGrants: lockWaitMs does not fit a timer");
	}
	if (!(limits.upstreamTimeoutMs <= limits.upstreamHardTimeoutMs)) {
		throw new RangeError(
			"federationGrants: upstreamTimeoutMs must not exceed upstreamHardTimeoutMs — the soft deadline only answers the caller, and the hard one is where the request is aborted",
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
			"federationGrants: upstreamHardTimeoutMs + persistRetryBudgetMs must leave a second of refreshLockTtlMs — the refresh lock has no renewal, and one that expires mid-refresh lets two replicas present the same refresh token",
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

/** `work`, or `"elapsed"` when it has not settled within `ms`. No timer is left behind. */
async function within<T>(work: Promise<T>, ms: number): Promise<T | "elapsed"> {
	const limit = after(ms);
	try {
		return await Promise.race([work, limit.elapsed]);
	} finally {
		limit.cancel();
	}
}

/** Tells the composer's logger what was swallowed. A reporter that throws is not worth an answer. */
function report(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	during: FederationGrantRetrievalFailure["during"],
	error: unknown,
): void {
	try {
		deps.report?.({
			during,
			error,
			grantId: request.grantId,
			correlationId: request.correlationId,
		});
	} catch {
		// See above.
	}
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
 * Which look this is. Every look judges the grant the same way; they differ in
 * what becomes of a stored token that would be refreshed.
 *
 * - The first look, and the same look again once the lock is held, when
 *   another replica may have refreshed already: it sends the call to the
 *   refresh.
 * - `"own"` — the last look before a token this call refreshed is disclosed.
 *   What is stored is answered with its true lifetime, whatever was asked of
 *   it: a call refreshes at most once, and the caller decides (D10).
 * - The only look after a lock timeout or a lost write is a first look again:
 *   what is stored is somebody else's, or the token that had run down. A token
 *   that is not half spent is answered as it is, somebody else's included, and
 *   what would have been a refresh is answered by `refresh` below as the
 *   outage that brought the call there. `refresh` runs once per call.
 */
type Look = "any" | "own";

type StoredAccessToken = NonNullable<FederationGrantCredentials["accessToken"]>;

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
			readonly connection: FederationGrantConnection;
			readonly refreshToken: string;
			/**
			 * The stored access token, when it is one that could still be disclosed:
			 * eligible under the current maximum, alive, and dated believably. A
			 * refresh that brings nothing usable keeps it (D5).
			 */
			readonly keep?: StoredAccessToken;
	  };

const unavailable = (reason: FederationGrantUnavailableReason): FederationGrantDenial => ({
	code: "temporarily_unavailable",
	reason,
});

const NOT_PERMITTED: FederationGrantDenial = {
	code: "access_denied",
	reason: "connection_not_permitted",
};

async function evaluate(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	look: Look,
): Promise<Evaluation> {
	// The boundary first and the record last, so that the record — the thing a
	// revocation changes — is the freshest thing evaluated. A boundary that
	// cannot be read is held, not thrown: it must not turn "not yours" or a
	// stored revocation into a 503.
	//
	// Neither read is bounded here. A store or a boundary reader that can hang
	// carries its own timeout; what this function bounds is what holds the lock.
	const boundary = await settle(() => deps.grantsBoundary(request.subject));
	if (!boundary.ok) report(deps, request, "boundary", boundary.error);
	const read = await settle(() => deps.store.open(request.grantId, deps.now()));
	if (!read.ok) {
		report(deps, request, "open", read.error);
		return { kind: "deny", denial: unavailable("storage") };
	}
	const opened = read.value;
	// After the awaited reads, not before them.
	const now = deps.now();

	// One answer for an unknown ID, another client's grant and another
	// subject's, so that a known ID tells a stranger nothing (D9).
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
	if (!boundary.ok) return { kind: "deny", denial: unavailable("storage"), grant };

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
		report(deps, request, "status", error);
		return { kind: "deny", denial: unavailable("storage"), grant };
	}

	if (status.status === "revoked") {
		// The backstop: a subject-wide revocation that never reached this record
		// (D13). Made durable on the first touch. A write that FAILS is a
		// revocation outage, and D13 has those surface; one that changes nothing
		// means somebody else got there, and the answer stands.
		const revoked = await settle(() => deps.store.revoke(grant.id, "backstop", now));
		if (!revoked.ok) {
			report(deps, request, "backstop_revoke", revoked.error);
			return { kind: "deny", denial: unavailable("storage"), grant };
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
		// A key that is missing from the ring is an outage, and not a status (D1,
		// D16): the credential may be perfectly good. It is answered here, where
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

	// What the request asserts is checked here, so that a request that can
	// never succeed does not cost an upstream call (D10).
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
	const token = credentials.accessToken;
	let keep: StoredAccessToken | undefined;
	if (token !== undefined) {
		// The same predicate guards every disclosure, cached or fresh, against
		// the CURRENT maximum (D5).
		const eligible = judgeUpstreamAccessToken({
			issuedLifetime: token.issuedLifetime,
			scopes: token.scopes,
			consentedScopes: grant.consent.scopes,
			maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
		}).eligible;
		const lifetimeMs = token.issuedLifetime * 1000;
		const age = now.getTime() - token.obtainedAt.getTime();
		// A token dated far ahead is not believed: read as it stands it would be
		// unspent, and alive, for as long as its date is ahead. One dated a little
		// ahead is — by as much as the refresh buffer absorbs, or as replicas'
		// clocks may differ where the buffer is set to less. Believing it costs
		// that it is refreshed so much later; not believing it costs a second
		// rotation on the heels of the first, whenever the replica that refreshed
		// is the one that is ahead. And no token has more life left than it was
		// issued with, whatever its date says.
		const believed = age >= -Math.max(deps.limits.refreshBufferMs, deps.limits.revocationSkewMs);
		const tokenEndsAt = Math.min(token.obtainedAt.getTime(), now.getTime()) + lifetimeMs;
		const remainingMs = tokenEndsAt - now.getTime();
		if (eligible && believed && remainingMs > 0) {
			keep = token;
			// Against the scopes THIS token carries, not what the grant once got (D10).
			const carries = request.scope === undefined || scopesWithin(request.scope, token.scopes);
			// A token is never refreshed before it is half spent. Until then a
			// refresh has little more life to give, and an upstream that has just
			// left a scope out is not going to change its mind — while every refresh
			// rotates the refresh token at an IdP that rotates. Without this bound a
			// client asking an hour of tokens issued for an hour, or a scope the
			// upstream never puts in one, or anything at all of tokens issued with
			// less life than the buffer, would get a rotation on every request: the
			// harm D5's marker exists to prevent, on a path the marker does not
			// cover, since such a token is eligible. With it, a client can cause
			// two rotations in a token's lifetime and no more, while the upstream
			// answers. What an upstream that FAILS costs is not bounded here (D12).
			const halfSpent = age >= lifetimeMs / 2;
			const ranDown = remainingMs <= deps.limits.refreshBufferMs;
			const wantsMore = !carries || remainingMs <= minTtlSeconds * 1000;
			const refreshIt = look !== "own" && halfSpent && (ranDown || wantsMore);
			if (carries && (!refreshIt || notAsked !== undefined)) {
				const grantEndsAt = federationGrantEffectiveExpiry(grant, deps.limits.maxExpiresInMs);
				return {
					kind: "token",
					grant,
					token,
					// A cache hint for a cooperating worker, never enforcement (D15).
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
	return {
		kind: "refresh",
		grant,
		connection,
		refreshToken: credentials.refreshToken,
		...(keep !== undefined ? { keep } : {}),
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
	const authorized =
		grant !== undefined && hasFederationGrantAuthorization(grant) ? grant : undefined;
	const told = await within(
		settle(() =>
			sink({
				type,
				correlationId: request.correlationId,
				grantId: request.grantId,
				clientId: request.clientId,
				subject: request.subject,
				...(grant !== undefined ? { connection: grant.connection } : {}),
				...(authorized !== undefined
					? {
							upstream: { ...authorized.upstream },
							scopes: [...authorized.scopes],
							...(authorized.resource !== undefined ? { resource: authorized.resource } : {}),
						}
					: {}),
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
	return { ok: false, ...denial };
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
	/** `brought`: whether an access token came with it. Without one, what is stored is what the grant had. */
	(
		| { readonly kind: "written"; readonly brought: boolean }
		/** A guarded write lost. Never the fetched token: the last look answers with what is there. */
		| { readonly kind: "lost" }
		| { readonly kind: "denied"; readonly denial: FederationGrantDenial }
	) & {
		readonly audits: readonly PendingAudit[];
		/**
		 * Something of this call's is still IN FLIGHT: an upstream request that
		 * was aborted may be rotating the refresh token all the same, and a write
		 * that was still going at the end of its budget may yet land. The lock is
		 * then left to run out instead of being let go of. A failure that arrived
		 * is not that: nothing is in flight any more. Whoever acquired it next would present the
		 * stored refresh token — the old one — beside an operation that is about to
		 * replace it, and an IdP that detects reuse answers that by revoking the
		 * family, the new token included. The price is that others wait out what is
		 * left of the lock, while the store or the upstream is failing anyway.
		 */
		readonly keepLock?: true;
	};

const PERSIST_RETRY_DELAY_MS = 100;

interface ReadResponse {
	/** The rotated refresh token, or the stored one when the upstream sent none that is usable. */
	readonly refreshToken: string;
	/** `undefined` when the response is not one an adapter should report. */
	readonly token?: {
		readonly accessToken: string;
		readonly tokenType: string;
		readonly expiresIn: number | null;
		/** NaN when the adapter named no expiry, or one that is not a date. */
		readonly expiresAtMs: number;
		readonly scopes: readonly string[];
	};
}

/**
 * Reads a refresh response without trusting its shape, and without throwing:
 * the refresh token is taken first and whatever else is wrong with the
 * response, it is kept. Discarding the response would discard the only valid
 * credential (D5).
 */
function readResponse(
	response: unknown,
	grant: AuthorizedFederationGrant,
	storedRefreshToken: string,
): ReadResponse {
	const fields = (typeof response === "object" && response !== null ? response : {}) as Record<
		string,
		unknown
	>;
	const refreshToken =
		typeof fields.refreshToken === "string" && fields.refreshToken !== ""
			? fields.refreshToken
			: storedRefreshToken;

	const { accessToken, tokenType = "Bearer", expiresIn = null, expiresAt = null, scope } = fields;
	if (typeof accessToken !== "string" || accessToken === "") return { refreshToken };
	if (typeof tokenType !== "string" || tokenType === "") return { refreshToken };
	if (expiresIn !== null && typeof expiresIn !== "number") return { refreshToken };
	if (expiresAt !== null && !(expiresAt instanceof Date)) return { refreshToken };
	if (scope !== undefined && typeof scope !== "string") return { refreshToken };

	// RFC 6749 §3.3: space-delimited. Absent — or empty, which is not a scope —
	// means "as the grant's" (§6).
	const named = scope === undefined ? [] : scope.split(" ").filter((entry) => entry !== "");
	return {
		refreshToken,
		token: {
			accessToken,
			tokenType,
			expiresIn,
			expiresAtMs: expiresAt === null ? Number.NaN : expiresAt.getTime(),
			scopes: named.length === 0 ? [...grant.scopes] : named,
		},
	};
}

/**
 * Whether the record holds the credentials this call tried to store. Waited
 * for no longer than `budgetMs`: the lock is sized for ONE persist budget
 * after the hard deadline, and this look is spent of the same one.
 */
async function isStored(
	deps: RetrieveFederationGrantTokenDeps,
	grant: AuthorizedFederationGrant,
	credentials: FederationGrantCredentials,
	budgetMs: number,
): Promise<boolean> {
	const read = await within(
		settle(() => deps.store.open(grant.id, deps.now())),
		budgetMs,
	);
	if (read === "elapsed" || !read.ok || read.value === null) return false;
	const held = read.value.credentials;
	return (
		held.state === "ok" &&
		held.value.refreshToken === credentials.refreshToken &&
		held.value.accessToken?.value === credentials.accessToken?.value
	);
}

async function refreshUnderLock(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
	held: Extract<Evaluation, { kind: "refresh" }>,
	refresher: FederationGrantRefresher,
	hardDeadline: number,
): Promise<RefreshOutcome> {
	const { grant, connection } = held;
	const { limits } = deps;
	const failed = (during: FederationGrantRetrievalFailure["during"], error: unknown): void =>
		report(deps, request, during, error);

	const controller = new AbortController();
	const calledAt = deps.now().getTime();
	// Settled into a value either way: once the hard deadline has passed nobody
	// looks at this again, and a late rejection must not go unhandled.
	const call = settle(() =>
		refresher.refreshDelegatedToken({
			refreshToken: held.refreshToken,
			// The grant's scopes: RFC 6749 §6 lets a refresh ask for no more, and an
			// IdP that honours it never starves a narrow grant (D5).
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
		return {
			kind: "denied",
			denial: unavailable("upstream"),
			audits: [["federation.grant.refresh_persist_failed", "hard_timeout"]],
			keepLock: true,
		};
	}

	if (!settled.ok) {
		failed("upstream", settled.error);
		// The classifier is the session-bound route's, unchanged, and it can
		// throw on a thing that cannot be made a string. The failure ARRIVED all
		// the same, which is what matters below.
		let classified: ReturnType<typeof classifyFederationRefreshError>;
		try {
			classified = classifyFederationRefreshError(settled.error);
		} catch {
			classified = { reason: "unknown", structured: false };
		}
		// Only a STRUCTURED rejection ends the credentials. The classifier's
		// message fallback is a guess, and a wrong one here would send a user
		// through consent again for nothing.
		if (classified.reason === "invalid_grant" && classified.structured) {
			const marked = await within(
				settle(() =>
					deps.store.requireReauthorization({
						grantId: grant.id,
						expectedVersion: grant.version,
						now: deps.now(),
					}),
				),
				limits.persistRetryBudgetMs,
			);
			if (marked === "elapsed" || !marked.ok) {
				if (marked !== "elapsed") failed("mark", marked.error);
				return {
					kind: "denied",
					denial: unavailable("storage"),
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
		// None of the rest changes the record.
		let denial: FederationGrantDenial;
		if (classified.reason === "rate_limited") {
			denial = {
				code: "rate_limited",
				reason: "upstream",
				...(classified.retryAfterSeconds !== undefined
					? { retryAfterSeconds: classified.retryAfterSeconds }
					: {}),
			};
		} else if (classified.reason === "network") {
			denial = unavailable("upstream");
		} else {
			// The upstream's error code when it is one this provider knows, and
			// never its message: this goes into a response.
			denial = { code: "upstream_rejected", reason: classified.upstreamCode ?? "unknown" };
		}
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
	const response = readResponse(settled.value, grant, held.refreshToken);
	// A rotated refresh token is ALWAYS persisted, even beside an access token
	// that cannot be disclosed. The access token that cannot be is never
	// written — and the stored one that still can be is kept: a refresh that
	// brought nothing usable must not cost the grant the token that worked. It
	// is judged again, against the maximum and the clock, at every disclosure.
	let credentials: FederationGrantCredentials = {
		refreshToken: response.refreshToken,
		...(held.keep !== undefined ? { accessToken: held.keep } : {}),
	};
	let ineligible: FederationGrantIneligibilityMarker | null = null;
	const marker = (
		reason: FederationGrantIneligibilityMarker["reason"],
	): FederationGrantIneligibilityMarker => ({
		reason,
		at: new Date(receivedAt),
		judgedAgainst: connection.maxAccessTokenLifetime,
	});
	if (response.token === undefined) {
		ineligible = marker("malformed_token_response");
	} else {
		const { expiresIn, expiresAtMs, scopes } = response.token;
		// Both, or the token has no finite lifetime: the raw `expires_in` is what
		// is judged, and the adapter's expiry is what dates the token.
		const lifetime =
			expiresIn !== null && Number.isFinite(expiresIn) && !Number.isNaN(expiresAtMs)
				? expiresIn
				: null;
		const judgement = judgeUpstreamAccessToken({
			issuedLifetime: lifetime,
			scopes,
			consentedScopes: grant.consent.scopes,
			maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
		});
		if (!judgement.eligible) {
			ineligible = marker(judgement.reason);
		} else if (lifetime !== null) {
			// When the token was obtained, on the adapter's reading of the clock —
			// held inside the window of the call, so that a wild `expiresAt` can
			// neither date it in the future nor lengthen its life.
			const obtainedAt = Math.min(Math.max(expiresAtMs - lifetime * 1000, calledAt), receivedAt);
			credentials = {
				refreshToken: response.refreshToken,
				accessToken: {
					value: response.token.accessToken,
					tokenType: response.token.tokenType,
					obtainedAt: new Date(obtainedAt),
					issuedLifetime: lifetime,
					scopes: [...scopes],
				},
			};
		}
	}

	// --- the guarded write, retried only when it THROWS -------------------------
	// Bounded twice: by the clock, and by a count, for a clock that does not move.
	const persistDeadline = receivedAt + limits.persistRetryBudgetMs;
	const attempts = Math.max(1, Math.ceil(limits.persistRetryBudgetMs / PERSIST_RETRY_DELAY_MS));
	const brought = ineligible === null;
	const refreshedAudit: PendingAudit = [
		"federation.grant.refreshed",
		ineligible === null ? "success" : `upstream_token_ineligible/${ineligible.reason}`,
	];
	let threwBefore = false;
	for (let attempt = 0; attempt < attempts; attempt++) {
		const remaining = persistDeadline - deps.now().getTime();
		if (remaining <= 0) break;
		const result = await within(
			settle(() =>
				deps.store.replaceCredentials({
					grantId: grant.id,
					expectedVersion: grant.version,
					credentials,
					ineligible,
					// Sampled at the write: a refresh that straddles the expiry must fail (D2).
					now: deps.now(),
				}),
			),
			remaining,
		);
		// A write that hangs is not waited for past the budget. If it lands
		// later it is still guarded by the version — and until it has had the
		// time to, nobody else is let at the refresh token it replaces.
		if (result === "elapsed") {
			return {
				kind: "denied",
				denial: unavailable("storage"),
				audits: [["federation.grant.refresh_persist_failed", "write_in_flight"]],
				keepLock: true,
			};
		}
		if (result.ok) {
			// A writer whose precondition fails does not use what it fetched (D2).
			// That includes this call's own earlier attempt having landed with its
			// acknowledgement lost: the last look then finds its token stored. The
			// upstream was asked, and may have rotated: that leaves a trail.
			if (!result.value.ok) {
				// Refused on the version — which this call's own earlier attempt
				// bumped, if that one landed and only its acknowledgement was lost.
				// One look, still under the lock, tells the two apart: it is this
				// call's write exactly when what is stored is what it tried to store.
				const left = persistDeadline - deps.now().getTime();
				if (threwBefore && (await isStored(deps, grant, credentials, left))) {
					return { kind: "written", brought, audits: [refreshedAudit] };
				}
				return { kind: "lost", audits: [["federation.grant.refresh_failed", "write_lost"]] };
			}
			return { kind: "written", brought, audits: [refreshedAudit] };
		}
		threwBefore = true;
		failed("write", result.error);
		await after(Math.min(PERSIST_RETRY_DELAY_MS, remaining)).elapsed;
	}
	// The new credentials are dropped. The stored refresh credential is not
	// assumed to be still good: the next refresh decides (D12).
	return {
		kind: "denied",
		denial: unavailable("storage"),
		audits: [["federation.grant.refresh_persist_failed", "storage"]],
	};
}

async function refresh(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
): Promise<FederationGrantTokenResult> {
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
			// against every replica that needs it. Not handed to `background`: it
			// may never arrive, and what is handed over has to settle.
			void asking.then((late) => {
				if (!late.ok || !late.value.acquired) return;
				const arrived = late.value;
				void settle(() => arrived.release());
			});
		}
		report(deps, request, "lock", asked === "elapsed" ? NOT_ANSWERED : asked.error);
		const denial = unavailable("storage");
		return conclude(deps, request, { kind: "deny", denial }, false, denial);
	}
	const lock = asked.value;
	if (!lock.acquired) {
		// Whoever held it may have refreshed. One look, which never refreshes.
		const stored = await evaluate(deps, request, "any");
		return conclude(deps, request, stored, false, unavailable("lock_timeout"));
	}

	// One owner of the release, whichever way this ends. Never waited for by the
	// caller: a lock that is slow to let go of must not turn a refresh that was
	// persisted into an outage.
	const release = async (): Promise<void> => {
		const released = await within(
			settle(() => lock.release()),
			SIDE_EFFECT_WAIT_MS,
		);
		// The lock has a TTL: one that could not be let go of runs out.
		if (released === "elapsed") report(deps, request, "release", NOT_ANSWERED);
		else if (!released.ok) report(deps, request, "release", released.error);
	};

	let held: Extract<Evaluation, { kind: "refresh" }>;
	let refresher: FederationGrantRefresher;
	let leaseStartedAt: number;
	let startedAt: number;
	try {
		// The lease has one clock, started here. Every deadline counts from it:
		// what this call spends under the lock before it asks the upstream is
		// spent of the same lease (D12).
		leaseStartedAt = deps.now().getTime();
		const again = await evaluate(deps, request, "any");
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
			report(
				deps,
				request,
				"refresh",
				new Error("the look under the refresh lock used up the lease; the upstream was not asked"),
			);
			const denial = unavailable("storage");
			return conclude(deps, request, { kind: "deny", denial, grant: again.grant }, false, denial);
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
	// stops waiting at the soft deadline the whole of it does (D12).
	const work = refreshUnderLock(
		deps,
		request,
		held,
		refresher,
		leaseStartedAt + deps.limits.upstreamHardTimeoutMs,
	).catch((error: unknown): RefreshOutcome => {
		// Nothing in there is expected to reject. If something did, the upstream
		// may have been asked, and nothing is known about what it did.
		report(deps, request, "refresh", error);
		return {
			kind: "denied",
			denial: unavailable("upstream"),
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
		// the caller is answered now.
		const denial = unavailable("upstream");
		return conclude(deps, request, { kind: "deny", denial, grant: held.grant }, false, denial);
	}
	if (first.kind === "denied") {
		return conclude(
			deps,
			request,
			{ kind: "deny", denial: first.denial, grant: held.grant },
			false,
			first.denial,
		);
	}
	// Written or lost, the last look is the same: the record as it is NOW, the
	// boundary as it is now, and the token that is stored — never the one this
	// call fetched and holds in a variable.
	// `refreshed` says that what is answered is what this call fetched: a write
	// that brought no access token kept the one the grant had (D5).
	const own = first.kind === "written" && first.brought;
	const stored = await evaluate(deps, request, own ? "own" : "any");
	return conclude(
		deps,
		request,
		stored,
		own,
		// A write that landed was overtaken by nothing: if its token cannot be
		// answered, the upstream's token is what failed the call.
		unavailable(first.kind === "written" ? "upstream" : "concurrent_update"),
	);
}

/**
 * An upstream access token for a federation grant (#593, D10–D12): every
 * retrieval re-evaluates the grant, a call refreshes at most once, and a
 * writer that loses never returns the token it fetched. The package maps the
 * typed result to HTTP and does nothing else.
 *
 * It answers with a typed result for everything its dependencies may do at
 * run time — reject, throw, answer late or answer nonsense. It rejects only
 * for a bug in how it was composed: a `connection`, `refresher` or `now` that
 * throws. Even then no lock is left behind.
 */
export async function retrieveFederationGrantToken(
	deps: RetrieveFederationGrantTokenDeps,
	request: RetrieveFederationGrantTokenRequest,
): Promise<FederationGrantTokenResult> {
	const first = await evaluate(deps, request, "any");
	if (first.kind !== "refresh") {
		return conclude(deps, request, first, false, unavailable("upstream"));
	}
	return refresh(deps, request);
}
