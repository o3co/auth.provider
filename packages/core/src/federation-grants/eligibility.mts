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

import { isBearerTokenType } from "../federations/token-type.mjs";
import type {
	FederationGrantConnection,
	FederationGrantIneligibilityMarker,
	FederationGrantIneligibilityReason,
	FederationGrantRefreshFailure,
	FederationGrantRefreshFailureKind,
} from "./types.mjs";

/**
 * Whether every name in `scopes` is in `within`. Exact, on the names the
 * connection configures: an adapter whose IdP answers in another vocabulary
 * normalizes before it reports, or its connections fail closed (#593, D7).
 */
export function scopesWithin(scopes: readonly string[], within: readonly string[]): boolean {
	const allowed = new Set(within);
	return scopes.every((scope) => allowed.has(scope));
}

/**
 * Whether a connection's `maxAccessTokenLifetime` is a maximum at all: a
 * positive, finite number of seconds. A schema guarantees that, and a
 * hand-built config bypasses a schema (#448).
 *
 * Infinity is not one. Every finite lifetime is within it, so residual access
 * (D15) would be a number nobody chose; admitting unbounded tokens is an
 * opt-in the ADR leaves for later (D5). Under a maximum that is not usable no
 * token is eligible, and the three rules below all say so.
 */
export function isUsableMaxUpstreamAccessTokenLifetime(maxAccessTokenLifetime: number): boolean {
	return Number.isFinite(maxAccessTokenLifetime) && maxAccessTokenLifetime > 0;
}

export type UpstreamTokenJudgement =
	| { readonly eligible: true }
	| { readonly eligible: false; readonly reason: FederationGrantIneligibilityReason };

/**
 * Whether an upstream access token may be disclosed (#593, D5).
 *
 * It guards every disclosure, cached or fresh, against the connection's
 * CURRENT `maxAccessTokenLifetime` — so lowering that takes effect on the next
 * call, and not when a cached token happens to run out.
 *
 * - The lifetime must be finite. A provider cannot shorten what a token it
 *   already handed out still allows, so a token with no expiry would make
 *   residual access unbounded.
 * - It must not exceed the maximum. "Finite" alone would admit a 30-day token;
 *   the maximum is what turns residual access into a number the operator chose.
 *   The lifetime judged is the one the token was ISSUED with, not what remains
 *   of it, so a token does not become disclosable by ageing.
 * - The scopes it carries must be within what the user consented to. An IdP
 *   that accumulates consent answers a refresh with every scope the user has
 *   since granted to the same upstream client, and an upstream token cannot be
 *   narrowed after the fact.
 * - It must be a bearer token, however the upstream spells it. The comparison
 *   and the reason for it live in `federations/token-type.mts`, next to the
 *   port that declares the field, because `POST /oauth/federation/:name/token`
 *   discloses an upstream token too and asks the same question (#645).
 *
 * A maximum that is not usable refuses every token. It is tested by name, and
 * not left to the comparison: a hand-built config that omits the key hands
 * `undefined` through a cast, every comparison with `undefined` or NaN is
 * false, and "is it over?" would answer no for a 30-day token — while
 * Infinity compares well and admits all of them.
 */
export function judgeUpstreamAccessToken(token: {
	/** Seconds, as issued; `null` when the upstream named no finite lifetime. */
	readonly issuedLifetime: number | null;
	readonly scopes: readonly string[];
	readonly consentedScopes: readonly string[];
	/** Seconds. */
	readonly maxAccessTokenLifetime: number;
	/** As the upstream answered it; compared without regard to case. */
	readonly tokenType: string;
}): UpstreamTokenJudgement {
	const lifetime = token.issuedLifetime;
	if (lifetime === null || !Number.isFinite(lifetime) || lifetime <= 0) {
		return { eligible: false, reason: "no_finite_lifetime" };
	}
	if (
		!isUsableMaxUpstreamAccessTokenLifetime(token.maxAccessTokenLifetime) ||
		!(lifetime <= token.maxAccessTokenLifetime)
	) {
		return { eligible: false, reason: "lifetime_over_maximum" };
	}
	if (!scopesWithin(token.scopes, token.consentedScopes)) {
		return { eligible: false, reason: "scope_exceeded" };
	}
	if (!isBearerTokenType(token.tokenType)) {
		return { eligible: false, reason: "token_type_unsupported" };
	}
	return { eligible: true };
}

/**
 * Whether a marker still says the grant's last refresh brought no token that
 * could be disclosed. This is what the status route reports (D5, D9): it never
 * calls a grant `active` that cannot be refreshed into a usable token. The
 * converse does not hold: `/token` goes on answering the token the grant had,
 * while that one lasts, under a marker that stands.
 *
 * Three things clear a marker: an eligible refresh, a reauthorization, and a
 * change to the maximum it was judged against — the operator fixing the
 * setting must not have to wait. Time is not one of them. The retry interval
 * below limits how often `/token` tries again; it says nothing about whether
 * the next try will succeed.
 *
 * A change to a maximum that is not usable is no fix: every token is refused
 * under it, so the marker stands. Comparing alone would void it — and a marker
 * judged against NaN would never stand at all, `NaN === NaN` being false,
 * which puts back the refresh on every call the marker exists to prevent.
 */
export function federationGrantIneligibilityStands(
	marker: FederationGrantIneligibilityMarker | undefined,
	/** Seconds; the connection's current value. */
	maxAccessTokenLifetime: number,
): boolean {
	if (marker === undefined) return false;
	if (!isUsableMaxUpstreamAccessTokenLifetime(maxAccessTokenLifetime)) return true;
	return marker.judgedAgainst === maxAccessTokenLifetime;
}

/**
 * Whether `/token` may call the upstream again for a grant whose marker
 * stands. Without the interval a starved grant would take the lock, call the
 * upstream and rotate the refresh token on every request — each rotation
 * another chance to lose the credential, and a drain on an upstream rate limit
 * that other grants share.
 *
 * The marker is outside the authenticated envelope, so whoever can write the
 * record can date it in the future. One dated further ahead than `allowanceMs`
 * — what replicas' clocks may differ by, and the refresh buffer absorbs — is
 * not believed, and a retry is due: clamping only what the client is TOLD
 * would leave such a marker standing until its date caught up. The wait is
 * rounded up, so a client is never told to retry in zero seconds, and never
 * longer than the interval. When the arithmetic is not a number a retry is
 * due. That is the safe direction here, because `judgeUpstreamAccessToken`
 * still guards what is disclosed.
 */
export function federationGrantIneligibilityRetry(
	marker: FederationGrantIneligibilityMarker | undefined,
	context: { readonly now: Date; readonly retryAfterMs: number; readonly allowanceMs: number },
): { readonly due: true } | { readonly due: false; readonly retryAfterSeconds: number } {
	if (marker === undefined) return { due: true };
	const at = marker.at.getTime();
	const now = context.now.getTime();
	if (!(at <= now + context.allowanceMs)) return { due: true };
	const remainingMs = at + context.retryAfterMs - now;
	if (!(remainingMs > 0)) return { due: true };
	return {
		due: false,
		retryAfterSeconds: Math.ceil(Math.min(remainingMs, context.retryAfterMs) / 1000),
	};
}

/**
 * The codes an IdP answers a refresh with when it wants the user, and not a
 * new token (OIDC Core §3.1.2.6, echoed by RFC 6749 §5.2 token endpoints):
 * conditional access changed under a paused job, a consent was withdrawn, a
 * session policy demands a fresh sign-in. None of them says the refresh token
 * is bad — the next refresh after the user returns may well succeed — so the
 * credential is kept, and none of them is mended by waiting.
 */
export const FEDERATION_GRANT_INTERACTION_CODES = [
	"interaction_required",
	"login_required",
	"consent_required",
	"account_selection_required",
] as const;

export type FederationGrantInteractionCode = (typeof FEDERATION_GRANT_INTERACTION_CODES)[number];

const INTERACTION_CODES: ReadonlySet<string> = new Set(FEDERATION_GRANT_INTERACTION_CODES);

/**
 * What a stamp remembers when a refresh was refused for the user's absence
 * (#616, D11, D12): the code, when the stamp is a refusal carrying one of the
 * four, and `undefined` for every other stamp — an outage or a rate limit that
 * happens to carry the same string is not the user being asked for. A stamp
 * that answers here reads as `reauthorization_required` for as long as it
 * stands, whatever its date, its count or its retry advice say: those are the
 * timed backoff's, and time mends nothing here.
 */
export function federationGrantInteractionCode(
	failure: FederationGrantRefreshFailure | undefined,
): FederationGrantInteractionCode | undefined {
	if (failure === undefined || failure.kind !== "rejected") return undefined;
	return isFederationGrantInteractionCode(failure.upstreamCode) ? failure.upstreamCode : undefined;
}

/** Whether an upstream's error code — one the classifier read off the error's own field — is one of the four. */
export function isFederationGrantInteractionCode(
	code: unknown,
): code is FederationGrantInteractionCode {
	return typeof code === "string" && INTERACTION_CODES.has(code);
}

/**
 * Whether the stamp of a failed refresh (D12) still keeps `/token` from asking
 * the upstream, and for how long a client is told to wait. What the wait is
 * depends on what failed:
 *
 * - `unavailable` — nothing for the FIRST failure in a row: the request may
 *   have been processed and its answer lost, and an IdP that keeps a grace
 *   window for exactly that takes the old refresh token back on a prompt
 *   retry, not a late one. The next poll is that retry. From the second
 *   failure on, `backoffMs`.
 * - `rate_limited` — the upstream's advice, never less than `backoffMs` and
 *   never more than `ceilingMs`: a 429 was not processed, and there is
 *   nothing to recover promptly.
 * - `rejected` — `ceilingMs`: an error code this provider knows is a
 *   configuration fault, the marker's class of problem, and gets the marker's
 *   interval.
 *
 * A stamp dated further ahead than `allowanceMs` is not believed (as the
 * marker above), one that is not a date does not stand, and the wait a
 * client is told is rounded up and never longer than `ceilingMs`.
 */
export function federationGrantRefreshFailureStands(
	failure: FederationGrantRefreshFailure | undefined,
	context: {
		readonly now: Date;
		readonly allowanceMs: number;
		readonly backoffMs: number;
		readonly ceilingMs: number;
	},
):
	| { readonly stands: false }
	| {
			readonly stands: true;
			readonly kind: FederationGrantRefreshFailureKind;
			readonly retryAfterSeconds: number;
	  } {
	if (failure === undefined) return { stands: false };
	const at = failure.at.getTime();
	const now = context.now.getTime();
	if (!(at <= now + context.allowanceMs)) return { stands: false };
	let waitMs: number;
	switch (failure.kind) {
		case "unavailable":
			waitMs = failure.count > 1 ? context.backoffMs : 0;
			break;
		case "rate_limited":
			waitMs = Math.max(context.backoffMs, (failure.retryAfterSeconds ?? 0) * 1000);
			break;
		case "rejected":
			waitMs = context.ceilingMs;
			break;
	}
	// No wait is no wait, whatever the date says: a replica that runs ahead
	// within the allowance must not turn the prompt retry into a short one.
	if (!(waitMs > 0)) return { stands: false };
	// The ceiling bounds what the stamp does, and not only what the client is
	// told: a backoff set above it is held to it here as well.
	const remainingMs = at + Math.min(waitMs, context.ceilingMs) - now;
	if (!(remainingMs > 0)) return { stands: false };
	return {
		stands: true,
		kind: failure.kind,
		retryAfterSeconds: Math.ceil(Math.min(remainingMs, context.ceilingMs) / 1000),
	};
}

export type FederationGrantIntentScopes =
	| { readonly ok: true; readonly scopes: readonly string[] }
	| {
			readonly ok: false;
			readonly reason: "outside_connection" | "required_scope_missing" | "subsets_not_allowed";
	  };

/**
 * The scopes an intent is lodged with (#593, D6): what consent will show and
 * what is requested upstream, in the order the connection lists them. The
 * connection's scopes are the ceiling.
 *
 * The result always keeps `openid`, because the adapter requires an id_token,
 * and `offline_access` where the connection lists it, because a grant without
 * a refresh credential is not one. That is one rule, applied to the set that
 * was resolved — whether the full set was asked for by name, by omission, or
 * forced by `allowScopeSubsets = false`, which a connection on an IdP that
 * accumulates consent sets (D19).
 */
export function resolveFederationGrantIntentScopes(
	requested: readonly string[] | undefined,
	connection: Pick<FederationGrantConnection, "scopes" | "allowScopeSubsets">,
): FederationGrantIntentScopes {
	const full = [...new Set(connection.scopes)];
	const asked = requested === undefined ? new Set(full) : new Set(requested);

	if (!scopesWithin([...asked], full)) return { ok: false, reason: "outside_connection" };
	const scopes = full.filter((scope) => asked.has(scope));

	if (connection.allowScopeSubsets === false && scopes.length !== full.length) {
		return { ok: false, reason: "subsets_not_allowed" };
	}
	const required = ["openid", ...(full.includes("offline_access") ? ["offline_access"] : [])];
	if (!scopesWithin(required, scopes)) return { ok: false, reason: "required_scope_missing" };
	return { ok: true, scopes };
}
