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

import type {
	FederationGrantConnection,
	FederationGrantIneligibilityMarker,
	FederationGrantIneligibilityReason,
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
	return { eligible: true };
}

/**
 * Whether a marker still says the grant cannot yield a token. This is what the
 * status route reports (D5, D9): it never calls a grant `active` that cannot
 * be used.
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
 * The wait is rounded up, so a client is never told to retry in zero seconds,
 * and clamped to the interval: the marker is outside the authenticated
 * envelope, so whoever can write the record can date it in the future. When
 * the arithmetic is not a number a retry is due. That is the safe direction
 * here, because `judgeUpstreamAccessToken` still guards what is disclosed.
 */
export function federationGrantIneligibilityRetry(
	marker: FederationGrantIneligibilityMarker | undefined,
	context: { readonly now: Date; readonly retryAfterMs: number },
): { readonly due: true } | { readonly due: false; readonly retryAfterSeconds: number } {
	if (marker === undefined) return { due: true };
	const remainingMs = marker.at.getTime() + context.retryAfterMs - context.now.getTime();
	if (!(remainingMs > 0)) return { due: true };
	return {
		due: false,
		retryAfterSeconds: Math.ceil(Math.min(remainingMs, context.retryAfterMs) / 1000),
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
