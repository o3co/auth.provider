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

import { instantOf } from "../federations/token-lifetime.mjs";
import { isBearerTokenType } from "../federations/token-type.mjs";
import type {
	FederationGrantConnection,
	FederationGrantIneligibilityMarker,
	FederationGrantIneligibilityReason,
	FederationGrantRefreshFailure,
	FederationGrantRefreshFailureInput,
	FederationGrantRefreshFailureKind,
} from "./types.mjs";

/**
 * The stamp a report becomes once the store has counted it: every field
 * named, so a field added to the report must be carried here explicitly.
 */
export function federationGrantRefreshFailureStamp(
	report: FederationGrantRefreshFailureInput,
	count: number,
): FederationGrantRefreshFailure {
	return {
		at: report.at,
		kind: report.kind,
		retryAfterSeconds: report.retryAfterSeconds,
		upstreamCode: report.upstreamCode,
		count,
	};
}

/**
 * Whether every name in `scopes` is in `within`. Exact, on the names the
 * connection configures: an adapter whose IdP answers in another vocabulary
 * normalizes before it reports, or its connections fail closed.
 */
export function scopesWithin(scopes: readonly string[], within: readonly string[]): boolean {
	const allowed = new Set(within);
	return scopes.every((scope) => allowed.has(scope));
}

/**
 * Whether a connection's `maxAccessTokenLifetime` is a maximum at all: a
 * positive, finite number of seconds. Checked here because a hand-built
 * config bypasses the schema. Infinity is not a maximum (residual access
 * would be unbounded); under an unusable maximum no token is eligible.
 */
export function isUsableMaxUpstreamAccessTokenLifetime(maxAccessTokenLifetime: number): boolean {
	return Number.isFinite(maxAccessTokenLifetime) && maxAccessTokenLifetime > 0;
}

export type UpstreamTokenJudgement =
	| { readonly eligible: true }
	| { readonly eligible: false; readonly reason: FederationGrantIneligibilityReason };

/**
 * Whether an upstream access token may be disclosed, judged on every
 * disclosure (cached or fresh) against the connection's CURRENT
 * `maxAccessTokenLifetime`, so lowering it takes effect on the next call.
 *
 * - The lifetime must be finite: a disclosed token cannot be shortened, so
 *   no expiry means unbounded residual access.
 * - It must not exceed the maximum. The ISSUED lifetime is judged, not what
 *   remains, so a token never becomes disclosable by ageing.
 * - Its scopes must be within the user's consent: an IdP that accumulates
 *   consent may answer a refresh with more, and a token cannot be narrowed.
 * - It must be a bearer token (see `federations/token-type.mts`).
 *
 * An unusable maximum is tested by name rather than left to the comparison,
 * since `undefined` or NaN compares false and would admit any lifetime.
 * See ADR 2026-09-17-federation-grants-offline-delegation, D5.
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
 * Whether a marker still says the grant's last refresh brought no
 * disclosable token. The status route never reports such a grant `active`;
 * `/token` still answers the token the grant had while it lasts.
 *
 * A marker is cleared by an eligible refresh, a reauthorization, or a change
 * to the maximum it was judged against — never by time. Changing to an
 * unusable maximum is no fix, so the marker stands (and a NaN maximum must
 * not void it via `NaN === NaN` being false).
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
 * stands. The interval stops a starved grant from rotating its refresh token
 * (risking the credential) and draining a shared upstream rate limit on
 * every request.
 *
 * The marker is outside the authenticated envelope, so one dated more than
 * `allowanceMs` (replica clock skew) ahead is not believed and a retry is
 * due. The wait is rounded up and never exceeds the interval. A marker date
 * that holds no instant (a store's string or `null` included) and NaN
 * arithmetic mean a retry is due, which is safe because
 * `judgeUpstreamAccessToken` still guards disclosure.
 */
export function federationGrantIneligibilityRetry(
	marker: FederationGrantIneligibilityMarker | undefined,
	context: { readonly now: Date; readonly retryAfterMs: number; readonly allowanceMs: number },
): { readonly due: true } | { readonly due: false; readonly retryAfterSeconds: number } {
	if (marker === undefined) return { due: true };
	const at = instantOf(marker.at) ?? Number.NaN;
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
 * The interaction code a `rejected` refresh stamp carries, or `undefined` for
 * any other stamp (an outage or rate limit carrying the same string does not
 * ask for the user). Such a stamp reads as `reauthorization_required` for as
 * long as it stands, regardless of its date, count or retry advice.
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
 * Whether a failed-refresh stamp still keeps `/token` from asking the
 * upstream, and how long a client is told to wait:
 *
 * - `unavailable` — no wait on the FIRST failure in a row: the answer may
 *   have been lost, and an IdP's grace window accepts the old refresh token
 *   only on a prompt retry. From the second failure on, `backoffMs`.
 * - `rate_limited` — the upstream's advice, clamped to
 *   [`backoffMs`, `ceilingMs`].
 * - `rejected` — `ceilingMs`: a configuration fault, like the marker.
 *
 * A stamp dated more than `allowanceMs` ahead, or not a date, does not
 * stand. The wait is rounded up and never exceeds `ceilingMs`.
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
	const at = instantOf(failure.at) ?? Number.NaN;
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
 * The scopes an intent is lodged with: what consent shows and what is
 * requested upstream, in the connection's order, capped by the connection's
 * scopes. The result must keep `openid` (the adapter needs an id_token) and
 * `offline_access` where listed (a grant needs a refresh credential).
 * `allowScopeSubsets = false` (for IdPs that accumulate consent) demands the
 * full set.
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
