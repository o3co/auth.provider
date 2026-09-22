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
 * Core's result union as HTTP (#593, D11).
 *
 * The route adds transport; this is the whole of what it decides about an
 * answer, which is why it is one exhaustive switch in one file. `code` is
 * never widened and `reason` is never turned into prose: within this package
 * `error_description` is a stable identifier a client may switch on, not a
 * sentence — prose is what clients end up parsing when nothing else is
 * offered, and then it can no longer be reworded.
 */

import type {
	FederationGrantReauthorizationResult,
	FederationGrantTokenResult,
} from "@o3co/auth-provider-core";

export interface SerializedFederationGrantResponse {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
	/**
	 * `Retry-After`, when the union said when to come back. Carried for 502
	 * and 503 as well as 429: an ineligible upstream token and a lock that
	 * timed out both know, and a client told only by the throttle retries the
	 * others immediately and for ever.
	 */
	readonly retryAfterSeconds?: number;
}

/** The status D11 gives each code. Exhaustive: a new code is a compile error. */
function statusOf(result: Exclude<FederationGrantTokenResult, { ok: true }>): number {
	switch (result.code) {
		case "grant_not_found":
			return 404;
		// The grant exists and is the caller's; it is not usable yet. Not 404,
		// which would say it does not exist, and not 403, which would say it
		// never will be.
		case "authorization_pending":
		case "invalid_request":
		case "invalid_scope":
		case "invalid_target":
			return 400;
		case "access_denied":
			return 403;
		// 410 Gone, for the four ways a grant has ended — and for the one way it
		// has not, the upstream asking for the user (#616), whose credential is
		// kept: either way the user has to be asked again, and no amount of
		// retrying changes that.
		case "grant_expired":
		case "grant_revoked":
		case "connection_identity_changed":
		case "reauthorization_required":
			return 410;
		// 502: this provider reached the upstream and what came back cannot be
		// handed on. The caller did nothing wrong and neither did this
		// provider.
		case "upstream_token_ineligible":
		case "upstream_rejected":
			return 502;
		case "rate_limited":
			return 429;
		case "temporarily_unavailable":
			return 503;
	}
}

export function serializeFederationGrantTokenResult(
	result: FederationGrantTokenResult,
): SerializedFederationGrantResponse {
	if (result.ok) {
		return {
			status: 200,
			body: {
				access_token: result.accessToken,
				// The upstream's own spelling: RFC 6749 §7.1 makes it
				// case-insensitive, and a client comparing it exactly should see
				// what the upstream said rather than what this route preferred.
				token_type: result.tokenType,
				// Always present, including `0` and `""`: a client that reads
				// `expires_in` to schedule its next call must not have to guess
				// whether an absent field means "for ever" or "already gone".
				expires_in: result.expiresIn,
				scope: result.scopes.join(" "),
			},
		};
	}
	const reason = (result as { reason?: unknown }).reason;
	const retryAfterSeconds = (result as { retryAfterSeconds?: number }).retryAfterSeconds;
	return {
		status: statusOf(result),
		body: {
			error: result.code,
			...(typeof reason === "string" ? { error_description: reason } : {}),
		},
		...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
	};
}

// ---------------------------------------------------------------------------
// Slice 6: lodging's refusals as HTTP (D6), in the same vocabulary — `error` a
// code, `error_description` a stable identifier, never prose.
// ---------------------------------------------------------------------------

type LodgingRefusal = Exclude<FederationGrantReauthorizationResult, { ok: true }>;

/** Exhaustive: a new refusal is a compile error here, not a 500 in production. */
export function serializeFederationGrantLodgingRefusal(
	result: LodgingRefusal,
): SerializedFederationGrantResponse {
	const answer = (status: number, error: string, description?: string) => ({
		status,
		body: { error, ...(description === undefined ? {} : { error_description: description }) },
	});
	switch (result.reason) {
		case "connection_not_permitted":
			return answer(403, "access_denied", result.reason);
		// The client asked for something the deployment should have; it is the
		// deployment that is wrong, and it may be put right without the client.
		case "connection_not_configured":
		case "storage":
		case "key_unavailable":
			return answer(503, "temporarily_unavailable", result.reason);
		case "redirect_uri_not_registered":
		case "redirect_uri_invalid":
		case "redirect_uri_reserved_parameter":
		case "expires_in_out_of_range":
		case "connection_mismatch":
			return answer(400, "invalid_request", result.reason);
		case "scope_exceeded":
		case "openid_required":
		case "offline_access_required":
		case "scope_subsets_not_allowed":
			return answer(400, "invalid_scope", result.reason);
		// The bound is on this client and this user: the client's own throttle,
		// in the words this package's throttle already uses.
		case "intent_limit":
			return answer(429, "rate_limited", result.reason);
		case "grant_not_found":
			return answer(404, "grant_not_found");
		case "authorization_pending":
			return answer(400, "authorization_pending");
		case "grant_revoked":
			return answer(410, "grant_revoked", result.revokedBy);
		case "grant_expired":
			return answer(410, "grant_expired", result.expiredBy);
		case "connection_identity_changed":
			return answer(410, "connection_identity_changed");
		case "upstream_token_ineligible":
			return answer(502, "upstream_token_ineligible", result.ineligibleBy);
	}
}
