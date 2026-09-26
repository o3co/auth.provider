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

import { isError, isFederationUpstreamOutage } from "./upstreamOutage.mjs";

/**
 * SF-13 — what an upstream federation refresh failed with.
 *
 * - `invalid_grant`: the IdP rejected the refresh token (revoked, expired,
 *   mismatched). Only ever the IdP's structured answer — an `error` of
 *   `invalid_grant` or `invalid_token` on what the library raised — and never
 *   under a 429 or during an outage: a caller may end the credential on it.
 * - `rate_limited`: the IdP answered 429, whatever code it named, or named
 *   `too_many_requests` — under a 5xx too: asked to slow down, a caller does,
 *   and the upstream has judged nothing about the credential.
 * - `network`: the IdP could not be reached, did not answer in time, or
 *   answered 5xx — whatever else its body said.
 * - `unknown`: anything else.
 */
export type FederationRefreshErrorReason = "invalid_grant" | "rate_limited" | "network" | "unknown";

export interface FederationRefreshErrorClassification {
	readonly reason: FederationRefreshErrorReason;
	/**
	 * Whether `reason` was read off the error's structured properties, and not
	 * matched in its message. The message fallback is a guess, so it answers
	 * only `network` or `unknown`: an `invalid_grant` is always structured,
	 * because acting on one ends a credential — the session's upstream tokens,
	 * or a federation grant's, whose user goes through consent again (#593,
	 * D12).
	 */
	readonly structured: boolean;
	/**
	 * The upstream's error code, when it is one this provider knows. Never a
	 * message, and never an unknown string: a caller may put this in a response.
	 */
	readonly upstreamCode?: string;
	/** Whole seconds, from the response's `Retry-After`, when it named a usable number. */
	readonly retryAfterSeconds?: number;
}

/**
 * Node/undici fetch failures bubble up as `TypeError("fetch failed")` with the
 * underlying network error code on `.cause.code` (one level deep).
 * openid-client v6 rethrows these as-is. Walk the cause chain so
 * `ECONNREFUSED` / `ENOTFOUND` / `ETIMEDOUT` reach the `network` classification
 * regardless of whether the code lands on the top-level error or its `cause`.
 *
 * The code is read on the thrown value itself, whatever it is — a hand-written
 * adapter may throw a plain object — and on a cause only when that cause is an
 * Error: openid-client's `ResponseBodyError` carries the IdP's parsed JSON body
 * as its cause, and a `code` the IdP wrote there says nothing about this
 * server's transport. `isFederationUpstreamOutage` follows causes by the same
 * rule.
 */
const NETWORK_CODES: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ENOTFOUND",
	"ETIMEDOUT",
	"EAI_AGAIN",
]);

function extractNetworkCode(error: unknown): string | undefined {
	let cur: unknown = error;
	for (let depth = 0; depth < 4 && cur !== null && typeof cur === "object"; depth++) {
		if (depth > 0 && !isError(cur)) return undefined;
		const code = (cur as { code?: unknown }).code;
		if (typeof code === "string" && NETWORK_CODES.has(code)) return code;
		cur = (cur as { cause?: unknown }).cause;
	}
	return undefined;
}

/**
 * The error codes this provider repeats. An allow-list, and not a pattern: any
 * pattern that fits `invalid_client` fits an opaque token as well, and an
 * upstream that echoes what it was sent must not get a refresh token repeated
 * through this field. Anything else an upstream sends is left out, and a
 * caller reports it as unknown.
 */
export const KNOWN_ERROR_CODES: ReadonlySet<string> = new Set([
	// RFC 6749 §5.2 — the token endpoint.
	"invalid_request",
	"invalid_client",
	"invalid_grant",
	"unauthorized_client",
	"unsupported_grant_type",
	"invalid_scope",
	// RFC 6749 §4.1.2.1, which IdPs also answer a token request with.
	"access_denied",
	"server_error",
	"temporarily_unavailable",
	// RFC 6750 §3.1, RFC 8707 §2, RFC 6585 §4 as some IdPs echo it.
	"invalid_token",
	"insufficient_scope",
	"invalid_target",
	"too_many_requests",
	// OpenID Connect Core §3.1.2.6.
	"interaction_required",
	"login_required",
	"consent_required",
	"account_selection_required",
]);

/** A day: beyond it a `Retry-After` is not advice a worker can use. */
const MAX_RETRY_AFTER_SECONDS = 86_400;

function retryAfterSeconds(error: object): number | undefined {
	try {
		const headers = (error as { response?: { headers?: { get?: unknown } } }).response?.headers;
		if (headers === undefined || typeof headers.get !== "function") return undefined;
		const value: unknown = headers.get("retry-after");
		// Delta-seconds only. The HTTP-date form would need this process's clock
		// to agree with the upstream's.
		if (typeof value !== "string" || !/^\d{1,8}$/.test(value)) return undefined;
		const seconds = Number(value);
		return seconds >= 1 && seconds <= MAX_RETRY_AFTER_SECONDS ? seconds : undefined;
	} catch {
		// An error object is whatever an adapter threw; reading it must not throw.
		return undefined;
	}
}

function structuredReason(error: object): FederationRefreshErrorReason | undefined {
	const e = error as { error?: unknown; status?: unknown };
	// An outage is read before the codes that reject the refresh token: the
	// upstream could not be reached, did not answer in time, or answered 5xx — on the error, its
	// Error causes or the Response it was raised over (`isFederationUpstreamOutage`),
	// or a 5xx status on a thrown value that is not an Error, which a hand-written
	// adapter may throw. A 5xx is never a verdict on the refresh token, whatever
	// its body says: an IdP that is down and answers `invalid_grant` must not
	// cost the user their upstream tokens. A 429 is no outage.
	const outage =
		isFederationUpstreamOutage(error) ||
		(typeof e.status === "number" && e.status >= 500 && e.status < 600);
	// Rate-limit indicators per RFC 6749 token-endpoint behavior + RFC 6585 §4,
	// read before any code that would end the credential: a 429 is the upstream
	// asking for less, not a verdict on the refresh token, whatever its body
	// names. RFC 6585 defines `too_many_requests` as an HTTP status name — some
	// IdPs (Google, Microsoft) echo it back as the error code in `.error`.
	if (e.error === "too_many_requests" || e.status === 429) return "rate_limited";
	// openid-client v6 surfaces token-endpoint errors with `.error` populated
	// from the IdP response body (RFC 6749 §5.2 error codes). `invalid_grant` is
	// the canonical "refresh token rejected"; `invalid_token` is RFC 6750 §3.1 —
	// both require re-auth.
	if (!outage && (e.error === "invalid_grant" || e.error === "invalid_token")) {
		return "invalid_grant";
	}
	if (outage) return "network";
	// Node network-layer failures: ECONNREFUSED / ENOTFOUND / ETIMEDOUT may be on
	// the top-level error (legacy adapters) or wrapped as `.cause` of a TypeError
	// thrown by undici/fetch (openid-client v6's transport) — here also when the
	// thrown value itself is not an Error, which the outage test does not read.
	// Never in a cause that is not an Error: that is a peer's parsed body.
	if (extractNetworkCode(error) !== undefined) return "network";
	return undefined;
}

/**
 * Whether a code may be repeated to a caller (#593, D11, D18).
 *
 * The allow-list above is applied where a classification is *made*, and a
 * stamped code is read back where one is *remembered* (D12) — a stamp a
 * fixture seeded, a version wrote before this list, or someone edited in the
 * keyspace would otherwise reach a caller unchecked. So the same question is
 * asked again wherever a reason is built from stored data, which is what keeps
 * D11's promise true rather than merely intended.
 */
export function isKnownFederationRefreshErrorCode(code: unknown): code is string {
	return typeof code === "string" && KNOWN_ERROR_CODES.has(code);
}

/**
 * Classifies what an upstream refresh rejected with. Structured properties
 * (`.error`, `.status`, `.code`, and the outage shapes
 * `isFederationUpstreamOutage` knows) are read first; the message fallback is
 * defense-in-depth for legacy or non-openid-client errors, reads an outage
 * only, and `structured` says which of the two answered.
 *
 * `reason` is safe to act on alone: `invalid_grant` is the IdP's structured
 * verdict on the refresh token, and never read during an outage or off a
 * message. The session-bound token route acts on it so; the federation grant
 * retrieval (#593, D12) is the second caller.
 */
export function classifyFederationRefreshError(
	error: unknown,
): FederationRefreshErrorClassification {
	const extras: { upstreamCode?: string; retryAfterSeconds?: number } = {};
	if (error !== null && typeof error === "object") {
		const code = (error as { error?: unknown }).error;
		if (typeof code === "string" && KNOWN_ERROR_CODES.has(code)) extras.upstreamCode = code;
		const retryAfter = retryAfterSeconds(error);
		if (retryAfter !== undefined) extras.retryAfterSeconds = retryAfter;

		const reason = structuredReason(error);
		if (reason !== undefined) return { reason, structured: true, ...extras };
	}
	// Defense-in-depth string fallback for non-openid-client errors (legacy
	// stubs, mocks, custom adapters). It reads an outage and nothing else: a
	// message is whatever the library, a proxy or the upstream wrote, so an
	// `invalid_grant` in it is not the IdP's verdict and ends no credential.
	// An adapter that throws a plain `Error("invalid_grant: ...")` is read as
	// `unknown`; to have a rejection acted on it sets `.error`, as
	// openid-client's `ResponseBodyError` does.
	const msg = error instanceof Error ? error.message : String(error);
	if (msg.includes("temporarily_unavailable") || /5\d\d/.test(msg)) {
		return { reason: "network", structured: false, ...extras };
	}
	return { reason: "unknown", structured: false, ...extras };
}
