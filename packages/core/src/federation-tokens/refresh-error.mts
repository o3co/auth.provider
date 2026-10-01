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

import { guardedRead, isError, thrownText } from "../logging/loggableError.mjs";
import { isFederationUpstreamOutage } from "./upstreamOutage.mjs";

/**
 * What an upstream federation refresh failed with.
 *
 * - `invalid_grant`: the IdP rejected the refresh token. Only ever read off
 *   its structured `error` (`invalid_grant` or `invalid_token`), and never
 *   under a 429 or during an outage: a caller may end the credential on it.
 * - `rate_limited`: a 429 whatever code it named, or a `too_many_requests`
 *   code even under a 5xx. It judges nothing about the credential.
 * - `network`: unreachable, timed out, or 5xx, whatever the body said.
 * - `unknown`: anything else.
 */
export type FederationRefreshErrorReason = "invalid_grant" | "rate_limited" | "network" | "unknown";

export interface FederationRefreshErrorClassification {
	readonly reason: FederationRefreshErrorReason;
	/**
	 * Whether `reason` came from the error's structured properties rather than
	 * its message. The message fallback is a guess and answers only `network`
	 * or `unknown`: an `invalid_grant` ends a credential, so it is never guessed.
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

/** Transport failure codes Node sets on an error's `code`. */
const NETWORK_CODES: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ENOTFOUND",
	"ETIMEDOUT",
	"EAI_AGAIN",
]);

/** What a field reads as when reading it throws (a getter, a Proxy's trap). */
const UNREADABLE: unique symbol = Symbol("unreadable");

/** `value[key]`, or {@link UNREADABLE}: the thrown value is whatever an adapter threw. */
const field = (value: object, key: string): unknown => {
	const read = guardedRead(value, key);
	return read === null ? UNREADABLE : read.value;
};

/**
 * Finds a `NETWORK_CODES` code on the thrown value or its cause chain: undici
 * throws `TypeError("fetch failed")` with the code on `.cause`, and
 * openid-client v6 rethrows it as-is. The thrown value is read whatever it is,
 * since an adapter may throw a plain object; a cause only when it is an Error,
 * because openid-client's `ResponseBodyError` carries the IdP's parsed body as
 * its cause and a `code` there says nothing about this server's transport.
 * `isFederationUpstreamOutage` follows causes by the same rule.
 */
function extractNetworkCode(error: object): string | undefined | typeof UNREADABLE {
	let cur: unknown = error;
	for (let depth = 0; depth < 4 && cur !== null && typeof cur === "object"; depth++) {
		if (depth > 0 && !isError(cur)) return undefined;
		const code = field(cur, "code");
		if (code === UNREADABLE) return UNREADABLE;
		if (typeof code === "string" && NETWORK_CODES.has(code)) return code;
		cur = field(cur, "cause");
		if (cur === UNREADABLE) return UNREADABLE;
	}
	return undefined;
}

/**
 * The upstream error codes this provider repeats. An allow-list, not a
 * pattern: any pattern that fits `invalid_client` also fits an opaque token,
 * and an upstream that echoes its input must not get a refresh token repeated
 * through this field. Other codes are left out and reported as unknown.
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

/** The fields of the thrown value the structured reading decides by, each read once. */
interface ReadFields {
	readonly code: unknown;
	readonly status: unknown;
	readonly networkCode: string | undefined;
}

function structuredReason(
	error: object,
	{ code, status, networkCode }: ReadFields,
): FederationRefreshErrorReason | undefined {
	// An outage (unreachable, timed out or 5xx, on the error, its Error causes or
	// its Response, or a 5xx `status` on a non-Error an adapter threw) is read
	// before the codes that reject the refresh token. A 5xx is never a verdict
	// on it: an IdP that is down and answers `invalid_grant` must not cost the
	// user their upstream tokens. A 429 is no outage.
	const outage =
		isFederationUpstreamOutage(error) ||
		(typeof status === "number" && status >= 500 && status < 600);
	// A 429 (RFC 6585 §4) asks for less and is no verdict on the refresh token,
	// whatever its body names, so it is read before any code that ends the
	// credential. Some IdPs (Google, Microsoft) echo `too_many_requests` as `.error`.
	if (code === "too_many_requests" || status === 429) return "rate_limited";
	// `.error` is the IdP's RFC 6749 §5.2 code. `invalid_grant` and
	// `invalid_token` (RFC 6750 §3.1) both require re-auth.
	if (!outage && (code === "invalid_grant" || code === "invalid_token")) {
		return "invalid_grant";
	}
	if (outage) return "network";
	// Also catches a network code on a thrown non-Error, which the outage test
	// does not read.
	if (networkCode !== undefined) return "network";
	return undefined;
}

/**
 * Whether a code may be repeated to a caller. The classifier applies the
 * allow-list when it classifies; ask again wherever a reason is built from a
 * stored code, which a fixture, an older version or a keyspace edit may have
 * written. See ADR 2026-09-17-federation-grants-offline-delegation.
 */
export function isKnownFederationRefreshErrorCode(code: unknown): code is string {
	return typeof code === "string" && KNOWN_ERROR_CODES.has(code);
}

/**
 * Classifies what an upstream refresh rejected with. Structured properties
 * (`.error`, `.status`, `.code`, and the outage shapes
 * `isFederationUpstreamOutage` knows) are read first; the message fallback
 * reads an outage only, and `structured` says which of the two answered.
 *
 * `reason` is safe to act on alone: `invalid_grant` is the IdP's structured
 * verdict on the refresh token, never read during an outage or off a message.
 * Never throws: a field that cannot be read makes the error `unknown`.
 */
export function classifyFederationRefreshError(
	error: unknown,
): FederationRefreshErrorClassification {
	const extras: { upstreamCode?: string; retryAfterSeconds?: number } = {};
	if (error !== null && typeof error === "object") {
		const code = field(error, "error");
		const status = field(error, "status");
		const networkCode = extractNetworkCode(error);
		// Nothing read off an error with an unreadable field is safe to act on.
		if (code === UNREADABLE || status === UNREADABLE || networkCode === UNREADABLE) {
			return { reason: "unknown", structured: false };
		}
		if (typeof code === "string" && KNOWN_ERROR_CODES.has(code)) extras.upstreamCode = code;
		const retryAfter = retryAfterSeconds(error);
		if (retryAfter !== undefined) extras.retryAfterSeconds = retryAfter;

		const reason = structuredReason(error, { code, status, networkCode });
		if (reason !== undefined) return { reason, structured: true, ...extras };
	}
	// Message fallback for errors not from openid-client. It reads an outage
	// and nothing else: a message is whatever the library, a proxy or the
	// upstream wrote, so an `invalid_grant` in it ends no credential. An
	// adapter that wants a rejection acted on sets `.error`, as openid-client's
	// `ResponseBodyError` does.
	const msg = thrownText(error);
	if (msg.includes("temporarily_unavailable") || /5\d\d/.test(msg)) {
		return { reason: "network", structured: false, ...extras };
	}
	return { reason: "unknown", structured: false, ...extras };
}
