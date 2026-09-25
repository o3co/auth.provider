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
 * Whether a failed call to an upstream IdP is an OUTAGE — not reached, not
 * answered in time, or answered with a 5xx — rather than the upstream's
 * verdict. The connect callback's code exchange answers the first
 * `temporarily_unavailable` and logs it as an outage, and the second
 * `upstream_error` (#593, D7). A 5xx is an outage here as it is on the
 * refresh path, where core's `classifyFederationRefreshError` reads a 5xx
 * `status` as `network`.
 *
 * Read off what an error IS — its `name`, its `code`, a numeric `status`, on
 * the error or on any of its first causes — and never off what its text
 * says: a message is whatever the library or the upstream wrote, and matching
 * it reads an upstream's description as this provider's outage. The shapes it
 * knows are what openid-client / oauth4webapi and undici throw, held to the
 * real libraries by federation-oidc's `delegated-outage.test.mts`:
 *
 * - `AbortError` / `TimeoutError`, bare or as the cause of openid-client's
 *   `ClientError` `OAUTH_TIMEOUT` — a request given up on;
 * - a connection code from {@link UNREACHABLE}, or `fetch`'s `TypeError` over
 *   a coded cause (the socket's, or the TLS layer's) — nothing answered;
 * - a `status` from 500 to 599 on the error (an OAuth error body under a 5xx)
 *   or on its cause (oauth4webapi's `OAUTH_RESPONSE_IS_NOT_CONFORM` over the
 *   `Response` it would not read) — the upstream answered that it is down.
 *
 * It never throws: every read is guarded.
 */

/** The names a request that was given up on is raised under: `AbortSignal.timeout` raises `TimeoutError`. */
const ABANDONED: ReadonlySet<string> = new Set(["AbortError", "TimeoutError"]);

/** Node's and undici's codes for a connection that could not be made, or was lost. */
const UNREACHABLE: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ECONNRESET",
	"ENOTFOUND",
	"ETIMEDOUT",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EPIPE",
	"UND_ERR_CONNECT_TIMEOUT",
	"UND_ERR_HEADERS_TIMEOUT",
	"UND_ERR_BODY_TIMEOUT",
	"UND_ERR_SOCKET",
]);

/** How many causes deep the chain is followed: the libraries nest two or three. */
const MAX_CAUSE_DEPTH = 4;

/** `value[key]`, or `undefined` when there is nothing to read or the read throws. */
const field = (value: unknown, key: string): unknown => {
	if (value === null || (typeof value !== "object" && typeof value !== "function")) {
		return undefined;
	}
	try {
		return (value as Record<string, unknown>)[key];
	} catch {
		return undefined;
	}
};

const serverError = (status: unknown): boolean =>
	typeof status === "number" && Number.isInteger(status) && status >= 500 && status <= 599;

/** Whether `error`, a failed upstream call, is the upstream's outage rather than its answer. */
export function isFederationUpstreamOutage(error: unknown): boolean {
	let current = error;
	for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth++) {
		if (current === null || current === undefined) return false;
		const name = field(current, "name");
		const code = field(current, "code");
		if (typeof name === "string" && ABANDONED.has(name)) return true;
		if (typeof code === "string" && UNREACHABLE.has(code)) return true;
		if (serverError(field(current, "status"))) return true;
		const cause = field(current, "cause");
		if (name === "TypeError" && typeof field(cause, "code") === "string") return true;
		current = cause;
	}
	return false;
}
