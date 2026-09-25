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
 * verdict. Both federation-grant paths that call the upstream decide on it:
 * the connect callback's code exchange answers an outage
 * `temporarily_unavailable` and anything else `upstream_error` (#593, D7);
 * the retrieval's refresh answers an outage `503 upstream` — reading it this
 * way beside the refresh-error classifier's `network`, which knows fewer
 * shapes — and a refusal `upstream_rejected`.
 *
 * Read off what the library raised — the `name`, the `code` and a numeric
 * `status` of the error and of its first causes that are themselves Errors
 * (of this realm or another), and the `status` of a `Response` it was raised
 * over (this realm's fetch or another copy's) — and never off what a
 * text says or what a peer wrote: a message is whatever the library or the
 * upstream wrote, and openid-client puts the IdP's parsed error body on a
 * `ResponseBodyError` as its `cause`, where a `status`, a `code` or a `name`
 * would be the IdP's to choose. So the walk follows a cause only into an
 * Error, and reads a status only on an Error or a `Response`; a thrown value
 * that is not an Error is no outage. The shapes it knows are what
 * openid-client / oauth4webapi and undici throw, held to the real libraries
 * by federation-oidc's `delegated-outage.test.mts`:
 *
 * - `AbortError` / `TimeoutError`, bare or as the cause of openid-client's
 *   `ClientError` `OAUTH_TIMEOUT` — a request given up on;
 * - a connection code from {@link UNREACHABLE} on any of them, or `fetch`'s
 *   `TypeError` over an Error whose code is a transport's
 *   ({@link isTransportCode}: a connection code, the TLS layer's, an
 *   unparseable URL) — nothing answered. Any other code under a `TypeError` —
 *   an adapter's validation error wrapped that way — is not an outage;
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

/**
 * The TLS layer's codes, as Node raises them under `fetch`'s `TypeError`: the
 * certificate-verification names OpenSSL gives without a common prefix. The
 * rest of the family is matched by {@link TLS_PREFIXES}.
 */
const TLS_VERIFICATION: ReadonlySet<string> = new Set([
	"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	"UNABLE_TO_GET_ISSUER_CERT",
	"UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	"DEPTH_ZERO_SELF_SIGNED_CERT",
	"SELF_SIGNED_CERT_IN_CHAIN",
	"HOSTNAME_MISMATCH",
]);

/** The TLS families by prefix: `CERT_HAS_EXPIRED`, `ERR_TLS_CERT_ALTNAME_INVALID`, `ERR_SSL_WRONG_VERSION_NUMBER`. */
const TLS_PREFIXES: readonly string[] = ["CERT_", "ERR_TLS_", "ERR_SSL_"];

/**
 * Whether `code`, on the cause of `fetch`'s `TypeError`, says the request
 * never got an answer: a connection code ({@link UNREACHABLE}), the TLS
 * layer's, or `ERR_INVALID_URL` (a URL `fetch` could not parse — nothing was
 * sent). An explicit set: a `TypeError` is also what wraps an adapter's own
 * validation error, whose code says nothing about the transport.
 */
const isTransportCode = (code: unknown): boolean =>
	typeof code === "string" &&
	(UNREACHABLE.has(code) ||
		TLS_VERIFICATION.has(code) ||
		code === "ERR_INVALID_URL" ||
		TLS_PREFIXES.some((prefix) => code.startsWith(prefix)));

/** How many causes deep the chain is followed: the libraries nest two or three. */
const MAX_CAUSE_DEPTH = 4;

/**
 * `value[key]`, or `undefined` when the read throws (a getter, a Proxy's
 * trap). Only ever asked of an Error or a Response.
 */
const field = (value: object, key: string): unknown => {
	try {
		return (value as Record<string, unknown>)[key];
	} catch {
		return undefined;
	}
};

const serverError = (status: unknown): boolean =>
	typeof status === "number" && Number.isInteger(status) && status >= 500 && status <= 599;

/**
 * An Error — this realm's or another's (`Error.isError` where the runtime has
 * it) — and not a plain object shaped like one: what a library raised, never
 * what a peer's parsed body says. Asking never throws.
 */
const isError = (value: unknown): value is object => {
	try {
		const brand = (Error as { isError?: (candidate: unknown) => boolean }).isError;
		if (typeof brand === "function") return brand(value);
		return (
			value instanceof Error ||
			(typeof value === "object" &&
				value !== null &&
				Object.prototype.toString.call(value) === "[object Error]")
		);
	} catch {
		return false;
	}
};

/**
 * A fetch `Response` — what oauth4webapi raises a status it would not read
 * over — of this realm's fetch or of another copy: npm undici's, which a
 * deployment's own `fetch` answers with and oauth4webapi accepts by its tag.
 * Recognised as oauth4webapi recognises one: the global class, or the
 * `Response` tag. A parsed body cannot carry the tag — it is symbol-keyed,
 * and JSON has no symbols — and the walk reaches this only through an Error's
 * cause, so peer-written data still decides nothing. Asking never throws.
 */
const isResponse = (value: unknown): value is object => {
	try {
		return (
			(typeof Response === "function" && value instanceof Response) ||
			Object.prototype.toString.call(value) === "[object Response]"
		);
	} catch {
		return false;
	}
};

/** Whether `error`, a failed upstream call, is the upstream's outage rather than its answer. */
export function isFederationUpstreamOutage(error: unknown): boolean {
	let current = error;
	for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth++) {
		// The Response an error was raised over says what the upstream answered.
		if (isResponse(current)) return serverError(field(current, "status"));
		if (!isError(current)) return false;
		const name = field(current, "name");
		const code = field(current, "code");
		if (typeof name === "string" && ABANDONED.has(name)) return true;
		if (typeof code === "string" && UNREACHABLE.has(code)) return true;
		if (serverError(field(current, "status"))) return true;
		const cause = field(current, "cause");
		if (name === "TypeError" && isError(cause) && isTransportCode(field(cause, "code"))) {
			return true;
		}
		current = cause;
	}
	return false;
}
