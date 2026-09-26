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
 * verdict. Every path that calls an upstream decides on it:
 *
 * - the refresh-error classifier (`classifyFederationRefreshError` in
 *   `refresh-error.mts`, beside it) reads it before the OAuth codes that
 *   reject a refresh token, so an outage is never a rejected refresh token —
 *   for the session-bound token route and a federation grant's retrieval
 *   alike;
 * - the federation-grant connect callback's code exchange answers an outage
 *   `temporarily_unavailable` and anything else `upstream_error` (#593, D7);
 * - the federation-grant retrieval's refresh answers an outage `503 upstream`
 *   and a refusal `upstream_rejected`.
 *
 * It sits with the classifier, not with the grants, because the classifier
 * reads it and the grants read the classifier.
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
 * - a transport's code on any of them ({@link isTransportCode}: a connection
 *   code, a certificate that could not be verified, undici's, llhttp's, the
 *   TLS layer's, an unparseable URL), whether under `fetch`'s `TypeError` or
 *   raised on its own — nothing answered. Any other code — an adapter's
 *   validation error, even wrapped in a `TypeError` — is not an outage;
 * - a `status` from 500 to 599 on the error (an OAuth error body under a 5xx)
 *   or on its cause (oauth4webapi's `OAUTH_RESPONSE_IS_NOT_CONFORM` over the
 *   `Response` it would not read) — the upstream answered that it is down.
 *
 * It never throws: every read is guarded.
 */

/** The names a request that was given up on is raised under: `AbortSignal.timeout` raises `TimeoutError`. */
const ABANDONED: ReadonlySet<string> = new Set(["AbortError", "TimeoutError"]);

/** The codes a socket reports for a connection that could not be made, or was lost. */
const CONNECTION: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ECONNRESET",
	"ECONNABORTED",
	"ENOTFOUND",
	"ETIMEDOUT",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"EHOSTDOWN",
	"ENETUNREACH",
	"ENETDOWN",
	"ENETRESET",
	"EPIPE",
	"EPROTO",
]);

/**
 * Node's X509 verification codes — OpenSSL's `X509_V_ERR_*` names as Node
 * reports them on a TLS error, all of them: the certificate chain could not
 * be verified, so nothing was asked of the upstream.
 */
const X509_VERIFICATION: ReadonlySet<string> = new Set([
	"UNABLE_TO_GET_ISSUER_CERT",
	"UNABLE_TO_GET_CRL",
	"UNABLE_TO_DECRYPT_CERT_SIGNATURE",
	"UNABLE_TO_DECRYPT_CRL_SIGNATURE",
	"UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
	"CERT_SIGNATURE_FAILURE",
	"CRL_SIGNATURE_FAILURE",
	"CERT_NOT_YET_VALID",
	"CERT_HAS_EXPIRED",
	"CRL_NOT_YET_VALID",
	"CRL_HAS_EXPIRED",
	"ERROR_IN_CERT_NOT_BEFORE_FIELD",
	"ERROR_IN_CERT_NOT_AFTER_FIELD",
	"ERROR_IN_CRL_LAST_UPDATE_FIELD",
	"ERROR_IN_CRL_NEXT_UPDATE_FIELD",
	"OUT_OF_MEM",
	"DEPTH_ZERO_SELF_SIGNED_CERT",
	"SELF_SIGNED_CERT_IN_CHAIN",
	"UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	"CERT_CHAIN_TOO_LONG",
	"CERT_REVOKED",
	"INVALID_CA",
	"PATH_LENGTH_EXCEEDED",
	"INVALID_PURPOSE",
	"CERT_UNTRUSTED",
	"CERT_REJECTED",
	"HOSTNAME_MISMATCH",
]);

/**
 * Families of codes, each the closed vocabulary of its producer, bounded so
 * that a value which merely starts like one is not one: undici's own
 * (`UND_ERR_SOCKET`, `UND_ERR_CLOSED`, … — this server's transport or its
 * composition, a 503 whichever member), llhttp's parser errors
 * (`HPE_INVALID_CONSTANT`, undici's `HTTPParserError`), Node's TLS codes
 * (`ERR_TLS_CERT_ALTNAME_INVALID`) and OpenSSL's (`ERR_SSL_WRONG_VERSION_NUMBER`;
 * OpenSSL 3's `ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE`, one slash in it).
 * foundation's Store transport (`repositories/storeErrors.mts`) keeps the same
 * families for what it may say of a Store it could not reach.
 */
const FAMILIES: readonly RegExp[] = [
	/^UND_ERR_[A-Z_]{1,48}$/,
	/^HPE_[A-Z_]{1,48}$/,
	/^ERR_TLS_[A-Z_]{1,64}$/,
	/^ERR_SSL_[A-Z0-9_]{1,64}(?:\/[A-Z0-9_]{1,64})?$/,
];

/**
 * Whether `code` says the request never got an answer: a connection code
 * ({@link CONNECTION}), a certificate that could not be verified
 * ({@link X509_VERIFICATION}), a member of a transport family
 * ({@link FAMILIES}), or `ERR_INVALID_URL` (a URL `fetch` could not parse —
 * nothing was sent). A closed vocabulary: any other code — an adapter's
 * validation error, a token library's, a programming error — says nothing
 * about the transport, even under `fetch`'s `TypeError`.
 */
const isTransportCode = (code: unknown): boolean =>
	typeof code === "string" &&
	(CONNECTION.has(code) ||
		X509_VERIFICATION.has(code) ||
		code === "ERR_INVALID_URL" ||
		FAMILIES.some((family) => family.test(code)));

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
 * what a peer's parsed body says. Asking never throws. The refresh-error
 * classifier follows a cause by the same test (`refresh-error.mts`).
 */
export const isError = (value: unknown): value is object => {
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
		if (isTransportCode(code)) return true;
		if (serverError(field(current, "status"))) return true;
		// `fetch`'s TypeError says only that the request failed; its cause, one
		// step down, is read by the same rule on the next turn.
		current = field(current, "cause");
	}
	return false;
}
