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
 * Whether a failed upstream IdP call is an OUTAGE (not reached, timed out, or
 * answered 5xx) rather than the upstream's verdict. The refresh-error
 * classifier (`refresh-error.mts`) checks it before the OAuth codes that
 * reject a refresh token, and the federation-grant connect callback and
 * retrieval answer an outage `temporarily_unavailable` / `503 upstream`
 * instead of treating it as a refusal.
 *
 * Decided only from what the library raised, never from text or peer-written
 * data: openid-client puts the IdP's parsed error body on a
 * `ResponseBodyError` as `cause`, where `status`, `code` and `name` are the
 * IdP's to choose. So the walk follows a cause only into an Error (of any
 * realm), reads a status only on an Error or a `Response`, and a thrown
 * non-Error is no outage. Recognised shapes, pinned to the real openid-client,
 * oauth4webapi and undici by federation-oidc's `delegated-outage.test.mts`:
 * - `AbortError` / `TimeoutError`, bare or as the cause of openid-client's
 *   `OAUTH_TIMEOUT`;
 * - a transport code ({@link isTransportCode}), under `fetch`'s `TypeError`
 *   or on its own; any other code, even under a `TypeError`, is not;
 * - a 5xx `status` on the error, or on the `Response` it was raised over.
 *
 * Never throws: every read is guarded.
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
 * Code families, each its producer's closed vocabulary, anchored and bounded
 * so a value that merely starts like one does not match: undici's
 * (`UND_ERR_*`), llhttp's parser errors (`HPE_*`), Node's TLS codes
 * (`ERR_TLS_*`) and OpenSSL's (`ERR_SSL_*`; an OpenSSL 3 code may hold one
 * slash). `repositories/storeErrors.mts` keeps the same families.
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
