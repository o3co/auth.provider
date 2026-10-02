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
 * realm) or a `Response`, and reads fields only on those. A thrown non-Error
 * is no outage itself; only its `cause` is read, and followed by that rule:
 * an adapter may throw its own object over a library's error. Recognised
 * shapes, pinned to the real openid-client,
 * oauth4webapi and undici by federation-oidc's `delegated-outage.test.mts`:
 * - `AbortError` / `TimeoutError`, bare or as the cause of openid-client's
 *   `OAUTH_TIMEOUT`;
 * - a transport code ({@link isTransportCode}), under `fetch`'s `TypeError`
 *   or on its own; any other code, even under a `TypeError`, is not;
 * - a 5xx `status` on the error, or on the `Response` it was raised over.
 *
 * Never throws: every read is guarded.
 */

import { guardedRead, isError } from "../logging/loggableError.mjs";

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

const serverError = (status: unknown): boolean =>
	typeof status === "number" && Number.isInteger(status) && status >= 500 && status <= 599;

/**
 * A fetch `Response` — what oauth4webapi raises a status it would not read
 * over — of this realm's fetch or of another copy: npm undici's, which a
 * deployment's own `fetch` answers with and oauth4webapi accepts by its tag.
 * Recognised as oauth4webapi recognises one: the global class, or the
 * `Response` tag. A parsed body cannot carry the tag — it is symbol-keyed,
 * and JSON has no symbols — so peer-written data still decides nothing.
 * Asking never throws.
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

/**
 * What the walk read: an outage; none; or none found while a field it read
 * threw (a getter, a Proxy's trap), so a field it could not read might have
 * held one. Internal to core: the refresh-error classifier acts on no
 * verdict beside an `unreadable`.
 */
export type FederationUpstreamOutageReading = "outage" | "none" | "unreadable";

/** The walk {@link isFederationUpstreamOutage} answers from, saying when it could not read a field. */
export function readFederationUpstreamOutage(error: unknown): FederationUpstreamOutageReading {
	let unreadable = false;
	// `value[key]`, read as absent when the read throws, and remembered.
	// Asked of an Error or a Response, and of a thrown non-Error for its `cause` alone.
	const field = (value: object, key: string): unknown => {
		const read = guardedRead(value, key);
		if (read === null) unreadable = true;
		return read?.value;
	};
	const found = (outage: boolean): FederationUpstreamOutageReading =>
		outage ? "outage" : unreadable ? "unreadable" : "none";
	let current = error;
	if (
		typeof current === "object" &&
		current !== null &&
		!isError(current) &&
		!isResponse(current)
	) {
		current = field(current, "cause");
	}
	for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth++) {
		// The Response an error was raised over says what the upstream answered.
		if (isResponse(current)) return found(serverError(field(current, "status")));
		if (!isError(current)) return found(false);
		const name = field(current, "name");
		const code = field(current, "code");
		if (typeof name === "string" && ABANDONED.has(name)) return "outage";
		if (isTransportCode(code)) return "outage";
		if (serverError(field(current, "status"))) return "outage";
		// `fetch`'s TypeError says only that the request failed; its cause, one
		// step down, is read by the same rule on the next turn.
		current = field(current, "cause");
	}
	return found(false);
}

/**
 * Whether `error`, a failed upstream call, is the upstream's outage rather
 * than its answer. A field it cannot read is read as absent.
 */
export function isFederationUpstreamOutage(error: unknown): boolean {
	return readFederationUpstreamOutage(error) === "outage";
}

/** The connection codes of a request that never left: no connection was made. */
const NOT_SENT: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ENOTFOUND",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"EHOSTDOWN",
	"ENETUNREACH",
	"ENETDOWN",
	"UND_ERR_CONNECT_TIMEOUT",
	"ERR_INVALID_URL",
]);

const HTTP_ERROR = (status: unknown): boolean =>
	typeof status === "number" && Number.isInteger(status) && status >= 400 && status <= 599;

/**
 * Whether what a failed upstream call did is known, and it issued nothing:
 * the upstream answered with an HTTP error status (on the error, an Error
 * cause, or the `Response` it was raised over), the thrown value carries the
 * upstream's own error code (`.error`), or the request never left — refused,
 * unresolvable, unreachable, a connection that timed out before it was made,
 * a certificate or TLS handshake that failed. A request given up on
 * (`AbortError`, `TimeoutError`), a connection lost once the request may have
 * been sent, anything else, and a field that cannot be read are not: the
 * upstream may have acted on it. Read by the rule
 * {@link readFederationUpstreamOutage} reads by. Never throws.
 */
export function isDefiniteFederationUpstreamFailure(error: unknown): boolean {
	let unreadable = false;
	const field = (value: unknown, key: string): unknown => {
		const read = guardedRead(value as object, key);
		if (read === null) unreadable = true;
		return read?.value;
	};
	if (typeof error !== "object" || error === null) return false;
	// The thrown value, whatever it is, may carry the upstream's answer.
	if (!isResponse(error)) {
		const status = field(error, "status");
		const code = field(error, "error");
		if (unreadable) return false;
		if (HTTP_ERROR(status) || typeof code === "string") return true;
	}
	let current: unknown = isError(error) || isResponse(error) ? error : field(error, "cause");
	for (let depth = 0; depth < MAX_CAUSE_DEPTH && !unreadable; depth++) {
		if (isResponse(current)) {
			const status = field(current, "status");
			return !unreadable && HTTP_ERROR(status);
		}
		if (!isError(current)) return false;
		const name = field(current, "name");
		const code = field(current, "code");
		const status = field(current, "status");
		if (unreadable) return false;
		if (typeof name === "string" && ABANDONED.has(name)) return false;
		if (HTTP_ERROR(status)) return true;
		if (typeof code === "string") {
			if (
				NOT_SENT.has(code) ||
				X509_VERIFICATION.has(code) ||
				/^ERR_TLS_[A-Z_]{1,64}$/.test(code)
			) {
				return true;
			}
			if (isTransportCode(code)) return false;
		}
		current = field(current, "cause");
	}
	return false;
}
