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
 * The failures `HttpUserRepository` throws about the exchange with the Store
 * rather than about a user: the Store refusing this deployment's credential,
 * and a transport that failed. Each is built from an allowlist — the
 * endpoint, a status, a transport code — and never from what the Store or the
 * transport said, which may quote the request.
 */

/**
 * The Store refused the credential this deployment presented: a `401` or a
 * `403` carrying a `Bearer` challenge (RFC 6750 §3 — `invalid_token`,
 * `insufficient_scope`) to a request that sent `bearerToken`. An outage, not
 * an answer about the user: thrown, so every caller answers it as it answers
 * any Store failure.
 *
 * `name` is part of the contract. A caller that does not depend on this
 * package recognises the refusal by it — federation-grants' sanitized
 * reporter classifies it `store_credential_refused`. The message names the
 * endpoint, the status and the option to check; never the token, and nothing
 * the Store wrote.
 *
 * The Store's status is `storeStatus`, never `status` or `statusCode`: those
 * are what Express's finalhandler, http-errors and the standalone's terminal
 * handler read as the status to ANSWER with, and a 4xx there is taken for a
 * client error — the Store's 401 would reach the browser as its own, and go
 * unlogged.
 */
export class StoreCredentialRefusedError extends Error {
	readonly storeStatus: 401 | 403;

	constructor(url: string, status: 401 | 403) {
		super(
			`HttpUserRepository: the Store at ${url} refused this deployment's credential ` +
				`(HTTP ${status} with a Bearer challenge) — bearerToken (CLIENT_USER_BEARER_TOKEN) is ` +
				"not a token the Store accepts",
		);
		this.name = "StoreCredentialRefusedError";
		this.storeStatus = status;
	}
}

/** What went wrong with the exchange, when it was not the Store's answer. */
export type StoreTransportFailure =
	/**
	 * No connection to exchange on: refused, DNS, TLS, a route or host the
	 * network cannot reach. The network path, or TLS to the Store.
	 */
	| "unreachable"
	/**
	 * A connection that closed — or was reset — before a complete response
	 * arrived: before any byte, after an interim `1xx`, mid-head, or a pooled
	 * keep-alive connection the Store, a proxy or an idle timeout closed
	 * between two requests. The transport cannot tell which, so this says no
	 * more than that; it is not the network path, and not a malformed answer.
	 */
	| "connection_closed"
	/**
	 * The Store (or whatever answers at the URL) sent a response head the
	 * transport cannot take: the parser refused the status line or a header,
	 * or the head outgrew the size limit. The Store's answer, or a proxy's.
	 */
	| "malformed_response"
	/** An HTTP answer arrived, and its body broke before it was read. */
	| "unreadable";

/**
 * The Store could not be reached, or what it answered could not be read — a
 * transport failure rather than an answer. Thrown so every caller answers it
 * as it answers any Store failure; `name` is part of the contract (the
 * federation-grants reporter classifies it `store_transport_failed`), as are
 * `reason` and `code`.
 *
 * Built only from what an operator can act on: a fixed message naming the
 * endpoint and the failure, and `code` — a transport code from the allowlist
 * below, when there is one. Never a `cause`: the transport's own error may
 * quote what was sent or received. And no `status` (see
 * {@link StoreCredentialRefusedError}).
 */
export class StoreTransportError extends Error {
	readonly reason: StoreTransportFailure;
	readonly code: string | undefined;

	constructor(message: string, reason: StoreTransportFailure, code?: string) {
		super(message);
		this.name = "StoreTransportError";
		this.reason = reason;
		this.code = code;
	}
}

/**
 * Transport codes an operator can act on. A transport's error is never passed
 * on: undici's parser errors carry the bytes they choked on as `data`, and a
 * peer that reflects the request — a broken proxy, a debugging echo — puts the
 * `Authorization` header there. A code from this list, or of one of the
 * closed families below, found on the error or its causes, is all that is
 * kept of one.
 */
const TRANSPORT_CODES: ReadonlySet<string> = new Set([
	"ECONNREFUSED",
	"ECONNRESET",
	"ECONNABORTED",
	"ENOTFOUND",
	"EAI_AGAIN",
	"ETIMEDOUT",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EPIPE",
	"EPROTO",
	"CERT_HAS_EXPIRED",
	"CERT_NOT_YET_VALID",
	"DEPTH_ZERO_SELF_SIGNED_CERT",
	"SELF_SIGNED_CERT_IN_CHAIN",
	"UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	"ERR_TLS_CERT_ALTNAME_INVALID",
]);

/**
 * Families of codes, each a closed vocabulary of its producer: undici's own
 * (`UND_ERR_SOCKET`, `UND_ERR_HEADERS_OVERFLOW`, …), llhttp's parser errors
 * (`HPE_INVALID_HEADER_TOKEN`, … — where the runtime sets them), and
 * OpenSSL's (`ERR_SSL_WRONG_VERSION_NUMBER` — an https URL on a port that
 * speaks plain HTTP; `ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE` — OpenSSL 3's
 * name for a TLS 1.2 handshake the Store refused, one slash in it). Bounded,
 * so a value that merely starts like one is not kept whole.
 */
const CODE_FAMILIES: readonly RegExp[] = [
	/^UND_ERR_[A-Z_]{1,48}$/,
	/^HPE_[A-Z_]{1,48}$/,
	/^ERR_SSL_[A-Z0-9_]{1,64}(?:\/[A-Z0-9_]{1,64})?$/,
];

const MAX_CAUSE_DEPTH = 4;

/** Each of `err` and its causes, a few levels deep. */
function* causes(err: unknown): Generator<object> {
	let current = err;
	for (
		let depth = 0;
		depth < MAX_CAUSE_DEPTH && typeof current === "object" && current !== null;
		depth++
	) {
		yield current;
		current = (current as { cause?: unknown }).cause;
	}
}

/** The first allowlisted `code` on `err` or its causes. */
export function transportCode(err: unknown): string | undefined {
	for (const error of causes(err)) {
		const code = (error as { code?: unknown }).code;
		if (
			typeof code === "string" &&
			(TRANSPORT_CODES.has(code) || CODE_FAMILIES.some((family) => family.test(code)))
		) {
			return code;
		}
	}
	return undefined;
}

/** Codes that say the connection closed or was reset under the request. */
const CLOSED_CODES: ReadonlySet<string> = new Set([
	"UND_ERR_SOCKET",
	"ECONNRESET",
	"EPIPE",
	"ECONNABORTED",
]);

/**
 * Which failure a rejected request is, read by the error's name and code
 * only. A head the transport cannot take — an `HTTPParserError` (an `HPE_*`
 * code where the runtime sets one), `UND_ERR_HEADERS_OVERFLOW` — is
 * `malformed_response`. A connection closed or reset under the request —
 * undici's `UND_ERR_SOCKET` ("other side closed"), `ECONNRESET`, `EPIPE` — is
 * `connection_closed`, whatever the socket had read: undici counts bytes over
 * the socket's life, and fetch reuses keep-alive connections, so a pooled
 * connection closed between two requests has read an entire earlier answer.
 * Anything else is `unreachable`.
 */
function requestFailureReason(
	err: unknown,
): "unreachable" | "connection_closed" | "malformed_response" {
	let closed = false;
	for (const error of causes(err)) {
		const { name, code } = error as { name?: unknown; code?: unknown };
		if (name === "HTTPParserError") return "malformed_response";
		if (typeof code !== "string") continue;
		if (code.startsWith("HPE_") || code === "UND_ERR_HEADERS_OVERFLOW") {
			return "malformed_response";
		}
		if (CLOSED_CODES.has(code)) closed = true;
	}
	return closed ? "connection_closed" : "unreachable";
}

const withCode = (message: string, code: string | undefined): string =>
	code === undefined ? message : `${message} (${code})`;

/**
 * A request that failed before a response could be taken, as its reason's
 * message — `unreachable`, `closed` or `malformed` — with the code, when
 * there is one. Only `unreachable` points an operator at the network.
 */
export function requestFailure(
	err: unknown,
	messages: {
		readonly unreachable: string;
		readonly closed: string;
		readonly malformed: string;
	},
): StoreTransportError {
	const code = transportCode(err);
	const reason = requestFailureReason(err);
	const message =
		reason === "malformed_response"
			? messages.malformed
			: reason === "connection_closed"
				? messages.closed
				: messages.unreachable;
	return new StoreTransportError(withCode(message, code), reason, code);
}

/** An answer whose body broke before it was read. */
export function readFailure(err: unknown, message: string): StoreTransportError {
	const code = transportCode(err);
	return new StoreTransportError(withCode(message, code), "unreadable", code);
}
