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
 */
export class StoreCredentialRefusedError extends Error {
	readonly status: 401 | 403;

	constructor(url: string, status: 401 | 403) {
		super(
			`HttpUserRepository: the Store at ${url} refused this deployment's credential ` +
				`(HTTP ${status} with a Bearer challenge) — bearerToken (CLIENT_USER_BEARER_TOKEN) is ` +
				"not a token the Store accepts",
		);
		this.name = "StoreCredentialRefusedError";
		this.status = status;
	}
}

/**
 * Transport codes an operator can act on. A transport's error is never passed
 * on: undici's parser errors carry the bytes they choked on as `data`, and a
 * peer that reflects the request — a broken proxy, a debugging echo — puts the
 * `Authorization` header there. A code from this list, found on the error or
 * its causes, is all that is kept of one.
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
	"CERT_HAS_EXPIRED",
	"DEPTH_ZERO_SELF_SIGNED_CERT",
	"SELF_SIGNED_CERT_IN_CHAIN",
	"UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	"ERR_TLS_CERT_ALTNAME_INVALID",
]);

/** undici's own codes (`UND_ERR_SOCKET`, `UND_ERR_CONNECT_TIMEOUT`, …): a closed vocabulary. */
const UNDICI_CODE = /^UND_ERR_[A-Z_]{1,48}$/;

/** The first allowlisted `code` on `err` or its causes, a few levels deep. */
export function transportCode(err: unknown): string | undefined {
	let current = err;
	for (let depth = 0; depth < 4 && typeof current === "object" && current !== null; depth++) {
		const code = (current as { code?: unknown }).code;
		if (typeof code === "string" && (TRANSPORT_CODES.has(code) || UNDICI_CODE.test(code))) {
			return code;
		}
		current = (current as { cause?: unknown }).cause;
	}
	return undefined;
}

/**
 * The error thrown for a transport failure: `HttpUserRepository: <what>`, and
 * the allowlisted code in the message and as `code` when there is one — no
 * cause, and nothing else of `err`.
 */
export function transportFailure(what: string, err: unknown): Error {
	const code = transportCode(err);
	if (code === undefined) return new Error(`HttpUserRepository: ${what}`);
	return Object.assign(new Error(`HttpUserRepository: ${what} (${code})`), { code });
}
