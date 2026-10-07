/*
 * Copyright 2026 1o1 Co. Ltd.
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

import { randomUUID } from "node:crypto";
import type { JWTPayload, KeyStore } from "../keys/KeyStore.mjs";
import type { Token } from "./token.mjs";

/**
 * Options for `generateLogoutToken` (OIDC Back-Channel Logout 1.0).
 */
export interface GenerateLogoutTokenOptions {
	/** Issuer URL (MUST match the id_token `iss` claim for the session being logged out). */
	readonly issuer: string;
	/** Subject identifier of the user being logged out. */
	readonly sub: string;
	/** Audience — the client_id of the RP receiving this logout_token. */
	readonly aud: string | string[];
	/** Session identifier (MUST match the id_token `sid` claim when present). */
	readonly sid?: string;
	/**
	 * Whether to include the `sid` claim. Defaults to `true` for security — most RPs
	 * require sid to correlate the logout with their local session. Set to `false`
	 * only when the RP registered with `backchannel_logout_session_required: false`.
	 */
	readonly includeSid?: boolean;
	/** JWT signer. */
	readonly keyStore: KeyStore;
	/** TTL in seconds. Defaults to 300 (5 minutes) per Back-Channel Logout 1.0 best practice. */
	readonly expiresIn?: number;
}

export const BACKCHANNEL_LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout";

/**
 * Generates a signed logout_token JWT (OIDC Back-Channel Logout 1.0 §2.4).
 *
 * Claim composition:
 *   - iss, sub, aud (required)
 *   - iat, exp (seconds since epoch; default TTL 300s)
 *   - jti (unique token identifier)
 *   - events: { [BACKCHANNEL_LOGOUT_EVENT_URI]: {} } (required by spec)
 *   - sid (session identifier; included by default, omit with includeSid: false)
 *
 * Spec constraints enforced:
 *   - nonce MUST NOT be present (§2.4)
 *   - typ header set to "logout+jwt"
 */
export async function generateLogoutToken(opts: GenerateLogoutTokenOptions): Promise<Token> {
	if ((opts.includeSid ?? true) && opts.sid !== undefined && opts.sid === "") {
		throw new Error("generateLogoutToken: sid must not be empty when includeSid is true");
	}
	const now = Math.floor(Date.now() / 1000);
	const expiresIn = opts.expiresIn ?? 300;
	const includeSid = opts.includeSid ?? true;
	const claims: JWTPayload = {
		iss: opts.issuer,
		sub: opts.sub,
		aud: opts.aud,
		iat: now,
		exp: now + expiresIn,
		jti: randomUUID(),
		events: { [BACKCHANNEL_LOGOUT_EVENT_URI]: {} },
		...(includeSid && opts.sid ? { sid: opts.sid } : {}),
	};
	const token = await opts.keyStore.sign({ claims, header: { typ: "logout+jwt" } });
	// Token.audience is string — join multi-audience arrays with comma for storage.
	const audience = Array.isArray(opts.aud) ? opts.aud.join(",") : opts.aud;
	return {
		token,
		expiresIn,
		subject: opts.sub,
		audience,
		issuer: opts.issuer,
		// tokenType is intentionally omitted — logout_token is not at+jwt / rt+jwt.
	};
}
