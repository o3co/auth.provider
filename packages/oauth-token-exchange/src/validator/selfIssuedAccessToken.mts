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

import type { KeyStore, RefreshTokenStoreBase } from "@o3co/auth-provider-core";
import { decodeProtectedHeader, jwtVerify } from "jose";
import type { ExchangeTokenValidator, ValidatedToken } from "./types.mjs";

export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface CreateSelfIssuedAccessTokenValidatorOptions {
	keyStore: KeyStore;
	refreshTokenStore?: RefreshTokenStoreBase;
	issuer?: string;
}

/**
 * Built-in validator for RFC 8693 subject_token_type=access_token when the
 * token was issued by this auth.provider instance. Verifies:
 *   - JWT signature (via KeyStore)
 *   - `typ: "at+jwt"` header (rejects id_tokens and logout_tokens even
 *     when signed by the same KeyStore — prevents token-type-confusion)
 *   - Standard claims (exp via jose)
 *   - Issuer match
 *   - When refreshTokenStore is wired: family_id cascading revoke
 *
 * When refreshTokenStore is absent, the family revoke check is silently
 * skipped here; the grant handler is responsible for detecting this
 * misconfiguration and responding with invalid_grant (spec §7.2 state 1:
 * "not wired"). The validator alone is NOT fail-closed against store
 * misconfiguration.
 *
 * Throws on infrastructure failures (store unavailable during runtime).
 * Returns null on validation failures (bad signature, wrong typ, missing/empty sub,
 * expired, revoked, issuer mismatch).
 */
export function createSelfIssuedAccessTokenValidator(
	options: CreateSelfIssuedAccessTokenValidatorOptions,
): ExchangeTokenValidator {
	const { keyStore, refreshTokenStore, issuer } = options;

	return {
		async validate(token: string): Promise<ValidatedToken | null> {
			let payload: Record<string, unknown>;
			let header: Awaited<ReturnType<typeof decodeProtectedHeader>>;
			try {
				header = decodeProtectedHeader(token);
				const key = await keyStore.getVerificationKey(
					header.kid ?? keyStore.getSigningKidFallback(),
				);
				const verified = await jwtVerify(token, key);
				payload = verified.payload as Record<string, unknown>;
			} catch {
				return null;
			}

			// Token-type-confusion defense: the RFC 8693 `access_token` subject_token_type
			// means "a token that was issued as an access_token". Reject any JWT whose
			// `typ` header is anything other than `at+jwt` — in particular id_tokens
			// (typ=JWT or typ=id+jwt) and logout_tokens (typ=logout+jwt) minted by the
			// same KeyStore must never be accepted as a Token Exchange subject.
			if (header.typ !== "at+jwt") {
				return null;
			}

			if (issuer && payload.iss !== issuer) {
				return null;
			}

			if (typeof payload.sub !== "string" || payload.sub.length === 0) {
				return null;
			}

			const familyId = typeof payload.family_id === "string" ? payload.family_id : undefined;

			if (familyId && refreshTokenStore) {
				// Throws on runtime failure — grant handler converts to 503.
				const revoked = await refreshTokenStore.isFamilyRevoked(familyId);
				if (revoked) return null;
			}

			const result: ValidatedToken = {
				sub: payload.sub,
				claims: payload,
			};
			if (typeof payload.scope === "string") result.scope = payload.scope;
			if (typeof payload.aud === "string" || Array.isArray(payload.aud)) {
				result.aud = payload.aud as string | string[];
			}
			if (familyId) result.familyId = familyId;
			if (payload.act && typeof payload.act === "object" && !Array.isArray(payload.act)) {
				result.act = payload.act as Record<string, unknown>;
			}
			return result;
		},
	};
}
