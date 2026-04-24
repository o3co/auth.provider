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
 * token was issued by this auth.provider instance. Verifies JWT signature
 * (KeyStore), standard claims (exp via jose), issuer match, and — when a
 * refreshTokenStore is wired — family_id cascading revoke.
 *
 * Throws on infrastructure failures (store unavailable). Returns null on
 * validation failures (bad signature, expired, revoked, issuer mismatch).
 */
export function createSelfIssuedAccessTokenValidator(
	options: CreateSelfIssuedAccessTokenValidatorOptions,
): ExchangeTokenValidator {
	const { keyStore, refreshTokenStore, issuer } = options;

	return {
		async validate(token: string): Promise<ValidatedToken | null> {
			let payload: Record<string, unknown>;
			try {
				const header = decodeProtectedHeader(token);
				const key = await keyStore.getVerificationKey(
					header.kid ?? keyStore.getSigningKidFallback(),
				);
				const verified = await jwtVerify(token, key);
				payload = verified.payload as Record<string, unknown>;
			} catch {
				return null;
			}

			if (issuer && payload.iss !== issuer) {
				return null;
			}

			const familyId = typeof payload.family_id === "string" ? payload.family_id : undefined;

			if (familyId && refreshTokenStore) {
				// Throws on runtime failure — grant handler converts to 503.
				const revoked = await refreshTokenStore.isFamilyRevoked(familyId);
				if (revoked) return null;
			}

			const result: ValidatedToken = {
				sub: String(payload.sub ?? ""),
				claims: payload,
			};
			if (typeof payload.scope === "string") result.scope = payload.scope;
			if (typeof payload.aud === "string" || Array.isArray(payload.aud)) {
				result.aud = payload.aud as string | string[];
			}
			if (familyId) result.familyId = familyId;
			if (payload.act && typeof payload.act === "object") {
				result.act = payload.act as Record<string, unknown>;
			}
			return result;
		},
	};
}
