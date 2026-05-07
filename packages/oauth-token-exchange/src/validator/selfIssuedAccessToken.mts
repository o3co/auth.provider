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

import {
	type KeyStore,
	type Logger,
	type RefreshTokenFamilyRevocation,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type {
	ExchangeTokenValidationContext,
	ExchangeTokenValidator,
	ValidatedToken,
} from "./types.mjs";

export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface CreateSelfIssuedAccessTokenValidatorOptions {
	keyStore: KeyStore;
	refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	issuer: string;
	/**
	 * SF-1 (v0.5.1): when true (default), the central JWT verifier accepts
	 * tokens whose `typ` header is absent and emits a deprecation warning.
	 */
	legacyTypAccept?: boolean;
	logger?: Logger;
}

/**
 * Built-in validator for RFC 8693 subject_token_type=access_token when the
 * token was issued by this auth.provider instance. Verifies:
 *   - JWT signature (via KeyStore)
 *   - `typ: "at+jwt"` header (rejects id_tokens and logout_tokens even
 *     when signed by the same KeyStore — prevents token-type-confusion)
 *   - Standard claims (exp via jose)
 *   - Issuer match (always — `issuer` is a required option)
 *   - When refreshTokenFamilyRevocation is wired: family_id cascading revoke
 *
 * When refreshTokenFamilyRevocation is absent, the family revoke check is silently
 * skipped here; the grant handler is responsible for detecting this
 * misconfiguration and responding with invalid_grant (spec §7.2 state 1:
 * "not wired"). The validator alone is NOT fail-closed against store
 * misconfiguration.
 *
 * `issuer` is required; the constructor throws synchronously when it is
 * missing or an empty string. Without an issuer to compare against, an
 * at+jwt signed by the same KeyStore but with a different (or absent) `iss`
 * claim could be accepted — exactly the token-type-confusion gap Copilot
 * flagged on PR #100.
 *
 * Throws on infrastructure failures (store unavailable during runtime).
 * Returns null on validation failures (bad signature, wrong typ, missing/empty sub,
 * expired, revoked, issuer mismatch).
 */
export function createSelfIssuedAccessTokenValidator(
	options: CreateSelfIssuedAccessTokenValidatorOptions,
): ExchangeTokenValidator {
	const { keyStore, refreshTokenFamilyRevocation, issuer, legacyTypAccept, logger } = options;
	if (typeof issuer !== "string" || issuer.length === 0) {
		throw new Error(
			"createSelfIssuedAccessTokenValidator: issuer is required (a non-empty string). Without an issuer to compare against, an at+jwt signed by the same KeyStore but with a different `iss` claim could be accepted.",
		);
	}

	return {
		async validate(
			token: string,
			_context: ExchangeTokenValidationContext,
		): Promise<ValidatedToken | null> {
			// SF-1: alg / iss / typ (=at+jwt) + signature pinned by the central
			// verifier. Token-type-confusion (id_tokens / logout_tokens minted by
			// the same KeyStore) is closed by the typ pin. Audience is NOT
			// pinned here: ExchangeTokenValidationContext intentionally does not
			// carry the calling-client identity (the grant handler authenticated
			// it upstream and applies may_act / policy gates downstream), so the
			// expected aud is unknown at this layer. The verifier records the
			// gap via `jwt_verify_aud_skipped`.
			let payload: Record<string, unknown>;
			try {
				const verified = await verifyJwt(token, keyStore, {
					type: "access_token",
					expectedIssuer: issuer,
					legacyTypAccept: legacyTypAccept ?? true,
					logger,
				});
				payload = verified.payload as Record<string, unknown>;
			} catch {
				return null;
			}

			if (typeof payload.sub !== "string" || payload.sub.length === 0) {
				return null;
			}

			const familyId = typeof payload.family_id === "string" ? payload.family_id : undefined;

			if (familyId && refreshTokenFamilyRevocation) {
				// Throws on runtime failure — grant handler converts to 503.
				const revoked = await refreshTokenFamilyRevocation.isFamilyRevoked(familyId);
				if (revoked) return null;
			}

			return {
				sub: payload.sub,
				claims: payload,
				...(typeof payload.scope === "string" ? { scope: payload.scope } : {}),
				...(typeof payload.aud === "string" || Array.isArray(payload.aud)
					? { aud: payload.aud as string | string[] }
					: {}),
				...(familyId ? { familyId } : {}),
				...(payload.act && typeof payload.act === "object" && !Array.isArray(payload.act)
					? { act: payload.act as Record<string, unknown> }
					: {}),
			};
		},
	};
}
