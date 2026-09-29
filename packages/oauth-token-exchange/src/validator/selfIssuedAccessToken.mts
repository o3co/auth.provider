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
	type AccessTokenDenylist,
	type ExchangeTokenValidationContext,
	type ExchangeTokenValidator,
	isVerificationUnavailable,
	type KeyStore,
	type Logger,
	livenessSidOf,
	type SubjectRevocation,
	type ValidatedToken,
	verifyJwt,
} from "@o3co/auth-provider-core";

export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface CreateSelfIssuedAccessTokenValidatorOptions {
	keyStore: KeyStore;
	/**
	 * A subject_token is presented as a credential for a NEW token, so accepting a
	 * revoked one would launder it. The jti denylist and the subject watermark are
	 * consulted as on the other token-accepting surfaces (userinfo, introspection).
	 * Optional: whether each store exists is the composition's decision;
	 * `tokenExchangeModule` forwards both slots.
	 */
	accessTokenDenylist?: AccessTokenDenylist;
	subjectRevocation?: SubjectRevocation;
	issuer: string;
	/**
	 * When true, the central JWT verifier accepts tokens without a `typ` header and
	 * warns `jwt_verify_legacy_typ`. Default `false`: typ-less tokens are rejected.
	 */
	legacyTypAccept?: boolean;
	logger?: Logger;
	/**
	 * Not an option: the grant checks the refresh-token family (see the
	 * factory's JSDoc). Typed `never` so a deps object spread into these
	 * options fails to compile; present at runtime, even as `undefined`, it
	 * makes the factory throw.
	 */
	refreshTokenFamilyRevocation?: never;
}

/**
 * Built-in validator for RFC 8693 `subject_token_type` access_token when the
 * token was issued by this provider. Verifies the signature (via `KeyStore`), the
 * `typ: "at+jwt"` header (so an id_token or logout_token signed by the same keys
 * is refused), `exp`, the issuer, and, when wired, the access-token denylist and
 * the subject watermark.
 *
 * It does not check the refresh-token family or the session. It projects
 * `family_id` as `familyId` and the session (`sid`, or an exchanged token's
 * `liveness_sid`, via core's `livenessSidOf`) as `sid`, and
 * `createTokenExchangeGrant` checks both for subject and actor, so a revoked
 * family gets its own `family_revoked` answer instead of an opaque `null`. A
 * caller using this validator elsewhere must check `familyId` itself and refuse
 * the token when it has no family store. Passing `refreshTokenFamilyRevocation`
 * throws at construction, so a caller expecting the check finds out.
 *
 * `issuer` is required (a non-empty string, else the constructor throws): without
 * it an at+jwt from the same `KeyStore` with another `iss` could be accepted.
 *
 * `validate` returns `null` for an unacceptable token (bad signature, wrong
 * `typ`, missing `sub`, expired, issuer mismatch, denylisted or watermarked) and
 * throws when the answer is unknowable (`isVerificationUnavailable`: a keystore
 * or revocation store unreachable), which the grant answers with a 503.
 */
export function createSelfIssuedAccessTokenValidator(
	options: CreateSelfIssuedAccessTokenValidatorOptions,
): ExchangeTokenValidator {
	const { keyStore, accessTokenDenylist, subjectRevocation, issuer, legacyTypAccept, logger } =
		options;
	if ("refreshTokenFamilyRevocation" in options) {
		throw new Error(
			"createSelfIssuedAccessTokenValidator: refreshTokenFamilyRevocation is not an option. The validator does not check the refresh-token family; createTokenExchangeGrant does, given refreshTokenFamilyRevocation in its own dependencies. A caller using this validator outside createTokenExchangeGrant must check ValidatedToken.familyId itself and refuse the token when it has no family store.",
		);
	}
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
			// The central verifier pins alg, iss, typ (at+jwt) and the signature; the typ pin
			// closes token-type confusion. Audience is not pinned: the validation context
			// deliberately carries no client identity (the grant authenticates the client
			// and applies `may_act` and policy), so the verifier logs `jwt_verify_aud_skipped`.
			let payload: Record<string, unknown>;
			try {
				const verified = await verifyJwt(token, keyStore, {
					type: "access_token",
					expectedIssuer: issuer,
					legacyTypAccept: legacyTypAccept ?? false,
					// A revoked subject_token must not be exchangeable for a fresh token.
					revocation: { denylist: accessTokenDenylist, subjectRevocation },
					logger,
				});
				payload = verified.payload as Record<string, unknown>;
			} catch (err) {
				// An unreachable keystore, denylist or watermark is an outage, not a finding
				// about the token: rethrown so the grant answers 503 instead of telling the
				// client to discard a possibly good credential. Every other failure, an unknown
				// kid included, is the token's.
				if (isVerificationUnavailable(err)) throw err;
				return null;
			}

			if (typeof payload.sub !== "string" || payload.sub.length === 0) {
				return null;
			}

			// Projected, not checked: the grant owns the family rule (see the
			// factory's JSDoc), so a revoked family gets the grant's answer.
			const familyId = typeof payload.family_id === "string" ? payload.family_id : undefined;
			// The same for the session: the grant checks it and carries it on.
			// Its own `sid`, or the `liveness_sid` of a token that was itself
			// exchanged, so a chain of exchanges stays tied to the session.
			const sid = livenessSidOf(payload) ?? undefined;
			const mayAct =
				isRecord(payload.may_act) ||
				(Array.isArray(payload.may_act) && payload.may_act.every(isRecord))
					? payload.may_act
					: undefined;

			return {
				sub: payload.sub,
				claims: payload,
				...(typeof payload.scope === "string" ? { scope: payload.scope } : {}),
				...(typeof payload.aud === "string" || Array.isArray(payload.aud)
					? { aud: payload.aud as string | string[] }
					: {}),
				...(familyId ? { familyId } : {}),
				...(sid ? { sid } : {}),
				...(payload.act && typeof payload.act === "object" && !Array.isArray(payload.act)
					? { act: payload.act as Record<string, unknown> }
					: {}),
				...(mayAct !== undefined
					? {
							may_act: mayAct as
								| Readonly<Record<string, unknown>>
								| readonly Readonly<Record<string, unknown>>[],
						}
					: {}),
			};
		},
	};
}
