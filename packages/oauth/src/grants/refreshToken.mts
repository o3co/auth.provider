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
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
} from "@o3co/auth-provider-core";
import { decodeProtectedHeader, type JWTPayload, jwtVerify } from "jose";

export const createRefreshTokenGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;
			const {
				refresh_token: refreshTokenValue,
				client_id,
				scope: requestedScope,
			} = body as {
				refresh_token?: string;
				client_id?: string;
				scope?: string;
			};

			if (!refreshTokenValue) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "refresh_token is required",
					},
				};
			}

			let tokenPayload: JWTPayload;
			let typ: string | undefined;
			try {
				const header = decodeProtectedHeader(refreshTokenValue);
				typ = header.typ;
				const key = await keyStore.getVerificationKey(header.kid ?? keyStore.getCurrentKid());
				const { payload } = await jwtVerify(refreshTokenValue, key);
				tokenPayload = payload;
			} catch {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			// Accept both new typ header ("rt+jwt") and legacy type payload ("refresh")
			const legacyType = (tokenPayload as Record<string, unknown>).type;
			if (typ !== "rt+jwt" && legacyType !== "refresh") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			// Validate client_id matches audience if provided
			const tokenAud = Array.isArray(tokenPayload.aud) ? tokenPayload.aud[0] : tokenPayload.aud;
			if (client_id && tokenAud !== client_id) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid client_id",
					},
				};
			}

			const claims = tokenPayload as Record<string, unknown>;
			// Read standard claims, with legacy fallback for pre-standardization tokens
			const subjectStr =
				typeof tokenPayload.sub === "string"
					? tokenPayload.sub
					: typeof (claims.user as Record<string, unknown> | undefined)?.id === "string"
						? ((claims.user as Record<string, unknown>).id as string)
						: undefined;
			const azpStr =
				typeof claims.azp === "string"
					? (claims.azp as string)
					: typeof (claims.client as Record<string, unknown> | undefined)?.id === "string"
						? ((claims.client as Record<string, unknown>).id as string)
						: undefined;
			const scopeStr =
				typeof claims.scope === "string"
					? (claims.scope as string)
					: Array.isArray(claims.scopes)
						? (claims.scopes as string[]).join(" ")
						: undefined;

			if (!subjectStr) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "refresh token has no subject",
					},
				};
			}

			// RFC 6749 Section 6: requested scope MUST NOT exceed original scope
			let grantedScope = scopeStr ?? null;
			if (requestedScope) {
				const requested = [...new Set(requestedScope.split(" ").filter(Boolean))];
				const original = scopeStr ? scopeStr.split(" ") : [];
				const invalid = requested.filter((s) => !original.includes(s));
				if (invalid.length > 0) {
					return {
						result: {
							status: 400,
							error: "invalid_scope",
							errorDescription: `requested scope exceeds original grant: ${invalid.join(" ")}`,
						},
					};
				}
				grantedScope = requested.join(" ");
			}

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(
							{},
							{
								expiresIn: config.oauth.accessToken.expiresIn,
								keyStore,
								issuer,
								audience: tokenAud ?? client_id ?? null,
								subject: subjectStr ?? null,
								authorizedParty: azpStr ?? null,
								scope: grantedScope,
								tokenType: "at+jwt",
							},
						),
						refreshToken: await generateToken(
							{},
							{
								expiresIn: config.oauth.refreshToken.expiresIn,
								keyStore,
								issuer,
								audience: tokenAud ?? client_id ?? null,
								subject: subjectStr ?? null,
								authorizedParty: azpStr ?? null,
								scope: grantedScope,
								tokenType: "rt+jwt",
							},
						),
					}),
				},
			};
		},
	};
};
