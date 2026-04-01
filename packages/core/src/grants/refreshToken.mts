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
import jwt, { type JwtPayload } from "jsonwebtoken";

import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type { GrantContext, GrantDependencies, GrantHandler, GrantHandlerResult } from "./types.mjs";

export const createRefreshTokenGrant = (deps: GrantDependencies): GrantHandler => {
	const { config } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer, metadata } = ctx;
			const { refresh_token: refreshTokenValue, client_id } = body as {
				refresh_token?: string;
				client_id?: string;
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

			let tokenPayload: JwtPayload;
			try {
				tokenPayload = jwt.verify(refreshTokenValue, config.oauth.jwt.secret) as JwtPayload;
			} catch {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			if (tokenPayload.type !== "refresh") {
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

			const { user, client, scopes: existingScopes } = tokenPayload;
			const refreshPayload = formatObject({ user, client, ...metadata });

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: generateToken(refreshPayload, {
							expiresIn: config.oauth.accessToken.expiresIn,
							secret: config.oauth.jwt.secret,
							issuer,
							audience: tokenAud ?? client_id ?? null,
							scopes: existingScopes as string[] | null,
							type: "access",
						}),
						refreshToken: generateToken(refreshPayload, {
							expiresIn: config.oauth.refreshToken.expiresIn,
							secret: config.oauth.jwt.secret,
							issuer,
							audience: tokenAud ?? client_id ?? null,
							scopes: existingScopes as string[] | null,
							type: "refresh",
						}),
					}),
				},
			};
		},
	};
};
