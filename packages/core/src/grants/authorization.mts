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
import crypto from "node:crypto";

import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type {
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
} from "./types.mjs";

export const createAuthorizationGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, codeRepository, keyStore } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer, metadata } = ctx;
			const {
				code,
				code_verifier = null,
				client_id,
			} = body as {
				code?: string;
				code_verifier?: string | null;
				client_id?: string;
			};

			if (!code || code !== session.code) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			if (!client_id || client_id !== session.code_client_id) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid client_id",
					},
				};
			}

			// Atomically consume code data from repository (replay attack prevention)
			const codeData = await codeRepository.consumeByCode(code);
			if (!codeData) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			const grantedScopes = session.granted_scopes;

			// Validate code_verifier using code data from repository
			if (codeData.code_challenge_method) {
				if (!code_verifier) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "code_verifier required",
						},
					};
				}
				// RFC 7636: must be 43-128 characters, unreserved characters only
				if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(code_verifier)) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "invalid code_verifier format",
						},
					};
				}
				switch (codeData.code_challenge_method) {
					case "S256": {
						const hash = crypto.createHash("sha256").update(code_verifier).digest();
						const base64url = hash.toString("base64url");
						if (base64url !== codeData.code_challenge) {
							return {
								result: {
									status: 400,
									error: "invalid_grant",
									errorDescription: "invalid code_verifier",
								},
							};
						}
						break;
					}
					case "plain":
						if (code_verifier !== codeData.code_challenge) {
							return {
								result: {
									status: 400,
									error: "invalid_grant",
									errorDescription: "invalid code_verifier",
								},
							};
						}
						break;
					default:
						return {
							result: {
								status: 400,
								error: "invalid_request",
								errorDescription: "invalid code_challenge_method",
							},
						};
				}
			}

			const payload = formatObject({
				user: session.user,
				client: session.client,
				...metadata,
			});

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(payload, {
							expiresIn: config.oauth.accessToken.expiresIn,
							keyStore,
							issuer,
							audience: client_id,
							scopes: grantedScopes,
							type: "access",
						}),
						refreshToken: await generateToken(payload, {
							expiresIn: config.oauth.refreshToken.expiresIn,
							keyStore,
							issuer,
							audience: client_id,
							scopes: grantedScopes,
							type: "refresh",
						}),
					}),
				},
				sessionMutation: {
					clear: ["code", "code_client_id", "granted_scopes"],
				},
			};
		},
	};
};
