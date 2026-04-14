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

import {
	generateToken,
	generateTokenResponse,
	type ClientRepository,
	type CodeRepository,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
} from "@o3co/auth-provider-core";

export const createAuthorizationGrant = (deps: GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository }): GrantHandler => {
	const { config, codeRepository, clientRepository, keyStore } = deps;

	const grantsConfig = config.oauth.grants as Record<string, Record<string, unknown>> | undefined;
	const authorizationConfig = grantsConfig?.authorization as Record<string, unknown> | undefined;
	const pkceConfig = authorizationConfig?.pkce as Record<string, unknown> | undefined;

	// B-7: structured pkce config (supportedMethods, defaultMethod, required)
	// Fall back to legacy requireS256 for backward compatibility
	const supportedMethods: string[] = Array.isArray(pkceConfig?.supportedMethods)
		? (pkceConfig.supportedMethods as string[])
		: ["S256", "plain"];
	const pkceRequired: boolean = pkceConfig?.required === true;
	// Legacy fallback: requireS256=true means only S256 is supported
	const requireS256Legacy = pkceConfig?.requireS256 === true;
	const effectiveSupportedMethods = requireS256Legacy ? ["S256"] : supportedMethods;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer } = ctx;
			const {
				code,
				code_verifier = null,
				client_id,
				client_secret = null,
				redirect_uri = null,
			} = body as {
				code?: string;
				code_verifier?: string | null;
				client_id?: string;
				client_secret?: string | null;
				redirect_uri?: string | null;
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

			// A-3: Client secret verification (RFC 6749 §3.2.1)
			// Only verify when client_secret is provided (confidential clients send it;
			// public clients omit it). If provided, authenticate against the repository.
			if (client_secret !== null && client_secret !== undefined) {
				const authenticated = await clientRepository.authenticate(client_id, client_secret);
				if (!authenticated) {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "client authentication failed",
						},
					};
				}
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

			// A-2: redirect_uri binding (RFC 6749 §4.1.3)
			// If redirect_uri was stored at authorization time, it MUST be present and match.
			const storedRedirectUri = codeData.redirect_uri ?? session.code_redirect_uri;
			if (storedRedirectUri) {
				if (!redirect_uri || redirect_uri !== storedRedirectUri) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "redirect_uri mismatch",
						},
					};
				}
			}

			const grantedScopes = session.granted_scopes;

			// B-8: PKCE required check at token endpoint
			if (pkceRequired && !codeData.code_challenge_method) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "PKCE is required but code was issued without code_challenge",
					},
				};
			}

			// Validate code_verifier using code data from repository
			if (codeData.code_challenge_method) {
				// B-7: check method is in supportedMethods
				if (!effectiveSupportedMethods.includes(codeData.code_challenge_method)) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: `code_challenge_method "${codeData.code_challenge_method}" is not supported`,
						},
					};
				}

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

			const rawUserId = (session.user as Record<string, unknown> | undefined)?.id;
			const userId = typeof rawUserId === "string" ? rawUserId : undefined;

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken({}, {
							expiresIn: config.oauth.accessToken.expiresIn,
							keyStore,
							issuer,
							audience: client_id,
							subject: userId ?? null,
							authorizedParty: client_id ?? null,
							scope: grantedScopes?.join(" ") ?? null,
							tokenType: "at+jwt",
						}),
						refreshToken: await generateToken({}, {
							expiresIn: config.oauth.refreshToken.expiresIn,
							keyStore,
							issuer,
							audience: client_id,
							subject: userId ?? null,
							authorizedParty: client_id ?? null,
							scope: grantedScopes?.join(" ") ?? null,
							tokenType: "rt+jwt",
						}),
					}),
				},
				sessionMutation: {
					clear: ["code", "code_client_id", "code_redirect_uri", "granted_scopes"],
				},
			};
		},
	};
};
