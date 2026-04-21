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
	type ClientRepository,
	type CodeRepository,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
} from "@o3co/auth-provider-core";
import { decodeJwtPayload } from "./_jwtPayload.mjs";

export const createAuthorizationGrant = (
	deps: GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository },
): GrantHandler => {
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

			// C-2: prefer narrowed values persisted on Code at /authorize time; fall back
			// to session for pre-C-2 codes and tests that bypass the authorize endpoint.
			// Do NOT re-run grantPolicy here — evaluate-once-at-authorize is the contract.
			const grantedScopes: readonly string[] | undefined =
				codeData.grantedScope ?? session.granted_scopes;
			const grantedAudiencesFromCode = codeData.grantedAudience;

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

			// TODO-F-3: sid is required on the code record — it is written at /authorize
			// time by the login/federation callback wiring (Task 2). A missing sid means
			// the operator has not yet deployed the F-2 login wiring; fail with a clear
			// error so the misconfiguration is surfaced immediately rather than silently
			// producing tokens without a session link.
			const sid = codeData.sid;
			if (!sid) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							"code record is missing session identifier (sid) — ensure login wiring records sid at authorize time",
					},
				};
			}

			const rawUserId = (session.user as Record<string, unknown> | undefined)?.id;
			const userId = typeof rawUserId === "string" ? rawUserId : undefined;

			// Initial rt+jwt opens a new refresh-token family for replay detection
			// per RFC 6819 §5.2.2.3. All subsequent rotations carry the same
			// family_id; revoking the family revokes every descendant.
			const familyId = crypto.randomUUID();

			// generateToken carries a single `aud` claim; if policy narrowed to multiple
			// audiences we flatten to the first. Multi-audience tokens are out of scope
			// for the authorization code grant.
			const audience =
				grantedAudiencesFromCode && grantedAudiencesFromCode.length > 0
					? grantedAudiencesFromCode[0]
					: client_id;

			// CP-12: normalize empty scope array to null so the token response
			// omits `scope` entirely instead of emitting `scope: ""` (which
			// consumers can't distinguish from "scope claim omitted").
			const scopeClaim = grantedScopes && grantedScopes.length > 0 ? grantedScopes.join(" ") : null;

			// TODO-F-3: both access_token and refresh_token carry family_id + sid so
			// introspect (Task 5) and refresh (Task 4) can propagate them without
			// re-reading the session store on every request.
			const accessToken = await generateToken(
				{ family_id: familyId, sid },
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject: userId ?? null,
					authorizedParty: client_id ?? null,
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);
			const refreshToken = await generateToken(
				{ family_id: familyId, sid },
				{
					expiresIn: config.oauth.refreshToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject: userId ?? null,
					authorizedParty: client_id ?? null,
					scope: scopeClaim,
					tokenType: "rt+jwt",
				},
			);

			// Register the initial refresh token in the store so the family is known
			// from issuance. rotate(null, ...) is the initial-registration shape per
			// RefreshTokenStoreBase§2.4; without this step the first rotation would
			// observe an unknown previousJti and replay detection would be blind to
			// attackers replaying the initial token.
			if (deps.refreshTokenStore) {
				const payload = decodeJwtPayload(refreshToken.token);
				const jti = payload.jti as string | undefined;
				const exp = payload.exp as number | undefined;
				if (typeof jti === "string" && typeof exp === "number") {
					// CP-16: fail-closed when the store is unavailable. If we cannot
					// register the initial rt, we cannot guarantee replay detection
					// for the family — serving a token whose replay-detection is
					// blind would undermine the RFC 6819 §5.2.2.3 contract. Return
					// a controlled 503 JSON so clients see a retryable error instead
					// of an unhandled HTML 500 from express.
					try {
						await deps.refreshTokenStore.rotate(null, jti, familyId, new Date(exp * 1000));
					} catch {
						return {
							result: {
								status: 503,
								error: "temporarily_unavailable",
								errorDescription: "refresh token store unavailable",
							},
						};
					}
				}
			}

			// TODO-F-3: link the new token family to the user session and register
			// the RP for back/front-channel logout. Both calls are fail-closed: if the
			// session store is unavailable, return 503 rather than issuing tokens that
			// are invisible to logout orchestration.
			if (deps.userSessionStore) {
				const clientRecord = await clientRepository.findById(client_id);
				try {
					await deps.userSessionStore.linkFamily(sid, familyId);
					await deps.userSessionStore.registerRP(sid, {
						clientId: client_id,
						backchannelLogoutUri: (clientRecord as Record<string, unknown> | null)
							?.backchannelLogoutUri as string | undefined,
						frontchannelLogoutUri: (clientRecord as Record<string, unknown> | null)
							?.frontchannelLogoutUri as string | undefined,
						registeredAt: new Date(),
					});
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session store unavailable",
						},
					};
				}
			}

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({ accessToken, refreshToken }),
				},
				sessionMutation: {
					clear: ["code", "code_client_id", "code_redirect_uri", "granted_scopes"],
				},
			};
		},
	};
};
