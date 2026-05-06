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
	generateIdToken,
	generateToken,
	generateTokenResponse,
	type Token,
	type UserSession,
} from "@o3co/auth-provider-core";
import { decodeJwtPayload } from "./_jwtPayload.mjs";

export const createAuthorizationGrant = (
	deps: GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository },
): GrantHandler => {
	const { config, codeRepository, clientRepository, keyStore } = deps;

	const grantsConfig = config.oauth.grants as Record<string, Record<string, unknown>> | undefined;
	const authorizationConfig = grantsConfig?.authorization_code as
		| Record<string, unknown>
		| undefined;
	const pkceConfig = authorizationConfig?.pkce as Record<string, unknown> | undefined;

	// TODO-F-4: id_token issuance requires a configured issuer URL. We read it
	// directly from config (not ctx.issuer) because the express adapter falls
	// back to `req.get("host")` — which is a host string, not an issuer URL —
	// when config.oauth.jwt.issuer is unset. Emitting a request-derived `iss`
	// in id_tokens would violate OIDC Core §2 (iss MUST be a URL).
	const configuredIssuer: string | undefined = (() => {
		const jwt = (config.oauth as { jwt?: { issuer?: unknown } } | undefined)?.jwt;
		const value = jwt?.issuer;
		return typeof value === "string" && value.length > 0 ? value : undefined;
	})();

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

			// D-1: presence-only check on `code`. The string itself is verified by
			// `consumeByCode` (atomic getDel), which is the sole authenticity gate.
			// The previous `code !== session.code` cross-check was redundant
			// defense-in-depth that introduced the CR-2 last-write-wins race when
			// two /authorize requests shared an Express session.
			if (!code) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			// D-1: hoist client_id presence check ahead of consumeByCode so a
			// missing client_id rejects symmetrically for confidential and public
			// clients without burning the (otherwise valid) code via the atomic
			// getDel inside consumeByCode.
			if (!client_id) {
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

			// D-1: client_id binding moved from session.code_client_id to
			// codeData.client_id. Custom impls predating v0.5.1 may emit a
			// codeData without client_id — treat that as invalid_grant rather
			// than crashing on undefined comparison.
			if (client_id !== codeData.client_id) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid client_id",
					},
				};
			}

			// A-2: redirect_uri binding (RFC 6749 §4.1.3)
			// D-1: codeData.redirect_uri is now always populated (required field).
			// The previous `?? session.code_redirect_uri` fallback hid the IH-4
			// vacuous-pass bug where Redis silently dropped redirect_uri and the
			// check was skipped entirely. Now strictly enforced.
			if (!redirect_uri || redirect_uri !== codeData.redirect_uri) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "redirect_uri mismatch",
					},
				};
			}

			// C-2 / D-1: only the values persisted on Code at /authorize time are
			// authoritative. The session.granted_scopes fallback is removed along
			// with the four /authorize session writes. Do NOT re-run grantPolicy
			// here — evaluate-once-at-authorize is the contract.
			const grantedScopes: readonly string[] | undefined = codeData.grantedScope;
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

			// TODO-F-3: sid from the code record — written at /authorize time by the
			// login/federation callback wiring (Task 2).
			// Only enforce sid presence when userSessionStore is wired. Deployments
			// that opt out of session tracking (userSessionStore not configured) have
			// no store to write sid at login time, so requiring it here would be a
			// backward-compat regression. When the store IS wired, sid is mandatory
			// so subsequent linkFamily / registerRP can execute.
			const sid = codeData.sid;
			// TODO-F-4: nonce from the code record — written at /authorize time and
			// must be reflected verbatim in the id_token per OIDC Core §2.
			const nonce = codeData.nonce;
			if (deps.userSessionStore && !sid) {
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

			// TODO-F-3: both access_token and refresh_token carry family_id and, when
			// sid is present, the sid claim so introspect (Task 5) and refresh (Task 4)
			// can propagate them without re-reading the session store on every request.
			// sid is omitted when no userSessionStore is wired (backward-compat path).
			const accessToken = await generateToken(
				{ family_id: familyId, ...(sid ? { sid } : {}) },
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
				{ family_id: familyId, ...(sid ? { sid } : {}) },
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

			// Register the initial refresh token family so replay detection is
			// active from the first use. Per A3 §5.2: use the dedicated
			// RefreshTokenFamilyRotation.register(newJti, familyId, expiresAtMs) rather
			// than the v0.4.x rotate(null, ...) trick — expiresAtMs is epoch-ms.
			if (deps.refreshTokenFamilyRotation) {
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
						await deps.refreshTokenFamilyRotation.register(jti, familyId, exp * 1000);
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

			// TODO-F-3: link the new token family to the user session (via
			// sessionFamilyIndex.addFamilyId) and register the RP for back/front-channel
			// logout (via sessionRPRegistry.registerRP). All calls are fail-closed: if the
			// session store is unavailable or the session was deleted between /authorize
			// and /token, we return a controlled error rather than issuing tokens that
			// are invisible to logout orchestration.
			// sid is guaranteed non-null here when deps.userSessionStore is set because
			// the earlier guard (deps.userSessionStore && !sid) already rejected that case.
			// TODO-F-4: userSession is lifted outside the block so id_token generation
			// (below) can use it after the block completes.
			let userSession: UserSession | null = null;
			if (deps.userSessionStore && sid) {
				// Fix I1: validate session still exists (mirrors refresh_token grant pattern).
				// A session deleted between /authorize and /token exchange must not produce
				// tokens — they would be orphaned from logout orchestration.
				let fetchedSession: Awaited<ReturnType<typeof deps.userSessionStore.get>>;
				try {
					fetchedSession = await deps.userSessionStore.get(sid);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session store unavailable",
						},
					};
				}
				if (!fetchedSession) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "session_invalid",
						},
					};
				}
				userSession = fetchedSession;
				// Fix I2: clientRepository.findById is fallible — move inside try/catch
				// so a throw here returns a controlled 503 instead of propagating to the
				// express default handler as an unhandled HTML 500.
				try {
					const clientRecord = await clientRepository.findById(client_id);
					// Composition-root invariant (A4 §3.4/§8): the bundled session-stores
					// module wires all 4 sibling stores together. When deps.userSessionStore is
					// present (outer guard), sessionFamilyIndex and sessionRPRegistry are also
					// present. Using ?. would silently no-op on a misconfigured root instead of
					// surfacing the bug at the throw site.
					// biome-ignore lint/style/noNonNullAssertion: intentional — see invariant comment above
					await deps.sessionFamilyIndex!.addFamilyId(sid, familyId, userSession.expiresAt);
					// biome-ignore lint/style/noNonNullAssertion: intentional — same invariant
					await deps.sessionRPRegistry!.registerRP(
						sid,
						{
							clientId: client_id,
							backchannelLogoutUri: (clientRecord as Record<string, unknown> | null)
								?.backchannelLogoutUri as string | undefined,
							backchannelLogoutSessionRequired: (clientRecord as Record<string, unknown> | null)
								?.backchannelLogoutSessionRequired as boolean | undefined,
							frontchannelLogoutUri: (clientRecord as Record<string, unknown> | null)
								?.frontchannelLogoutUri as string | undefined,
							frontchannelLogoutSessionRequired: (clientRecord as Record<string, unknown> | null)
								?.frontchannelLogoutSessionRequired as boolean | undefined,
							registeredAt: new Date(),
						},
						userSession.expiresAt,
					);
				} catch {
					// Fail-closed for any downstream dependency throw in this block —
					// clientRepository.findById, sessionFamilyIndex.addFamilyId, or
					// sessionRPRegistry.registerRP. The errorDescription is intentionally
					// generic because the try spans both client lookup and session-store
					// mutations; a more specific message would misattribute failures.
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session linking unavailable",
						},
					};
				}
			}

			// TODO-F-4: issue id_token when the openid scope was granted and the
			// session is available. The condition naturally handles all cases:
			//   F-4-1: openid scope + userSession wired  → id_token issued
			//   F-4-2: no openid scope                   → id_token omitted
			//   F-4-3: no userSessionStore               → userSession is null → omitted
			//   no configured issuer                     → id_token omitted
			//     We gate on `configuredIssuer` (read directly from
			//     config.oauth.jwt.issuer at factory time) rather than ctx.issuer,
			//     because the express adapter falls back to `req.get("host")` when
			//     config is unset — that is a host string, not an OIDC-compliant
			//     URL, and using it as `iss` would violate OIDC Core §2.
			// userSession truthy implies (deps.userSessionStore && sid) were both truthy
			// earlier, so the `&& sid` guard below is defensive rather than redundant.
			let idToken: Token | undefined;
			if (grantedScopes?.includes("openid") && userSession && sid && configuredIssuer) {
				idToken = await generateIdToken({
					sub: userSession.sub,
					aud: client_id,
					azp: client_id,
					authTime: userSession.authTime,
					...(nonce ? { nonce } : {}),
					sid,
					scopes: grantedScopes,
					userClaims: userSession.claims,
					keyStore,
					issuer: configuredIssuer,
				});
			}

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({ accessToken, refreshToken, idToken }),
				},
				sessionMutation: {
					// D-1: /authorize no longer writes session.code* in v0.5.1.
					// `code` is the only key still cleared here because the
					// authorization grant doesn't read the other v0.4.x keys
					// (`code_client_id`, `code_redirect_uri`, `granted_scopes`)
					// at all anymore — they age out with the session TTL on
					// rolling-deploy nodes that still have stale values.
					clear: ["code"],
				},
			};
		},
	};
};
