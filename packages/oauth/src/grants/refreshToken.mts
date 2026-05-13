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

import { randomUUID } from "node:crypto";
import {
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { JWTPayload } from "jose";
import { decodeJwtPayload } from "./_jwtPayload.mjs";
import { extractResourceParam } from "./_resourceIndicator.mjs";

export const createRefreshTokenGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore, logger } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;
			const { refresh_token: refreshTokenValue, scope: requestedScope } = body as {
				refresh_token?: string;
				// D-6: `client_id` from body is no longer authoritative — `clientAuthMw`
				// populates `ctx.authenticatedClient` and we read identity from there.
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

			// D-6: client identity comes from RFC 6749 §2.3 token-endpoint
			// authentication (clientAuthMw). A grant invocation that did not pass
			// through that middleware (custom route, direct unit-test call) cannot
			// be bound to a client and MUST be refused — accepting it would
			// re-introduce the body-spoofable flow that PB-2 closes.
			if (!ctx.authenticatedClient) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "Client authentication is required",
					},
				};
			}
			const authenticatedClientId = ctx.authenticatedClient.clientId;

			let tokenPayload: JWTPayload;
			let typ: string | undefined;
			try {
				// SF-1: pin alg / iss / typ + signature in one place.
				// aud + azp are NOT pinned at the verifier — the manual azp /
				// aud-fallback check below produces a more specific error
				// ("refresh_token was not issued to this client", which is the
				// PB-2 binding-violation signal) and accommodates pre-D-6 RTs
				// that emit aud only (no azp). v0.6+ can pass
				// `expectedAzp: authenticatedClientId` once the legacy upgrade
				// window closes and remove the manual check.
				const verified = await verifyJwt(refreshTokenValue, keyStore, {
					type: "refresh_token",
					expectedIssuer: issuer ?? "",
					legacyTypAccept: config.oauth.jwt.legacyTypAccept ?? false,
					logger,
				});
				tokenPayload = verified.payload;
				typ = verified.header.typ;
			} catch {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			// Invariant — see RT-OC test: this gate keeps AT-as-RT confusion
			// defended. A JWT with no `header.typ === "rt+jwt"` is rejected
			// even when SF-1's `legacyTypAccept = true` opt-in lets a typ-less
			// token through the central verifier (Phase G S2 flipped the
			// default to false but operators can still opt back). Refactors that touch
			// this condition MUST keep RT-OC green.
			if (typ !== "rt+jwt") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			// D-6: bind RT to its issuing client via `azp` (RFC 9068 §2.2). Pre-D-6
			// tokens predate explicit `azp` issuance — for backward compat the
			// gate falls back to `aud`. Tokens minted by post-D-6 issuers always
			// emit `azp = ctx.authenticatedClient.clientId`, so once the legacy
			// upgrade window closes the `aud` fallback is dead code.
			const tokenAud = Array.isArray(tokenPayload.aud) ? tokenPayload.aud[0] : tokenPayload.aud;
			const claims = tokenPayload as Record<string, unknown>;
			const tokenAzp =
				typeof claims.azp === "string" && claims.azp.length > 0 ? claims.azp : tokenAud;
			if (tokenAzp !== authenticatedClientId) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "refresh_token was not issued to this client",
					},
				};
			}

			const subjectStr = typeof tokenPayload.sub === "string" ? tokenPayload.sub : undefined;
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

			let finalScope = grantedScope;
			// D-6: token aud/azp default to the authenticated client. `tokenAud`
			// from the input refresh token is no longer authoritative for new-
			// token issuance — the binding gate above already proves authenticated
			// client matched the input azp/aud, so reusing
			// `ctx.authenticatedClient.clientId` directly is equivalent and avoids
			// a body-spoofable identity flow.
			let finalAudience: string | null = authenticatedClientId;

			if (deps.grantPolicy) {
				// CP-18: fail-closed. grantPolicy is a security boundary (it
				// narrows scope/audience); if it throws we cannot know what
				// the narrowed decision would have been. Failing open would
				// effectively grant the pre-policy scope ceiling, which is
				// exactly what policy exists to prevent.
				const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
				const resource = resourceIndicatorEnabled
					? extractResourceParam(body as Record<string, unknown>)
					: null;
				let decision: Awaited<ReturnType<typeof deps.grantPolicy.evaluate>>;
				try {
					decision = await deps.grantPolicy.evaluate(
						{
							grantType: "refresh_token",
							// D-6: policy gate sees the authenticated client, not the
							// raw body — same rationale as for token aud/azp.
							clientId: authenticatedClientId,
							subject: subjectStr,
							requestedScope: requestedScope
								? [...new Set(requestedScope.split(" ").filter(Boolean))]
								: undefined,
							originalScope: scopeStr ? scopeStr.split(" ") : undefined,
							// RFC 8707: populated only when oauth.resourceIndicator.enabled
							// is true; undefined otherwise (flag-off preserves pre-existing
							// semantics and token-exchange's independent resource contract).
							resource: resource ?? undefined,
						},
						{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: issuer ?? "" },
					);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "policy evaluation unavailable",
						},
					};
				}
				if (decision.outcome === "deny") {
					return {
						result: {
							status: 400,
							error: decision.error,
							errorDescription: decision.errorDescription,
						},
					};
				}
				if (decision.grantedScope) {
					// CP-15: RFC 6749 §6 says the issued scope MUST NOT exceed
					// the scope of the original grant. Re-enforce after policy
					// so a buggy/compromised policy cannot expand privileges
					// beyond what the refresh token originally carried.
					const originalSet = scopeStr ? scopeStr.split(" ") : [];
					const exceeded = decision.grantedScope.filter((s) => !originalSet.includes(s));
					if (exceeded.length > 0) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `policy returned scopes exceeding original grant: ${exceeded.join(" ")}`,
							},
						};
					}
					// CP-15: empty array → null so response omits scope.
					finalScope = decision.grantedScope.length > 0 ? decision.grantedScope.join(" ") : null;
				}
				if (decision.grantedAudience && decision.grantedAudience.length > 0) {
					// generateToken carries a single `aud` claim; policy may narrow
					// to multiple audiences, but we flatten to the first one here.
					// Multi-audience tokens are out of scope for this grant path.
					finalAudience = decision.grantedAudience[0];
				}
			}

			const tokenPayloadClaims = tokenPayload as Record<string, unknown>;
			const familyIdRaw = tokenPayloadClaims.family_id;
			const familyId =
				typeof familyIdRaw === "string" && familyIdRaw.length > 0 ? familyIdRaw : null;
			const sidRaw = tokenPayloadClaims.sid;
			const sid = typeof sidRaw === "string" && sidRaw.length > 0 ? sidRaw : undefined;
			const previousJti =
				typeof tokenPayloadClaims.jti === "string" ? tokenPayloadClaims.jti : null;
			const newFamilyId = familyId ?? randomUUID();

			// Fail-closed session check — only when both sid + store are present.
			if (sid && deps.userSessionStore) {
				let session: Awaited<ReturnType<typeof deps.userSessionStore.get>>;
				try {
					session = await deps.userSessionStore.get(sid);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session store unavailable",
						},
					};
				}
				if (!session) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "session_invalid",
						},
					};
				}
			}

			// SF-6 / Phase G / M6: when rotation is wired, refresh
			// tokens MUST carry both jti AND family_id. Fail-fast BEFORE
			// `generateToken()` runs so (a) we don't burn keystore signatures
			// on a request that is going to be rejected anyway, and (b) a
			// transient keystore failure cannot mask the deterministic
			// `invalid_grant / missing_jti_or_family_id` response. Pre-M6
			// the gate sat after token mint because the `accept-with-warning`
			// branch needed the minted tokens; with M6 removing that branch,
			// rejection is unconditional and the gate is free to move.
			if (deps.refreshTokenFamilyRotation && (previousJti === null || familyId === null)) {
				logger?.warn(
					{
						clientId: authenticatedClientId,
						hasJti: previousJti !== null,
						hasFamilyId: familyId !== null,
					},
					"legacy_rt_rejected",
				);
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "missing_jti_or_family_id",
					},
				};
			}

			// CP-15: empty string (e.g. requested=" ") normalizes to null so the
			// token response omits scope rather than emitting `scope: ""`.
			const scopeClaim = finalScope && finalScope.length > 0 ? finalScope : null;

			const newAccessToken = await generateToken(
				{ family_id: newFamilyId, ...(sid ? { sid } : {}) },
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer,
					audience: finalAudience,
					subject: subjectStr ?? null,
					// D-6: new token `azp` is the authenticated client. The legacy
					// `tokenAzp` resolution (`claims.azp ?? tokenAud`) has been
					// subsumed by the binding gate above (which proves the input
					// token's azp/aud equalled `authenticatedClientId`), so
					// reading from `ctx.authenticatedClient.clientId` is strictly
					// equivalent and removes the body-spoofable surface.
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);

			const newRefreshToken = await generateToken(
				{ family_id: newFamilyId, ...(sid ? { sid } : {}) },
				{
					expiresIn: config.oauth.refreshToken.expiresIn,
					keyStore,
					issuer,
					audience: finalAudience,
					subject: subjectStr ?? null,
					// D-6: same rationale as above — `azp` is bound to the
					// authenticated client at issuance.
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "rt+jwt",
				},
			);

			if (deps.refreshTokenFamilyRotation) {
				// SF-6 fail-fast above already returned for missing
				// jti/family_id when rotation is wired. The check below
				// documents that invariant, narrows for TS, and acts as
				// defense-in-depth if a future refactor moves the gate.
				if (previousJti === null || familyId === null) {
					throw new Error(
						"invariant violation: SF-6 fail-fast must run before refresh-token rotation block",
					);
				}
				const newRefreshPayload = decodeJwtPayload(newRefreshToken.token);
				const newJti = newRefreshPayload.jti as string | undefined;
				const newExp = newRefreshPayload.exp as number | undefined;
				if (typeof newJti === "string" && typeof newExp === "number") {
					// CP-17: fail-closed when the store is unavailable. Same
					// rationale as CP-16 — we cannot atomically consume the old
					// jti and register the new one, so replay detection cannot
					// be guaranteed. Return 503 so the client retries rather
					// than bubbling an unhandled 500 HTML from express.
					let rotateResult: Awaited<ReturnType<typeof deps.refreshTokenFamilyRotation.rotate>>;
					try {
						rotateResult = await deps.refreshTokenFamilyRotation.rotate(
							previousJti,
							newJti,
							newFamilyId,
							newExp * 1000,
						);
					} catch {
						return {
							result: {
								status: 503,
								error: "temporarily_unavailable",
								errorDescription: "refresh token store unavailable",
							},
						};
					}
					// Exhaustive switch over the 4-outcome rotation union.
					// Each case explicitly handles the security-relevant
					// outcome; falling through to issuance (the v0.4.x
					// behavior for unknown_family) is now an explicit
					// policy decision under operator control (CC-2).
					switch (rotateResult.outcome) {
						case "rotated":
							// Successful rotation — fall through to the
							// success path below (token issuance).
							break;
						case "replayed": {
							// PB-1: RFC 6819 §5.2.2 / OAuth 2.1 BCP §4.14.2
							// require revoking the entire family on replay
							// so siblings cannot continue to redeem. Fail
							// closed when the revocation dep is missing or
							// throws — silently rejecting only the present
							// request would leave sibling RTs valid.
							if (!deps.refreshTokenFamilyRevocation) {
								logger?.error(
									{ clientId: authenticatedClientId },
									"rt_reuse_detected_but_no_revocation_dep",
								);
								return {
									result: {
										status: 503,
										error: "temporarily_unavailable",
										errorDescription: "refresh token family revocation not configured",
									},
								};
							}
							try {
								await deps.refreshTokenFamilyRevocation.revokeFamily(newFamilyId);
							} catch {
								return {
									result: {
										status: 503,
										error: "temporarily_unavailable",
										errorDescription: "refresh token store unavailable",
									},
								};
							}
							logger?.warn(
								{ familyId: newFamilyId, clientId: authenticatedClientId },
								"rt_reuse_detected_family_revoked",
							);
							return {
								result: {
									status: 400,
									error: "invalid_grant",
									errorDescription: "replay_detected",
								},
							};
						}
						case "revoked":
							return {
								result: {
									status: 400,
									error: "invalid_grant",
									errorDescription: "family_revoked",
								},
							};
						case "unknown_family": {
							// CC-2: defense-in-depth — SF-6 already rejects
							// tokens with familyId === null when rotation is
							// wired, but if a future change reorders gates,
							// fall through to a hard reject regardless of
							// policy when there was never a family to consult.
							if (familyId === null) {
								logger?.warn(
									{ clientId: authenticatedClientId },
									"unknown_family_rejected_no_family_id_claim",
								);
								return {
									result: {
										status: 400,
										error: "invalid_grant",
										errorDescription: "unknown_family",
									},
								};
							}
							const policy = config.oauth.refreshToken.unknownFamilyPolicy ?? "reject";
							if (policy === "reject") {
								logger?.warn(
									{
										familyId: newFamilyId,
										jti: previousJti,
										clientId: authenticatedClientId,
									},
									"unknown_family_rejected",
								);
								return {
									result: {
										status: 400,
										error: "invalid_grant",
										errorDescription: "unknown_family",
									},
								};
							}
							// "accept" — legacy migration mode only; emit
							// audit log and fall through to issuance.
							logger?.warn(
								{
									familyId: newFamilyId,
									jti: previousJti,
									clientId: authenticatedClientId,
								},
								"unknown_family_accepted_legacy_mode",
							);
							break;
						}
						default: {
							// Exhaustiveness guard: every outcome above
							// either returns or breaks. A future addition
							// to RefreshTokenFamilyRotationOutcome that
							// forgets to update this switch will produce a
							// compile error here rather than silently
							// falling through to token issuance.
							const _exhaustive: never = rotateResult;
							throw new Error(`unhandled rotation outcome: ${JSON.stringify(_exhaustive)}`);
						}
					}
				}
			}

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: newAccessToken,
						refreshToken: newRefreshToken,
					}),
				},
			};
		},
	};
};
