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
	isRevocationUnavailable,
	matchConfirmation,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { JWTPayload } from "jose";
import { decodeJwtPayload } from "./_jwtPayload.mjs";
import {
	deriveAudienceFromResources,
	extractResourceParam,
	unrepresentedResources,
} from "./_resourceIndicator.mjs";

export const createRefreshTokenGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore, logger, subjectRevocation } = deps;

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
					// #367/#376: no AT jti denylist here — RT revocation runs off
					// the family store (`refreshTokenFamilyRevocation`, consulted
					// below). The subject watermark IS consulted: it is the
					// backstop for a partial #322 cascade failure, and a rotated
					// RT carries a fresh `iat`, so only RTs minted before the
					// credential change are refused.
					revocation: { subjectRevocation },
					logger,
				});
				tokenPayload = verified.payload;
				typ = verified.header.typ;
			} catch (err) {
				// #408: a revocation store that could not be consulted is an
				// outage, not a finding. The verifier fails closed either way —
				// an unreachable store must never read as "not revoked" — but
				// answering `invalid_grant` here told the client to discard its
				// refresh token (RFC 6749 §5.2), so a transient Redis blip
				// force-logged-out every user who refreshed during it. This
				// handler already answers a family-store outage with `503`
				// below; the same event class gets the same answer.
				//
				// Only this reason is remapped. Every other verification
				// failure — a bad signature, the wrong `typ`, an expired or
				// genuinely revoked token — is still the client's problem and
				// still `invalid_grant`.
				if (isRevocationUnavailable(err)) {
					logger?.error({ err }, "refresh_token_revocation_store_unavailable");
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "revocation store unavailable",
						},
					};
				}
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

			// Wave 2 Phase 2 §9.2 + Phase 3 §9.2 (mTLS rows): refresh-time
			// binding matrices for DPoP (RFC 9449 §5) and mTLS (RFC 8705 §4).
			// RT carries `cnf` (jkt or x5t#S256) only when issued to a public
			// client with proof; confidential-client RTs are always plain.
			// The matrix itself is core's `matchConfirmation` (#324) — one
			// implementation shared with the token-exchange grant,
			// `protectedResourceBindingMw`, and introspection; this grant
			// keeps only the row → `invalid_grant` error mapping below. It is
			// evaluated BEFORE any further work so rejections short-circuit
			// ahead of policy evaluation, store I/O, and `generateToken`
			// keystore signatures.
			//
			// DPoP matrix (unchanged from Phase 2):
			//   RT cnf.jkt | proof JKT       | Outcome
			//   no         | no              | issue plain Bearer (legacy)
			//   no         | yes             | issue DPoP-bound AT (opt-in upgrade)
			//   yes        | no              | reject invalid_grant
			//   yes        | yes, differs    | reject invalid_grant (multi-key attack)
			//   yes        | yes, equal      | issue DPoP-bound AT + bound RT (rotation preserves)
			//
			// mTLS matrix (new in Phase 3, parallel to DPoP):
			//   RT cnf.x5t#S256 | client cert    | Outcome
			//   no              | no             | issue plain Bearer (legacy)
			//   no              | yes            | issue mTLS-bound AT (opt-in upgrade)
			//   yes             | no             | reject invalid_grant — errorDescription
			//                                       "refresh_token requires a client certificate"
			//   yes             | yes, differs   | reject invalid_grant — errorDescription
			//                                       "client certificate does not match refresh_token binding"
			//   yes             | yes, equal     | issue mTLS-bound AT + bound RT (rotation preserves)
			//
			// Row 3 vs row 4 use distinct errorDescription strings so SIEMs
			// can distinguish "stolen RT replayed without cert" from
			// "mid-rotation / multi-cert attack" today. A future cross-cutting
			// sub-PR will add audit-emission reason codes (spec §12.2:
			// `rt_binding_mismatch` with `reason: "cert_absent" |
			// "thumbprint_mismatch"`) — those are NOT wire strings and are
			// out of Sub-PR 3c scope; do not grep the code for them.
			//
			// **Compound-cnf rejection (Codex Critical #2):** if the RT
			// carries BOTH `cnf.jkt` AND `cnf.x5t#S256` we short-circuit
			// with `invalid_grant` BEFORE running either matrix. Stage 1
			// only supports single-mechanism bindings; a compound cnf could
			// only arise from a bug or an attacker-crafted RT and accepting
			// it would create ambiguous enforcement semantics. The reject
			// makes the boundary explicit and structural.
			//
			// Error code is `invalid_grant` (RFC 6749 §5.2) — at refresh
			// time the RT IS the grant; a missing/mismatched proof means
			// the grant cannot be used. Neither RFC 9449 §5 nor RFC 8705
			// §4 pin a specific OAuth error code for this branch;
			// `invalid_grant` is more caller-actionable than
			// `invalid_dpop_proof` / a future `invalid_client_certificate`
			// (the proof / cert itself is well-formed; the grant is what
			// cannot be honored).
			// `presentedConfirmation` is mechanism-agnostic and feeds the
			// AT cnf claim emission below (RFC 7800 — mechanism-neutral).
			// `matchConfirmation` gates each cnf member on its owning
			// mechanism kind (PR #185 / Codex Important #2) — see
			// `core/grants/confirmationMatch.mts` for the kind-boundary and
			// thumbprint-timing rationale.
			const presentedConfirmation = ctx.tokenBinding?.confirmation;
			const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
			const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";
			const match = matchConfirmation((tokenPayload as { cnf?: unknown }).cnf, ctx.tokenBinding);
			if (match.status === "compound") {
				// Compound-cnf pre-matrix reject — see comment above.
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							"refresh_token has compound cnf binding which is not supported (Stage 1)",
					},
				};
			}
			if (match.status === "no-proof") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							match.member === "jkt"
								? "refresh_token requires a DPoP proof"
								: "refresh_token requires a client certificate",
					},
				};
			}
			if (match.status === "mismatch") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							match.member === "jkt"
								? "DPoP proof does not match refresh_token binding"
								: "client certificate does not match refresh_token binding",
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

			// Stage 2 (#173): read outside the policy block. Enforcement below is
			// gated on the flag ALONE — with no policy wired `finalAudience`
			// stays the authenticated client id, and issuing that in response to
			// a `resource` request is the RFC 8707 §2 violation Stage 2 closes.
			const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
			const requestedResource = resourceIndicatorEnabled
				? extractResourceParam(body as Record<string, unknown>)
				: null;

			if (deps.grantPolicy) {
				// CP-18: fail-closed. grantPolicy is a security boundary (it
				// narrows scope/audience); if it throws we cannot know what
				// the narrowed decision would have been. Failing open would
				// effectively grant the pre-policy scope ceiling, which is
				// exactly what policy exists to prevent.
				const resource = requestedResource;
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
					// Fail-closed audience validation: policy may only narrow to
					// audiences already in client.allowedAudiences. An out-of-bounds
					// audience from a buggy/compromised policy would mint a token
					// accepted by a resource server the client is not authorized for.
					// Mirrors clientCredentials.mts exactly (same ceiling, error code,
					// message phrasing). Activated by T18 wiring resource into this
					// path; pre-T18 grantPolicy paths that returned no grantedAudience
					// are byte-equivalent (this block only runs on non-empty arrays).
					const allowedAudSet = new Set(ctx.authenticatedClient.allowedAudiences ?? []);
					const exceeded = decision.grantedAudience.filter((a) => !allowedAudSet.has(a));
					if (exceeded.length > 0) {
						return {
							result: {
								status: 400,
								error: "invalid_request",
								errorDescription: `policy returned audiences outside client allowedAudiences: ${exceeded.join(" ")}`,
							},
						};
					}
					// Flatten to first entry (multi-audience tokens are out of scope
					// for this grant path — matches cc and authorization_code patterns).
					finalAudience = decision.grantedAudience[0];
				}
			}

			// RFC 8707 §2 audience derivation (Stage 2, #173). `finalAudience` is
			// still the authenticated client id unless a policy narrowed it, so
			// without this a request for an otherwise-allowed resource would be
			// rejected even though the AS could satisfy it. Only applies when the
			// policy left the audience alone — a policy decision always wins.
			if (finalAudience === authenticatedClientId && requestedResource) {
				const derived = deriveAudienceFromResources(
					requestedResource,
					new Set([...(ctx.authenticatedClient.allowedAudiences ?? []), authenticatedClientId]),
				);
				if (derived !== undefined) finalAudience = derived;
			}

			// RFC 8707 §2 (Stage 2, #173): the refreshed token's audience MUST be
			// the resource indicator(s) the client asked for. Placed after both
			// the policy block and the derivation above, so a request that could
			// not be satisfied either way still fails closed.
			const unrepresented = unrepresentedResources(requestedResource, finalAudience);
			if (unrepresented.length > 0) {
				return {
					result: {
						status: 400,
						error: "invalid_target",
						errorDescription: `requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
					},
				};
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

			// Wave 2 Phase 2 §9.2 + Phase 3 §9.2 (mTLS rows): new tokens
			// inherit the request-time binding.
			//
			// **AT cnf** is mechanism-agnostic. `presentedConfirmation`
			// (defined above) is the full `ctx.tokenBinding?.confirmation`
			// regardless of kind — DPoP `{jkt}`, mTLS `{x5t#S256}`, and
			// future mechanisms all flow through unchanged because RFC 7800
			// cnf claim shape is mechanism-neutral.
			//
			// **New RT cnf** is gated on
			// `(bindingIsDpop || bindingIsMtls) && isPublicClient`,
			// mirroring §9.1's auth_code rule. The gate is a mechanism
			// allowlist: only the mechanisms whose refresh-time matrix
			// (above) actually enforces continuity may emit a bound RT.
			// Adding a future mechanism MUST land its refresh-time matrix
			// BEFORE being added here (PR #185 / Codex Important #1
			// convergence — silent degradation prevention).
			//
			// The wire-level `token_type` is "DPoP" only for the DPoP kind
			// (mTLS keeps "Bearer" per RFC 8705 §3).
			const tokenType = bindingIsDpop ? "DPoP" : "Bearer";
			const isPublicClient = ctx.authenticatedClient.tokenEndpointAuthMethod === "none";
			// #275: `bindConfidentialClientRefreshTokens` opts a deployment out of
			// the `isPublicClient` restriction.
			//
			// Neither RFC requires the restriction and neither forbids lifting
			// it. RFC 9449 §5's "refresh tokens issued to confidential clients
			// ... are not bound" is descriptive prose with no RFC 2119 keyword,
			// sitting next to three MUSTs for public clients; RFC 8705 §7.1 says
			// the same about certificates. Their shared rationale holds here —
			// this grant refuses an unauthenticated caller and refuses an RT
			// whose `azp` is not the authenticated client — so a stolen RT is
			// unusable without the client's own credential and binding buys
			// nothing against the threat as usually stated.
			//
			// It buys something only where the two credentials are protected
			// differently: a client secret in an environment variable, a DPoP
			// key in an HSM or TPM. Leaking the secret alone is then not enough.
			// Off by default because the cost is real in the other direction — a
			// bound RT pins the client to one key or certificate for the RT's
			// whole lifetime, so rotating mid-lifetime breaks refresh.
			//
			// Mechanism-neutral, because the gate is and because
			// `oauth.tokenBinding` is where cross-mechanism policy already
			// lives. Nothing else is needed to make it mean something: the
			// refresh-time continuity matrix runs off the RT's own `cnf`, so a
			// confidential client's newly bound RT is enrolled in it by the same
			// rule that already covers public clients.
			const bindConfidentialClients =
				config.oauth.tokenBinding?.bindConfidentialClientRefreshTokens === true;
			const bindNewRefreshToken =
				(bindingIsDpop || bindingIsMtls) && (isPublicClient || bindConfidentialClients);

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
					...(presentedConfirmation ? { confirmation: presentedConfirmation } : {}),
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
					...(bindNewRefreshToken ? { confirmation: presentedConfirmation } : {}),
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
							// so siblings cannot continue to redeem.
							//
							// #274: the shipped rotation now revokes the family
							// inside the same compare-and-swap that detected the
							// replay and says so with `familyRevoked: true`. That
							// is the ONLY ordering with no race — this handler
							// used to issue the revoke as a second write, and a
							// sibling holding the still-active token could rotate
							// successfully in between.
							//
							// The fallback below is not dead code: `familyRevoked`
							// is optional, so a custom `RefreshTokenFamilyRotation`
							// written before #274 still reports a bare
							// `{ outcome: "replayed" }`. Absence is treated as "not
							// revoked" and we revoke separately — the pre-#274
							// behaviour, race and all, but never worse than it.
							// Fail closed when the revocation dep is missing or
							// throws: silently rejecting only the present request
							// would leave sibling RTs valid.
							if (rotateResult.familyRevoked !== true) {
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
					tokens: generateTokenResponse(
						{
							accessToken: newAccessToken,
							refreshToken: newRefreshToken,
						},
						{ tokenType },
					),
				},
			};
		},
	};
};
