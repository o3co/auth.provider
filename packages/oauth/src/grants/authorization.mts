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
	constantTimeStringEqual,
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
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";
import { decodeJwtPayload } from "./_jwtPayload.mjs";
import { extractResourceParam, unrepresentedResources } from "./_resourceIndicator.mjs";
import { PKCE_METHOD_S256, pkceMethodsForClient } from "./pkce.mjs";

export const createAuthorizationGrant = (
	deps: GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository },
): GrantHandler => {
	const { config, codeRepository, clientRepository, keyStore, logger } = deps;

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

	// #273: ONE PKCE policy, resolved from the same config through the same
	// resolver `/authorize` uses (`grants/session.mts` reads its own knob the
	// same way). Pre-#273 this site re-derived its own view — a `required`
	// flag plus a `requireS256` legacy fallback the authorization endpoint did
	// not honour — so `/authorize` could mint a code that `/token` refused.
	// Resolved once at composition; `logger` carries the inert-config warning.
	const pkce = resolveOAuthOptions(config, logger).pkce;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer } = ctx;
			const {
				code,
				code_verifier = null,
				redirect_uri = null,
			} = body as {
				code?: string;
				code_verifier?: string | null;
				// D-6: `client_id` / `client_secret` from body are no longer
				// destructured — `clientAuthMw` populates `ctx.authenticatedClient`
				// and the binding gate below verifies `codeData.client_id` against
				// the authenticated identity.
				redirect_uri?: string | null;
			};

			// D-6: client identity comes from RFC 6749 §2.3 token-endpoint
			// authentication (clientAuthMw). A grant invocation that did not pass
			// through that middleware (custom route, direct unit-test call) cannot
			// be bound to a client and MUST be refused — the previous body-based
			// `client_secret` check was superseded by route-level middleware.
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

			// D-1: hoist redirect_uri presence check ahead of consumeByCode so
			// requests missing it reject without burning the (otherwise valid)
			// code via the atomic getDel. The full equality check against
			// codeData.redirect_uri still happens below.
			if (!redirect_uri) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "redirect_uri mismatch",
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

			// D-6: canonical authority binding. The middleware authenticated the
			// presenter; the code repository persisted the original `/authorize`
			// caller. They must agree, otherwise an authenticated client could
			// redeem a code issued to a different client.
			if (codeData.client_id !== authenticatedClientId) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "code was not issued to this client",
					},
				};
			}

			// A-2: redirect_uri binding (RFC 6749 §4.1.3)
			// D-1: codeData.redirect_uri is now always populated (required field).
			// The previous `?? session.code_redirect_uri` fallback hid the IH-4
			// vacuous-pass bug where Redis silently dropped redirect_uri and the
			// check was skipped entirely. Now strictly enforced. The presence
			// check on `redirect_uri` is hoisted above consumeByCode; this site
			// only verifies the equality binding.
			if (redirect_uri !== codeData.redirect_uri) {
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

			// SF-3 fixup: a code record carrying `code_challenge` without
			// `code_challenge_method` would silently bypass PKCE validation
			// because the outer `if (codeData.code_challenge_method)` gate
			// below is falsy. The /authorize route never persists this shape
			// (challenge is stored only when method is resolved — see
			// `routes.mts:632-661`), so in practice this guard fires only on
			// a corrupt store record or a custom CodeRepository implementation
			// that wrote the partial state.
			//
			// RFC 6749 error mapping (Copilot review on PR #126): the request
			// itself is well-formed; the persisted authorization code is
			// unredeemable. `invalid_grant` is the standard code for "this
			// code cannot be used", which matches what is happening here
			// (and is also what the other unredeemable-code branches in this
			// handler return). errorDescription says "invalid code" (the
			// same wording used by the other invalid-code branches above)
			// so storage implementation details do not leak to the client.
			if (codeData.code_challenge && !codeData.code_challenge_method) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			// #273: PKCE is required of every authorization-code client, so a
			// code carrying neither challenge nor method is unredeemable — by a
			// confidential client too. `/authorize` no longer mints one, so
			// reaching here means a code issued before the upgrade or by a
			// custom CodeRepository.
			//
			// Unconditional, deliberately. `ResolvedPkceOptions.required` is the
			// literal `true`, so gating this on it would be a branch that cannot
			// take its other path — dead code reading as though PKCE were still
			// switchable here. The type is the guarantee; the runtime read that
			// ties this endpoint to `/authorize` is `pkceMethodsForClient(pkce, …)`
			// below, which consults the very object `/authorize` consults.
			//
			// Ordered AFTER the corrupt-shape guard above on purpose: a record
			// that carries a challenge but no method is a storage defect, not a
			// client that skipped PKCE, and it keeps its own `invalid_grant` /
			// "invalid code" answer rather than being relabelled as a missing
			// challenge the client never actually omitted.
			const challengeMethod = codeData.code_challenge_method;
			if (!challengeMethod) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "PKCE is required but code was issued without code_challenge",
					},
				};
			}

			// Validate code_verifier against the code record. Unconditional and
			// un-nested: this used to sit inside `if (codeData.code_challenge_method)`,
			// the shape from when PKCE was optional and a code could legitimately
			// carry no method. The mandatory check above returns for exactly that
			// case now, so the wrapper could never take its false path.
			//
			// SF-3 (v0.5.1): a code record with `code_challenge_method` set
			// but no `code_challenge` is structurally invalid — the two are a
			// pair persisted together at /authorize. Pre-SF-3 this state was
			// silently accepted because `verifier !== undefined` is always
			// true (the comparison "passed" for the wrong reason). Now that
			// `constantTimeStringEqual` requires both arguments to be
			// strings, the malformed shape is rejected explicitly. Reject as
			// invalid_request; the code is consumed already so no replay risk.
			if (typeof codeData.code_challenge !== "string") {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "code_challenge missing on code record",
					},
				};
			}
			// #273: the method must be one THIS client may use — `S256`,
			// plus `plain` only for a registration that opted in. Same
			// `pkceMethodsForClient` call `/authorize` made when it minted
			// the code, against the same registration, so a code this AS
			// issued is never refused here for its method.
			if (!pkceMethodsForClient(pkce, ctx.authenticatedClient).includes(challengeMethod)) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: `code_challenge_method "${challengeMethod}" is not supported`,
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
			// #273: `pkceMethodsForClient` admits exactly `S256` and `plain`,
			// and the allowlist check above already refused anything else —
			// against a frozen constant in `grants/pkce.mts`, not an
			// operator-supplied list. So this is a two-way choice, not a
			// switch with a `default` guard against operator/switch
			// divergence: that divergence used to be reachable through the
			// `pkce.supportedMethods` knob, and #273 removed the knob.
			// `pkce.test.mts` pins the admissible set to exactly these two,
			// so growing it without revisiting this comparison fails there.
			//
			// For `S256` the stored challenge is the digest of the verifier;
			// for `plain` it is the verifier itself (RFC 7636 §4.2).
			const expectedChallenge =
				challengeMethod === PKCE_METHOD_S256
					? crypto.createHash("sha256").update(code_verifier).digest("base64url")
					: code_verifier;
			// SF-3 + MIN-4 (v0.5.1): timing-safe compare, on both methods —
			// a short-circuit `!==` leaks per-byte progress of a candidate
			// verifier against the stored challenge (RFC 7636 §4.1, OAuth 2.1
			// BCP §4.5). One call site now instead of two identical ones.
			if (!constantTimeStringEqual(expectedChallenge, codeData.code_challenge)) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code_verifier",
					},
				};
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

			// The subject of every token issued here is the user the *code* was
			// bound to, resolved through `sid` — not whoever owns the session that
			// happens to accompany the token request. For a confidential client
			// `/token` is a back-channel call with no end-user cookie, so
			// `session.user` is undefined; reading it there produced access and
			// refresh tokens with no `sub` at all, while the id_token (which has
			// always read the UserSession) carried one. In a same-origin topology
			// where `/token` does carry cookies, the two could name different
			// users if the session changed between `/authorize` and `/token`.
			//
			// Resolving the session here rather than in the linking block below
			// also means a session deleted between `/authorize` and `/token` is
			// rejected before any token is signed.
			let userSession: UserSession | null = null;
			if (deps.userSessionStore && sid) {
				try {
					userSession = await deps.userSessionStore.get(sid);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session store unavailable",
						},
					};
				}
				if (!userSession) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "session_invalid",
						},
					};
				}
			}

			// The fallback is gated on the *store* being absent, not on `sub` being
			// nullish. `userSession?.sub ?? sessionUserId` would look equivalent,
			// but it silently reverts to the cookie-derived identity whenever a
			// store returns a record with no usable `sub` — reintroducing exactly
			// the cross-user mismatch this fix removes, in the one topology
			// (same-origin/BFF) where `/token` does carry cookies. `UserSession.sub`
			// is typed `string`, but the store boundary is not enforced at runtime
			// and custom implementations exist.
			let subject: string | null;
			if (deps.userSessionStore) {
				const sub = userSession?.sub;
				if (typeof sub !== "string" || sub.length === 0) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "session_invalid",
						},
					};
				}
				subject = sub;
			} else {
				// No store wired means no sid to resolve, so the token-request
				// session is the only available subject.
				const rawUserId = (session.user as Record<string, unknown> | undefined)?.id;
				subject = typeof rawUserId === "string" ? rawUserId : null;
			}

			// Initial rt+jwt opens a new refresh-token family for replay detection
			// per RFC 6819 §5.2.2.3. All subsequent rotations carry the same
			// family_id; revoking the family revokes every descendant.
			const familyId = crypto.randomUUID();

			// generateToken carries a single `aud` claim; if policy narrowed to multiple
			// audiences we flatten to the first. Multi-audience tokens are out of scope
			// for the authorization code grant.
			// D-6: default `aud` to the authenticated client (was raw body
			// `client_id`). The binding gate above already proved the two are
			// identical to `codeData.client_id`, so this rewrite is equivalent
			// and removes the body-spoofable surface that Codex M2 flagged.
			const audience =
				grantedAudiencesFromCode && grantedAudiencesFromCode.length > 0
					? grantedAudiencesFromCode[0]
					: authenticatedClientId;

			// RFC 8707 §2 (Stage 2, #173). RFC 8707 permits `resource` at both
			// `/authorize` and `/token` for this flow, so a conformant client may
			// present it here — but the audience was already decided at
			// `/authorize` and persisted on the code.
			//
			// This is enforcement ONLY: a comparison against the persisted value,
			// with no policy invocation. Re-running `grantPolicy` here to
			// re-narrow would reintroduce exactly the token-endpoint surface D-1
			// removed and break evaluate-once-at-authorize (C-2 / D-1). Ignoring
			// the parameter instead would silently hand back a token whose `aud`
			// is not what the client asked for, which is the §2 violation. So the
			// request is honoured by being checked, not by being re-decided.
			//
			// The `/authorize` endpoint forwards `resource` to the policy hook so
			// the audience persisted on the code can reflect it; see the ADR
			// `packages/core/docs/adr/2026-07-31-rfc8707-resource-audience-binding.md`.
			const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
			if (resourceIndicatorEnabled) {
				const requestedResource = extractResourceParam(body as Record<string, unknown>);
				const unrepresented = unrepresentedResources(requestedResource, audience);
				if (unrepresented.length > 0) {
					return {
						result: {
							status: 400,
							error: "invalid_target",
							errorDescription: `requested_resources_not_in_audience: ${unrepresented.join(" ")}`,
						},
					};
				}
			}

			// CP-12: normalize empty scope array to null so the token response
			// omits `scope` entirely instead of emitting `scope: ""` (which
			// consumers can't distinguish from "scope claim omitted").
			const scopeClaim = grantedScopes && grantedScopes.length > 0 ? grantedScopes.join(" ") : null;

			// Wave 2 Phase 2 §9.1 + Phase 3 §9.1 (mTLS RT binding):
			// propagate the token-binding confirmation (RFC 7800 `cnf`) into
			// the issued tokens.
			//
			// **AT cnf** is mechanism-agnostic: any binding's confirmation
			// (DPoP `{jkt}`, mTLS `{x5t#S256}`, future mechanisms) flows
			// through unchanged because RFC 7800 cnf claim shape is
			// mechanism-neutral.
			//
			// **RT cnf** is gated on `(bindingIsDpop || bindingIsMtls) &&
			// isPublicClient`:
			//   1. RT binding is restricted to **public clients**
			//      (`tokenEndpointAuthMethod === "none"`): confidential
			//      clients use the client secret as the refresh-time
			//      authenticator (RFC 9449 §5 for DPoP; the same rationale
			//      generalizes to mTLS per RFC 8705 §4 which talks about
			//      client-cert-bound RTs for clients that have no other
			//      strong refresh-time credential). RT-key-binding adds no
			//      security for confidential clients and would force key /
			//      cert retention across the RT lifetime.
			//   2. The gate is a **mechanism allowlist** — only the binding
			//      kinds whose refresh-time enforcement matrix this grant
			//      knows how to honor are admitted. A future mechanism
			//      (FIDO attestation etc.) MUST land its refresh-time
			//      matrix in `refreshToken.mts` BEFORE being added here,
			//      mirroring the PR #185 mechanism-allowlist rationale that
			//      stopped Phase 2 from silently emitting unenforceable
			//      mTLS-bound RTs.
			//
			// The wire-level `token_type` is "DPoP" only for the DPoP kind
			// (mTLS keeps "Bearer" per RFC 8705 §3).
			const confirmation = ctx.tokenBinding?.confirmation;
			const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
			const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";
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
			const bindRefreshToken =
				(bindingIsDpop || bindingIsMtls) && (isPublicClient || bindConfidentialClients);

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
					subject,
					// D-6: `azp` is the authenticated client (was raw body `client_id`).
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
					...(confirmation ? { confirmation } : {}),
				},
			);
			const refreshToken = await generateToken(
				{ family_id: familyId, ...(sid ? { sid } : {}) },
				{
					expiresIn: config.oauth.refreshToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject,
					// D-6: `azp` is the authenticated client (was raw body `client_id`).
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "rt+jwt",
					...(bindRefreshToken ? { confirmation } : {}),
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
			// `userSession` was resolved before token generation (Fix I1: a session
			// deleted between /authorize and /token must not produce tokens, which
			// would be orphaned from logout orchestration); the re-check below keeps
			// the CR-4 window narrow across the findById await.
			if (deps.userSessionStore && sid) {
				// Fix I2: clientRepository.findById is fallible — move inside try/catch
				// so a throw here returns a controlled 503 instead of propagating to the
				// express default handler as an unhandled HTML 500.
				try {
					// D-6: logout-metadata lookup uses the authenticated client id
					// (was raw body `client_id`). The two are guaranteed equal by
					// the binding gate above, but reading from the authenticated
					// slot keeps Codex M2's "no raw body for identity" invariant.
					const clientRecord = await clientRepository.findById(authenticatedClientId);

					// CR-4: re-validate session liveness immediately before mutating the
					// family index. The first `get` now happens before token generation,
					// so the span between the two reads also covers both `generateToken`
					// signings and `refreshTokenFamilyRotation.register` in addition to
					// the `findById` awaited just above — a `cascadeLogout` in that window
					// would leave the just-issued tokens orphaned from logout orchestration.
					// Per Codex Delta 1, this REDUCES the window for the common case
					// (logout fully completes before the second check). It does NOT close
					// the sub-millisecond window between this check and `addFamilyId`;
					// Phase F's atomic `addFamilyIdIfSessionActive` Lua EVAL closes that.
					//
					// The store-availability path is handled by its OWN try/catch (mirrors
					// the first-get pattern before token generation) so a Redis blip emits the same
					// `"session store unavailable"` errorDescription as the first-get path,
					// rather than being misattributed to the outer "session linking
					// unavailable" catch (which spans findById + addFamilyId + registerRP).
					let revalidatedSession: Awaited<ReturnType<typeof deps.userSessionStore.get>>;
					try {
						revalidatedSession = await deps.userSessionStore.get(sid);
					} catch {
						return {
							result: {
								status: 503,
								error: "temporarily_unavailable",
								errorDescription: "session store unavailable",
							},
						};
					}
					if (!revalidatedSession) {
						// Codex Delta 3: log security-relevant rejection so SIEMs can
						// correlate against cascadeLogout audit events. The audit payload
						// intentionally omits a code identifier — the `Code` / `CodeData`
						// type does not carry a stable jti, and logging the raw `code`
						// string would leak secret material.
						logger?.warn(
							{ sid, clientId: authenticatedClientId },
							"authorization_grant_rejected_session_invalidated_during_token_issuance",
						);
						return {
							result: {
								status: 400,
								error: "invalid_grant",
								errorDescription: "session_invalidated",
							},
						};
					}
					// The access and refresh tokens were signed from the FIRST read's
					// `sub`; the id_token below is minted from this one. A store that
					// returned a different subject for the same `sid` between the two
					// reads would hand back tokens that disagree about who the user is
					// — the exact confusion this grant's subject handling exists to
					// prevent. A `sub` change under a fixed `sid` is a store invariant
					// violation, not a race worth tolerating, so refuse rather than
					// reconcile.
					if (revalidatedSession.sub !== subject) {
						logger?.warn(
							{ sid, clientId: authenticatedClientId },
							"authorization_grant_rejected_session_subject_changed_during_token_issuance",
						);
						return {
							result: {
								status: 400,
								error: "invalid_grant",
								errorDescription: "session_invalidated",
							},
						};
					}
					// Use the revalidated session for downstream TTL bookkeeping. Subsequent
					// id_token generation reads `userSession`, so refresh the outer binding.
					userSession = revalidatedSession;

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
							// D-6: RP record carries the authenticated client id.
							clientId: authenticatedClientId,
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
					// D-6: id_token `aud` / `azp` bind to the authenticated client.
					aud: authenticatedClientId,
					azp: authenticatedClientId,
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
					tokens: generateTokenResponse({ accessToken, refreshToken, idToken }, { tokenType }),
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
