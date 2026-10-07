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

/**
 * The `refresh_token` grant (RFC 6749 §6): redeems a refresh token issued to
 * the authenticated client for a new access token and a rotated refresh
 * token in the same family.
 *
 * What it keeps:
 * - The presented token is the original grant, and its ceiling. Its scope
 *   bounds the scope the request or the policy may narrow to, and its
 *   effective audience (its `aud`, or the client id when it carries none)
 *   bounds the audience a `resource` or the policy may narrow to (RFC 8707
 *   §2.2). Each audience is also held to the client's registration.
 * - Narrowing applies to the access token issued, never to the rotated
 *   refresh token, which carries the original scope and audience. An
 *   original audience the registration no longer holds is refused, never
 *   re-issued.
 * - Sender binding continues (DPoP, mTLS); the session is admitted and the
 *   subject's revocation watermark read again before signing; the family
 *   rotation is committed before anything is signed, and a replay revokes
 *   the family.
 */

import { randomUUID } from "node:crypto";
import {
	type Admission,
	type AdmissionDeps,
	admitSession,
	boundPolicyAudience,
	checkOAuthTokenSettings,
	checkResolver,
	deriveAudienceFromResources,
	describeAdmissionOutage,
	evaluateGrantPolicy,
	extractResourceParam,
	type GrantContext,
	type GrantDependencies,
	type GrantError,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	isVerificationUnavailable,
	loggableError,
	matchConfirmation,
	ownedConfirmation,
	type ProviderDeps,
	readIssuedScope,
	readSpaceDelimitedParameter,
	tokenClaim,
	unrepresentedResources,
	VERIFICATION_UNAVAILABLE_DESCRIPTION,
	verifyJwt,
	wellFormedAcr,
	wellFormedAmr,
	wellFormedAuthTime,
} from "@o3co/auth-provider-core";
import type { JWTPayload } from "jose";
import { stepUpRefusal } from "../admission.mjs";
import type { REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { bindConfidentialClientRefreshTokensFrom } from "./tokenBindingRule.mjs";

/**
 * Subtracted from the family ceiling a rotation reports before the refresh
 * token's `exp` is set from it: `cappedExpiresAtMs` may drift forward by
 * milliseconds, and a token must not outlive the record that catches its
 * replay.
 */
const CAPPED_EXPIRY_DRIFT_MARGIN_MS = 1_000;

/**
 * What the refresh grant reads. `sessionRequirementResolver` and `auditSink`
 * feed admission of the token's session; the resolver is required, and a
 * factory built without one is refused. The lifetimes, `legacyTypAccept` and
 * the resource-indicator switch come from the `oauthTokenSettings` slot, and
 * the refresh-token binding rule from core's `tokenBindingSettings`. It
 * reads nothing of the configuration: `unknownFamilyPolicy` is the module's
 * `oauth-authorization.grants.refreshToken.unknownFamilyPolicy`, handed over
 * as the section parsed it.
 */
export type RefreshTokenGrantDeps = Pick<
	GrantDependencies,
	| "keyStore"
	| "logger"
	| "grantPolicy"
	| "refreshTokenFamilyRotation"
	| "refreshTokenFamilyRevocation"
	| "subjectRevocation"
	| "userSessionStore"
> &
	ProviderDeps<
		"sessionRequirementResolver" | "oauthTokenSettings" | "tokenBindingSettings",
		"auditSink" | "sessionLifecycleStore"
	> & {
		/**
		 * What a refresh token whose family no record holds gets: issued only
		 * under `"accept"`, a migration window's setting; anything else, absent
		 * included, refuses it.
		 */
		readonly unknownFamilyPolicy?: "accept" | "reject";
	};

/**
 * The token endpoint's answer to an admission that does not refresh, or
 * `undefined` when admitted: a gone, expired or foreign session is
 * `invalid_grant` `session_invalid`; `unmet`/`reauthenticate` is
 * `invalid_grant` naming the requirement; `step_up` adds `step_up` beside it
 * (a token has no browser to redirect); an outage is `503`.
 */
const refusalFor = (admission: Admission): GrantError | undefined => {
	switch (admission.outcome) {
		case "admitted":
			return undefined;
		case "not_live":
		// `revoked` and `unauthenticated` cannot occur for a token carrier
		// (verifyJwt applied the boundary; `tokenClaim` is authenticated) but are
		// listed so the switch stays exhaustive: a missing case would refresh.
		case "revoked":
		case "unauthenticated":
			return { status: 400, error: "invalid_grant", errorDescription: "session_invalid" };
		case "unmet":
		case "reauthenticate":
			return {
				status: 400,
				error: "invalid_grant",
				errorDescription: `the refresh token does not meet the ${admission.requirement} requirement`,
			};
		case "step_up":
			return stepUpRefusal(admission.requirement);
		case "unavailable":
			return {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: describeAdmissionOutage(admission.store),
			};
	}
};

/**
 * The presented refresh token's audience: the ceiling and the default for the
 * audience a refresh issues. A token that names none was issued for its
 * client, the one the `azp` binding proved.
 */
const readOriginalAudience = (aud: JWTPayload["aud"], clientId: string): readonly string[] => {
	const named = (Array.isArray(aud) ? aud : [aud]).filter(
		(value): value is string => typeof value === "string" && value.length > 0,
	);
	return named.length > 0 ? named : [clientId];
};

export const createRefreshTokenGrant = (deps: RefreshTokenGrantDeps): GrantHandler => {
	const { keyStore, logger, subjectRevocation } = deps;
	if (deps.userSessionStore !== undefined && deps.sessionLifecycleStore === undefined) {
		throw new Error(
			"The refresh_token grant: userSessionStore is wired, but sessionLifecycleStore is not. " +
				"Where a user-session store is wired, core's session lifecycle is required: the grant " +
				"admits the token's session through its lifecycle record. Wire core's session " +
				"lifecycle: a session-store module that fills sessionLifecycleStore " +
				"(memorySessionStoresModule or redisSessionStoresModule) and sessionLifecycleModule.",
		);
	}
	// Read once, here. Only `"accept"` issues for an unknown family: any other
	// value a hand-built deps carries refuses, as absent does.
	const acceptUnknownFamily = deps.unknownFamilyPolicy === "accept";
	// What admission reads for the token's session; no acr table, since a
	// refresh asks for no acr.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: deps.userSessionStore,
		sessionLifecycleStore: deps.sessionLifecycleStore,
		subjectRevocation,
		requirements: checkResolver(deps.sessionRequirementResolver, "createRefreshTokenGrant"),
		acrTable: {},
		logger,
		auditSink: deps.auditSink,
	};
	// The token settings are read once, here, from the `oauthTokenSettings`
	// slot alone, checked whole first: a hand-built value the check refuses,
	// or none, fails at composition, naming the slot, before any request —
	// not after client authentication and the rotation have spent the
	// presented token.
	const tokenSettings = checkOAuthTokenSettings(deps.oauthTokenSettings);
	const accessTokenExpiresIn = tokenSettings.accessTokenLifetime.defaultExpiresIn;
	const requestedRefreshExpiresIn = tokenSettings.refreshTokenExpiresIn;
	const { legacyTypAccept, resourceIndicatorEnabled } = tokenSettings;
	// The refresh-token binding rule, read once from core's
	// `tokenBindingSettings` slot.
	const bindConfidentialClients = bindConfidentialClientRefreshTokensFrom(
		deps.tokenBindingSettings,
		"createRefreshTokenGrant",
	);

	/**
	 * The presented token's verification, with its refusal as the token
	 * endpoint answers it. Run again after each slow await before signing,
	 * so the subject's revocation watermark is read anew without depending
	 * on a session.
	 */
	const verifyPresented = async (
		refreshTokenValue: string,
		issuer: string | undefined,
	): Promise<
		| { readonly ok: true; readonly payload: JWTPayload; readonly typ: string | undefined }
		| { readonly ok: false; readonly result: GrantError }
	> => {
		try {
			// The verifier pins alg / iss / typ and the signature. aud/azp are
			// checked by the grant instead, for a more specific error and to
			// accept tokens that carry `aud` but no `azp`.
			const verified = await verifyJwt(refreshTokenValue, keyStore, {
				type: "refresh_token",
				expectedIssuer: issuer ?? "",
				legacyTypAccept,
				// No access-token jti denylist: refresh tokens are revoked through
				// the family store. The subject watermark is the backstop for a
				// partial revocation cascade; a rotated token carries a fresh
				// `iat`, so only tokens minted before the credential change are
				// refused.
				revocation: { subjectRevocation },
				logger,
			});
			return { ok: true, payload: verified.payload, typ: verified.header.typ };
		} catch (err) {
			// A dependency the verifier could not consult (revocation store,
			// keystore) is an outage: `503`, not `invalid_grant`, which tells
			// the client to discard its refresh token (RFC 6749 §5.2) and would
			// log out everyone who refreshed during a blip. The verifier still
			// fails closed. Every other failure stays `invalid_grant`.
			if (isVerificationUnavailable(err)) {
				// The verifier's own closed vocabulary, not text a store wrote.
				const { reason } = err;
				logger?.error(
					{ site: "refresh_token", reason, err: loggableError(err) },
					"token_verification_unavailable",
				);
				return {
					ok: false,
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: VERIFICATION_UNAVAILABLE_DESCRIPTION[reason],
					},
				};
			}
			return {
				ok: false,
				result: { status: 400, error: "invalid_grant", errorDescription: "invalid refresh_token" },
			};
		}
	};

	/**
	 * Revokes a family whose rotation committed but whose tokens are not
	 * signed. Without the revocation dep, or when it fails (logged), the
	 * family is still left unusable: its newest token was never issued, and
	 * the spent one replays as a revocation.
	 */
	const revokeRotatedFamily = async (familyId: string, clientId: string): Promise<void> => {
		if (!deps.refreshTokenFamilyRevocation) return;
		try {
			await deps.refreshTokenFamilyRevocation.revokeFamily(familyId);
		} catch (err) {
			logger?.error(
				{
					store: "refresh_token_family",
					step: "revoke",
					familyId,
					clientId,
					err: loggableError(err),
				},
				"refresh_token_store_unavailable",
			);
		}
	};

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;
			const { refresh_token: refreshTokenValue, scope: requestedScope } = body as {
				refresh_token?: string;
				// Not `client_id`: identity comes from `ctx.authenticatedClient`.
				scope?: unknown;
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

			// Client identity comes only from RFC 6749 §2.3 authentication
			// (clientAuthMw); the body's `client_id` is spoofable. A call that
			// bypassed the middleware cannot be bound to a client and is refused.
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

			const verified = await verifyPresented(refreshTokenValue, issuer);
			if (!verified.ok) return { result: verified.result };
			const { payload: tokenPayload, typ } = verified;

			// Defends against an access token presented as a refresh token. The
			// verifier refuses any `typ` but `rt+jwt`, yet under `legacyTypAccept`
			// passes a token with none; this grant refuses that one too.
			if (typ !== "rt+jwt") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid refresh_token",
					},
				};
			}

			// Bind the refresh token to its issuing client via `azp` (RFC 9068
			// §2.2), falling back to `aud` for tokens issued without `azp`.
			const tokenAud = Array.isArray(tokenPayload.aud) ? tokenPayload.aud[0] : tokenPayload.aud;
			const claims = tokenPayload as Record<string, unknown>;
			// A refresh does not repeat authentication, so `amr`, `acr` and
			// `auth_time` carry forward from the presented token (OIDC Core §12.2,
			// RFC 9470 §6.1), and a token that carries none yields none. Only
			// well-formed values: a claim copied forward is vouched for again.
			const carriedAmr = wellFormedAmr(claims.amr);
			const carriedAcr = wellFormedAcr(claims.acr);
			const carriedAuthTime = wellFormedAuthTime(claims.auth_time);
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

			// Refresh-time binding continuity for DPoP (RFC 9449 §5) and mTLS
			// (RFC 8705 §4), via core's `matchConfirmation` (shared with token
			// exchange, resource binding and introspection). Checked before any
			// policy, store I/O or signing so rejections short-circuit.
			//
			//   RT cnf | proof / cert  | outcome
			//   no     | no            | plain Bearer
			//   no     | yes           | bound access token (opt-in upgrade)
			//   yes    | no            | invalid_grant "requires ..."
			//   yes    | yes, differs  | invalid_grant "does not match ..."
			//   yes    | yes, equal    | bound access token + bound refresh token
			//
			// The two rejections have distinct descriptions so a SIEM can tell a
			// stolen token replayed without its key from a key mismatch. A
			// compound `cnf` (both `jkt` and `x5t#S256`) can only come from a bug
			// or a crafted token and is refused outright. `invalid_grant` because
			// at refresh the token is the grant (RFC 6749 §5.2); neither binding
			// RFC pins an error code here.
			const presentedConfirmation = ownedConfirmation(ctx.tokenBinding);
			const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
			const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";
			const match = matchConfirmation((tokenPayload as { cnf?: unknown }).cnf, ctx.tokenBinding);
			if (match.status === "compound") {
				// Compound-cnf pre-matrix reject — see comment above.
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "refresh_token has compound cnf binding which is not supported",
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

			// RFC 6749 §3.3, two readings. The token's claim is this server's
			// record: read so it never widens (`readIssuedScope`) and carried on
			// in canonical form. The request is the client's: read strictly, so a
			// malformed one is refused; a repeated parameter arrives as an array.
			// Empty or `null` means no change.
			const originalScopes = readIssuedScope(scopeStr);
			let requested: readonly string[] | undefined;
			if (requestedScope !== undefined && requestedScope !== null) {
				if (typeof requestedScope !== "string") {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "scope must be a space-delimited string",
						},
					};
				}
				const named = readSpaceDelimitedParameter(requestedScope);
				if (named === null) {
					return {
						result: {
							status: 400,
							error: "invalid_scope",
							errorDescription: "scope is not a space-delimited list of scope-tokens",
						},
					};
				}
				if (named.length > 0) requested = named;
			}

			// RFC 6749 Section 6: requested scope MUST NOT exceed original scope
			let grantedScope = originalScopes.length > 0 ? originalScopes.join(" ") : null;
			if (requested) {
				const invalid = requested.filter((s) => !originalScopes.includes(s));
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
			// RFC 8707 §2.2: the issued audience stays within the original grant's,
			// and within the client's registration, as the scope stays within the
			// original grant's (RFC 6749 §6). The refresh token carries the
			// original audience, its first entry (`generateToken` carries one
			// `aud`), which is also the access token's when nothing narrows it.
			const originalAudience = readOriginalAudience(tokenPayload.aud, authenticatedClientId);
			const withinOriginal = (audiences: readonly string[]): readonly string[] =>
				audiences.filter((audience) => originalAudience.includes(audience));
			const refreshAudience = originalAudience[0] ?? authenticatedClientId;
			let finalAudience: string | null = refreshAudience;
			// Whether the policy named the audience, which may be the client id itself.
			let policyChoseAudience = false;

			// Read under the flag alone: with no policy wired, issuing the client
			// id in answer to a `resource` request would violate RFC 8707 §2.
			const requestedResource = resourceIndicatorEnabled
				? extractResourceParam(body as Record<string, unknown>)
				: null;

			if (deps.grantPolicy) {
				// Fail closed: the policy narrows scope and audience, so a throw
				// must not fall back to the pre-policy ceiling.
				const outcome = await evaluateGrantPolicy(
					deps.grantPolicy,
					{
						grantType: "refresh_token",
						// The authenticated client, never the body's `client_id`.
						clientId: authenticatedClientId,
						subject: subjectStr,
						requestedScope: requested === undefined ? undefined : [...requested],
						// A copy: `originalScopes` is the ceiling the answer is held to.
						originalScope: scopeStr ? [...originalScopes] : undefined,
						// A copy, as above: `originalAudience` is the audience ceiling.
						originalAudience: [...originalAudience],
						// RFC 8707: only under `oauth.resourceIndicator.enabled`.
						resource: requestedResource ?? undefined,
					},
					{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: issuer ?? "" },
					requested ?? originalScopes,
					// RFC 6749 §6: the issued scope must not exceed the original
					// grant — the ceiling, wider than what this refresh asked for,
					// which a silent policy leaves.
					{ scopeCeiling: { scopes: originalScopes, name: "original grant" }, logger },
				);
				if (!outcome.ok) return { result: outcome.result };
				const { decision } = outcome;
				// An empty grant → null so the response omits scope.
				finalScope = outcome.scopes.length > 0 ? outcome.scopes.join(" ") : null;
				// A policy may narrow the audience to one of this client's
				// `allowedAudiences` within the original audience, and nothing
				// else; naming none leaves it as is.
				const policyAudience = boundPolicyAudience(
					decision,
					withinOriginal(ctx.authenticatedClient.allowedAudiences ?? []),
				);
				if (!policyAudience.ok) return { result: policyAudience.result };
				if (policyAudience.audience !== null) {
					finalAudience = policyAudience.audience;
					policyChoseAudience = true;
				}
			}

			// RFC 8707 §2: when no policy narrowed the audience, derive it from
			// the requested resource within `allowedAudiences ∪ {clientId}` and
			// the original audience. A policy decision always wins. A resource
			// that derives nothing is `invalid_target` here, never left to the
			// original audience's default.
			if (!policyChoseAudience && requestedResource && requestedResource.length > 0) {
				const derived = deriveAudienceFromResources(
					requestedResource,
					new Set(
						withinOriginal([
							...(ctx.authenticatedClient.allowedAudiences ?? []),
							authenticatedClientId,
						]),
					),
				);
				if (derived === undefined) {
					return {
						result: {
							status: 400,
							error: "invalid_target",
							errorDescription: `requested_resources_not_in_audience: ${requestedResource.join(" ")}`,
						},
					};
				}
				finalAudience = derived;
			}

			// RFC 8707 §2: the audience must represent the requested resource.
			// After both the policy and the derivation, so an unsatisfiable
			// request fails closed.
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

			// The original audience, which the refresh token carries and the
			// access token defaults to, is held to the registration as a policy's
			// or a resource's choice is; one no longer registered is refused,
			// never replaced or re-issued. Before admission and the rotation, so
			// the family is left as it was.
			if (
				refreshAudience !== authenticatedClientId &&
				!(ctx.authenticatedClient.allowedAudiences ?? []).includes(refreshAudience)
			) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "the grant's audience is no longer registered for this client",
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

			// Admit the token's session, after the policy and before the rotation
			// spends the presented token: the live session by `sid` (skipped
			// without a `sid` or a store), fail-closed, with requirements judged
			// on the token's own `amr`. Admission skips the revocation boundary for
			// a token carrier, so the presented token is verified again after it:
			// the subject's watermark is the last read, independent of any session,
			// and a revocation that landed during the policy or the requirements
			// mints nothing. Each refusal is answered as its first check.
			const recheck = async (): Promise<GrantError | undefined> => {
				const refusal = refusalFor(
					await admitSession(admissionDeps, {
						// `subjectStr` was refused above when the token carries no `sub`.
						claim: tokenClaim({ sid, sub: subjectStr, amr: carriedAmr }),
						action: "oauth.refresh" satisfies keyof typeof REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
					}),
				);
				if (refusal !== undefined) return refusal;
				const reverified = await verifyPresented(refreshTokenValue, issuer);
				return reverified.ok ? undefined : reverified.result;
			};
			const refusal = await recheck();
			if (refusal !== undefined) return { result: refusal };

			// With rotation wired, a refresh token must carry `jti` and
			// `family_id`. Checked before signing, so no signature is spent on a
			// doomed request and a keystore failure cannot mask this answer.
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

			// An empty string (e.g. requested=" ") becomes null so the token
			// response omits scope rather than emitting `scope: ""`.
			const scopeClaim = finalScope && finalScope.length > 0 ? finalScope : null;
			// RFC 6749 §6: the new refresh token's scope is the presented one's,
			// whatever this access token was narrowed to.
			const refreshScopeClaim = originalScopes.length > 0 ? originalScopes.join(" ") : null;

			// New tokens inherit the request-time binding. The access token's
			// `cnf` is `presentedConfirmation`: only the member the binding's
			// mechanism owns, so a contributed mechanism cannot mint a binding no
			// owning mechanism validated. A new refresh token is bound only for
			// DPoP and mTLS — the mechanisms whose refresh-time matrix above
			// enforces continuity; a new mechanism must add its matrix before it
			// is added here. `generateTokenResponse` reads `token_type` off the
			// access token's `cnf` ("DPoP" for `jkt`, else "Bearer"; RFC 8705 §3).
			const isPublicClient = ctx.authenticatedClient.tokenEndpointAuthMethod === "none";
			// Confidential clients' refresh tokens are unbound unless
			// `bindConfidentialClientRefreshTokens` is set. Neither RFC 9449 §5
			// nor RFC 8705 §7.1 requires or forbids binding them: this grant
			// already requires client authentication and a matching `azp`, so a
			// stolen token is useless without the client's credential. Binding
			// helps only when the key is better protected than the secret (HSM vs
			// environment variable). Off by default because a bound token pins
			// the client to one key or certificate for its lifetime, so rotating
			// it mid-lifetime breaks refresh.
			const bindNewRefreshToken =
				(bindingIsDpop || bindingIsMtls) &&
				presentedConfirmation !== undefined &&
				(isPublicClient || bindConfidentialClients);

			// The rotation is a reservation: the new token's `jti` and issuance
			// instant are fixed here, committed to the family store below, and
			// signed only once the commit holds. A replay or revoked family
			// returns having signed nothing, so a KMS-backed key is not billed for
			// a lost race.
			const issuedAt = Math.floor(Date.now() / 1000);
			const newRefreshJti = randomUUID();
			const newRefreshExp = issuedAt + requestedRefreshExpiresIn;
			// What the rotation actually committed: a family's TTL is set once at
			// creation and never extended, so a late rotation may commit a
			// shorter expiry than asked. Signing past it would outlive the record
			// that catches the token's replay.
			let refreshExpiresIn = requestedRefreshExpiresIn;

			// Whether the family store committed this rotation: only then is the
			// presented token spent and `newRefreshJti` reserved, which makes a
			// later signing failure an orphan rather than an ordinary outage.
			let rotationCommitted = false;
			if (deps.refreshTokenFamilyRotation) {
				// Guaranteed by the fail-fast above; narrows the types and guards
				// against a refactor that reorders the gates.
				if (previousJti === null || familyId === null) {
					throw new Error(
						"invariant violation: a refresh token without a jti or a family_id must be refused before rotation",
					);
				}
				// Fail closed when the store is unavailable: without an atomic
				// consume-and-register, replay detection cannot be guaranteed.
				// `503` so the client retries.
				let rotateResult: Awaited<ReturnType<typeof deps.refreshTokenFamilyRotation.rotate>>;
				try {
					rotateResult = await deps.refreshTokenFamilyRotation.rotate(
						previousJti,
						newRefreshJti,
						newFamilyId,
						newRefreshExp * 1000,
					);
				} catch (err) {
					logger?.error(
						{
							store: "refresh_token_family",
							step: "rotate",
							familyId: newFamilyId,
							clientId: authenticatedClientId,
							err: loggableError(err),
						},
						"refresh_token_store_unavailable",
					);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "refresh token store unavailable",
						},
					};
				}
				// Every outcome is handled explicitly; issuing for an unknown family
				// is operator policy (`unknownFamilyPolicy`), never a fall-through.
				switch (rotateResult.outcome) {
					case "rotated": {
						rotationCommitted = true;
						// Issue at no more than the ceiling the store committed. A
						// capped ceiling drifts forward by milliseconds after the
						// adapter's round-trip, so a margin is subtracted; flooring
						// alone can land past the true ceiling.
						const capped = rotateResult.cappedExpiresAtMs;
						if (capped !== undefined && capped < newRefreshExp * 1000) {
							refreshExpiresIn = Math.min(
								requestedRefreshExpiresIn,
								Math.floor((capped - CAPPED_EXPIRY_DRIFT_MARGIN_MS) / 1000) - issuedAt,
							);
						}
						break;
					}
					case "replayed": {
						// RFC 6819 §5.2.2 / OAuth 2.1 BCP §4.14.2: a replay revokes the
						// whole family so siblings cannot keep redeeming. The rotation
						// should revoke it inside the compare-and-swap that detected the
						// replay (`familyRevoked: true`), the only race-free ordering.
						// `familyRevoked` is optional, so a custom rotation may not; then
						// revoke separately, failing closed when the revocation dep is
						// missing or throws — rejecting only this request would leave
						// sibling tokens valid.
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
							} catch (err) {
								logger?.error(
									{
										store: "refresh_token_family",
										step: "revoke",
										familyId: newFamilyId,
										clientId: authenticatedClientId,
										err: loggableError(err),
									},
									"refresh_token_store_unavailable",
								);
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
						// Defense in depth: the fail-fast above already refuses a
						// token with no `family_id`; never accept one here.
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
						if (!acceptUnknownFamily) {
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
						// Compile-time exhaustiveness: a new rotation outcome must
						// not fall through to issuance.
						const _exhaustive: never = rotateResult;
						throw new Error(`unhandled rotation outcome: ${JSON.stringify(_exhaustive)}`);
					}
				}

				// The session's admission and the watermark again, after the
				// rotation's await and before signing: a revocation or a session
				// end that landed meanwhile mints nothing.
				const refusalAfter = await recheck();
				if (refusalAfter !== undefined) {
					// A committed rotation spent the presented token and reserved one
					// never signed; the family is revoked so nothing rotates it on.
					if (rotationCommitted) await revokeRotatedFamily(newFamilyId, authenticatedClientId);
					return { result: refusalAfter };
				}

				// `issuedAt` was reserved before the store call, so measure what is
				// left against the clock now, after every await: a cap at the end of
				// the family's life, or a store slow enough to spend it, leaves a
				// token that would be signed already expired.
				if (rotationCommitted && issuedAt + refreshExpiresIn <= Math.floor(Date.now() / 1000)) {
					logger?.info(
						{ familyId: newFamilyId, clientId: authenticatedClientId },
						"refresh_token_family_lifetime_exhausted",
					);
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "refresh token family has reached its lifetime",
						},
					};
				}
			}

			// A carried `auth_time` is never later than the presented token's own
			// `iat` — an authentication precedes the token that records it — nor
			// than this issuance, so `max_age` never reads a negative age.
			const presentedIat = wellFormedAuthTime(tokenPayload.iat);
			const authenticationClaims = {
				...(carriedAmr ? { amr: carriedAmr } : {}),
				...(carriedAcr ? { acr: carriedAcr } : {}),
				...(carriedAuthTime !== undefined
					? { auth_time: Math.min(carriedAuthTime, presentedIat ?? issuedAt, issuedAt) }
					: {}),
			};

			// From here the rotation is committed, so a signer failure orphans
			// the family's newest token: the client's retry with the old token
			// reads as a replay and revokes the family — the price of reserving
			// before signing. Answer `503` and log the family so the orphan is
			// traceable, rather than an unhandled 500.
			let newAccessToken: Awaited<ReturnType<typeof generateToken>>;
			let newRefreshToken: Awaited<ReturnType<typeof generateToken>>;
			try {
				newAccessToken = await generateToken(
					{ family_id: newFamilyId, ...(sid ? { sid } : {}), ...authenticationClaims },
					{
						expiresIn: accessTokenExpiresIn,
						keyStore,
						issuer,
						audience: finalAudience,
						subject: subjectStr ?? null,
						// The authenticated client, which the binding gate proved
						// equals the presented token's azp/aud.
						authorizedParty: authenticatedClientId,
						scope: scopeClaim,
						tokenType: "at+jwt",
						// The rotation's issuance instant, which `auth_time` is capped at.
						issuedAt,
						...(presentedConfirmation ? { confirmation: presentedConfirmation } : {}),
					},
				);

				newRefreshToken = await generateToken(
					// Onto the new refresh token too, or the second refresh drops them.
					{ family_id: newFamilyId, ...(sid ? { sid } : {}), ...authenticationClaims },
					{
						expiresIn: refreshExpiresIn,
						keyStore,
						issuer,
						// The original grant's, never this access token's narrowing.
						audience: refreshAudience,
						subject: subjectStr ?? null,
						// As above.
						authorizedParty: authenticatedClientId,
						scope: refreshScopeClaim,
						tokenType: "rt+jwt",
						// The identity reserved with the family store above.
						jti: newRefreshJti,
						issuedAt,
						...(bindNewRefreshToken ? { confirmation: presentedConfirmation } : {}),
					},
				);
			} catch (err) {
				if (!rotationCommitted) {
					// Nothing was reserved (no rotation wired, or an unknown family
					// accepted), so this is an ordinary signer outage and the
					// presented token is still valid.
					throw err;
				}
				logger?.error(
					{ err: loggableError(err), familyId: newFamilyId, previousJti, newRefreshJti },
					"refresh_token_rotation_orphaned",
				);
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "token signing unavailable",
					},
				};
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
