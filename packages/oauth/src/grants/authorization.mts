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
	type Admission,
	type AdmissionDeps,
	admitSession,
	auditErrorText,
	authTimeAt,
	checkResolver,
	codeClaimFirstRead,
	codeClaimRevalidation,
	consoleLogger,
	constantTimeStringEqual,
	describeAdmissionOutage,
	extractResourceParam,
	type GrantContext,
	type GrantDependencies,
	type GrantError,
	type GrantHandler,
	type GrantHandlerResult,
	generateIdToken,
	generateToken,
	generateTokenResponse,
	logClientRepositoryUnavailable,
	loggableError,
	ownedConfirmation,
	type ProviderDeps,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
	resolveTokenBindingSettings,
	type Token,
	type UserSession,
	unrepresentedResources,
	wellFormedAcr,
	wellFormedAmr,
} from "@o3co/auth-provider-core";
import { stepUpRefusal } from "../admission.mjs";
import type { AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS } from "../admissionActions.mjs";
import { behindClientBoundary } from "../clients/clientBoundary.mjs";
import { usableFrontchannelLogoutUri } from "../logout/frontchannelLogoutUri.mjs";
import { joinSession } from "../logout/sessionEnd.mjs";
import { resolveOAuthOptions } from "../resolveOAuthOptions.mjs";
import { PKCE_METHOD_S256, pkceMethodsForClient } from "./pkce.mjs";

/**
 * What the authorization-code grant reads: the shared grant slots it uses,
 * plus the repositories only this grant redeems against. The module's
 * `ProviderDeps<R, O>` must satisfy this at the wiring, so a slot read here
 * without the module declaring it is a compile error.
 */
export type AuthorizationGrantDeps = Pick<
	GrantDependencies,
	| "config"
	| "keyStore"
	| "logger"
	| "userSessionStore"
	| "subjectRevocation"
	| "refreshTokenFamilyRotation"
	| "refreshTokenFamilyRevocation"
	| "sessionFamilyIndex"
	| "sessionRPRegistry"
> &
	// `sessionRequirementResolver` (the synthetic key, by its slot's name, so
	// the module hands its deps over whole) is what the two reads of the
	// code's session go through (ADR 2026-09-28-session-admission). Required:
	// a factory built by hand without one is refused.
	ProviderDeps<"codeRepository" | "clientRepository" | "sessionRequirementResolver", "auditSink">;

/**
 * A requirement's verdict or an outage, as the token endpoint answers it:
 * `step_up` is `invalid_grant` with `step_up: "<requirement>"`, `unmet` and
 * `reauthenticate` are `invalid_grant` naming the requirement, and
 * `unavailable` is `503`, logged once by admission.
 */
const requirementOrOutageRefusal = (
	admission: Extract<
		Admission,
		{ outcome: "step_up" | "unmet" | "reauthenticate" | "unavailable" }
	>,
): GrantError => {
	switch (admission.outcome) {
		case "step_up":
			return stepUpRefusal(admission.requirement);
		case "unmet":
		case "reauthenticate":
			return {
				status: 400,
				error: "invalid_grant",
				errorDescription: `the session does not meet the ${admission.requirement} requirement`,
			};
		case "unavailable":
			return {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: describeAdmissionOutage(admission.store),
			};
	}
};

export const createAuthorizationGrant = (deps: AuthorizationGrantDeps): GrantHandler => {
	const { config, codeRepository, keyStore, logger } = deps;
	// The client's logout metadata is snapshotted into the session RP
	// registry, so the record is read through core's client-record boundary:
	// a record it refuses rejects the lookup, answered as the store's outage.
	const clientRepository = behindClientBoundary(deps.clientRepository, logger ?? consoleLogger);
	// No acr table: the acr was chosen at /authorize and travels on the code.
	const admissionDeps: AdmissionDeps = {
		userSessionStore: deps.userSessionStore,
		subjectRevocation: deps.subjectRevocation,
		requirements: checkResolver(deps.sessionRequirementResolver, "createAuthorizationGrant"),
		acrTable: {},
		logger,
		auditSink: deps.auditSink,
	};
	// A store this grant reads or writes itself that cannot answer is `503`,
	// logged once at error with the error's projection, never the error, which
	// can carry what the store was sent. The session store is read through
	// admission, which logs its own outage.
	const storeUnavailable = (
		store:
			| "authorization_code"
			| "refresh_token_family"
			| "session_family_index"
			| "session_rp_registry",
		step: "consume" | "register" | "add",
		clientId: string,
		err: unknown,
	): void => {
		logger?.error(
			{ store, step, clientId: auditErrorText(clientId), err: loggableError(err) },
			"authorization_grant_store_unavailable",
		);
	};

	/**
	 * Revoke the family a refused exchange registered, whose tokens were never
	 * served. Never throws: a failure is one error line, and the refusal
	 * stands. With a rotation and no revocation wired, the record stays
	 * active; `oauthAuthorizationModule` warns of that at boot.
	 */
	const revokeRefusedFamily = async (
		familyId: string,
		at: { readonly sid: string; readonly clientId: string },
	): Promise<void> => {
		if (!deps.refreshTokenFamilyRotation || !deps.refreshTokenFamilyRevocation) return;
		try {
			await deps.refreshTokenFamilyRevocation.revokeFamily(familyId);
		} catch (err) {
			logger?.error(
				{
					sid: at.sid,
					clientId: auditErrorText(at.clientId),
					familyId,
					err: loggableError(err),
				},
				"authorization_grant_refused_family_revocation_failed",
			);
		}
	};

	/**
	 * The first read's answer when it does not admit: a code with no `sid`
	 * while a store is wired is refused naming the login wiring; a record
	 * gone, past its expiry or without a subject, and a session established
	 * before the subject's sessions were revoked, are `session_invalid`; a
	 * requirement's verdict or an outage as {@link requirementOrOutageRefusal}.
	 */
	const firstReadRefusal = (admission: Exclude<Admission, { outcome: "admitted" }>): GrantError => {
		switch (admission.outcome) {
			case "not_live":
				return admission.reason === "no_sid"
					? {
							status: 400,
							error: "invalid_grant",
							errorDescription:
								"code record is missing session identifier (sid); ensure login wiring records sid at authorize time",
						}
					: { status: 400, error: "invalid_grant", errorDescription: "session_invalid" };
			case "revoked":
			// Never reached: a code's claim is authenticated by construction
			// (`codeClaimFirstRead`). Listed so `default` is left only the
			// outcomes `requirementOrOutageRefusal` answers.
			case "unauthenticated":
				return { status: 400, error: "invalid_grant", errorDescription: "session_invalid" };
			default:
				return requirementOrOutageRefusal(admission);
		}
	};

	/**
	 * The answer for a session that ended while the tokens were being issued:
	 * `session_invalidated`, logged at warn (subject change or otherwise) with
	 * the `sid` and the client for SIEM correlation with `cascadeLogout`'s
	 * audit events, and never a code identifier (`CodeData` has no stable jti,
	 * and the raw `code` is secret).
	 */
	const sessionInvalidated = (
		at: { readonly sid: string; readonly clientId: string },
		subjectChanged = false,
	): GrantError => {
		logger?.warn(
			at,
			subjectChanged
				? "authorization_grant_rejected_session_subject_changed_during_token_issuance"
				: "authorization_grant_rejected_session_invalidated_during_token_issuance",
		);
		return { status: 400, error: "invalid_grant", errorDescription: "session_invalidated" };
	};

	/**
	 * The second read's answer when it does not admit: a session that went
	 * away, expired, was revoked or changed its subject since the first read
	 * is {@link sessionInvalidated}. A requirement's verdict or an outage is
	 * answered as on the first read.
	 */
	const revalidationRefusal = (
		admission: Admission,
		at: { readonly sid: string; readonly clientId: string },
	): GrantError => {
		switch (admission.outcome) {
			case "not_live":
			case "revoked":
			case "unauthenticated":
			case "admitted":
				return sessionInvalidated(
					at,
					admission.outcome === "not_live" && admission.reason === "subject_mismatch",
				);
			default:
				return requirementOrOutageRefusal(admission);
		}
	};

	// id_token issuance requires a configured issuer URL, read from config and
	// not `ctx.issuer`: the express adapter falls back to the Host header when
	// the issuer is unset, and OIDC Core §2 requires `iss` to be a URL.
	const configuredIssuer: string | undefined = (() => {
		const jwt = (config.oauth as { jwt?: { issuer?: unknown } } | undefined)?.jwt;
		const value = jwt?.issuer;
		return typeof value === "string" && value.length > 0 ? value : undefined;
	})();

	// One PKCE policy, through the same resolver `/authorize` uses, so
	// `/authorize` cannot mint a code that `/token` refuses. Resolved once at
	// composition.
	const pkce = resolveOAuthOptions(config).pkce;

	// The lifetimes, also resolved once when the grant is built, so a
	// hand-built configuration the resolvers refuse fails composition rather
	// than a request after `consumeByCode` has spent the code.
	const accessTokenExpiresIn = resolveAccessTokenLifetime(config).defaultExpiresIn;
	const refreshTokenExpiresIn = resolveRefreshTokenLifetime(config);

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
				redirect_uri?: string | null;
			};

			// Client identity comes from RFC 6749 §2.3 token-endpoint
			// authentication (`clientAuthMw`). An invocation that bypassed it
			// cannot be bound to a client and is refused.
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

			// Presence only: `consumeByCode` (atomic getDel) is the sole
			// authenticity gate. A cross-check against the Express session would
			// race when two /authorize requests share one.
			if (!code) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			// Before consumeByCode, so a request missing it does not burn a valid
			// code. The equality check against the code's redirect_uri is below.
			if (!redirect_uri) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "redirect_uri mismatch",
					},
				};
			}

			// The client's logout metadata, read before the code is spent: a
			// record the boundary refuses, or a repository that cannot answer, is
			// a logged `503` that leaves the code redeemable and nothing signed or
			// registered. Read only where it is used, with a session store wired.
			let clientRecord: Awaited<ReturnType<typeof clientRepository.findById>> = null;
			if (deps.userSessionStore) {
				try {
					clientRecord = await clientRepository.findById(authenticatedClientId);
				} catch (err) {
					logClientRepositoryUnavailable(
						logger,
						{ site: "authorization_code", step: "find", clientId: authenticatedClientId },
						err,
					);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session linking unavailable",
						},
					};
				}
			}

			// Atomic consume (replay prevention). A store that cannot answer is a
			// logged `503`, not `500`: the client did nothing wrong. If the
			// consume never ran, a retry redeems the code; if it ran and the reply
			// was lost, the code is spent and the retry gets `400 invalid_grant`,
			// as single-use codes require. Nothing was issued either way.
			let codeData: Awaited<ReturnType<typeof codeRepository.consumeByCode>>;
			try {
				codeData = await codeRepository.consumeByCode(code);
			} catch (err) {
				storeUnavailable("authorization_code", "consume", authenticatedClientId, err);
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "authorization code store unavailable",
					},
				};
			}
			if (!codeData) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			// The authenticated presenter must be the client the code was issued
			// to, or a client could redeem another client's code.
			if (codeData.client_id !== authenticatedClientId) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "code was not issued to this client",
					},
				};
			}

			// redirect_uri binding (RFC 6749 §4.1.3), strict: the code always
			// carries one, and no fallback may let a missing value skip the check.
			if (redirect_uri !== codeData.redirect_uri) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "redirect_uri mismatch",
					},
				};
			}

			// Only the values persisted on the code at /authorize are
			// authoritative. Do NOT re-run grantPolicy here: it is evaluated once,
			// at /authorize.
			const grantedScopes: readonly string[] | undefined = codeData.grantedScope;
			const grantedAudiencesFromCode = codeData.grantedAudience;

			// A challenge without a method is a corrupt record (/authorize never
			// persists that shape) or a custom CodeRepository's. The request is
			// well-formed but the code is unredeemable: `invalid_grant` /
			// "invalid code", as the other such branches, so storage details do
			// not leak.
			if (codeData.code_challenge && !codeData.code_challenge_method) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code",
					},
				};
			}

			// PKCE is required of every authorization-code client, confidential
			// ones too, so a code with neither challenge nor method (a custom
			// CodeRepository's, or minted before PKCE was mandatory) is
			// unredeemable. Unconditional: `ResolvedPkceOptions.required` is the
			// literal `true`; the runtime tie to `/authorize` is
			// `pkceMethodsForClient(pkce, …)` below. After the corrupt-shape guard
			// above, so a storage defect keeps its own answer.
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

			// A method without a challenge is a structurally invalid record (the
			// two are persisted together) and must not reach the comparison. The
			// code is already consumed, so there is no replay risk.
			if (typeof codeData.code_challenge !== "string") {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "code_challenge missing on code record",
					},
				};
			}
			// The method must be one this client may use (`S256`, plus `plain`
			// only for a registration that opted in): the call `/authorize` made
			// when it minted the code, so a code this AS issued is never refused
			// here for its method.
			if (!pkceMethodsForClient(pkce, ctx.authenticatedClient).includes(challengeMethod)) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: `code_challenge_method '${challengeMethod}' is not supported`,
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
			// `pkceMethodsForClient` admits exactly `S256` and `plain` (a frozen
			// constant in `grants/pkce.mts`, pinned by `pkce.test.mts`), and the
			// check above refused anything else, so this is a two-way choice. For
			// `S256` the stored challenge is the verifier's digest; for `plain`,
			// the verifier itself (RFC 7636 §4.2).
			const expectedChallenge =
				challengeMethod === PKCE_METHOD_S256
					? crypto.createHash("sha256").update(code_verifier).digest("base64url")
					: code_verifier;
			// Timing-safe for both methods: `!==` leaks per-byte progress of a
			// candidate verifier (RFC 7636 §4.1, OAuth 2.1 BCP §4.5).
			if (!constantTimeStringEqual(expectedChallenge, codeData.code_challenge)) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "invalid code_verifier",
					},
				};
			}

			// `sid` is written at /authorize by the login or federation callback.
			// Required only when userSessionStore is wired (for the family and RP
			// linking below); without a store nothing writes it at login.
			const sid = codeData.sid;
			// Reflected verbatim in the id_token (OIDC Core §2).
			const nonce = codeData.nonce;

			// Every token's subject is the user the code was bound to, resolved
			// through `sid`, not the owner of whatever session accompanies the
			// token request: a confidential client's back-channel `/token` has no
			// end-user cookie, and in a same-origin topology the cookie's user may
			// have changed since `/authorize`.
			//
			// Read through admission here, before any token is signed, so a session
			// deleted, expired or revoked since `/authorize` is refused. `CodeData`
			// names no subject, so this first read's record supplies it and the
			// second read is compared against it.
			const firstRead = await admitSession(admissionDeps, {
				claim: codeClaimFirstRead(codeData),
				action:
					"oauth.code_exchange" satisfies keyof typeof AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
			});
			if (firstRead.outcome !== "admitted") {
				return { result: firstReadRefusal(firstRead) };
			}
			let userSession: UserSession | null = firstRead.session;

			// With a store, admission read a live record with a non-empty `sub`,
			// and that is the subject. The cookie fallback is gated on the store
			// being absent, never on the record, or the cross-user mismatch above
			// returns in the same-origin/BFF topology.
			let subject: string | null;
			if (deps.userSessionStore) {
				if (userSession === null) {
					// Unreachable: admission admits no store-backed claim without a record.
					return {
						result: { status: 400, error: "invalid_grant", errorDescription: "session_invalid" },
					};
				}
				subject = userSession.sub;
			} else {
				// No store wired means no sid to resolve, so the token-request
				// session is the only available subject.
				const rawUserId = (session.user as Record<string, unknown> | undefined)?.id;
				subject = typeof rawUserId === "string" ? rawUserId : null;
			}

			// The primary authentication's time, which a step-up never moves, read
			// once against the minting clock (core's `authTimeAt`): never later
			// than it, and the same on the access, refresh and id tokens (RFC 9470
			// §6.1). One this clock cannot read — further ahead than the skew
			// allows — refuses the exchange before anything is signed.
			// One issuance instant for the exchange: `authTime` is read against it
			// and every token signed here carries it as `iat` (the id_token's own
			// `auth_time` is read against the clock it signs with, never later than
			// its `iat`), so a wall clock moved back before the signing cannot put
			// `auth_time` after `iat`.
			const mintingNow = Date.now();
			const issuedAt = Math.floor(mintingNow / 1000);
			const authTime =
				userSession === null ? undefined : authTimeAt(userSession.authTime, mintingNow);
			if (userSession !== null && authTime === undefined) {
				logger?.warn(
					{
						sid,
						clientId: authenticatedClientId,
						aheadMs: userSession.authTime.getTime() - mintingNow,
					},
					"auth_time_ahead_of_clock",
				);
				return {
					result: { status: 400, error: "invalid_grant", errorDescription: "session_invalid" },
				};
			}

			// Initial rt+jwt opens a new refresh-token family for replay detection
			// per RFC 6819 §5.2.2.3. All subsequent rotations carry the same
			// family_id; revoking the family revokes every descendant.
			const familyId = crypto.randomUUID();

			// generateToken carries a single `aud`: several granted audiences are
			// flattened to the first, and the default is the authenticated client,
			// never the body's `client_id`.
			const audience =
				grantedAudiencesFromCode && grantedAudiencesFromCode.length > 0
					? grantedAudiencesFromCode[0]
					: authenticatedClientId;

			// RFC 8707 §2: a client may present `resource` at `/token` too, but the
			// audience was decided at `/authorize` and persisted on the code. It is
			// checked, not re-decided: re-running `grantPolicy` would break
			// evaluate-once-at-authorize, and ignoring it would hand back an `aud`
			// the client did not ask for. See ADR
			// 2026-07-31-rfc8707-resource-audience-binding.
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

			// An empty scope is null, so the response omits `scope` rather than
			// emitting `scope: ""`.
			const scopeClaim = grantedScopes && grantedScopes.length > 0 ? grantedScopes.join(" ") : null;

			// Token-binding confirmation (RFC 7800 `cnf`) on the issued tokens;
			// see README, "Token binding (`cnf`)".
			//
			// AT `cnf` is the member the binding's mechanism kind owns (core's
			// `ownedConfirmation`, the boundary `matchConfirmation` enforces on
			// the way back in). `Confirmation` is extensible by mechanism, so a
			// member no owning mechanism validated is not minted: that request is
			// issued unbound, and a compound one keeps the owning member alone.
			//
			// RT `cnf` needs a mechanism on the allowlist below and, unless opted
			// out, a public client (`tokenEndpointAuthMethod === "none"`): a
			// confidential client's own authentication is its refresh-time
			// authenticator (RFC 9449 §5, RFC 8705 §4). The allowlist admits only
			// kinds whose refresh-time matrix `refreshToken.mts` honours; a new
			// mechanism MUST land that matrix before being added here
			// (CONTRIBUTING.md §5).
			const confirmation = ownedConfirmation(ctx.tokenBinding);
			const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
			const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";
			const isPublicClient = ctx.authenticatedClient.tokenEndpointAuthMethod === "none";
			// `bindConfidentialClientRefreshTokens` lifts the public-client
			// restriction, which neither RFC requires (RFC 9449 §5 and RFC 8705
			// §7.1 are descriptive there). A stolen RT is already unusable without
			// the client's credential; binding helps only where the two are
			// protected differently (a secret in an env var, a DPoP key in an HSM).
			// Off by default: a bound RT pins the client to one key or certificate
			// for the RT's lifetime. The refresh-time matrix runs off the RT's own
			// `cnf`, so a newly bound confidential RT is enforced like any other.
			const bindConfidentialClients =
				resolveTokenBindingSettings(config).bindConfidentialClientRefreshTokens;
			const bindRefreshToken =
				(bindingIsDpop || bindingIsMtls) && (isPublicClient || bindConfidentialClients);

			// How, and to which acr, the user authenticated: read off the code and
			// stamped on the id_token, the access token and the refresh token
			// alike. Both were decided at `/authorize`; `amr` is what the session
			// vouched for then (`vouchedAmr`), so a second factor recorded on the
			// session since reaches none of them, and a code that carries none
			// yields tokens without one. The record admission read above decides
			// liveness, the subject, `auth_time` and the id_token's claims.
			const amr = wellFormedAmr(codeData.amr);
			const acr = wellFormedAcr(codeData.acr);

			// Both tokens carry family_id and, when present, sid, so introspect and
			// refresh need not re-read the session store. No sid without a
			// userSessionStore.
			const accessToken = await generateToken(
				{
					family_id: familyId,
					...(sid ? { sid } : {}),
					// So a resource server (or auth.policy-verifier) can gate on them.
					...(amr ? { amr } : {}),
					...(acr ? { acr } : {}),
					...(authTime !== undefined ? { auth_time: authTime } : {}),
				},
				{
					expiresIn: accessTokenExpiresIn,
					keyStore,
					issuer,
					audience,
					subject,
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
					issuedAt,
					...(confirmation ? { confirmation } : {}),
				},
			);
			// The refresh token's `jti` and issue instant are fixed here, so the
			// family below is registered under exactly the `jti` and `exp` the
			// token carries. Never read back from the signer's output, which a
			// `KeyStore` may return in a form this grant cannot decode.
			const refreshTokenIssuedAt = issuedAt;
			const refreshTokenJti = crypto.randomUUID();
			const refreshToken = await generateToken(
				{
					family_id: familyId,
					...(sid ? { sid } : {}),
					// For the refresh grant to mirror onto the access tokens it mints:
					// `amr` and `acr` live on the code, spent here, so nowhere else
					// holds them.
					...(amr ? { amr } : {}),
					...(acr ? { acr } : {}),
					...(authTime !== undefined ? { auth_time: authTime } : {}),
				},
				{
					expiresIn: refreshTokenExpiresIn,
					keyStore,
					issuer,
					audience,
					subject,
					authorizedParty: authenticatedClientId,
					scope: scopeClaim,
					tokenType: "rt+jwt",
					jti: refreshTokenJti,
					issuedAt: refreshTokenIssuedAt,
					...(bindRefreshToken && confirmation ? { confirmation } : {}),
				},
			);

			// Register the family so replay detection is active from the first
			// use; with a rotation wired, no refresh token is served unregistered.
			if (deps.refreshTokenFamilyRotation) {
				// Fail closed: a token whose replay detection is blind would break
				// RFC 6819 §5.2.2.3. A retryable 503, not an HTML 500.
				try {
					await deps.refreshTokenFamilyRotation.register(
						refreshTokenJti,
						familyId,
						(refreshTokenIssuedAt + refreshTokenExpiresIn) * 1000,
					);
				} catch (err) {
					storeUnavailable("refresh_token_family", "register", authenticatedClientId, err);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "refresh token store unavailable",
						},
					};
				}
			}

			// Link the new family to the user session and register the RP for
			// back/front-channel logout. Fail closed: a store that cannot answer or
			// a session gone since /authorize is an error, never tokens invisible
			// to logout. With a store wired, the first read already refused a code
			// without a sid.
			if (deps.userSessionStore && sid) {
				// The second read, right before the family is added: a session
				// ended since the first read (spanning both signings and the
				// family registration) is refused here. A logout between
				// this read and the add is caught by the add itself (below).
				//
				// The claim carries the first read's `sub`: the tokens were signed
				// from it and the id_token's other claims are read from this one, so a different
				// subject under the same `sid` would yield tokens that disagree on
				// the user. That is a store invariant violation, refused by
				// admission (`subject_mismatch`, audited).
				const revalidation = await admitSession(admissionDeps, {
					// With a store wired and admitted, the subject is the record's
					// non-empty `sub` (above).
					claim: codeClaimRevalidation(codeData, subject as string),
					action:
						"oauth.code_exchange" satisfies keyof typeof AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
				});
				if (revalidation.outcome !== "admitted" || revalidation.session === null) {
					return {
						result: revalidationRefusal(revalidation, {
							sid,
							clientId: authenticatedClientId,
						}),
					};
				}
				// The revalidated session drives the TTLs below and the id_token's other claims.
				userSession = revalidation.session;

				// Composition-root invariant: the session-stores module wires its
				// sibling stores together, so with userSessionStore present these
				// two are too. `?.` would silently no-op on a misconfigured root.
				const joined = await joinSession(
					{
						// biome-ignore lint/style/noNonNullAssertion: intentional — see the invariant above
						sessionRPRegistry: deps.sessionRPRegistry!,
						// biome-ignore lint/style/noNonNullAssertion: intentional — same invariant
						sessionFamilyIndex: deps.sessionFamilyIndex!,
					},
					{
						sid,
						rp: {
							clientId: authenticatedClientId,
							// Typed reads: a misspelt field would silently drop the RP
							// from the logout cascade.
							backchannelLogoutUri: clientRecord?.backchannelLogoutUri,
							backchannelLogoutSessionRequired: clientRecord?.backchannelLogoutSessionRequired,
							// http(s) only, checked here as at logout: a refused URI
							// leaves this RP without a front-channel entry, and the
							// exchange goes on.
							frontchannelLogoutUri: usableFrontchannelLogoutUri(
								{
									// The RP is registered under the authenticated id,
									// so the warn names that one.
									clientId: authenticatedClientId,
									// Read by the helper, inside its guard.
									get frontchannelLogoutUri(): unknown {
										return clientRecord?.frontchannelLogoutUri;
									},
								},
								"authorization_code",
								// The refusal is logged even on a grant built without one.
								logger ?? consoleLogger,
							),
							frontchannelLogoutSessionRequired: clientRecord?.frontchannelLogoutSessionRequired,
							registeredAt: new Date(),
						},
						familyId,
						expiresAt: userSession.expiresAt,
					},
				);
				if (joined.outcome === "ended") {
					const at = { sid, clientId: authenticatedClientId };
					const refusal = sessionInvalidated(at);
					await revokeRefusedFamily(familyId, at);
					return { result: refusal };
				}
				if (joined.outcome === "unavailable") {
					storeUnavailable(joined.store, joined.step, authenticatedClientId, joined.error);
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "session linking unavailable",
						},
					};
				}
			}

			// An id_token needs the openid scope, a session (none without a
			// userSessionStore) and a configured issuer (see `configuredIssuer`).
			// A session implies a sid here; `&& sid` is defensive.
			let idToken: Token | undefined;
			if (
				grantedScopes?.includes("openid") &&
				userSession &&
				sid &&
				configuredIssuer &&
				authTime !== undefined
			) {
				idToken = await generateIdToken({
					sub: userSession.sub,
					aud: authenticatedClientId,
					azp: authenticatedClientId,
					// The instant read above, so the three tokens agree.
					authTime: new Date(authTime * 1000),
					...(nonce ? { nonce } : {}),
					sid,
					...(amr ? { amr } : {}),
					...(acr ? { acr } : {}),
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
					// Only `code`: stale `code_*` keys nothing reads age out with the
					// session TTL.
					clear: ["code"],
				},
			};
		},
	};
};
