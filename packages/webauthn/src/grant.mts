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
 * WebAuthn grant handler: `urn:o3co:oauth:grant-type:webauthn`. Exchanges a verified passkey
 * assertion for an access token, plus a refresh token when the authenticated client is allowed
 * `refresh_token`. Client authentication is optional: the passkey is the authentication event.
 *
 * Because a passkey authenticates rather than authorizes scope, there is no `allowedScopes`
 * ceiling: `grantPolicy` is the only scope bound, and `webauthnModule` refuses to boot without it.
 * A store that cannot answer is 503 temporarily_unavailable, never a verdict on the passkey. The
 * package README's SECURITY sections state the full rules.
 *
 * `auth_time` is the challenge's recorded issuance; for a challenge recorded without a usable
 * one (none, one that yields no claim, or one after the redemption, which is warned), one
 * challenge lifetime before the redemption.
 *
 * With `oauth.requireEmailVerified` on, the user behind the credential is read through
 * `userRepository.findBySubject` after the sign-count update and before the scope, the policy, the
 * family and signing; a user the Store does not hold or whose email is not verified
 * (`isEmailVerified`) is `invalid_grant`, and a lookup that throws is 503. A grant built with the
 * setting on and no repository that can look a user up is refused at composition.
 *
 * With `subjectRevocation` wired, the subject's revocation boundary is read after every slow step
 * and before anything is registered or signed, and an authentication it covers
 * (`subjectBoundaryCovers`, the rule `verifyJwt` applies) is `invalid_grant`; a
 * boundary that cannot be read or compared is 503. Both tokens carry one `iat`, fixed before that
 * read, so a revocation stamped after it covers them.
 */

import { randomUUID } from "node:crypto";

import {
	auditErrorText,
	authTimeClaim,
	boundPolicyAudience,
	checkOAuthTokenSettings,
	consoleLogger,
	evaluateGrantPolicy,
	extractResourceParam,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	isEmailVerified,
	isGrantTypeAllowed,
	loggableError,
	ownedConfirmation,
	type ProviderDeps,
	readSpaceDelimitedParameter,
	type SupportsSubjectLookup,
	subjectBoundaryCovers,
	supportsSubjectLookup,
	type Token,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { readClientData } from "./internal/clientData.mjs";
import { userHandleOf } from "./internal/options.mjs";
import { storeUnavailableDescription, type WebAuthnStore } from "./internal/storeUnavailable.mjs";
import { verifyWebAuthnAssertion } from "./internal/verification.mjs";

// ---------------------------------------------------------------------------
// Public constant
// ---------------------------------------------------------------------------

export const WEBAUTHN_GRANT_TYPE = "urn:o3co:oauth:grant-type:webauthn";

/** The grant type a client must be allowed to receive a refresh token (RFC 6749 §6). */
const REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

// ---------------------------------------------------------------------------
// Deps type
// ---------------------------------------------------------------------------

/**
 * What the WebAuthn grant reads: the shared grant slots (`keyStore` to mint, `grantPolicy`,
 * `refreshTokenFamilyRotation`, `subjectRevocation`, `logger`), the credential store and
 * challenge ceremony, the `oauthTokenSettings` slot (the token lifetimes, the
 * resource-indicator switch and `requireEmailVerified`), `userRepository` (read under
 * `requireEmailVerified` alone), core's
 * `tokenBindingSettings` slot (whether a confidential client's refresh token is bound), and the
 * RP fields of `webauthnConfig` — `webauthnModule` hands it its own section there. Nothing is
 * read from the whole configuration.
 *
 * `webauthnModule` hands its deps over whole and checks with `satisfies` that every key here is a
 * slot it declares; `grant.types.test.mts` pins that the `webauthnConfig` fields exist on
 * `WebAuthnConfig`. `grantPolicy` stays optional so a handler built directly (as unit tests do)
 * runs without one; the module refuses to boot without it.
 */
export interface WebAuthnGrantDeps
	extends Pick<
			GrantDependencies,
			"keyStore" | "grantPolicy" | "refreshTokenFamilyRotation" | "subjectRevocation" | "logger"
		>,
		ProviderDeps<
			| "webauthnCredentialStore"
			| "challengeCeremony"
			| "oauthTokenSettings"
			| "tokenBindingSettings",
			"userRepository"
		> {
	readonly webauthnConfig: {
		readonly rpId: string;
		readonly origin: readonly string[];
		/**
		 * Origins this RP accepts being framed by in a cross-origin (iframe) ceremony. Absent, a
		 * browser-reported cross-origin authentication is refused.
		 */
		readonly topOrigin?: readonly string[];
		/**
		 * UserVerificationRequirement (W3C WebAuthn §5.8.6); "required" makes the assertion check
		 * enforce the UV flag.
		 */
		readonly userVerification: "required" | "preferred" | "discouraged";
		/**
		 * How long an issued challenge stays redeemable: how long before the grant the gesture
		 * behind an assertion may have been made, which `auth_time` allows for.
		 */
		readonly challengeTtlMs: number;
	};
}

// ---------------------------------------------------------------------------
// Grant factory
// ---------------------------------------------------------------------------

/**
 * Creates a GrantHandler for the `urn:o3co:oauth:grant-type:webauthn` grant type.
 *
 * @param deps - Injected dependencies (credential store, challenge ceremony,
 *   RP config, optional grant policy).
 * @returns GrantHandler compatible with GrantRegistry.
 */
export const createWebAuthnGrant = (deps: WebAuthnGrantDeps): GrantHandler => {
	const { keyStore } = deps;
	// The token settings are read once, here, from the `oauthTokenSettings` slot alone, checked
	// whole first: a hand-built value the check refuses, or none, fails at composition, naming
	// the slot, before any challenge is consumed.
	const tokenSettings = checkOAuthTokenSettings(deps.oauthTokenSettings);
	const accessTokenExpiresIn = tokenSettings.accessTokenLifetime.defaultExpiresIn;
	const refreshTokenExpiresIn = tokenSettings.refreshTokenExpiresIn;
	// Under `requireEmailVerified` the user behind the credential is read; a composition that
	// cannot read one fails here, before any challenge is consumed.
	let subjectLookup: SupportsSubjectLookup | undefined;
	if (tokenSettings.requireEmailVerified) {
		const userRepository = deps.userRepository;
		if (userRepository === undefined || !supportsSubjectLookup(userRepository)) {
			throw new Error(
				"webauthn grant: oauth.requireEmailVerified is on, and the userRepository slot is not " +
					"filled with a repository that has findBySubject, so the user behind a passkey cannot " +
					"be read. Fill the slot with a UserRepository that implements findBySubject.",
			);
		}
		subjectLookup = userRepository;
	}
	// The binding rule is read once, here, from core's `tokenBindingSettings` slot, which core
	// fills frozen from `core.tokenBinding`: a deps built without it, or with a value whose
	// rule is not a boolean, fails at composition too.
	const bindConfidentialClients = (
		deps.tokenBindingSettings as Partial<typeof deps.tokenBindingSettings> | null | undefined
	)?.bindConfidentialClientRefreshTokens;
	if (typeof bindConfidentialClients !== "boolean") {
		throw new TypeError(
			"webauthn grant: the tokenBindingSettings slot is not filled with a boolean bindConfidentialClientRefreshTokens",
		);
	}
	// One logger for every line this grant writes. The module hands over the
	// deployment's; a handler built without one still reports its outages.
	const logger = deps.logger ?? consoleLogger;

	/**
	 * A store this grant needs could not answer: the server's outage, never a verdict on the
	 * passkey. Logs one `webauthn_grant_store_unavailable` error line (`store`, `step`, the client
	 * if any, and the error's projection, since a store's error can carry what it was sent) and
	 * answers 503 temporarily_unavailable so the client retries.
	 */
	const storeUnavailable = (
		store: Exclude<WebAuthnStore, "challenge">,
		step: "find" | "consume" | "update_sign_count" | "read" | "register",
		clientId: string | undefined,
		err: unknown,
	): GrantHandlerResult => {
		logger.error(
			{
				store,
				step,
				...(clientId === undefined ? {} : { clientId: auditErrorText(clientId) }),
				err: loggableError(err),
			},
			"webauthn_grant_store_unavailable",
		);
		return {
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: storeUnavailableDescription(store),
			},
		};
	};

	return {
		// An authenticated client must name this grant type in `allowedGrantTypes` (absence
		// denies); /token dispatch enforces it before `handle` runs. With no authenticated client
		// there is nothing to check and the grant still runs: the passkey is the authentication.
		requiresExplicitGrantAllowlist: true,
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;

			// ------------------------------------------------------------------
			// Step 1: Parse assertion from body
			// ------------------------------------------------------------------
			const rawAssertion = body.assertion;
			const parseResult = parseAssertionBody(rawAssertion);
			if (!parseResult.ok) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: parseResult.reason,
					},
				};
			}
			const { assertion, challengeValue } = parseResult;
			const clientId = ctx.authenticatedClient?.clientId;
			// No ceremony identifies the user before it, so the handle is what names the account
			// (WebAuthn §7.2 step 6); a zero-length or non-string one names none.
			const userHandle: unknown = assertion.response.userHandle;
			if (typeof userHandle !== "string" || userHandle.length === 0) {
				return {
					result: { status: 400, error: "invalid_grant", errorDescription: "user_handle_missing" },
				};
			}

			// ------------------------------------------------------------------
			// Step 2: Look up credential
			//
			// Nothing is spent yet: after an outage here the same assertion can
			// be presented again, within the challenge's lifetime.
			// ------------------------------------------------------------------
			let credential: Awaited<ReturnType<typeof deps.webauthnCredentialStore.findByCredentialId>>;
			try {
				credential = await deps.webauthnCredentialStore.findByCredentialId(assertion.id);
			} catch (err) {
				return storeUnavailable("webauthn_credential", "find", clientId, err);
			}
			if (!credential) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "credential not found",
					},
				};
			}

			// ------------------------------------------------------------------
			// Step 3: Consume challenge (replay protection)
			//
			// An outage here may land after the atomic delete (the replay
			// seen-set is written afterwards), so the challenge can already be
			// spent: the retry of this assertion is then `invalid_grant`, and the
			// user starts the ceremony again.
			// ------------------------------------------------------------------
			// Read before the consume: a challenge still live when consumed, at or after this instant,
			// was issued after `redeemedAtMs - challengeTtlMs`, and the gesture came after its issuance.
			const redeemedAtMs = Date.now();
			let ceremonyOutcome: Awaited<ReturnType<typeof deps.challengeCeremony.consume>>;
			try {
				ceremonyOutcome = await deps.challengeCeremony.consume(
					"webauthn:authentication",
					challengeValue,
				);
			} catch (err) {
				return storeUnavailable("challenge_ceremony", "consume", clientId, err);
			}
			if (ceremonyOutcome.outcome !== "consumed") {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							ceremonyOutcome.outcome === "replayed" ? "challenge_replayed" : "challenge_unknown",
					},
				};
			}

			// ------------------------------------------------------------------
			// Step 4: Verify the assertion
			// ------------------------------------------------------------------
			const verificationResult = await verifyWebAuthnAssertion({
				credential,
				response: assertion,
				expectedChallenge: challengeValue,
				expectedRpId: deps.webauthnConfig.rpId,
				expectedOrigins: deps.webauthnConfig.origin,
				// Absent, a browser-reported cross-origin ceremony is refused.
				...(deps.webauthnConfig.topOrigin === undefined
					? {}
					: { expectedTopOrigins: deps.webauthnConfig.topOrigin }),
				// The owner's handle, as the registration options named it. The relying party's other
				// ceremonies can present this credential under another handle.
				expectedUserHandle: userHandleOf(credential.userId),
				userVerification: deps.webauthnConfig.userVerification,
			});
			if (!verificationResult.ok) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: verificationResult.reason,
					},
				};
			}
			// An assertion can be held until its challenge expires, so `auth_time` is the earliest
			// instant the gesture could have been made, the challenge's issuance: never fresher than
			// it was (RFC 9470 §6.1). A challenge recorded without a usable one — none, one that
			// yields no claim, or one after the redemption (the recording host's clock ahead of
			// this one's, which is warned) — leaves the earliest issuance a challenge still live at
			// the redemption could have had.
			const issuedAtMs = ceremonyOutcome.issuedAtMs;
			let fromIssuance: number | undefined;
			if (typeof issuedAtMs === "number" && Number.isFinite(issuedAtMs)) {
				if (issuedAtMs > redeemedAtMs) {
					logger.warn(
						{
							...(clientId === undefined ? {} : { clientId: auditErrorText(clientId) }),
							aheadMs: issuedAtMs - redeemedAtMs,
						},
						"passkey_challenge_issued_ahead_of_clock",
					);
				} else {
					fromIssuance = authTimeClaim(new Date(issuedAtMs));
				}
			}
			const authTime =
				fromIssuance ?? authTimeClaim(new Date(redeemedAtMs - deps.webauthnConfig.challengeTtlMs));

			// ------------------------------------------------------------------
			// Step 5: Atomic CAS sign-count update
			//
			// The challenge is spent by now, and a store that lost its reply may
			// have written the new count. Either way no token is issued; the next
			// ceremony's assertion carries a higher count than any written here.
			// ------------------------------------------------------------------
			let casOk: boolean;
			try {
				casOk = await deps.webauthnCredentialStore.updateSignCount(assertion.id, {
					expectedCurrentSignCount: credential.signCount,
					newSignCount: verificationResult.newSignCount,
					lastUsedAt: new Date(),
				});
			} catch (err) {
				return storeUnavailable("webauthn_credential", "update_sign_count", clientId, err);
			}
			if (!casOk) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "sign_count_update_conflict",
					},
				};
			}

			// ------------------------------------------------------------------
			// Step 6: The email gate
			//
			// Every path that mints for a user applies it. `invalid_grant`, as the
			// session grant answers: RFC 6749 §5.2 defines no `access_denied` for
			// the token endpoint.
			// ------------------------------------------------------------------
			if (subjectLookup !== undefined) {
				// The field is read inside the `try`: an accessor-backed record can reach its
				// backend on that read, and a throw there is the same outage.
				let emailVerified: boolean;
				try {
					emailVerified = isEmailVerified(await subjectLookup.findBySubject(credential.userId));
				} catch (err) {
					return storeUnavailable("user_repository", "read", clientId, err);
				}
				if (!emailVerified) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "email address is not verified",
						},
					};
				}
			}

			// ------------------------------------------------------------------
			// Step 7: Scope resolution
			// ------------------------------------------------------------------
			const scopeOutcome = resolveScope(ctx);
			if ("error" in scopeOutcome) {
				return { result: scopeOutcome };
			}
			let effectiveScopes = scopeOutcome.scopes;

			// ------------------------------------------------------------------
			// Step 8: grantPolicy gate
			//
			// Runs whenever `grantPolicy` is wired, as in the refresh grant; the
			// `oauthTokenSettings` slot's `resourceIndicatorEnabled` gates only whether
			// `resource` (RFC 8707) is forwarded. The policy is this grant's only scope bound,
			// so gating the call on that flag (default false) would let any valid assertion
			// mint any requested scope. A policy error fails closed. `webauthnModule` refuses to boot without a policy; the
			// check below serves handlers built directly, as in unit tests.
			// ------------------------------------------------------------------
			const resourceIndicatorEnabled = tokenSettings.resourceIndicatorEnabled;

			let policyGrantedAudience: string | null = null;

			if (deps.grantPolicy) {
				const resource = resourceIndicatorEnabled
					? extractResourceParam(body as Record<string, unknown>)
					: null;
				const client = ctx.authenticatedClient;

				const policy = await evaluateGrantPolicy(
					deps.grantPolicy,
					{
						grantType: WEBAUTHN_GRANT_TYPE,
						clientId: client?.clientId,
						subject: credential.userId,
						requestedScope: effectiveScopes.length > 0 ? [...effectiveScopes] : undefined,
						// Undefined: no resource requested.
						resource: resource ?? undefined,
					},
					{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: issuer ?? "" },
					effectiveScopes,
					{ logger },
				);
				if (!policy.ok) return { result: policy.result };
				// Re-validated against the requested set (there is no broader allowlist); an empty
				// array strips every scope.
				effectiveScopes = policy.scopes;

				// The policy may narrow the audience within the client's `allowedAudiences`, never
				// originate one; with no authenticated client there is no ceiling, so a policy
				// audience is refused. A resource `aud` on a passkey token needs a registered,
				// authenticated client.
				const policyAudience = boundPolicyAudience(
					policy.decision,
					client ? (client.allowedAudiences ?? []) : undefined,
				);
				if (!policyAudience.ok) return { result: policyAudience.result };
				policyGrantedAudience = policyAudience.audience;
			}

			// ------------------------------------------------------------------
			// Step 9: The issuance instant, then the subject's revocation boundary
			//
			// Both tokens are signed with this `iat`. The boundary is the last
			// read before anything is registered or signed, so a revocation
			// stamped after it is at or after this instant and covers both.
			// ------------------------------------------------------------------
			const issuedAt = Math.floor(Date.now() / 1000);
			if (deps.subjectRevocation) {
				// The earlier of the two claims `verifyJwt` compares: a boundary covering either
				// covers it. `auth_time` never follows `iat`, but the wall clock may step back
				// between the redemption and this instant.
				const boundary = await subjectBoundaryCovers(
					deps.subjectRevocation,
					credential.userId,
					authTime === undefined ? issuedAt : Math.min(authTime, issuedAt),
				);
				if (boundary.answer === "unavailable") {
					return storeUnavailable("revocation_boundary", "read", clientId, boundary.cause);
				}
				if (boundary.answer === "covered") {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "the authentication predates a revocation of the subject",
						},
					};
				}
			}

			// ------------------------------------------------------------------
			// Step 10: Derive audience + issue tokens
			// ------------------------------------------------------------------
			const client = ctx.authenticatedClient;
			// Policy audience > `allowedAudiences[0]` > client id, the rule every user-bound grant
			// applies (the token is for a resource, so the fallback is the client, not the AS).
			// Without a client, the issuer: RFC 9068 §2.2 requires `aud`.
			const audience =
				policyGrantedAudience ??
				(client ? (client.allowedAudiences?.[0] ?? client.clientId) : (issuer ?? null));

			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;

			// The request's confirmation goes on the access token whenever its mechanism owns it
			// (core's `ownedConfirmation`: DPoP `jkt`, mTLS `x5t#S256`), ungated, as in every
			// grant: an unbound token minted from a proven key would replay from anywhere. The
			// refresh token has its own, narrower gate below. `generateTokenResponse` derives
			// `token_type` from it: "DPoP" for `cnf.jkt` (RFC 9449 §5), "Bearer" for mTLS
			// (RFC 8705 §3).
			const confirmation = ownedConfirmation(ctx.tokenBinding);
			const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
			const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";

			// A refresh token requires both:
			//   1. An authenticated client: the refresh grant refuses an unauthenticated caller and
			//      binds the RT to `azp`, so a client-less RT could never be redeemed.
			//   2. `refresh_token` named in the client's `allowedGrantTypes`, absence denying: a
			//      standing credential must not be acquired by omission.
			const issueRefreshToken =
				client !== null &&
				isGrantTypeAllowed(client.allowedGrantTypes, REFRESH_TOKEN_GRANT_TYPE, {
					requireAllowlist: true,
				});

			// One family per issuance, opened here and revoked as a unit on replay
			// (RFC 6819 §5.2.2.3). Both tokens carry the id: introspect resolves
			// family revocation off the `family_id` claim, so an access token
			// without it survives a revocation that was meant to kill it.
			const familyId = issueRefreshToken ? randomUUID() : null;

			// The RT's `jti` and `iat` are reserved and its family registered before anything is
			// signed (as the refresh grant commits a rotation before signing), with exactly the
			// expiry that will be signed. A family-store outage then costs no signature (a billable
			// call under a KMS-backed key); a signing failure after registration leaves a family no
			// served token carries, which expires on its own. Fail closed: an RT with no registered
			// family has no replay detection (RFC 6819 §5.2.2.3). 503 tells the client to retry;
			// `invalid_grant` would make it discard the passkey session.
			const refreshReservation =
				familyId === null ? null : { familyId, jti: randomUUID(), issuedAt };
			if (refreshReservation !== null && deps.refreshTokenFamilyRotation) {
				try {
					await deps.refreshTokenFamilyRotation.register(
						refreshReservation.jti,
						refreshReservation.familyId,
						(refreshReservation.issuedAt + refreshTokenExpiresIn) * 1000,
					);
				} catch (err) {
					return storeUnavailable("refresh_token_family", "register", clientId, err);
				}
			}

			// `client_id` and `azp` when a client authenticated, so /oauth/revoke (which resolves the
			// owner as `client_id ?? azp ?? aud`) matches the revoking client. A client-less token
			// cannot be revoked there (RFC 7009); see the README's token revocation limitations.
			const accessToken = await generateToken(
				{
					...(client ? { client_id: client.clientId } : {}),
					...(familyId ? { family_id: familyId } : {}),
					// RFC 8176 `hwk`: the assertion proved a platform- or hardware-bound key. On the
					// token itself, since this grant mints no id_token and creates no session.
					amr: ["hwk"],
					...(authTime !== undefined ? { auth_time: authTime } : {}),
				},
				{
					expiresIn: accessTokenExpiresIn,
					keyStore,
					issuer,
					audience,
					subject: credential.userId,
					...(client ? { authorizedParty: client.clientId } : {}),
					scope: scopeClaim,
					tokenType: "at+jwt",
					issuedAt,
					...(confirmation ? { confirmation } : {}),
				},
			);

			let refreshToken: Token | undefined;
			if (client && refreshReservation) {
				// The RT binds on the gate `authorization.mts` and `refreshToken.mts` apply: a
				// mechanism the refresh grant enforces, AND a public client unless
				// `bindConfidentialClientRefreshTokens` is set. Narrower than the access token's gate
				// on purpose: a confidential client re-authenticates at every refresh, so RFC 9449 §5
				// leaves its RT unbound rather than pinned to one key for the RT's lifetime.
				const isPublicClient = client.tokenEndpointAuthMethod === "none";
				const bindRefreshToken =
					(bindingIsDpop || bindingIsMtls) && (isPublicClient || bindConfidentialClients);

				refreshToken = await generateToken(
					// The refresh grant copies `amr` and `auth_time` from the refresh token, so
					// they go here too.
					{
						family_id: refreshReservation.familyId,
						amr: ["hwk"],
						...(authTime !== undefined ? { auth_time: authTime } : {}),
					},
					{
						expiresIn: refreshTokenExpiresIn,
						keyStore,
						issuer,
						audience,
						subject: credential.userId,
						authorizedParty: client.clientId,
						scope: scopeClaim,
						tokenType: "rt+jwt",
						// The identity the family was registered under above.
						jti: refreshReservation.jti,
						issuedAt,
						...(bindRefreshToken && confirmation ? { confirmation } : {}),
					},
				);
			}

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken,
						...(refreshToken ? { refreshToken } : {}),
					}),
				},
			};
		},
	};
};

// ---------------------------------------------------------------------------
// File-private helpers
// ---------------------------------------------------------------------------

type AssertionParseOk = {
	ok: true;
	assertion: AuthenticationResponseJSON;
	challengeValue: string;
};
type AssertionParseErr = { ok: false; reason: string };
type AssertionParseResult = AssertionParseOk | AssertionParseErr;

/**
 * Shape-checks `body.assertion` as AuthenticationResponseJSON and extracts the challenge the
 * authenticator echoed in its clientDataJSON (base64url JSON `{ type, challenge, origin }`). That
 * challenge is the ceremony lookup key, as in registrationVerify.mts.
 */
function parseAssertionBody(raw: unknown): AssertionParseResult {
	if (raw === null || raw === undefined || typeof raw !== "object" || Array.isArray(raw)) {
		return { ok: false, reason: "assertion must be an object" };
	}

	const obj = raw as Record<string, unknown>;

	// assertion.id — credentialId as base64url string
	if (typeof obj.id !== "string" || obj.id.length === 0) {
		return { ok: false, reason: "assertion.id must be a non-empty string" };
	}

	// assertion.response.clientDataJSON — base64url-encoded JSON
	const innerResponse = obj.response;
	if (innerResponse === null || typeof innerResponse !== "object" || Array.isArray(innerResponse)) {
		return { ok: false, reason: "assertion.response must be an object" };
	}
	const responseObj = innerResponse as Record<string, unknown>;
	const clientDataJSONBase64 = responseObj.clientDataJSON;
	if (typeof clientDataJSONBase64 !== "string") {
		return { ok: false, reason: "assertion.response.clientDataJSON must be a string" };
	}

	// Read as the library decodes it: the challenge consumed is the one it verifies.
	const clientData = readClientData(clientDataJSONBase64);
	if (clientData === undefined) {
		return {
			ok: false,
			reason: "assertion.response.clientDataJSON is not a base64url JSON object",
		};
	}
	const challengeValue = clientData.challenge;
	if (typeof challengeValue !== "string" || challengeValue.length === 0) {
		return { ok: false, reason: "assertion.response.clientDataJSON has no valid challenge" };
	}

	return {
		ok: true,
		// Cast: minimal shape validation done above; full schema validation is
		// performed by SimpleWebAuthn inside verifyWebAuthnAssertion.
		assertion: raw as AuthenticationResponseJSON,
		challengeValue,
	};
}

/**
 * Reads the requested scope. There is no per-client `allowedScopes` ceiling; bounding it is
 * `grantPolicy`'s job. The RFC 6749 §3.3 syntax is enforced strictly here, since nothing
 * downstream would stop a malformed value from reaching the token's `scope` claim.
 */
function resolveScope(
	ctx: GrantContext,
):
	| { scopes: readonly string[] }
	| { status: 400; error: "invalid_request" | "invalid_scope"; errorDescription: string } {
	const requestedRaw = ctx.body.scope;
	if (requestedRaw === undefined || requestedRaw === null) {
		return { scopes: [] };
	}
	if (typeof requestedRaw !== "string") {
		return {
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a space-delimited string",
		};
	}
	// The space is the one delimiter and every entry a scope-token, as every
	// token-endpoint grant reads a request (`readSpaceDelimitedParameter`).
	// Spaces alone name nothing.
	const scopes = readSpaceDelimitedParameter(requestedRaw);
	if (scopes === null) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: "scope is not a space-delimited list of scope-tokens",
		};
	}
	return { scopes };
}
