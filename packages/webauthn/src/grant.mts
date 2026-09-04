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
 * WebAuthn grant handler — `urn:o3co:oauth:grant-type:webauthn` (spec §2.4).
 *
 * Flow:
 *   1. Parse `body.assertion` as AuthenticationResponseJSON. Malformed → 400 invalid_grant.
 *   2. Extract challenge from assertion.response.clientDataJSON (base64url JSON).
 *   3. Look up credential via credentialStore.findByCredentialId(assertion.id).
 *      Not found → 400 invalid_grant.
 *   4. Consume challenge via challengeCeremony.consume("webauthn:authentication", value).
 *      outcome !== "consumed" → 400 invalid_grant.
 *   5. Verify assertion via verifyWebAuthnAssertion. ok=false → 400 invalid_grant.
 *   6. Atomic CAS sign-count update via credentialStore.updateSignCount.
 *      Returns false → 400 invalid_grant (concurrent race / clone attack).
 *   7. Optional grantPolicy gate — rt-style: called unconditionally when deps.grantPolicy
 *      is wired (Codex Round 3 P1). The resourceIndicator flag gates ONLY whether
 *      body.resource is forwarded in the request payload (Stage 1 plumbing contract).
 *      CP-18 fail-closed — policy throw → 503 temporarily_unavailable.
 *
 *      SECURITY: webauthn grant has no client.allowedScopes ceiling (the passkey is
 *      the auth event, not scope authorization). Policy is the ONLY scope-bounding gate.
 *      Deployments wanting scope authorization MUST wire grantPolicy.
 *
 *   8. Issue an access token, and a refresh token when the authenticated client's
 *      `allowedGrantTypes` names `refresh_token` (#480). The refresh token opens a
 *      family through `refreshTokenFamilyRotation`, exactly as the authorization-code
 *      grant does, so rotation and RFC 6819 §5.2.2.3 replay detection are the shared
 *      ones. A registration that does not name `refresh_token` — including one that
 *      declares no `allowedGrantTypes` at all — receives the access token alone.
 *
 * Refresh-token binding:
 *   A DPoP- or mTLS-bound request carries its RFC 7800 confirmation into the refresh
 *   token on the same gate `authorization.mts` and `refreshToken.mts` apply: public
 *   clients always, confidential clients only under
 *   `oauth.tokenBinding.bindConfidentialClientRefreshTokens` (#275). The access token
 *   this grant issues is unbound, so the response `token_type` stays "Bearer".
 *
 * Audience derivation:
 *   - When ctx.authenticatedClient is present: allowedAudiences[0] ?? issuer ?? null
 *   - When no authenticated client: issuer ?? null
 *   (WebAuthn grant does not require client authentication — the passkey IS the
 *    authentication event. Consumers may optionally wire clientAuthMw before this
 *    handler to bind tokens to a specific client application.)
 *
 * RFC 8707 Stage 1 (Wave 1 §5.3):
 *   - resource forwarded to grantPolicy when resourceIndicator.enabled === true
 *   - Library-layer audience binding enforcement deferred to Stage 2 (issue #173)
 *
 * extractResourceParam: duplicated from packages/oauth/src/grants/_resourceIndicator.mts
 * because the webauthn package does not depend on @o3co/auth-provider-oauth and that
 * helper is explicitly NOT barrel-exported. Consolidation candidate for Wave 2.
 *
 * Cross-refs: Plan T30 / spec §2.4 / PR #172 W1P3 patterns / Codex Round 3 P1
 */

import { randomUUID } from "node:crypto";

import {
	type ChallengeCeremony,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	isGrantTypeAllowed,
	type Token,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { decodeJwtPayload } from "./internal/_jwtPayload.mjs";
import { extractResourceParam } from "./internal/_resourceIndicator.mjs";
import { verifyWebAuthnAssertion } from "./internal/verification.mjs";

// ---------------------------------------------------------------------------
// Public constant
// ---------------------------------------------------------------------------

export const WEBAUTHN_GRANT_TYPE = "urn:o3co:oauth:grant-type:webauthn";

/**
 * The grant type a client must be allowed before this grant hands it a refresh
 * token (#480). RFC 6749 §6 — a plain name, not a URN.
 */
const REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

// ---------------------------------------------------------------------------
// Deps type
// ---------------------------------------------------------------------------

/**
 * Dependencies for the WebAuthn grant handler.
 *
 * `webauthnCredentialStore` and `challengeCeremony` are required for the
 * WebAuthn assertion flow; `webauthnConfig` carries the RP config (rpId,
 * allowed origins) needed for verifyWebAuthnAssertion.
 *
 * All other slots mirror the standard GrantDependencies shape (config, keyStore,
 * optional grantPolicy).
 */
export interface WebAuthnGrantDeps extends GrantDependencies {
	readonly webauthnCredentialStore: WebAuthnCredentialStore;
	readonly challengeCeremony: ChallengeCeremony;
	readonly webauthnConfig: {
		readonly rpId: string;
		readonly origin: readonly string[];
		/**
		 * WebAuthn UserVerificationRequirement (W3C §5.8.6).
		 *
		 * Threaded through to verifyWebAuthnAssertion so SimpleWebAuthn enforces
		 * the UV flag when the deployment sets userVerification = "required".
		 *
		 * Cross-refs: Codex Round 2 P1-1 / spec §2.5
		 */
		readonly userVerification: "required" | "preferred" | "discouraged";
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
	const { config, keyStore } = deps;

	return {
		// allowedGrantTypes strictness for authenticated clients — mirroring
		// the cc pattern (§3.4.1 deny-by-absence): a client must be explicitly
		// authorized for the webauthn grant type. Declared here, enforced at
		// /token dispatch before `handle` runs (#326; previously a hand-rolled
		// Step 0 in this handler — Codex Round 2 P1-2 / cc parity).
		//
		// When ctx.authenticatedClient is null, dispatch skips the check
		// entirely: the webauthn grant does not require client authentication —
		// the passkey IS the auth event. Consumers may optionally wire
		// clientAuthMw before this handler; when they do not, there is no
		// allowedGrantTypes source to validate against.
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

			// ------------------------------------------------------------------
			// Step 2: Look up credential
			// ------------------------------------------------------------------
			const credential = await deps.webauthnCredentialStore.findByCredentialId(assertion.id);
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
			// ------------------------------------------------------------------
			const ceremonyOutcome = await deps.challengeCeremony.consume(
				"webauthn:authentication",
				challengeValue,
			);
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
				// Thread configured UV through to SimpleWebAuthn (Codex Round 2 P1-1).
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

			// ------------------------------------------------------------------
			// Step 5: Atomic CAS sign-count update
			// ------------------------------------------------------------------
			const casOk = await deps.webauthnCredentialStore.updateSignCount(assertion.id, {
				expectedCurrentSignCount: credential.signCount,
				newSignCount: verificationResult.newSignCount,
				lastUsedAt: new Date(),
			});
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
			// Step 6: Scope resolution
			// ------------------------------------------------------------------
			const scopeOutcome = resolveScope(ctx);
			if ("error" in scopeOutcome) {
				return { result: scopeOutcome };
			}
			let effectiveScopes = scopeOutcome.scopes;

			// ------------------------------------------------------------------
			// Step 7: Optional grantPolicy gate — rt-style (Codex Round 3 P1).
			//
			// Policy is invoked unconditionally when deps.grantPolicy is wired,
			// regardless of oauth.resourceIndicator.enabled. The resourceIndicator
			// flag gates ONLY whether body.resource is forwarded in the payload
			// (Stage 1 RFC 8707 plumbing contract from PR #172).
			//
			// SECURITY rationale: webauthn grant has no client.allowedScopes ceiling
			// (the passkey is the auth event, not scope authorization). Policy is the
			// ONLY scope-bounding gate. Gating the policy call on resourceIndicator
			// (the prior cc-style gate) would silently skip scope enforcement for all
			// deployments that left resourceIndicator at its default (false), allowing
			// any caller with a valid assertion to mint a token with any requested scope.
			//
			// Mirrors refreshToken.mts: unconditional policy call when wired;
			// resourceIndicator flag gates only the resource field.
			// CP-18 fail-closed — same rationale as clientCredentials.mts.
			//
			// H-2 invariant: webauthnModule's grant factory throws at boot when
			// grantPolicy is unwired, so the `deps.grantPolicy` check below is
			// effectively always true under the module wiring. Tests that drive
			// createWebAuthnGrant directly may still pass deps without grantPolicy;
			// the check keeps the unit-test surface usable.
			// ------------------------------------------------------------------
			const resourceIndicatorEnabled = config.oauth.resourceIndicator?.enabled === true;

			let policyGrantedAudience: string | null = null;

			if (deps.grantPolicy) {
				// Resource is forwarded only when the flag is on (PR #172 Stage 1 plumbing).
				// Policy invocation itself is unconditional when wired.
				const resource = resourceIndicatorEnabled
					? extractResourceParam(body as Record<string, unknown>)
					: null;
				const client = ctx.authenticatedClient;

				let decision: Awaited<ReturnType<typeof deps.grantPolicy.evaluate>>;
				try {
					decision = await deps.grantPolicy.evaluate(
						{
							grantType: WEBAUTHN_GRANT_TYPE,
							// clientId from authenticated client when present; undefined otherwise
							// (webauthn grant does not require client auth — the passkey IS the
							// auth event).
							clientId: client?.clientId,
							subject: credential.userId,
							requestedScope: effectiveScopes.length > 0 ? [...effectiveScopes] : undefined,
							// RFC 8707: resource is null when body has no `resource` param;
							// undefined passed to policy signals "no resource requested".
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

				if (decision.grantedScope !== undefined) {
					// CP-18: fail-closed. Re-validate the policy's returned scopes
					// against effectiveScopes (the post-narrowing set from the request),
					// NOT against some broader allowedScopes ceiling. A buggy/compromised
					// policy returning a scope outside the requested set is scope expansion.
					// Mirrors clientCredentials.mts CP-18 exactly.
					const requestedSet = new Set(effectiveScopes);
					const exceeded = decision.grantedScope.filter((s) => !requestedSet.has(s));
					if (exceeded.length > 0) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `policy returned scopes exceeding requested scope: ${exceeded.join(" ")}`,
							},
						};
					}
					// CP-15 mirror: assign unconditionally — empty array honored as strip-all.
					effectiveScopes = decision.grantedScope;
				}

				if (decision.grantedAudience && decision.grantedAudience.length > 0) {
					// Fail-closed audience validation: when a client is present, policy may
					// only narrow to audiences already in client.allowedAudiences. When no
					// client is authenticated there is no allowedAudiences ceiling — skip.
					//
					// TRUST ASYMMETRY (Wave 1 post-merge audit M-4): in client-less mode,
					// `grantPolicy` is the SOLE audience authority — policy can mint a token
					// for ANY audience it returns, with no library-side ceiling. This is
					// acceptable per spec §5.6 Stage 1 staging (Stage 2 will add library-layer
					// audience-binding enforcement per RFC 8707 — issue #173). Operators wiring
					// webauthn without client-auth MUST therefore trust `grantPolicy` end-to-end
					// for audience authorization.
					const client = ctx.authenticatedClient;
					if (client) {
						const allowedAudSet = new Set(client.allowedAudiences ?? []);
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
					}
					policyGrantedAudience = decision.grantedAudience[0];
				}
			}

			// ------------------------------------------------------------------
			// Step 8: Derive audience + issue tokens
			// ------------------------------------------------------------------
			const client = ctx.authenticatedClient;
			// Audience derivation:
			//   policy override > client.allowedAudiences[0] > issuer > null
			// When no client is authenticated, skip client.allowedAudiences (no source).
			const audience =
				policyGrantedAudience ??
				(client ? (client.allowedAudiences?.[0] ?? issuer ?? null) : (issuer ?? null));

			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;

			// #480: a passkey is the primary login on a native app, and the access
			// token is short-lived — without a refresh token the user is sent back
			// to the platform authenticator at every expiry. The grant now issues
			// one, on the same machinery `authorization_code` uses.
			//
			// Two conditions, both structural rather than policy:
			//
			//   1. There must be an authenticated client. `refresh_token`'s own
			//      handler refuses an unauthenticated caller with `invalid_client`
			//      and binds the RT to `azp`, so an RT minted in the client-less
			//      passkey-is-the-auth-event mode could never be redeemed. Issuing
			//      one would be a token that only looks like a capability.
			//
			//   2. The client's `allowedGrantTypes` must NAME `refresh_token` —
			//      absence denies (#268 / #311 / #326). A refresh token is a
			//      standing credential with a lifetime measured in days, so it is
			//      exactly the thing that must not be acquired by omission: a
			//      registration written before this shipped keeps getting today's
			//      access-token-only response. `isGrantTypeAllowed` with
			//      `requireAllowlist` is the central rule, not a second copy of it.
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

			// Mint client_id + authorizedParty when client authenticated so the AT is
			// revocable via /oauth/revoke (Wave 1 post-merge security audit H-1: the
			// revoke endpoint resolves the token's client via `client_id ?? azp ?? aud`
			// and requires it match the revoking client. Empty data + non-clientId aud
			// silently caused revoke 200 + no denylist insertion).
			// Unauthenticated client mode (passkey IS the auth event) remains unrevocable
			// by /oauth/revoke per RFC 7009 — documented as a known limitation.
			const accessToken = await generateToken(
				{
					...(client ? { client_id: client.clientId } : {}),
					...(familyId ? { family_id: familyId } : {}),
				},
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject: credential.userId,
					...(client ? { authorizedParty: client.clientId } : {}),
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);

			let refreshToken: Token | undefined;
			if (client && familyId) {
				// Sender-binding for the RT is the gate `authorization.mts` and
				// `refreshToken.mts` already apply, reused verbatim rather than
				// restated: a mechanism allowlist (only the kinds whose
				// refresh-time enforcement matrix `refreshToken.mts` knows) AND a
				// public-client restriction, which `#275`'s
				// `bindConfidentialClientRefreshTokens` lifts for a deployment that
				// protects its client secret and its key differently.
				//
				// The wire-level `token_type` deliberately stays "Bearer": the
				// access token this grant issues carries no `cnf` of its own, and
				// answering "DPoP" would describe an access token that is not
				// DPoP-bound.
				const confirmation = ctx.tokenBinding?.confirmation;
				const bindingIsDpop = ctx.tokenBinding?.kind === "dpop";
				const bindingIsMtls = ctx.tokenBinding?.kind === "mtls";
				const isPublicClient = client.tokenEndpointAuthMethod === "none";
				const bindConfidentialClients =
					config.oauth.tokenBinding?.bindConfidentialClientRefreshTokens === true;
				const bindRefreshToken =
					(bindingIsDpop || bindingIsMtls) && (isPublicClient || bindConfidentialClients);

				refreshToken = await generateToken(
					{ family_id: familyId },
					{
						expiresIn: config.oauth.refreshToken.expiresIn,
						keyStore,
						issuer,
						audience,
						subject: credential.userId,
						authorizedParty: client.clientId,
						scope: scopeClaim,
						tokenType: "rt+jwt",
						...(bindRefreshToken && confirmation ? { confirmation } : {}),
					},
				);

				if (deps.refreshTokenFamilyRotation) {
					// Fail-closed, mirroring authorization.mts CP-16: a refresh token
					// whose family was never registered has no replay detection behind
					// it, and serving it would quietly break the RFC 6819 §5.2.2.3
					// contract the family exists to keep. A controlled 503 tells the
					// client to retry; `invalid_grant` would tell it to throw the
					// passkey session away.
					//
					// EVERY way registration can fail lands here, not just a store
					// outage. Reading the `jti` / `exp` back off the token we just
					// minted can fail too — an unparseable token, a decode that
					// throws, a payload missing either claim (an unset
					// `oauth.refreshToken.expiresIn` produces exactly that, and a
					// remote signer is free to return claims we did not ask for) — and
					// the first shape of this code treated an unreadable payload as
					// "nothing to register" and served the refresh token anyway. That
					// is the same live-token-with-no-family outcome as the outage,
					// reached down a quieter branch, so it gets the same answer.
					const registered = await registerRefreshTokenFamily(
						deps.refreshTokenFamilyRotation,
						refreshToken.token,
						familyId,
					);
					if (!registered) {
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

/**
 * Opens the refresh-token family for a token this grant just minted.
 *
 * Returns `true` only when the family is durably registered. Everything else —
 * a payload that cannot be decoded, one carrying no usable `jti` or `exp`, a
 * store that throws — returns `false`, and the caller refuses the whole
 * request. The three are one event to the caller because they have one
 * consequence: without a registration the token has no rotation record, so
 * every replay of it would read as a first use (RFC 6819 §5.2.2.3). A boolean
 * rather than a thrown error keeps that single fail-closed answer in one place
 * at the call site.
 *
 * `exp` is validated as a finite number before the millisecond conversion:
 * `NaN * 1000` is `NaN`, which a store would happily accept as an expiry and
 * then never expire (or expire immediately), which is the failure this guard
 * exists to prevent rather than a variant of it.
 */
async function registerRefreshTokenFamily(
	rotation: NonNullable<GrantDependencies["refreshTokenFamilyRotation"]>,
	refreshTokenValue: string,
	familyId: string,
): Promise<boolean> {
	try {
		const payload = decodeJwtPayload(refreshTokenValue);
		const jti = payload.jti;
		const exp = payload.exp;
		if (typeof jti !== "string" || jti.length === 0) return false;
		if (typeof exp !== "number" || !Number.isFinite(exp)) return false;
		await rotation.register(jti, familyId, exp * 1000);
		return true;
	} catch {
		return false;
	}
}

type AssertionParseOk = {
	ok: true;
	assertion: AuthenticationResponseJSON;
	challengeValue: string;
};
type AssertionParseErr = { ok: false; reason: string };
type AssertionParseResult = AssertionParseOk | AssertionParseErr;

/**
 * Parses and validates `body.assertion` as AuthenticationResponseJSON and
 * extracts the challenge value from clientDataJSON.
 *
 * The challenge stored by the options endpoint is the base64url string from
 * SimpleWebAuthn's generateAuthenticationOptions output. The authenticator
 * echoes it back inside clientDataJSON (base64url-encoded JSON:
 * { type, challenge, origin }). We decode clientDataJSON → extract `challenge`
 * → use that as the ceremony lookup key. This matches the pattern in
 * registrationVerify.mts (T28).
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

	// Decode clientDataJSON → extract challenge
	let challengeValue: string;
	try {
		const clientDataJSON = JSON.parse(
			Buffer.from(clientDataJSONBase64, "base64url").toString("utf8"),
		) as Record<string, unknown>;
		if (typeof clientDataJSON.challenge !== "string" || clientDataJSON.challenge.length === 0) {
			return { ok: false, reason: "assertion.response.clientDataJSON has no valid challenge" };
		}
		challengeValue = clientDataJSON.challenge;
	} catch {
		return { ok: false, reason: "assertion.response.clientDataJSON is not valid base64url JSON" };
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
 * Resolves the effective scope set from the request body.
 *
 * Unlike client_credentials, the webauthn grant has no per-client allowedScopes
 * ceiling in the request (credentials are not associated with client registrations
 * at the grant-handler level — that is a consumer-policy concern). The handler
 * accepts whatever scopes the caller requests, relying on grantPolicy to enforce
 * policy ceilings when wired.
 *
 * RFC 6749 §3.3: scope must be a space-delimited string.
 */
function resolveScope(
	ctx: GrantContext,
):
	| { scopes: readonly string[] }
	| { status: 400; error: "invalid_request"; errorDescription: string } {
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
	if (requestedRaw.trim() === "") {
		return { scopes: [] };
	}
	// RFC 6749 §3.3 ABNF: scope-token delimiter is a single SP (0x20).
	// Literal " " split (not \s+) matches sibling grants (cc/rt).
	const scopes = requestedRaw.split(" ").filter(Boolean);
	return { scopes };
}
