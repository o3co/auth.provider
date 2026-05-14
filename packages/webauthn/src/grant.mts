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
 *   8. Issue access token. No refresh token (Wave 1 first slice, spec §2.4).
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

import {
	type ChallengeCeremony,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { extractResourceParam } from "./internal/_resourceIndicator.mjs";
import { verifyWebAuthnAssertion } from "./internal/verification.mjs";

// ---------------------------------------------------------------------------
// Public constant
// ---------------------------------------------------------------------------

export const WEBAUTHN_GRANT_TYPE = "urn:o3co:oauth:grant-type:webauthn";

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
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;

			// ------------------------------------------------------------------
			// Step 0: Enforce allowedGrantTypes for authenticated clients
			//
			// When a client is authenticated, verify it is explicitly authorized
			// for the webauthn grant type — mirroring the cc/rt/auth_code pattern
			// (clientCredentials.mts isGrantAllowed / §3.4.1 deny-by-absence).
			//
			// When ctx.authenticatedClient is null, skip the check entirely:
			// the webauthn grant does not require client authentication — the
			// passkey IS the auth event. Consumers may optionally wire
			// clientAuthMw before this handler; when they do not, there is no
			// allowedGrantTypes source to validate against.
			//
			// Cross-refs: Codex Round 2 P1-2 / cc parity
			// ------------------------------------------------------------------
			const authenticatedClientForCheck = ctx.authenticatedClient;
			if (
				authenticatedClientForCheck &&
				!authenticatedClientForCheck.allowedGrantTypes?.includes(WEBAUTHN_GRANT_TYPE)
			) {
				return {
					result: {
						status: 400,
						error: "unauthorized_client",
						errorDescription: `client is not authorized for ${WEBAUTHN_GRANT_TYPE}`,
					},
				};
			}

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
			// Documented gap (intended Wave 1 behavior): when grantPolicy is NOT wired
			// AND the caller requests scope, the scope is issued as-is (no library-side
			// ceiling). Deployments wanting scope authorization MUST wire grantPolicy.
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
			// Step 8: Derive audience + issue access token
			// ------------------------------------------------------------------
			const client = ctx.authenticatedClient;
			// Audience derivation:
			//   policy override > client.allowedAudiences[0] > issuer > null
			// When no client is authenticated, skip client.allowedAudiences (no source).
			const audience =
				policyGrantedAudience ??
				(client ? (client.allowedAudiences?.[0] ?? issuer ?? null) : (issuer ?? null));

			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;

			const accessToken = await generateToken(
				{},
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject: credential.userId,
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({ accessToken }),
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
