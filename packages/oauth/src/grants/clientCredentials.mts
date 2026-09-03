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

import {
	type AuthenticatedClient,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
} from "@o3co/auth-provider-core";
import { evaluateGrantPolicy } from "./_grantPolicy.mjs";
import {
	deriveAudienceFromResources,
	extractResourceParam,
	unrepresentedResources,
} from "./_resourceIndicator.mjs";

const GRANT_TYPE = "client_credentials";

/**
 * `client_credentials` grant per RFC 6749 §4.4 + Wave 1 §3.
 *
 * Public clients (`tokenEndpointAuthMethod === "none"`) are rejected (§3.4):
 * RFC 6749 §4.4 limits the grant to confidential clients. Per-client gating
 * is via `AuthenticatedClient.allowedGrantTypes`, enforced at `/token`
 * dispatch: the handler declares `requiresExplicitGrantAllowlist`, so an
 * absent or empty list denies the grant (§3.4.1
 * deny-by-absence-only-for-`client_credentials`, made declarative in #326).
 *
 * The issued access token has `sub = client.clientId` (RFC 6749 §4.4.2: no
 * end-user) and no refresh token is issued (RFC 6749 §4.4.3).
 */
export const createClientCredentialsGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore } = deps;

	return {
		// §3.4.1: machine-to-machine access is never acquired by omission — a
		// registration that never declared `allowedGrantTypes` does not get
		// this grant. Dispatch enforces the denial before `handle` runs
		// (#326); it used to be a hand-rolled check in this handler.
		requiresExplicitGrantAllowlist: true,
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const client = ctx.authenticatedClient;
			if (!client) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "Client authentication is required",
					},
				};
			}

			if (client.tokenEndpointAuthMethod === "none") {
				return {
					result: {
						status: 400,
						error: "invalid_client",
						errorDescription: "client_credentials requires a confidential client",
					},
				};
			}

			const scopeOutcome = resolveScope(ctx, client);
			if ("error" in scopeOutcome) {
				return { result: scopeOutcome };
			}
			let effectiveScopes = scopeOutcome.scopes;

			// Pass `ctx.issuer` through untouched: `generateToken` omits the
			// `iss` claim when it is null/undefined, matching the sibling
			// authorization_code / refresh_token grants. Coercing undefined to
			// `""` would emit a malformed `iss: ""` JWT.
			const issuer = ctx.issuer;

			// Audience from policy evaluation (Fix #3): set inside the
			// grantPolicy block when decision.grantedAudience is valid.
			// null means "no policy override — use the existing fallback".
			let policyGrantedAudience: string | null = null;

			// RFC 8707: resource-indicator policy check. Only runs when grantPolicy
			// is wired AND oauth.resourceIndicator.enabled === true. Flag-off
			// (the default) skips this block entirely — preserving pre-existing
			// semantics for deployments that wire grantPolicy without RFC 8707.
			const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
			// Stage 2 (#173): read outside the policy block. Enforcement is gated
			// on the flag ALONE — a deployment that enables RFC 8707 without a
			// policy hook still derives an audience below, and minting it for a
			// resource the client did not request is the §2 violation Stage 2
			// closes. Stage 1 only ever read this when a policy was wired.
			const requestedResource = resourceIndicatorEnabled
				? extractResourceParam(ctx.body as Record<string, unknown>)
				: null;
			if (deps.grantPolicy && resourceIndicatorEnabled) {
				// CP-18: the fail-closed evaluation (throw → 503, deny → 400)
				// and the scope re-validation — the policy may only narrow the
				// already-narrowed effective scope, never draw on the allowlist,
				// and an empty array is strip-all — live in `evaluateGrantPolicy`,
				// shared with the jwt-bearer grant. The audience half stays here
				// because its ceiling is this client's `allowedAudiences`.
				const resource = requestedResource;
				const policy = await evaluateGrantPolicy(
					deps.grantPolicy,
					{
						grantType: GRANT_TYPE,
						clientId: client.clientId,
						// RFC 6749 §4.4: client_credentials has no end-user;
						// subject is the client itself.
						subject: client.clientId,
						requestedScope: effectiveScopes.length > 0 ? [...effectiveScopes] : undefined,
						// RFC 8707: resource is null when body has no `resource` param;
						// undefined passed to policy signals "no resource requested".
						resource: resource ?? undefined,
					},
					{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: issuer ?? "" },
					effectiveScopes,
				);
				if (!policy.ok) return { result: policy.result };
				effectiveScopes = policy.scopes;
				const { decision } = policy;
				if (decision.grantedAudience && decision.grantedAudience.length > 0) {
					// Fail-closed audience validation: policy may only narrow to
					// audiences already in client.allowedAudiences. An out-of-bounds
					// audience from a buggy/compromised policy would mint a token
					// accepted by a resource server the client is not authorized for.
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
					// Use the policy-narrowed audience (flatten to first, matching
					// the refresh_token and authorization_code grant patterns).
					policyGrantedAudience = decision.grantedAudience[0];
				}
			}

			// RFC 8707 §2 audience derivation (Stage 2, #173). When a `resource`
			// was requested and no policy narrowed an audience, the AS derives
			// `aud` from the request instead of minting its default and then
			// rejecting it — otherwise resource indicators would be unusable
			// without a policy hook wired, which is not what the flag promises.
			// Bounded by allowedAudiences ∪ {clientId}, the same ceiling a
			// policy-returned audience is checked against.
			const derivedAudience =
				policyGrantedAudience ??
				deriveAudienceFromResources(
					requestedResource,
					new Set([...(client.allowedAudiences ?? []), client.clientId]),
				);
			const audience = derivedAudience ?? client.allowedAudiences?.[0] ?? issuer ?? null;

			// RFC 8707 §2 (Stage 2, #173): the token's audience MUST be the
			// resource indicator(s) the client asked for. Everything above only
			// *forwarded* `resource` to the policy; this is where an audience
			// that fails to represent the request stops being issued. Runs after
			// the audience is final so it covers all three derivations — policy
			// narrowing, the allowedAudiences fallback, and the issuer fallback.
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

			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;

			// Wave 2 Phase 2 §9.1: propagate the token-binding confirmation
			// (RFC 7800 `cnf`) into the issued AT. Mechanism-agnostic copy —
			// DPoP supplies `{ jkt }`, mTLS supplies `{ "x5t#S256" }`. The
			// wire-level `token_type` is "DPoP" only for the DPoP kind
			// (RFC 9449 §5); mTLS keeps "Bearer" per RFC 8705 §3. RFC 6749
			// §4.4.3 says client_credentials does not issue a refresh token,
			// so no RT-binding branch is needed here.
			const confirmation = ctx.tokenBinding?.confirmation;
			const tokenType = ctx.tokenBinding?.kind === "dpop" ? "DPoP" : "Bearer";

			const accessToken = await generateToken(
				{
					client_id: client.clientId,
				},
				{
					expiresIn: config.oauth.accessToken.expiresIn,
					keyStore,
					issuer,
					audience,
					subject: client.clientId,
					authorizedParty: client.clientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
					...(confirmation ? { confirmation } : {}),
				},
			);

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({ accessToken }, { tokenType }),
				},
			};
		},
	};
};

function resolveScope(
	ctx: GrantContext,
	client: AuthenticatedClient,
):
	| { scopes: readonly string[] }
	| {
			status: 400;
			error: "invalid_scope" | "invalid_request";
			errorDescription: string;
	  } {
	const allowed = client.allowedScopes ?? [];
	// #396: an omitted scope draws on the client's DECLARED default, never on
	// the whole allowlist — "forgot to send scope" used to be the maximum
	// grant. A client with no defaultScopes and a non-empty allowlist answers
	// invalid_scope (deny-by-absence); an empty allowlist keeps the empty
	// grant, since there is nothing to over-grant.
	const omittedScopeGrant = ():
		| { scopes: readonly string[] }
		| { status: 400; error: "invalid_scope"; errorDescription: string } => {
		if (client.defaultScopes !== undefined) {
			// Filtered even so: schema-validated registrations are ⊆ by boot,
			// custom repositories are under no such obligation.
			return { scopes: client.defaultScopes.filter((s) => allowed.includes(s)) };
		}
		if (allowed.length === 0) return { scopes: [] };
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: "scope is required: this client declares no defaultScopes",
		};
	};
	const requestedRaw = ctx.body.scope;
	if (requestedRaw === undefined) {
		return omittedScopeGrant();
	}
	// RFC 6749 §3.3: `scope` MUST be a single space-delimited string when
	// present. A non-string value (e.g. an array materialized by Express'
	// urlencoded body-parser from repeated `scope=a&scope=b` form keys) is
	// malformed — silently defaulting to the client's full `allowedScopes`
	// would grant a broader scope than the caller submitted.
	if (typeof requestedRaw !== "string") {
		return {
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a space-delimited string",
		};
	}
	if (requestedRaw.trim() === "") {
		return omittedScopeGrant();
	}
	// RFC 6749 §3.3 ABNF: scope-token delimiter is a single SP (0x20).
	// Match sibling grants (`refreshToken.mts`, `routes.mts`) on the literal
	// `" "` split rather than `\s+` so tab/newline-delimited scope strings
	// from non-conformant clients fail the subset check loudly instead of
	// being silently re-tokenized.
	const requested = requestedRaw.split(" ").filter(Boolean);
	const disallowed = requested.filter((s) => !allowed.includes(s));
	if (disallowed.length > 0) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: `requested scopes not permitted: ${disallowed.join(" ")}`,
		};
	}
	return { scopes: requested };
}
