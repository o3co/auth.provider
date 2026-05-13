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
import { extractResourceParam } from "./_resourceIndicator.mjs";

const GRANT_TYPE = "client_credentials";

/**
 * `client_credentials` grant per RFC 6749 §4.4 + Wave 1 §3.
 *
 * Public clients (`tokenEndpointAuthMethod === "none"`) are rejected (§3.4):
 * RFC 6749 §4.4 limits the grant to confidential clients. Per-client
 * gating is via `AuthenticatedClient.allowedGrantTypes`: an absent or empty
 * list denies the grant (§3.4.1 deny-by-absence-only-for-`client_credentials`).
 *
 * The issued access token has `sub = client.clientId` (RFC 6749 §4.4.2: no
 * end-user) and no refresh token is issued (RFC 6749 §4.4.3).
 */
export const createClientCredentialsGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore } = deps;

	return {
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

			if (!isGrantAllowed(client)) {
				return {
					result: {
						status: 400,
						error: "unauthorized_client",
						errorDescription: `client is not authorized for ${GRANT_TYPE}`,
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

			if (deps.grantPolicy) {
				// RFC 8707: resolve resource indicator (opt-in, default off).
				const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
				const resource = resourceIndicatorEnabled
					? extractResourceParam(ctx.body as Record<string, unknown>)
					: null;
				// CP-18 pattern: fail-closed on policy throw — same rationale
				// as the refresh_token path. Policy is a security boundary;
				// failing open would effectively grant the pre-policy scope
				// ceiling.
				let decision: Awaited<ReturnType<typeof deps.grantPolicy.evaluate>>;
				try {
					decision = await deps.grantPolicy.evaluate(
						{
							grantType: GRANT_TYPE,
							clientId: client.clientId,
							// RFC 6749 §4.4: client_credentials has no end-user;
							// subject is the client itself.
							subject: client.clientId,
							requestedScope: effectiveScopes.length > 0 ? [...effectiveScopes] : undefined,
							// RFC 8707: populated only when oauth.resourceIndicator.enabled
							// is true; undefined otherwise (flag-off preserves pre-existing
							// semantics).
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
					effectiveScopes = decision.grantedScope;
				}
			}

			const audience = client.allowedAudiences?.[0] ?? issuer ?? null;
			const scopeClaim = effectiveScopes.length > 0 ? effectiveScopes.join(" ") : null;

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

function isGrantAllowed(client: AuthenticatedClient): boolean {
	const allowed = client.allowedGrantTypes;
	if (allowed === undefined) return false;
	return allowed.includes(GRANT_TYPE);
}

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
	const requestedRaw = ctx.body.scope;
	if (requestedRaw === undefined) {
		return { scopes: allowed };
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
		return { scopes: allowed };
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
