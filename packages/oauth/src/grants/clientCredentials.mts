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

const GRANT_TYPE = "client_credentials";

/**
 * `client_credentials` grant per RFC 6749 §4.4 + Wave 1 §3.
 *
 * Public-client clients (`tokenEndpointAuthMethod === "none"`) are rejected
 * (§3.4): RFC 6749 §4.4 limits the grant to confidential clients. Per-client
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
						errorDescription: "client authentication is required",
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
			const effectiveScopes = scopeOutcome.scopes;

			const issuer = ctx.issuer ?? "";
			const audience = client.allowedAudiences?.[0] ?? issuer;
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
	| { status: 400; error: "invalid_scope"; errorDescription: string } {
	const allowed = client.allowedScopes ?? [];
	const requestedRaw = ctx.body.scope;
	if (typeof requestedRaw !== "string" || requestedRaw.trim() === "") {
		return { scopes: allowed };
	}
	const requested = requestedRaw.split(/\s+/).filter(Boolean);
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
