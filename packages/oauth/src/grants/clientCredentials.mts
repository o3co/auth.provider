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
	boundPolicyAudience,
	deriveAudienceFromResources,
	evaluateGrantPolicy,
	extractResourceParam,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
	ownedConfirmation,
	readSpaceDelimitedParameter,
	resolveAccessTokenLifetime,
	unrepresentedResources,
} from "@o3co/auth-provider-core";

const GRANT_TYPE = "client_credentials";

/** What the client_credentials grant reads; see `AuthorizationGrantDeps`. */
export type ClientCredentialsGrantDeps = Pick<
	GrantDependencies,
	"config" | "keyStore" | "grantPolicy" | "logger"
>;

/**
 * `client_credentials` grant (RFC 6749 §4.4), for confidential clients only:
 * a public client (`tokenEndpointAuthMethod === "none"`) is rejected. The
 * handler declares `requiresExplicitGrantAllowlist`, so `/token` dispatch
 * denies a client whose `allowedGrantTypes` is absent or empty.
 *
 * The access token has `sub = client.clientId` (RFC 6749 §4.4.2: no
 * end-user), and no refresh token is issued (RFC 6749 §4.4.3).
 */
export const createClientCredentialsGrant = (deps: ClientCredentialsGrantDeps): GrantHandler => {
	const { config, keyStore } = deps;
	// Resolved once when the grant is built, so a hand-built configuration the
	// resolver refuses fails composition rather than a request.
	const accessTokenExpiresIn = resolveAccessTokenLifetime(config).defaultExpiresIn;

	return {
		// Machine-to-machine access is never acquired by omission: dispatch
		// denies a registration without `allowedGrantTypes` before `handle`.
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

			// Untouched: `generateToken` omits `iss` when it is null/undefined,
			// where `""` would emit a malformed `iss: ""`.
			const issuer = ctx.issuer;

			// The policy's audience, when it narrowed one; null falls back below.
			let policyGrantedAudience: string | null = null;

			// RFC 8707 is read only under oauth.resourceIndicator.enabled (off by
			// default); the policy runs whenever grantPolicy is wired, and sees no
			// resource with the flag off.
			const resourceIndicatorEnabled = deps.config.oauth.resourceIndicator?.enabled === true;
			const requestedResource = resourceIndicatorEnabled
				? extractResourceParam(ctx.body as Record<string, unknown>)
				: null;
			if (deps.grantPolicy) {
				// `evaluateGrantPolicy` (core, shared by every minting path) fails
				// closed (throw → 503, deny → 400) and lets the policy only narrow
				// the effective scope, never draw on the allowlist; an empty array
				// strips all.
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
					{ logger: deps.logger },
				);
				if (!policy.ok) return { result: policy.result };
				effectiveScopes = policy.scopes;
				// The audience half, bounded by this client's `allowedAudiences`, so a
				// buggy or compromised policy cannot mint a token for a resource
				// server the client is not registered for.
				const policyAudience = boundPolicyAudience(policy.decision, client.allowedAudiences ?? []);
				if (!policyAudience.ok) return { result: policyAudience.result };
				policyGrantedAudience = policyAudience.audience;
			}

			// RFC 8707 §2: with a `resource` requested and no policy audience, `aud`
			// is derived from the request (bounded by allowedAudiences ∪
			// {clientId}), so resource indicators work without a policy hook.
			const derivedAudience =
				policyGrantedAudience ??
				deriveAudienceFromResources(
					requestedResource,
					new Set([...(client.allowedAudiences ?? []), client.clientId]),
				);
			const audience = derivedAudience ?? client.allowedAudiences?.[0] ?? issuer ?? null;

			// RFC 8707 §2: the audience MUST represent the requested resources.
			// After the audience is final, so it covers every derivation above.
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

			// The AT's `cnf` (RFC 7800) is the member the binding's mechanism kind
			// owns, nothing for a kind that owns neither; see README, "Token
			// binding (`cnf`)". No refresh token, so no RT binding.
			const confirmation = ownedConfirmation(ctx.tokenBinding);

			const accessToken = await generateToken(
				{
					client_id: client.clientId,
				},
				{
					expiresIn: accessTokenExpiresIn,
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
					tokens: generateTokenResponse({ accessToken }),
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
	// An omitted scope draws on the client's declared default, never on the
	// whole allowlist. No defaultScopes with a non-empty allowlist is
	// invalid_scope; an empty allowlist keeps the empty grant.
	const omittedScopeGrant = ():
		| { scopes: readonly string[] }
		| { status: 400; error: "invalid_scope"; errorDescription: string } => {
		if (client.defaultScopes !== undefined) {
			// Filtered even so: a grant handler is reachable through
			// `grantHandlerResolver`, so its caller may hand it an
			// `authenticatedClient` that did not come through core's
			// client-record boundary, which holds defaultScopes ⊆ allowedScopes.
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
	// RFC 6749 §3.2: a parameter sent without a value is treated as omitted —
	// `scope=""` in a form body, `"scope": null` in a JSON one.
	if (requestedRaw === undefined || requestedRaw === null) {
		return omittedScopeGrant();
	}
	// RFC 6749 §3.3: `scope` MUST be a single space-delimited string. A
	// non-string (e.g. an array from repeated `scope=a&scope=b` form keys) is
	// malformed, not defaulted, which would over-grant.
	if (typeof requestedRaw !== "string") {
		return {
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a space-delimited string",
		};
	}
	// RFC 6749 §3.3, read strictly: the space is the one delimiter, so a tab-
	// or newline-delimited value is refused as malformed. Spaces alone name
	// nothing, which is an omitted scope.
	const requested = readSpaceDelimitedParameter(requestedRaw);
	if (requested === null) {
		return {
			status: 400,
			error: "invalid_scope",
			errorDescription: "scope is not a space-delimited list of scope-tokens",
		};
	}
	if (requested.length === 0) {
		return omittedScopeGrant();
	}
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
