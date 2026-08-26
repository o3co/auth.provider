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
	type ClientRepository,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
	generateToken,
	generateTokenResponse,
} from "@o3co/auth-provider-core";

/**
 * `session` grant — mints an access token for the user of an already
 * authenticated browser session (first-party / BFF topologies).
 *
 * Authorization binds to `ctx.authenticatedClient`, which `clientAuthMw`
 * populates from RFC 6749 §2.3 token-endpoint authentication. The client's
 * `allowedScopes` are the ceiling for the request, and `aud` / `azp` name that
 * same client.
 *
 * The `clientRepository` dependency is retained in the signature for
 * compatibility with existing composition roots, but the grant no longer reads
 * from it: `clientAuthMw` already resolved the client record, so re-reading it
 * would be a second lookup of the same row — and looking it up by a body
 * `client_id` would reintroduce a body-spoofable identity (the D-6 / Codex M2
 * invariant that no identity decision reads the raw body).
 */
export const createSessionGrant = (
	deps: GrantDependencies & { clientRepository: ClientRepository },
): GrantHandler => {
	const { config, keyStore } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer } = ctx;
			const { scope: requestedScope } = body as { scope?: string };

			// Previously this grant read `body.client_id` and, when it was absent,
			// accepted the requested scopes as-is with `aud` / `azp` left null. A
			// confidential client authenticating with HTTP Basic sends its
			// client_id in the Authorization header and not in the body, so that
			// branch was the *normal* path for the canonical transport: any client
			// reaching this grant could mint an audience-less token carrying scopes
			// it was never registered for. Authorization now reads the
			// authenticated identity, which cannot be absent behind clientAuthMw.
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

			if (!session.isAuthenticated) {
				return {
					result: {
						status: 401,
						error: "unauthorized",
						errorDescription: "session is not authenticated",
					},
				};
			}

			// Parse and deduplicate scope
			const rawScopes = requestedScope ? requestedScope.split(" ").filter(Boolean) : undefined;
			const scopes = rawScopes?.length ? [...new Set(rawScopes)] : undefined;

			// An omitted scope stays omitted rather than widening to the client's
			// full allowlist: this grant runs on a live user session, so the
			// narrower reading is the safe one.
			if (scopes) {
				const allowed = client.allowedScopes ?? [];
				const invalid = scopes.filter((s) => !allowed.includes(s));
				if (invalid.length > 0) {
					return {
						result: {
							status: 400,
							error: "invalid_scope",
							errorDescription: `requested scope exceeds allowed: ${invalid.join(" ")}`,
						},
					};
				}
			}

			const rawUserId = (session.user as Record<string, unknown> | undefined)?.id;
			const userId = typeof rawUserId === "string" ? rawUserId : undefined;

			// `allowedAudiences[0]` is the client's configured resource audience, and
			// per the AuthenticatedClient contract a grant issuing tokens straight
			// from the client record takes it as the default `aud`. Forcing the
			// client id here instead would mint tokens that the very API the
			// operator configured would reject, since `aud` would never name it.
			//
			// The fallback is the client id rather than the issuer (the shape
			// `client_credentials` uses): this token is bound to an end user and
			// meant for a resource, so naming the authorization server would be
			// wrong, and `authorization_code` already falls back the same way. What
			// matters either way is that `aud` is never null — an audience-less
			// token was half of what made the old path a self-elevation.
			const audience = client.allowedAudiences?.[0] ?? client.clientId;

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(
							{},
							{
								keyStore,
								expiresIn: config.oauth.accessToken.expiresIn,
								issuer,
								audience,
								subject: userId ?? null,
								authorizedParty: client.clientId,
								scope: scopes?.join(" ") ?? null,
								tokenType: "at+jwt",
							},
						),
					}),
				},
			};
		},
	};
};
