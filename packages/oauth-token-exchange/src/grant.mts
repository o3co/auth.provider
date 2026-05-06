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

import type {
	ClientRepository,
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyRequest,
	PublicClient,
} from "@o3co/auth-provider-core";
import { formatObject, generateToken, generateTokenResponse } from "@o3co/auth-provider-core";
import { buildActClaim } from "./act.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
import type { ExchangeTokenValidator, ValidatedToken } from "./validator/types.mjs";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

/**
 * Local resolver shape that narrows core's
 * `TokenExchangeValidatorResolver.get(): unknown | undefined` to the
 * concrete `ExchangeTokenValidator` type used internally. Core declares
 * the value as `unknown` to avoid a cross-package import cycle (per
 * contributes-map.mts placeholder pattern). This grant package owns the
 * concrete type, so the narrowed shape is local.
 */
export interface ExchangeTokenValidatorResolver {
	get(tokenType: string): ExchangeTokenValidator | undefined;
}

export interface TokenExchangeDependencies extends GrantDependencies {
	tokenExchangeValidatorResolver: ExchangeTokenValidatorResolver;
	clientRepository: ClientRepository;
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { tokenExchangeValidatorResolver, clientRepository } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const body = ctx.body as Record<string, unknown>;
			const subjectToken = typeof body.subject_token === "string" ? body.subject_token : null;
			const subjectTokenType =
				typeof body.subject_token_type === "string" ? body.subject_token_type : null;
			const clientId = typeof body.client_id === "string" ? body.client_id : null;
			const clientSecretRaw = body.client_secret;
			let clientSecret: string | null;
			if (clientSecretRaw === undefined || clientSecretRaw === null) {
				// Token Exchange currently supports confidential clients only — the
				// core ClientRepository contract requires `clientSecret` (see
				// packages/core/src/repositories/types.mts) and PublicClient is
				// `Omit<Client, "clientSecret">`, so findById alone cannot
				// distinguish "no secret configured" from "secret omitted by
				// caller". Accepting an unauthenticated client_id here would let an
				// attacker exchange a stolen subject_token under any client's
				// allowlist. Refuse outright; revisit when a Client.public flag
				// lands.
				clientSecret = null;
			} else if (typeof clientSecretRaw === "string") {
				clientSecret = clientSecretRaw;
			} else {
				// Present but not a string (e.g., repeated param producing string[]).
				// Refuse to treat this as "omitted" — that path would bypass the
				// confidential-client auth check.
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "client_secret must be a single string value",
					},
				};
			}
			const actorToken = typeof body.actor_token === "string" ? body.actor_token : null;
			const actorTokenType =
				typeof body.actor_token_type === "string" ? body.actor_token_type : null;
			const requestedTokenType =
				typeof body.requested_token_type === "string" ? body.requested_token_type : null;

			if (!subjectToken || !subjectTokenType || !clientId) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "subject_token, subject_token_type, client_id are required",
					},
				};
			}

			// Client authentication. Token Exchange supports confidential clients
			// only — public (`"none"`) clients are refused regardless of route.
			//
			// D-6 (v0.5.1): when this grant is dispatched from the standard
			// `/token` route, `clientAuthMw` has already authenticated the client
			// (via Basic header OR body credentials) and populated
			// `ctx.authenticatedClient`. We trust that identity over the body —
			// without this branch, Basic-authenticated callers would fail here
			// because `body.client_secret` is empty when credentials travel in
			// the `Authorization` header. For consumers wiring this grant onto a
			// custom route that bypasses `clientAuthMw`, the `else` branch keeps
			// the original body-credential gate as the sole authenticity check.
			let client: PublicClient | null;
			if (ctx.authenticatedClient) {
				if (ctx.authenticatedClient.tokenEndpointAuthMethod === "none") {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "Token Exchange does not support public clients",
						},
					};
				}
				// Body-supplied client_id MUST match the authenticated identity —
				// otherwise an attacker could authenticate as A and request a
				// token exchange under B's allowlist.
				if (clientId !== ctx.authenticatedClient.clientId) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "client_id does not match authenticated client",
						},
					};
				}
				try {
					client = await clientRepository.findById(ctx.authenticatedClient.clientId);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "client repository unavailable",
						},
					};
				}
			} else {
				// Standalone wiring: no `clientAuthMw` ahead of us, so verify
				// the body-supplied secret directly.
				if (clientSecret === null) {
					return {
						result: {
							status: 401,
							error: "invalid_client",
							errorDescription: "client_secret is required",
						},
					};
				}
				client = await clientRepository.authenticate(clientId, clientSecret);
			}
			if (!client) {
				return {
					result: {
						status: 401,
						error: "invalid_client",
						errorDescription: "client authentication failed",
					},
				};
			}

			if (requestedTokenType !== null && requestedTokenType !== ACCESS_TOKEN_TYPE) {
				return {
					result: {
						status: 400,
						error: "unsupported_token_type",
						errorDescription: `requested_token_type "${requestedTokenType}" is not supported`,
					},
				};
			}

			const subjectValidator = tokenExchangeValidatorResolver.get(subjectTokenType);
			if (!subjectValidator) {
				return {
					result: {
						status: 400,
						error: "unsupported_token_type",
						errorDescription: `subject_token_type "${subjectTokenType}" is not supported`,
					},
				};
			}

			// Actor token type lookup — kept here so the validator reference is
			// available for validation below without a second registry call.

			// Reject actor_token_type without actor_token — prevents policies that
			// gate on req.actorTokenType for delegation from being bypassed by a
			// caller who only sets the type header.
			if (actorToken === null && actorTokenType !== null) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "actor_token is required when actor_token_type is provided",
					},
				};
			}

			if (actorToken !== null && actorTokenType === null) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "actor_token_type is required when actor_token is provided",
					},
				};
			}
			const actorValidator =
				actorToken !== null && actorTokenType !== null
					? tokenExchangeValidatorResolver.get(actorTokenType)
					: null;
			if (actorToken !== null && actorValidator === undefined) {
				return {
					result: {
						status: 400,
						error: "unsupported_token_type",
						errorDescription: `actor_token_type "${actorTokenType}" is not supported`,
					},
				};
			}

			let subjectValidated: ValidatedToken | null;
			try {
				subjectValidated = await subjectValidator.validate(subjectToken, { role: "subject" });
			} catch {
				return {
					result: {
						status: 503,
						error: "temporarily_unavailable",
						errorDescription: "subject_token validation store unavailable",
					},
				};
			}
			if (!subjectValidated) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "subject_token validation failed",
					},
				};
			}

			// Fail-closed: the self-issued validator silently skips the family check
			// when refreshTokenFamilyRevocation is absent, but Token Exchange must
			// not issue tokens whose revocation cannot be observed (spec §7.2 state 1).
			if (
				subjectValidated.familyId &&
				!deps.refreshTokenFamilyRevocation &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription:
							"refresh token family revocation not configured (revocation cannot be verified)",
					},
				};
			}

			// Revocation responsibility model (spec §7.2):
			//   - The built-in self-issued validator accepts an OPTIONAL
			//     refreshTokenFamilyRevocation as a convenience — but the
			//     RECOMMENDED wiring (used by integration tests and README) leaves
			//     the validator storeless and lets this handler own revocation.
			//   - Handler-owned revocation has two benefits: (a) it can surface the
			//     specific `family_revoked` errorDescription that RFC 8693 consumers
			//     expect, and (b) it applies fail-closed semantics (spec §7.2 state 1)
			//     when the slot is not wired at the grant level.
			//   - If a consumer wires the slot into BOTH the validator AND the grant,
			//     revocation is double-checked. Safe but wasteful — the validator's
			//     early null short-circuits the handler's specific error reporting.
			// Re-surface family_revoked for operators by consulting the slot directly
			// when a family_id was present. isFamilyRevoked is idempotent and cheap.
			if (
				subjectValidated.familyId &&
				deps.refreshTokenFamilyRevocation &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				let revoked: boolean;
				try {
					revoked = await deps.refreshTokenFamilyRevocation.isFamilyRevoked(
						subjectValidated.familyId,
					);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "refresh token store unavailable",
						},
					};
				}
				if (revoked) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "family_revoked",
						},
					};
				}
			}

			let actorValidated: typeof subjectValidated | null = null;
			if (actorToken !== null && actorValidator) {
				try {
					actorValidated = await actorValidator.validate(actorToken, { role: "actor" });
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "actor_token validation store unavailable",
						},
					};
				}
				if (!actorValidated) {
					return {
						result: {
							status: 400,
							error: "invalid_grant",
							errorDescription: "actor_token validation failed",
						},
					};
				}
			}

			// Scope narrowing: requested scope ⊆ subject scope.
			const subjectScope = subjectValidated.scope?.split(" ").filter(Boolean) ?? [];
			const requestedScopeStr = typeof body.scope === "string" ? body.scope : null;
			const requestedScopeRaw = requestedScopeStr?.split(" ").filter(Boolean) ?? null;
			// Normalize empty arrays to null — `scope=""` and `scope=" "` behave the
			// same as scope omitted (inherit subject scope), per the same rationale
			// that drives normalizeArrayParam for audience/resource.
			const requestedScope =
				requestedScopeRaw !== null && requestedScopeRaw.length === 0 ? null : requestedScopeRaw;
			if (requestedScope) {
				const subjectScopeSet = new Set(subjectScope);
				for (const s of requestedScope) {
					if (!subjectScopeSet.has(s)) {
						return {
							result: {
								status: 400,
								error: "invalid_scope",
								errorDescription: `scope "${s}" is not in subject_token scope`,
							},
						};
					}
				}
			}

			// Audience narrowing: requested audience ⊆ client.allowedAudiences ∪ {clientId}.
			const requestedAudience = normalizeArrayParam(body.audience);
			const requestedResource = normalizeArrayParam(body.resource);
			if (requestedAudience) {
				const allow = new Set([...(client.allowedAudiences ?? []), client.clientId]);
				for (const aud of requestedAudience) {
					if (!allow.has(aud)) {
						return {
							result: {
								status: 400,
								error: "invalid_target",
								errorDescription: `audience "${aud}" is not allowed for this client`,
							},
						};
					}
				}
			}

			// Policy hook — existing GrantPolicyHookBase contract.
			// grantedScope/grantedAudience start as the narrowed values from the
			// request validation phase above; the policy hook may further override them.
			let grantedScope: readonly string[] | undefined = requestedScope ?? subjectScope;
			let grantedAudience: readonly string[] | undefined = requestedAudience ?? undefined;
			if (deps.grantPolicy) {
				const policyRequest: GrantPolicyRequest = {
					grantType: GRANT_TYPE,
					clientId: client.clientId,
					subject: subjectValidated.sub,
					requestedScope: requestedScope ?? undefined,
					requestedAudience: requestedAudience ?? undefined,
					originalScope: subjectScope.length > 0 ? subjectScope : undefined,
					subjectTokenType,
					// actorTokenType is populated only when an actor_token was actually
					// validated — prevents policies that gate on actorTokenType from being
					// deceived by a request that supplied only the type header.
					actorTokenType:
						actorValidated !== null && actorTokenType !== null ? actorTokenType : undefined,
					resource: requestedResource ?? undefined,
				};
				const policyContext: GrantPolicyContext = {
					ip: ctx.ip,
					userAgent: ctx.userAgent,
					issuer: ctx.issuer ?? "",
				};
				let decision: GrantPolicyDecision;
				try {
					decision = await deps.grantPolicy.evaluate(policyRequest, policyContext);
				} catch {
					return {
						result: {
							status: 503,
							error: "temporarily_unavailable",
							errorDescription: "grant policy evaluation failed",
						},
					};
				}
				if (decision.outcome === "deny") {
					return {
						result: {
							status: decision.error === "access_denied" ? 403 : 400,
							error: decision.error,
							errorDescription: decision.errorDescription ?? "denied by policy",
						},
					};
				}
				// By design: policy hook output is trusted without re-verification against
				// the subject's scope/audience. Widening is permitted because the hook is
				// a first-party consumer-installed extension (spec §8.1 rule 4). If a
				// consumer's policy accidentally widens scope, the token reflects that
				// intent — detect via tests, not runtime checks.
				if (decision.grantedScope) grantedScope = decision.grantedScope;
				if (decision.grantedAudience) grantedAudience = decision.grantedAudience;
			}

			// Audience derivation (spec §8.1 rule 2):
			//   explicit narrowed audience  → use grantedAudience (first element).
			//     Note: grantedAudience reflects either the allowlist-validated request
			//     parameter OR a policy hook override. Policy overrides are NOT re-
			//     validated against the client allowlist by design (spec §8.1 rule 4);
			//     consumers with strict policies must enforce the boundary themselves.
			//   omitted + subject single    → inherit subject.aud IFF in allowlist;
			//                                   else fall back to clientId (prevents
			//                                   cross-client audience confusion when a
			//                                   stolen subject token is exchanged by a
			//                                   client outside its intended audience)
			//   omitted + subject multi/none → fall back to clientId (safe default)
			// Note: generateToken accepts a single-valued audience; when grantedAudience
			// has multiple entries only the first is used. This is a known limitation
			// (spec §8.1.1 multi-audience requires token introspection by all parties).
			const subjectAud = subjectValidated.aud;
			const audienceForToken: string = (() => {
				if (grantedAudience && grantedAudience.length > 0)
					return grantedAudience[0] ?? client.clientId; // `?? clientId` is forward-compat for noUncheckedIndexedAccess
				// When audience is omitted, only inherit subject.aud if it's in the
				// calling client's allowlist. Otherwise fall back to clientId. This
				// prevents cross-client audience confusion: a malicious client cannot
				// use a stolen subject_token to mint a token for an audience outside
				// its own allowlist just by omitting the audience parameter.
				//
				// RFC 7519 §4.1.3 permits `aud` to be either a string or an array of
				// strings. A single-element array is semantically equivalent to a
				// bare string, so we accept both. Multi-element arrays cannot be
				// represented as a single audience claim in the issued token (we
				// emit a single-valued aud), so they fall back to clientId.
				const single =
					typeof subjectAud === "string"
						? subjectAud
						: Array.isArray(subjectAud) && subjectAud.length === 1
							? subjectAud[0]
							: undefined;
				if (typeof single === "string") {
					const allow = new Set([...(client.allowedAudiences ?? []), client.clientId]);
					if (allow.has(single)) return single;
				}
				return client.clientId;
			})();

			const act = buildActClaim({
				subject: subjectValidated,
				actor: actorValidated ?? undefined,
			});
			const scopeClaim = grantedScope && grantedScope.length > 0 ? grantedScope.join(" ") : null;

			const expiresIn = getExpiresIn(deps);

			const accessToken = await generateToken(
				formatObject({
					family_id: subjectValidated.familyId,
					act,
				}),
				{
					expiresIn,
					keyStore: deps.keyStore,
					issuer: ctx.issuer,
					audience: audienceForToken,
					subject: subjectValidated.sub,
					authorizedParty: client.clientId,
					scope: scopeClaim,
					tokenType: "at+jwt",
				},
			);

			const tokens = generateTokenResponse({ accessToken });
			const tokensWithIssuedType: typeof tokens & { issued_token_type: string } = {
				...tokens,
				issued_token_type: ACCESS_TOKEN_TYPE,
			};

			return {
				result: {
					status: 200,
					tokens: tokensWithIssuedType,
				},
			};
		},
	};
}

function getExpiresIn(deps: TokenExchangeDependencies): number {
	// Reads the global OAuth accessToken.expiresIn. The per-grant
	// oauth.grants.token_exchange.accessToken.expiresIn path is unreachable
	// because core's GrantRegistry.addModule keys module config by grant-type
	// URN, not by friendly name. Consumers who want a different expiresIn
	// for Token Exchange should wrap createTokenExchangeGrant() instead.
	const top = (deps.config.oauth.accessToken as { expiresIn?: number } | undefined)?.expiresIn;
	return typeof top === "number" && top > 0 ? top : 300;
}

function normalizeArrayParam(value: unknown): string[] | null {
	if (value === undefined || value === null || value === "") return null;
	if (Array.isArray(value)) {
		const filtered = value.map(String).filter((s) => s.length > 0);
		return filtered.length === 0 ? null : filtered;
	}
	return [String(value)];
}

export { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
