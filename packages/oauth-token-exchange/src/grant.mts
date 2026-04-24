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
} from "@o3co/auth-provider-core";
import { formatObject, generateToken, generateTokenResponse } from "@o3co/auth-provider-core";
import { buildActClaim } from "./act.mjs";
import type { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";
import type { ValidatedToken } from "./validator/types.mjs";

const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

export interface TokenExchangeDependencies extends GrantDependencies {
	validatorRegistry: ExchangeTokenValidatorRegistry;
	clientRepository: ClientRepository;
}

export function createTokenExchangeGrant(deps: TokenExchangeDependencies): GrantHandler {
	const { validatorRegistry, clientRepository } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const body = ctx.body as Record<string, unknown>;
			const subjectToken = typeof body.subject_token === "string" ? body.subject_token : null;
			const subjectTokenType =
				typeof body.subject_token_type === "string" ? body.subject_token_type : null;
			const clientId = typeof body.client_id === "string" ? body.client_id : null;
			const clientSecret = typeof body.client_secret === "string" ? body.client_secret : null;
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

			// Client authentication: confidential clients send client_secret, public
			// clients omit it. Either way, the client must exist.
			const client =
				clientSecret !== null
					? await clientRepository.authenticate(clientId, clientSecret)
					: await clientRepository.findById(clientId);
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

			const subjectValidator = validatorRegistry.get(subjectTokenType);
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
					? validatorRegistry.get(actorTokenType)
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
			// when refreshTokenStore is absent, but Token Exchange must not issue
			// tokens whose revocation cannot be observed (spec §7.2 state 1).
			if (
				subjectValidated.familyId &&
				!deps.refreshTokenStore &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				return {
					result: {
						status: 400,
						error: "invalid_grant",
						errorDescription: "refresh token store not configured (revocation cannot be verified)",
					},
				};
			}

			// Revocation responsibility model (spec §7.2):
			//   - The built-in self-issued validator accepts an OPTIONAL refreshTokenStore
			//     as a convenience — but the RECOMMENDED wiring (used by integration
			//     tests and README) leaves the validator storeless and lets this handler
			//     own revocation.
			//   - Handler-owned revocation has two benefits: (a) it can surface the
			//     specific `family_revoked` errorDescription that RFC 8693 consumers
			//     expect, and (b) it applies fail-closed semantics (spec §7.2 state 1)
			//     when the store is not wired at the grant level.
			//   - If a consumer wires the store into BOTH the validator AND the grant,
			//     revocation is double-checked. Safe but wasteful — the validator's
			//     early null short-circuits the handler's specific error reporting.
			// Re-surface family_revoked for operators by consulting the store directly
			// when a family_id was present. isFamilyRevoked is idempotent and cheap.
			if (
				subjectValidated.familyId &&
				deps.refreshTokenStore &&
				subjectTokenType === ACCESS_TOKEN_TYPE
			) {
				let revoked: boolean;
				try {
					revoked = await deps.refreshTokenStore.isFamilyRevoked(subjectValidated.familyId);
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
			const requestedScope = requestedScopeStr?.split(" ").filter(Boolean) ?? null;
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
					actorTokenType: actorTokenType ?? undefined,
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
				if (typeof subjectAud === "string") {
					const allow = new Set([...(client.allowedAudiences ?? []), client.clientId]);
					if (allow.has(subjectAud)) return subjectAud;
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
