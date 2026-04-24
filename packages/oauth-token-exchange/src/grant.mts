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
} from "@o3co/auth-provider-core";
import type { ExchangeTokenValidatorRegistry } from "./validator/registry.mjs";
import { ACCESS_TOKEN_TYPE } from "./validator/selfIssuedAccessToken.mjs";

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

			if (actorToken !== null) {
				if (actorTokenType === null) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: "actor_token_type is required when actor_token is provided",
						},
					};
				}
				const actorValidator = validatorRegistry.get(actorTokenType);
				if (!actorValidator) {
					return {
						result: {
							status: 400,
							error: "unsupported_token_type",
							errorDescription: `actor_token_type "${actorTokenType}" is not supported`,
						},
					};
				}
			}

			const subjectValidated = await (async () => {
				try {
					return await subjectValidator.validate(subjectToken, { role: "subject" });
				} catch {
					return "runtime_error" as const;
				}
			})();
			if (subjectValidated === "runtime_error") {
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
			if (actorToken !== null && actorTokenType !== null) {
				const actorValidator = validatorRegistry.get(actorTokenType);
				// actorValidator existence already checked above, but narrow again.
				if (!actorValidator) {
					return {
						result: {
							status: 400,
							error: "unsupported_token_type",
							errorDescription: `actor_token_type "${actorTokenType}" is not supported`,
						},
					};
				}
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

			// Minting + policy hook + act-claim construction come in Task 8.
			// Stub: throw to prevent accidental 501 leak. See Task 6 comment below.
			void actorValidated;
			void requestedResource;
			throw new Error(
				"TokenExchange grant handler reached the Task 6 stub fall-through. " +
					"Task 7/8 implementation is incomplete — report this as a bug.",
			);
		},
	};
}

function normalizeArrayParam(value: unknown): string[] | null {
	if (value === undefined || value === null || value === "") return null;
	if (Array.isArray(value)) return value.map(String);
	return [String(value)];
}

export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
