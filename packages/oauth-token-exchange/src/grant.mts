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

			// Task 6 stub — subsequent steps (validate tokens, narrow scope/audience,
			// call policy hook, mint new token) are added in Tasks 7-9. If this line
			// is reached at runtime, a Task 7/8 branch failed to replace the stub.
			// We throw rather than returning a non-RFC status because HTTP 501 is not
			// a valid OAuth error code and must never leak to clients.
			throw new Error(
				"TokenExchange grant handler reached the Task 6 stub fall-through. " +
					"Task 7/8 implementation is incomplete — report this as a bug.",
			);
		},
	};
}

export { GRANT_TYPE as TOKEN_EXCHANGE_GRANT_TYPE };
