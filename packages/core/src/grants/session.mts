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
import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type {
	GrantContext,
	GrantDependencies,
	GrantHandler,
	GrantHandlerResult,
} from "./types.mjs";

export const createSessionGrant = (deps: GrantDependencies): GrantHandler => {
	const { config } = deps;

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, session, issuer, metadata } = ctx;
			const { client_id, scope: requestedScope } = body as {
				client_id?: string;
				scope?: string;
			};

			if (!session.isAuthenticated) {
				return {
					result: {
						status: 401,
						error: "unauthorized",
						errorDescription: "session is not authenticated",
					},
				};
			}

			const scopes = requestedScope ? requestedScope.split(" ").filter(Boolean) : undefined;

			const payload = formatObject({
				user: session.user,
				client: session.client,
				...metadata,
			});

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: generateToken(payload, {
							secret: config.oauth.jwt.secret,
							expiresIn: config.oauth.accessToken.expiresIn,
							issuer,
							audience: client_id ?? null,
							scopes: scopes ?? null,
							type: "access",
						}),
					}),
				},
			};
		},
	};
};
