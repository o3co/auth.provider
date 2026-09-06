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
import { generateToken, generateTokenResponse, } from "@o3co/auth-provider-core";
export const createSessionGrant = (deps) => {
    const { config, clientRepository, keyStore } = deps;
    return {
        async handle(ctx) {
            const { body, session, issuer } = ctx;
            const { client_id, scope: requestedScope } = body;
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
            // Validate scope against client's allowedScopes when client_id is provided.
            // Without client_id, scope is accepted as-is — this grant is intended for
            // first-party use where the server trusts the caller's scope request.
            if (client_id) {
                const client = await clientRepository.findById(client_id);
                if (!client) {
                    return {
                        result: {
                            status: 400,
                            error: "invalid_request",
                            errorDescription: "client not found",
                        },
                    };
                }
                if (scopes) {
                    const invalid = scopes.filter((s) => !client.allowedScopes.includes(s));
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
            }
            const rawUserId = session.user?.id;
            const userId = typeof rawUserId === "string" ? rawUserId : undefined;
            return {
                result: {
                    status: 200,
                    tokens: generateTokenResponse({
                        accessToken: await generateToken({}, {
                            keyStore,
                            expiresIn: config.oauth.accessToken.expiresIn,
                            issuer,
                            audience: client_id ?? null,
                            subject: userId ?? null,
                            authorizedParty: client_id ?? null,
                            scope: scopes?.join(" ") ?? null,
                            tokenType: "at+jwt",
                        }),
                    }),
                },
            };
        },
    };
};
