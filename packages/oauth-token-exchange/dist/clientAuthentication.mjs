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
/**
 * Client authentication for the exchange: the client `/oauth/token` authenticated,
 * or, on a route without it, the body's credentials. A public client and one whose
 * registration does not name this grant type are refused; a repository that cannot
 * answer is a `503`, never a verdict on the client.
 */
import { isGrantTypeAllowed, isWellFormedClientId, logClientRepositoryUnavailable, } from "@o3co/auth-provider-core";
import { invalidRequest } from "./answers.mjs";
import { GRANT_TYPE } from "./grantType.mjs";
export async function authenticateClient(deps, clientRepository, ctx, { bodyClientId, clientId, clientSecret, }) {
    // Client authentication; public (`"none"`) clients are refused on every route.
    // Dispatched from `/oauth/token`, `clientAuthMw` has already authenticated the
    // client (Basic header or body) and that identity is trusted over the body. On a
    // custom route without `clientAuthMw`, the body credentials are the only check.
    let client;
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
        // A body `client_id` must match the authenticated client, or a caller
        // authenticated as A could exchange under B's allowlist.
        if (bodyClientId !== null && bodyClientId !== ctx.authenticatedClient.clientId) {
            return invalidRequest("client_id does not match authenticated client");
        }
        try {
            client = await clientRepository.findById(ctx.authenticatedClient.clientId);
        }
        catch (err) {
            logClientRepositoryUnavailable(deps.logger, { site: "token_exchange", step: "find", clientId: ctx.authenticatedClient.clientId }, err);
            return {
                result: {
                    status: 503,
                    error: "temporarily_unavailable",
                    errorDescription: "client repository unavailable",
                },
            };
        }
    }
    else {
        // Standalone wiring: verify the body secret here. A repository failure is a 503,
        // as in the branch above.
        if (clientSecret === null) {
            return {
                result: {
                    status: 401,
                    error: "invalid_client",
                    errorDescription: "client_secret is required",
                },
            };
        }
        // A client_id no client can have is refused as the client's, and
        // never handed to the repository: a repository that throws is an
        // outage (503), and one may throw on it — a SQL driver refusing a
        // NUL byte (core's `isWellFormedClientId`).
        if (!isWellFormedClientId(clientId)) {
            return {
                result: {
                    status: 401,
                    error: "invalid_client",
                    errorDescription: "client authentication failed",
                },
            };
        }
        try {
            client = await clientRepository.authenticate(clientId, clientSecret);
        }
        catch (err) {
            logClientRepositoryUnavailable(deps.logger, { site: "token_exchange", step: "authenticate", clientId }, err);
            return {
                result: {
                    status: 503,
                    error: "temporarily_unavailable",
                    errorDescription: "client repository unavailable",
                },
            };
        }
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
    // The in-handler half of `requiresExplicitGrantAllowlist`: dispatch skips its
    // check when `ctx.authenticatedClient` is null, which is exactly the standalone
    // wiring. Core's rule (`isGrantTypeAllowed` with `requireAllowlist`) and
    // dispatch's exact wording, so a caller cannot tell which gate refused it.
    if (!isGrantTypeAllowed(client.allowedGrantTypes, GRANT_TYPE, { requireAllowlist: true })) {
        deps.logger?.warn({ clientId: client.clientId, grantType: GRANT_TYPE }, "token_exchange_grant_type_not_allowed");
        return {
            result: {
                status: 400,
                error: "unauthorized_client",
                errorDescription: `client is not authorized for grant_type '${GRANT_TYPE}'`,
            },
        };
    }
    return { client };
}
