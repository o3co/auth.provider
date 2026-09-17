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
import { fullSectionsSchema, } from "@o3co/auth-provider-core";
import * as oidcConfig from "./routes/OpenidConfiguration.mjs";
import { createOAuthRouter } from "./routes.mjs";
const oauthConfigSchema = fullSectionsSchema.pick({
    endpoints: true,
});
export const oauthModule = (params) => ({
    name: "oauth",
    configSchema: oauthConfigSchema,
    async init(context) {
        const config = context.config;
        // We need express-like factory for creating sub-router.
        // Use the express instance passed via params, or construct a minimal one.
        const express = params.express ??
            (await (async () => {
                const mod = await import(context.pathResolver("express"));
                return mod.default;
            })());
        const { router: oauthRouter } = await createOAuthRouter(express, {
            registry: context.grantRegistry,
            config,
            clientRepository: params.clientRepository,
            codeRepository: params.codeRepository,
            keyStore: context.keyStore,
            rateLimiter: context.rateLimiter,
            auditSink: context.auditSink,
            grantPolicy: context.grantPolicy,
            refreshTokenStore: context.refreshTokenStore,
            userSessionStore: context.userSessionStore,
            federationTokenStore: context.federationTokenStore,
            // Lazy closure: evaluated at request time, not at init time.
            // Captures `context` by reference so federation providers written by
            // sessionModule.init() are visible regardless of module init order.
            getFederationProviders: () => context.federationProviders,
        });
        context.router.use("/oauth", oauthRouter);
        // OIDC discovery — mount only when issuer is configured. The module
        // owns the OAuth endpoints this document advertises (/oauth/authorize,
        // /oauth/token, /oauth/userinfo, /oauth/introspect), so discovery
        // belongs here and not in createApp: a deployment that excludes the
        // OAuth module must not publish a discovery doc pointing at endpoints
        // that do not exist.
        const issuer = config.oauth?.jwt?.issuer;
        if (typeof issuer === "string" && issuer.length > 0) {
            // Advertise only the algorithm the configured KeyStore actually signs
            // with. Hardcoding the full union would mislead clients to fetch JWKS
            // expecting a key that is not there (OIDC Core §10.1 + RFC 8414 §2).
            //
            // logoutSupported mirrors the condition used in createOAuthRouter to mount
            // the logout router. When any required store is absent, the logout route
            // is not registered and discovery must not advertise the 5 logout fields.
            const logoutSupported = !!context.userSessionStore && !!context.federationTokenStore && !!context.refreshTokenStore;
            context.router.use(oidcConfig.createRouter(express, {
                issuer,
                signingAlgs: [context.keyStore.algorithm],
                logoutSupported,
            }));
        }
    },
});
