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
export function makeValidCoreConfig() {
    return {
        http: { port: 3000, trustProxy: false },
        oauth: {
            jwt: {
                signingKey: {
                    provider: "local",
                    local: {
                        algorithm: "HS256",
                        kid: "v0",
                        secret: "test-secret",
                        previousKeys: [],
                    },
                },
            },
            accessToken: { expiresIn: 3600 },
            refreshToken: { expiresIn: 86400 },
            grants: {},
        },
    };
}
export function makeValidFullSections() {
    return {
        session: {
            secret: "test-session-secret",
            maxAge: 3600000,
            secure: true,
            sameSite: "lax",
            domain: null,
            storage: { type: "memory" },
        },
        rateLimit: {
            login: { windowMs: 900000, limit: 20 },
        },
        federations: {},
        repositories: {
            client: { type: "yaml" },
            user: { type: "yaml" },
            code: { type: "memory" },
        },
        endpoints: {
            // `oauthModule.configSchema` requires a non-empty `endpoints.login.url`
            // because `routes.mts:339` builds the unauthenticated /authorize redirect
            // from it. Keeping the fixture valid across all v0.5.0 module schemas.
            login: { url: "/login" },
        },
        cors: { allowedOrigins: [] },
    };
}
export function makeValidAppConfig() {
    return {
        ...makeValidCoreConfig(),
        ...makeValidFullSections(),
    };
}
