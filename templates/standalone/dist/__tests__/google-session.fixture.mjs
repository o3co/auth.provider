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
 * A browser session with Google linked, on the standalone as a deployment
 * composes it: `oauthModule`, the session module and the real Google adapter,
 * booted through `createApp` under the shipped configuration.
 *
 * The routes that act on a session's federation — the two logout routes and
 * `POST /oauth/federation/:name/token` — live in `@o3co/auth-provider-oauth`,
 * which depends on no adapter, so its own tests stand one in. What they hand
 * the adapter, and what they make of what its library raises, can only be
 * seen here.
 *
 * Not `all-modules-composition.fixture.mts`: that one switches every module
 * on and signs with a key it keeps to itself. The tests here present an
 * `id_token_hint` and an access token of their own — a caller's, with the
 * claims the case needs — so the deployment signs with an HS256 secret this
 * file holds, and nothing but Google is federated.
 */
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { AppConfigSchema, createApp, createKeyStoreFactory, defineModule, InMemoryClientRepository, InMemoryUserRepository, memoryRefreshTokenFamilyStoreModule, registerBuiltinKeyStores, } from "@o3co/auth-provider-core";
import { googleFederationModule, } from "@o3co/auth-provider-federation-google";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { expect } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "#/configPath.mjs";
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
export const ISSUER = "https://auth.test";
const JWT_SECRET = "google-session.fixture.at-least-32-bytes.ok";
/** The one client: first-party, allowed federation tokens, one post-logout URI registered. */
export const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret-value";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
export const REGISTERED_POST_LOGOUT_REDIRECT_URI = "https://rp.example/signed-out";
const USERNAME = "alice";
const PASSWORD = "correct-horse-battery-staple";
const SUB = "u-alice";
/** The Google client the adapter is configured with. */
export const GOOGLE_CLIENT_ID = "google-client";
const GOOGLE_CLIENT_SECRET = "google-secret";
const GOOGLE_CALLBACK = `${ISSUER}/session/oauth/federation/google/callback`;
const ENV = {
    OAUTH_JWT_ALGORITHM: "HS256",
    OAUTH_JWT_SECRET: JWT_SECRET,
    OAUTH_JWT_ISSUER: ISSUER,
    SESSION_SECRET: "google-session.fixture-session.at-least-32-bytes.ok",
    SESSION_SECURE: "false",
    SESSION_NAME: "auth.session",
    SESSION_STORAGE_TYPE: "memory",
    CLIENT_USER_TYPE: "yaml",
    REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis.test:6379",
    USER_SESSION_STORES_ADAPTER: "memory",
    RATE_LIMITER_ADAPTER: "memory",
    OAUTH_CODE_ADAPTER: "memory",
    ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
    REPLAY_SEEN_SET_ADAPTER: "memory",
    FEDERATION_TOKEN_STORE_TYPE: "memory",
    CONSENT_STORE_ADAPTER: "none",
};
function resolveConfig(google) {
    const env = google === "shipped"
        ? {
            ...ENV,
            FEDERATIONS_GOOGLE_ENABLED: "true",
            FEDERATIONS_GOOGLE_CLIENT_ID: GOOGLE_CLIENT_ID,
            FEDERATIONS_GOOGLE_CLIENT_SECRET: GOOGLE_CLIENT_SECRET,
            FEDERATIONS_GOOGLE_CALLBACK_URL: GOOGLE_CALLBACK,
        }
        : { ...ENV };
    const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
    return validate(parseFile(envConfPath, { env })
        .withFallback(parseFile(applicationConfPath, { env }))
        .withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })), AppConfigSchema);
}
const testRepositoriesModule = defineModule({
    name: "test:repositories",
    provides: {
        clientRepository: () => new InMemoryClientRepository(new Map([
            [
                CLIENT_ID,
                {
                    tokenEndpointAuthMethod: "client_secret_basic",
                    clientSecret: CLIENT_SECRET,
                    allowedRedirectUris: [],
                    allowedScopes: ["openid", "profile"],
                    allowedAudiences: [],
                    allowedGrantTypes: ["session"],
                    postLogoutRedirectUris: [REGISTERED_POST_LOGOUT_REDIRECT_URI],
                    backchannelLogoutSessionRequired: true,
                    frontchannelLogoutSessionRequired: true,
                    allowedAzpForFederationToken: true,
                },
            ],
        ])),
        userRepository: () => new InMemoryUserRepository(new Map([[USERNAME, { id: SUB, password: PASSWORD, email: "alice@example.com" }]])),
    },
});
const testKeyStoreModule = defineModule({
    name: "test:key-store",
    requires: ["config"],
    provides: {
        keyStore: async ({ config: c }) => {
            const factory = createKeyStoreFactory();
            registerBuiltinKeyStores(factory);
            return factory.create({
                type: "local",
                ...(c.oauth.jwt.signingKey.local ?? {}),
            });
        },
    },
});
const base64url = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A JWT signed with the deployment's own HS256 key: what its keystore verifies. */
function signed(typ, claims) {
    const header = base64url({ alg: "HS256", kid: "v0", typ });
    const now = Math.floor(Date.now() / 1000);
    const payload = base64url({ iss: ISSUER, sub: SUB, iat: now, exp: now + 3600, ...claims });
    const signature = createHmac("sha256", JWT_SECRET)
        .update(`${header}.${payload}`)
        .digest("base64url");
    return `${header}.${payload}.${signature}`;
}
/**
 * A fresh id_token for the session, issued to the client: what an RP — or
 * anyone holding an id_token of their own — presents as `id_token_hint`.
 */
export const idTokenHint = (sid) => signed("JWT", { aud: CLIENT_ID, sid });
/**
 * An access token for the session as the authorization-code grant issues it
 * to the client: `azp`, `sid` and a refresh-token `family_id`. The `session`
 * grant's token names no family, and the federation token route asks for one.
 */
export const accessTokenWithFamily = (sid) => signed("at+jwt", { azp: CLIENT_ID, sid, family_id: "family-1", scope: "openid" });
const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8"));
/**
 * Boots the deployment, signs alice in with her password, and links Google to
 * her session as a federated sign-in would: the session's federation index
 * names it and the token store holds `tokens`.
 */
export async function signInLinkedToGoogle(options) {
    const { google, tokens } = options;
    const config = resolveConfig(google);
    const googleModules = google === "shipped"
        ? []
        : [
            googleFederationModule,
            defineModule({
                name: "test:google-federation-config",
                provides: {
                    googleFederationConfig: () => ({
                        clientId: GOOGLE_CLIENT_ID,
                        clientSecret: GOOGLE_CLIENT_SECRET,
                        callbackURL: GOOGLE_CALLBACK,
                        ...google,
                    }),
                },
            }),
        ];
    const handle = await createApp({
        modules: [
            ...buildModules(config, {
                keyStoreModule: testKeyStoreModule,
                repositoriesModule: testRepositoriesModule,
                refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
            }),
            ...googleModules,
        ],
        bootstrapComponents: { config, pathResolver: (s) => s },
    });
    try {
        const components = handle.components;
        const app = express();
        app.use(handle.router);
        const csrfRes = await request(app).get("/session/csrf");
        expect(csrfRes.status).toBe(200);
        const loginRes = await request(app)
            .post("/session/login")
            .set("Cookie", csrfRes.headers["set-cookie"])
            .set(csrfRes.body.header_name, csrfRes.body.csrf_token)
            .type("form")
            .send({ username: USERNAME, password: PASSWORD });
        expect(loginRes.status).toBe(200);
        const tokenRes = await request(app)
            .post("/oauth/token")
            .set("Authorization", BASIC)
            .set("Cookie", loginRes.headers["set-cookie"])
            .type("form")
            .send({ grant_type: "session" });
        expect(tokenRes.status).toBe(200);
        const accessToken = tokenRes.body.access_token;
        const claims = claimsOf(accessToken);
        expect(claims.azp).toBe(CLIENT_ID);
        const sid = claims.sid;
        expect(typeof sid).toBe("string");
        const session = await components.userSessionStore.get(sid);
        if (session === null)
            throw new Error("fixture: the sign-in left no session");
        await components.sessionFederationIndex.addFederation(sid, "google", session.expiresAt);
        await components.federationTokenStore.attach(sid, "google", tokens);
        return { app, sid, accessToken, ...components, dispose: () => handle.dispose() };
    }
    catch (error) {
        await handle.dispose();
        throw error;
    }
}
