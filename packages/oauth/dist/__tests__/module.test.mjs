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
import { createSecretKey } from "node:crypto";
import { createSymmetricKeyStore, GrantRegistry, } from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";
const mockConfig = {
    oauth: {
        jwt: { secret: "test-secret" },
        accessToken: { expiresIn: 3600 },
        refreshToken: { expiresIn: 86400 },
        grants: {},
    },
    endpoints: {
        login: { url: "/login" },
    },
};
const makeContext = (overrides) => ({
    pathResolver: (s) => s,
    config: mockConfig,
    keyStore: createSymmetricKeyStore("test-secret"),
    grantRegistry: new GrantRegistry(),
    router: {
        use: vi.fn().mockReturnThis(),
        get: vi.fn().mockReturnThis(),
        post: vi.fn().mockReturnThis(),
    },
    ...overrides,
});
describe("oauthModule", () => {
    it("has name 'oauth'", () => {
        const module = oauthModule({
            clientRepository: {},
            codeRepository: {},
        });
        expect(module.name).toBe("oauth");
    });
    it("forwards context.rateLimiter and context.auditSink into oauth routes", async () => {
        // End-to-end: createApp-style wiring uses a real express Router, so we
        // mount the module's sub-router onto an app and issue a real request.
        const app = express();
        app.set("trust proxy", 1);
        app.use(express.json());
        app.use(express.urlencoded({ extended: false }));
        const rootRouter = express.Router();
        const rateLimiter = {
            kind: "spy",
            check: vi.fn().mockResolvedValue({ allowed: false, reason: "limit:token" }),
        };
        const events = [];
        const auditSink = {
            kind: "spy",
            async record(event) {
                events.push(event);
            },
        };
        const ctx = {
            pathResolver: (s) => s,
            config: {
                ...mockConfig,
                oauth: { ...mockConfig.oauth, grants: {} },
            },
            keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
            grantRegistry: new GrantRegistry(),
            router: rootRouter,
            rateLimiter,
            auditSink,
        };
        const module = oauthModule({
            clientRepository: {},
            codeRepository: {},
            express,
        });
        await module.init(ctx);
        app.use(rootRouter);
        const res = await request(app).post("/oauth/token").send({ grant_type: "password" });
        // rateLimiter was forwarded and invoked by the route
        expect(rateLimiter.check).toHaveBeenCalled();
        expect(res.status).toBe(429);
        // If auditSink was forwarded, we can at least confirm rateLimiter reached
        // the handler. auditSink is exercised in hooks.test.mts.
    });
    it("mounts /oauth routes on context.router", async () => {
        const routerMock = {
            use: vi.fn().mockReturnThis(),
            get: vi.fn().mockReturnThis(),
            post: vi.fn().mockReturnThis(),
        };
        const ctx = makeContext({ router: routerMock });
        const module = oauthModule({
            clientRepository: {},
            codeRepository: {},
        });
        await module.init(ctx);
        // Should have mounted the oauth sub-router on /oauth
        expect(routerMock.use.mock.calls.length).toBeGreaterThanOrEqual(1);
        const oauthCall = routerMock.use.mock.calls.find((call) => call[0] === "/oauth");
        expect(oauthCall).toBeDefined();
    });
    // -----------------------------------------------------------------------
    // Integration: lazy getFederationProviders closure
    //
    // Proves that composing modules as [oauthModule, sessionModule, ...] (oauth
    // inits FIRST) still correctly resolves federation providers at request time
    // because createOAuthRouter receives `() => context.federationProviders`
    // rather than a snapshot of the map value at init time.
    // -----------------------------------------------------------------------
    it("federation logout works when oauth module inits BEFORE context.federationProviders is populated (lazy closure)", async () => {
        const SECRET = "test-secret-at-least-32-chars!!";
        const secretKey = createSecretKey(Buffer.from(SECRET));
        // A minimal access token for POST /oauth/federation/:name/logout
        const accessToken = await new SignJWT({ sub: "u-1", sid: "sid-1", family_id: "fam-1" })
            .setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
            .setExpirationTime("1h")
            .setIssuedAt()
            .sign(secretKey);
        // Session has "google" linked
        const session = {
            sid: "sid-1",
            sub: "u-1",
            authTime: new Date(),
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 3_600_000),
            federations: ["google"],
            activeRPs: [],
            familyIds: ["fam-1"],
            claims: {},
        };
        const sessionStore = {
            kind: "memory",
            create: vi.fn(),
            get: vi.fn().mockResolvedValue(session),
            registerRP: vi.fn(),
            linkFamily: vi.fn(),
            updateClaims: vi.fn(),
            removeFederation: vi.fn().mockResolvedValue(undefined),
            delete: vi.fn(),
        };
        const refreshStore = {
            kind: "memory",
            isFamilyRevoked: vi.fn().mockResolvedValue(false),
            rotate: vi.fn(),
            revokeFamily: vi.fn().mockResolvedValue(undefined),
        };
        const fedTokenStore = {
            kind: "memory",
            attach: vi.fn(),
            get: vi.fn().mockResolvedValue({ idToken: "id-token-hint" }),
            update: vi.fn(),
            deleteBySession: vi.fn().mockResolvedValue(undefined),
            delete: vi.fn().mockResolvedValue(undefined),
        };
        // The provider's endSession returns a redirect URL
        const endSessionUrl = new URL("https://accounts.google.com/logout?hint=id-token-hint");
        const googleProvider = {
            name: "google",
            endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
        };
        // Build context — federationProviders is undefined at construction time,
        // simulating the state when oauthModule.init runs before sessionModule.init.
        const rootRouter = express.Router();
        const ctx = makeContext({
            config: {
                ...mockConfig,
                oauth: {
                    ...mockConfig.oauth,
                    jwt: { secret: SECRET, issuer: "https://auth.example.com" },
                },
            },
            keyStore: createSymmetricKeyStore(SECRET),
            router: rootRouter,
            refreshTokenStore: refreshStore,
            userSessionStore: sessionStore,
            federationTokenStore: fedTokenStore,
            // NOT setting federationProviders yet — simulates oauth init running first
        });
        // Step 1: oauth module inits (federationProviders still undefined on ctx)
        const oauth = oauthModule({
            clientRepository: { findById: vi.fn(), authenticate: vi.fn() },
            codeRepository: {
                createCode: vi.fn(),
                getCode: vi.fn(),
                deleteCode: vi.fn(),
            },
            express,
        });
        await oauth.init(ctx);
        // Step 2: "session module" sets federationProviders AFTER oauth init — simulates
        // the real module composition order where session inits after oauth.
        ctx.federationProviders = new Map([
            ["google", googleProvider],
        ]);
        // Step 3: issue a real HTTP request — the closure in createOAuthRouter reads
        // context.federationProviders at request time, so it picks up the map set above.
        const app = express();
        app.use(rootRouter);
        const res = await request(app)
            .post("/oauth/federation/google/logout")
            .type("form")
            .set("Authorization", `Bearer ${accessToken}`)
            .send({});
        // The lazy closure resolved the provider → endSession redirect
        expect(res.status).toBe(303);
        expect(res.headers.location).toContain("accounts.google.com");
        expect(googleProvider.endSession).toHaveBeenCalledOnce();
    });
    it("federation token endpoint works when oauth module inits BEFORE context.federationProviders is populated (lazy resolution)", async () => {
        const SECRET = "test-secret-at-least-32-chars!!";
        const secretKey = createSecretKey(Buffer.from(SECRET));
        // Access token with azp identifying the permitted client
        const accessToken = await new SignJWT({
            sub: "u-1",
            sid: "sid-1",
            family_id: "fam-1",
            azp: "client-1",
        })
            .setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
            .setExpirationTime("1h")
            .setIssuedAt()
            .sign(secretKey);
        // Session has "google" linked
        const session = {
            sid: "sid-1",
            sub: "u-1",
            authTime: new Date(),
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 3_600_000),
            federations: ["google"],
            activeRPs: [],
            familyIds: ["fam-1"],
            claims: {},
        };
        const sessionStore = {
            kind: "memory",
            create: vi.fn(),
            get: vi.fn().mockResolvedValue(session),
            registerRP: vi.fn(),
            linkFamily: vi.fn(),
            updateClaims: vi.fn(),
            removeFederation: vi.fn().mockResolvedValue(undefined),
            delete: vi.fn(),
        };
        const refreshStore = {
            kind: "memory",
            isFamilyRevoked: vi.fn().mockResolvedValue(false),
            rotate: vi.fn(),
            revokeFamily: vi.fn().mockResolvedValue(undefined),
        };
        // Federation tokens — well within expiry so no refresh path is exercised
        const fedTokenStore = {
            kind: "memory",
            attach: vi.fn(),
            get: vi.fn().mockResolvedValue({
                accessToken: "upstream-access-token",
                expiresAt: new Date(Date.now() + 3_600_000),
                tokenType: "Bearer",
            }),
            update: vi.fn(),
            deleteBySession: vi.fn().mockResolvedValue(undefined),
            delete: vi.fn().mockResolvedValue(undefined),
        };
        // Client with permission to retrieve federation tokens
        const clientRepo = {
            findById: vi.fn().mockResolvedValue({
                id: "client-1",
                allowedRedirectUris: [],
                allowedScopes: [],
                allowedAzpForFederationToken: true,
            }),
            authenticate: vi.fn(),
        };
        // Build context — federationProviders is undefined at construction time
        const rootRouter = express.Router();
        const ctx = makeContext({
            config: {
                ...mockConfig,
                oauth: {
                    ...mockConfig.oauth,
                    jwt: { secret: SECRET, issuer: "https://auth.example.com" },
                },
            },
            keyStore: createSymmetricKeyStore(SECRET),
            router: rootRouter,
            refreshTokenStore: refreshStore,
            userSessionStore: sessionStore,
            federationTokenStore: fedTokenStore,
            // NOT setting federationProviders yet — simulates oauth init running first
        });
        // Step 1: oauth module inits (federationProviders still undefined on ctx)
        const oauth = oauthModule({
            clientRepository: clientRepo,
            codeRepository: {
                createCode: vi.fn(),
                getCode: vi.fn(),
                deleteCode: vi.fn(),
            },
            express,
        });
        await oauth.init(ctx);
        // Step 2: "session module" sets federationProviders AFTER oauth init
        ctx.federationProviders = new Map([
            ["google", { name: "google" }],
        ]);
        // Step 3: issue a real HTTP request — the token is fresh so no refresh is needed
        const app = express();
        app.use(rootRouter);
        const res = await request(app)
            .post("/oauth/federation/google/token")
            .set("Authorization", `Bearer ${accessToken}`)
            .send({});
        // The route is mounted and the token is returned
        expect(res.status).toBe(200);
        expect(res.body.access_token).toBe("upstream-access-token");
        expect(res.body.token_type).toBe("Bearer");
    });
    it("federation-token endpoint is mounted even when oauth.jwt.issuer is absent (returns 401, not 404)", async () => {
        const SECRET = "test-secret-at-least-32-chars!!";
        const sessionStore = {
            kind: "memory",
            create: vi.fn(),
            get: vi.fn(),
            registerRP: vi.fn(),
            linkFamily: vi.fn(),
            updateClaims: vi.fn(),
            removeFederation: vi.fn(),
            delete: vi.fn(),
        };
        const refreshStore = {
            kind: "memory",
            isFamilyRevoked: vi.fn(),
            rotate: vi.fn(),
            revokeFamily: vi.fn(),
        };
        const fedTokenStore = {
            kind: "memory",
            attach: vi.fn(),
            get: vi.fn(),
            update: vi.fn(),
            deleteBySession: vi.fn(),
            delete: vi.fn(),
        };
        // Config intentionally omits oauth.jwt.issuer — only secret is provided.
        const rootRouter = express.Router();
        const ctx = makeContext({
            config: {
                ...mockConfig,
                oauth: {
                    ...mockConfig.oauth,
                    jwt: { secret: SECRET },
                    // issuer is deliberately absent
                },
            },
            keyStore: createSymmetricKeyStore(SECRET),
            router: rootRouter,
            refreshTokenStore: refreshStore,
            userSessionStore: sessionStore,
            federationTokenStore: fedTokenStore,
        });
        const oauth = oauthModule({
            clientRepository: { findById: vi.fn(), authenticate: vi.fn() },
            codeRepository: {
                createCode: vi.fn(),
                getCode: vi.fn(),
                deleteCode: vi.fn(),
            },
            express,
        });
        await oauth.init(ctx);
        const app = express();
        app.use(rootRouter);
        // No Authorization header → should get 401 (route is mounted) not 404 (route missing)
        const res = await request(app).post("/oauth/federation/google/token").send({});
        expect(res.status).toBe(401);
    });
});
