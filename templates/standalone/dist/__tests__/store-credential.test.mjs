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
 * The credential auth.provider presents to the Store, through the shipped
 * composition: `CLIENT_USER_BEARER_TOKEN` in the environment → the HOCON
 * layers → `AppConfigSchema` → the production `repositoriesModule` → the
 * `"http"` user adapter → the `Authorization` header a real `node:http` Store
 * receives. Unset, the Store receives no `Authorization` header; set blank —
 * an exported-but-empty variable — the user repository is refused.
 *
 * And what a mismatch looks like from outside, with the app booted from the
 * shipped config through `createApp`: a Store that refuses the token with a
 * `401` and a `Bearer` challenge turns `POST /session/login` into a `503`
 * whose log line names the refused credential and never the token; a `401`
 * without the challenge is still a wrong password.
 */
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import { AppConfigSchema, createApp, createKeyStoreFactory, defineModule, memoryRefreshTokenFamilyStoreModule, registerBuiltinKeyStores, } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";
import { repositoriesModule } from "../modules.mjs";
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
/** 32 bytes of key material — what `openssl rand -hex 32` prints. */
const TOKEN = "7d1f0c3b9a5e2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f";
let servers = [];
afterEach(async () => {
    await Promise.all(servers.map((server) => {
        server.closeAllConnections();
        return new Promise((resolve) => server.close(() => resolve()));
    }));
    servers = [];
});
const USER = { status: 200, body: { id: "user-1", username: "alice" } };
/** A Store on its own loopback port that records each request's Authorization header. */
const recordingStore = async (answer = USER) => {
    const heard = [];
    const server = createServer((req, res) => {
        req.resume();
        req.on("end", () => {
            heard.push(req.headers.authorization);
            res.writeHead(answer.status, { "Content-Type": "application/json", ...answer.headers });
            res.end(JSON.stringify(answer.body));
        });
    });
    servers.push(server);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    return { origin: `http://127.0.0.1:${port}`, heard };
};
/** The shipped config for the production overlay, resolved against `env`. */
const resolve = (env) => {
    const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
    return validate(parseFile(envConfPath, { env })
        .withFallback(parseFile(applicationConfPath, { env }))
        .withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })), AppConfigSchema);
};
/** The user repository the production `repositoriesModule` builds from `config`. */
const userRepositoryFrom = (config) => Promise.resolve(repositoriesModule.provides?.userRepository?.({ config }));
const envFor = (origin) => ({
    OAUTH_JWT_ALGORITHM: "HS256",
    OAUTH_JWT_SECRET: "store-credential-composition.at-least-32-bytes.ok",
    OAUTH_JWT_ISSUER: "https://auth.test",
    SESSION_SECRET: "store-credential-composition-session.at-least-32-bytes.ok",
    CLIENT_USER_TYPE: "http",
    CLIENT_USER_AUTHENTICATE_URL: `${origin}/authenticate`,
    CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL: `${origin}/authenticate-by-token`,
});
describe("CLIENT_USER_BEARER_TOKEN reaches the Store through the shipped composition", () => {
    it("sends Authorization: Bearer <token> on every Store call when the variable is set", async () => {
        const { origin, heard } = await recordingStore();
        const repo = await userRepositoryFrom(resolve({ ...envFor(origin), CLIENT_USER_BEARER_TOKEN: TOKEN }));
        await repo.authenticate("alice", "pass");
        await repo.authenticateByToken("apple:a1");
        expect(heard).toEqual([`Bearer ${TOKEN}`, `Bearer ${TOKEN}`]);
    });
    it("sends no Authorization header when the variable is unset", async () => {
        const { origin, heard } = await recordingStore();
        const repo = await userRepositoryFrom(resolve(envFor(origin)));
        await repo.authenticate("alice", "pass");
        expect(heard).toEqual([undefined]);
    });
    it("refuses the user repository when the variable is exported but empty", async () => {
        const { origin, heard } = await recordingStore();
        const config = resolve({ ...envFor(origin), CLIENT_USER_BEARER_TOKEN: "" });
        await expect(userRepositoryFrom(config)).rejects.toThrow(/"bearerToken" must not be empty/);
        expect(heard).toEqual([]);
    });
});
describe("a token the Store refuses, seen from outside the booted app", () => {
    /** Every store on memory, so the boot opens no socket but the Store's. */
    const MEMORY_ENV = {
        SESSION_SECURE: "false",
        SESSION_NAME: "auth.session",
        SESSION_STORAGE_TYPE: "memory",
        USER_SESSION_STORES_ADAPTER: "memory",
        RATE_LIMITER_ADAPTER: "memory",
        OAUTH_CODE_ADAPTER: "memory",
        ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
        REPLAY_SEEN_SET_ADAPTER: "memory",
        FEDERATION_TOKEN_STORE_TYPE: "memory",
        CONSENT_STORE_ADAPTER: "none",
        FEDERATION_GRANT_STORE_ADAPTER: "memory",
        FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
    };
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
    /** Every log call, as the arguments it was made with. */
    const capturingLogger = () => {
        const lines = [];
        const at = (level) => (...args) => {
            lines.push({ level, args });
        };
        const logger = {
            trace: at("trace"),
            debug: at("debug"),
            info: at("info"),
            warn: at("warn"),
            error: at("error"),
            fatal: at("fatal"),
            child: () => logger,
        };
        return { logger, lines };
    };
    let handleRef;
    afterEach(async () => {
        await handleRef?.dispose();
        handleRef = undefined;
    });
    /**
     * The shipped config against a Store answering `answer`, booted with the
     * production repositories module; then a real browser login — a CSRF pair,
     * then the form post.
     */
    const logInAgainst = async (answer) => {
        const { origin, heard } = await recordingStore(answer);
        const config = resolve({ ...envFor(origin), ...MEMORY_ENV, CLIENT_USER_BEARER_TOKEN: TOKEN });
        const { logger, lines } = capturingLogger();
        handleRef = await createApp({
            modules: buildModules(config, {
                keyStoreModule: testKeyStoreModule,
                refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
            }),
            bootstrapComponents: { config, pathResolver: (s) => s, logger },
        });
        const app = express().use(handleRef.router);
        const csrf = await request(app).get("/session/csrf");
        expect(csrf.status).toBe(200);
        const login = await request(app)
            .post("/session/login")
            .set("Cookie", csrf.headers["set-cookie"])
            .set(csrf.body.header_name, csrf.body.csrf_token)
            .type("form")
            .send({ username: "alice", password: "correct-horse-battery-staple" });
        const logged = lines.map((line) => inspect(line, { depth: Number.POSITIVE_INFINITY, showHidden: true }));
        return { login, heard, logged };
    };
    it("answers the login 503 and logs the refused credential by name, never the token", async () => {
        const { login, heard, logged } = await logInAgainst({
            status: 401,
            headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' },
            body: { error: "invalid_token" },
        });
        expect(heard).toEqual([`Bearer ${TOKEN}`]);
        expect(login.status).toBe(503);
        expect(login.body.error).toBe("temporarily_unavailable");
        expect(logged.filter((line) => /refused this deployment's credential/.test(line))).toHaveLength(1);
        expect(logged.filter((line) => line.includes(TOKEN))).toEqual([]);
    });
    it("still answers a 401 without the challenge as a wrong password", async () => {
        const { login, heard, logged } = await logInAgainst({
            status: 401,
            body: { error: "invalid_credentials" },
        });
        expect(heard).toEqual([`Bearer ${TOKEN}`]);
        expect(login.status).toBe(401);
        expect(login.body.error).toBe("invalid_credentials");
        expect(logged.filter((line) => /refused this deployment's credential/.test(line))).toEqual([]);
    });
});
