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
import { describe, expect, it } from "vitest";
import { createRouter } from "#/routes/OpenidConfiguration.mjs";
function createMockExpress() {
    const routes = {};
    const router = {
        get(path, handler) {
            routes[path] = handler;
            return router;
        },
    };
    return { Router: () => router, routes };
}
function createMockRes() {
    let statusCode = 200;
    let body;
    return {
        status(code) {
            statusCode = code;
            return this;
        },
        json(data) {
            body = data;
            return this;
        },
        sendStatus(code) {
            statusCode = code;
            return this;
        },
        getStatusCode: () => statusCode,
        getBody: () => body,
    };
}
async function callRoute(opts) {
    const express = createMockExpress();
    createRouter(express, opts);
    const handler = express.routes["/.well-known/openid-configuration"];
    const res = createMockRes();
    await handler({}, res);
    return res.getBody();
}
describe("GET /.well-known/openid-configuration", () => {
    it("returns discovery metadata with F-4 scoped endpoints + signing algs", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: ["RS256", "ES256", "EdDSA", "HS256"],
        });
        expect(body.issuer).toBe("https://auth.example.com");
        expect(body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
        expect(body.token_endpoint).toBe("https://auth.example.com/oauth/token");
        expect(body.userinfo_endpoint).toBe("https://auth.example.com/oauth/userinfo");
        expect(body.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
        expect(body.introspection_endpoint).toBe("https://auth.example.com/oauth/introspect");
        expect(body.response_types_supported).toEqual(["code"]);
        expect(body.subject_types_supported).toEqual(["public"]);
        expect(body.id_token_signing_alg_values_supported).toEqual([
            "RS256",
            "ES256",
            "EdDSA",
            "HS256",
        ]);
        expect(body.scopes_supported).toEqual(["openid", "profile", "email", "groups"]);
        expect(body.code_challenge_methods_supported).toEqual(["S256"]);
        expect(body.token_endpoint_auth_methods_supported).toEqual(expect.arrayContaining(["client_secret_basic", "client_secret_post", "none"]));
    });
    it("does NOT advertise revocation_endpoint (out of F-5 scope)", async () => {
        const body = await callRoute({ issuer: "https://auth.example.com", signingAlgs: [] });
        expect(body.revocation_endpoint).toBeUndefined();
    });
    it("advertises end_session_endpoint per OIDC RP-Initiated Logout 1.0", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: [],
            logoutSupported: true,
        });
        expect(body.end_session_endpoint).toBe("https://auth.example.com/oauth/logout");
    });
    it("advertises Back-Channel Logout support per OIDC Back-Channel Logout 1.0", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: [],
            logoutSupported: true,
        });
        expect(body.backchannel_logout_supported).toBe(true);
        expect(body.backchannel_logout_session_supported).toBe(true);
    });
    it("advertises Front-Channel Logout support per OIDC Front-Channel Logout 1.0", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: [],
            logoutSupported: true,
        });
        expect(body.frontchannel_logout_supported).toBe(true);
        expect(body.frontchannel_logout_session_supported).toBe(true);
    });
    it("omits all logout fields when logoutSupported is not set (default false — explicit opt-in required)", async () => {
        const body = await callRoute({ issuer: "https://auth.example.com", signingAlgs: [] });
        // No logoutSupported option passed — default must be false (safe default for direct users)
        expect(body.end_session_endpoint).toBeUndefined();
        expect(body.backchannel_logout_supported).toBeUndefined();
        expect(body.backchannel_logout_session_supported).toBeUndefined();
        expect(body.frontchannel_logout_supported).toBeUndefined();
        expect(body.frontchannel_logout_session_supported).toBeUndefined();
    });
    it("omits all 5 logout fields when logoutSupported is false (stores not configured)", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: [],
            logoutSupported: false,
        });
        expect(body.end_session_endpoint).toBeUndefined();
        expect(body.backchannel_logout_supported).toBeUndefined();
        expect(body.backchannel_logout_session_supported).toBeUndefined();
        expect(body.frontchannel_logout_supported).toBeUndefined();
        expect(body.frontchannel_logout_session_supported).toBeUndefined();
    });
    it("strips trailing slashes from issuer in both the issuer field and endpoint URLs", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com///",
            signingAlgs: ["RS256"],
        });
        // Normalized form is used for both endpoints and the issuer field so
        // discovery.issuer matches the iss claim on issued tokens.
        expect(body.issuer).toBe("https://auth.example.com");
        expect(body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
        expect(body.token_endpoint).toBe("https://auth.example.com/oauth/token");
    });
    it("omits jwks_uri for HS256-only deployments (JWKS route returns 404 for symmetric keys)", async () => {
        const body = await callRoute({ issuer: "https://auth.example.com", signingAlgs: ["HS256"] });
        expect(body.jwks_uri).toBeUndefined();
    });
    it("advertises jwks_uri when any asymmetric alg is configured (RS256 alongside HS256)", async () => {
        const body = await callRoute({
            issuer: "https://auth.example.com",
            signingAlgs: ["RS256", "HS256"],
        });
        expect(body.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
    });
});
