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
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { idTokenHint, REGISTERED_POST_LOGOUT_REDIRECT_URI as REGISTERED, signInLinkedToGoogle, } from "./google-session.fixture.mjs";
const UNREGISTERED = "https://evil.example/landing";
const GOOGLE_LOGOUT = "https://accounts.google.com/Logout";
const UPSTREAM_END_SESSION = "https://idp-logout.example/end-session";
const UPSTREAM_ID_TOKEN = "upstream-id-token";
/** Google's end-session endpoint, where a deployment names one. */
const WITH_END_SESSION = { endSessionEndpoint: UPSTREAM_END_SESSION };
describe("a logout's post_logout_redirect_uri reaches the upstream only once it is registered", () => {
    let session;
    afterEach(async () => {
        await session?.dispose();
        session = undefined;
    });
    /** Alice signed in, with Google linked and its id_token held for the end-session call. */
    async function signedInWithGoogle(google) {
        session = await signInLinkedToGoogle({
            google,
            tokens: {
                accessToken: "upstream-access-token",
                expiresAt: null,
                refreshToken: undefined,
                idToken: UPSTREAM_ID_TOKEN,
                tokenType: "Bearer",
                scope: undefined,
                grantedScope: undefined,
            },
        });
        return session;
    }
    const rpLogout = (app, sid, postLogoutRedirectUri) => request(app)
        .get("/oauth/logout")
        .query({
        id_token_hint: idTokenHint(sid),
        post_logout_redirect_uri: postLogoutRedirectUri,
        state: "s-1",
    });
    const federationLogout = (app, accessToken, postLogoutRedirectUri) => request(app)
        .post("/oauth/federation/google/logout")
        .set("Authorization", `Bearer ${accessToken}`)
        .type("form")
        .send({ post_logout_redirect_uri: postLogoutRedirectUri, state: "s-1" });
    describe("GET /oauth/logout, Google with no end-session endpoint", () => {
        it("does not send the browser to an unregistered post_logout_redirect_uri", async () => {
            const { app, sid, userSessionStore } = await signedInWithGoogle("shipped");
            const res = await rpLogout(app, sid, UNREGISTERED);
            expect(res.status).toBe(303);
            expect(new URL(res.headers.location).origin).not.toBe("https://evil.example");
            // Google's own logout page: the adapter's answer when it is handed no
            // redirect target, which is what an unregistered one now is.
            expect(res.headers.location).toBe(`${GOOGLE_LOGOUT}?state=s-1`);
            // The logout itself still happened.
            expect(await userSessionStore.get(sid)).toBeNull();
        });
        it("still returns the browser to a registered post_logout_redirect_uri, with state", async () => {
            const { app, sid, userSessionStore } = await signedInWithGoogle("shipped");
            const res = await rpLogout(app, sid, REGISTERED);
            expect(res.status).toBe(303);
            expect(res.headers.location).toBe(`${REGISTERED}?state=s-1`);
            expect(await userSessionStore.get(sid)).toBeNull();
        });
    });
    describe("GET /oauth/logout, Google with a configured end-session endpoint", () => {
        it("does not forward an unregistered post_logout_redirect_uri to the upstream", async () => {
            const { app, sid } = await signedInWithGoogle(WITH_END_SESSION);
            const res = await rpLogout(app, sid, UNREGISTERED);
            expect(res.status).toBe(303);
            const location = new URL(res.headers.location);
            expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
            expect(location.searchParams.get("id_token_hint")).toBe(UPSTREAM_ID_TOKEN);
            expect(location.searchParams.has("post_logout_redirect_uri")).toBe(false);
            expect(res.headers.location).not.toContain("evil.example");
        });
        it("forwards a registered one", async () => {
            const { app, sid } = await signedInWithGoogle(WITH_END_SESSION);
            const res = await rpLogout(app, sid, REGISTERED);
            expect(res.status).toBe(303);
            const location = new URL(res.headers.location);
            expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
            expect(location.searchParams.get("post_logout_redirect_uri")).toBe(REGISTERED);
            expect(location.searchParams.get("state")).toBe("s-1");
        });
    });
    describe("POST /oauth/federation/google/logout", () => {
        it("does not send the browser to an unregistered post_logout_redirect_uri", async () => {
            const { app, sid, accessToken, sessionFederationIndex } = await signedInWithGoogle("shipped");
            const res = await federationLogout(app, accessToken, UNREGISTERED);
            expect(res.status).toBe(303);
            expect(new URL(res.headers.location).origin).not.toBe("https://evil.example");
            expect(res.headers.location).toBe(`${GOOGLE_LOGOUT}?state=s-1`);
            // The federation was disconnected all the same.
            expect(await sessionFederationIndex.listFederations(sid)).not.toContain("google");
        });
        it("still returns the browser to one registered for the token's client", async () => {
            const { app, accessToken } = await signedInWithGoogle("shipped");
            const res = await federationLogout(app, accessToken, REGISTERED);
            expect(res.status).toBe(303);
            expect(res.headers.location).toBe(`${REGISTERED}?state=s-1`);
        });
        it("does not forward an unregistered one to a configured end-session endpoint", async () => {
            const { app, accessToken } = await signedInWithGoogle(WITH_END_SESSION);
            const res = await federationLogout(app, accessToken, UNREGISTERED);
            expect(res.status).toBe(303);
            const location = new URL(res.headers.location);
            expect(`${location.origin}${location.pathname}`).toBe(UPSTREAM_END_SESSION);
            expect(location.searchParams.has("post_logout_redirect_uri")).toBe(false);
        });
    });
});
