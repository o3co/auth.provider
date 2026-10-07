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
 * `POST /oauth/federation/:name/token` ends a session's upstream tokens only
 * on the upstream's own verdict that the refresh token is bad — a structured
 * `invalid_grant` under a 4xx — and never while the upstream is down, whatever
 * the body of its 5xx says. An outage is `503`, and the tokens are kept for
 * the retry.
 *
 * Driven through the real Google adapter and its library (openid-client)
 * against a fake Google (`createFakeIdp`), so the errors the route classifies
 * are the ones the library raises: a 4xx whose body names a code is a
 * `ResponseBodyError` carrying `error` and `status`; a 5xx is an
 * `OperationProcessingError` raised over the `Response`, whose body the
 * library does not read — and which the route used to answer `500
 * refresh_failed`, as if the upstream had said something it could not place.
 */
import { createFakeIdp } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { accessTokenWithFamily, GOOGLE_CLIENT_ID, signInLinkedToGoogle, } from "./google-session.fixture.mjs";
const GOOGLE = {
    issuer: "https://accounts.google.com",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
};
const STORED_REFRESH_TOKEN = "stored-refresh-token";
describe("POST /oauth/federation/google/token: an upstream outage never ends the session's Google tokens", () => {
    let session;
    afterEach(async () => {
        await session?.dispose();
        session = undefined;
    });
    /**
     * Alice's session with Google linked, its access token expired so the
     * route refreshes, and the fake Google answering the refresh with `status`
     * and `body`.
     */
    async function refreshAnswered(status, body) {
        const idp = await createFakeIdp({ ...GOOGLE, clientId: GOOGLE_CLIENT_ID });
        idp.tokenStatus = status;
        idp.refusal = body;
        session = await signInLinkedToGoogle({
            google: { fetch: idp.fetch },
            tokens: {
                accessToken: "expired-upstream-access-token",
                expiresAt: new Date(Date.now() - 60_000),
                refreshToken: STORED_REFRESH_TOKEN,
                idToken: undefined,
                tokenType: "Bearer",
                scope: "openid profile email",
                grantedScope: "openid profile email",
            },
        });
        const res = await request(session.app)
            .post("/oauth/federation/google/token")
            .set("Authorization", `Bearer ${accessTokenWithFamily(session.sid)}`)
            .send();
        // The library did ask Google: what follows is its reading of the answer.
        expect(idp.requests.filter((r) => `${r.url.origin}${r.url.pathname}` === GOOGLE.tokenEndpoint &&
            r.body?.get("grant_type") === "refresh_token")).toHaveLength(1);
        return { res, ...session };
    }
    it("keeps them and answers 503 when Google answers 503 with a body naming invalid_grant", async () => {
        const { res, sid, federationTokenStore, sessionFederationIndex } = await refreshAnswered(503, {
            error: "invalid_grant",
            error_description: "Backend unavailable",
        });
        expect(res.status).toBe(503);
        expect(res.body).toEqual({
            error: "temporarily_unavailable",
            error_description: "upstream federation provider temporarily unavailable",
        });
        expect((await federationTokenStore.get(sid, "google"))?.refreshToken).toBe(STORED_REFRESH_TOKEN);
        expect(await sessionFederationIndex.listFederations(sid)).toContain("google");
    });
    it("keeps them and answers 503 when Google answers 502 with no OAuth body at all", async () => {
        const { res, sid, federationTokenStore } = await refreshAnswered(502, {});
        expect(res.status).toBe(503);
        expect((await federationTokenStore.get(sid, "google"))?.refreshToken).toBe(STORED_REFRESH_TOKEN);
    });
    it("ends them on Google's structured 400 invalid_grant", async () => {
        const { res, sid, federationTokenStore, sessionFederationIndex } = await refreshAnswered(400, {
            error: "invalid_grant",
            error_description: "Token has been expired or revoked.",
        });
        expect(res.status).toBe(410);
        expect(res.body.error).toBe("re_authentication_required");
        expect(await federationTokenStore.get(sid, "google")).toBeNull();
        expect(await sessionFederationIndex.listFederations(sid)).not.toContain("google");
    });
});
