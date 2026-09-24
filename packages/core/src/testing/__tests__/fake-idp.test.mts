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
 * The fake OpenID Provider the adapters' tests run the real library against
 * is held to what it promises them: keys it publishes and signs with, token
 * answers an OAuth client can parse, and one knob changing one thing. An
 * adapter test that passes against a fake laxer than its IdP proves nothing
 * about the IdP.
 */

import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { createFakeIdp } from "../fake-idp.mjs";

const ENDPOINTS = {
	issuer: "https://idp.test",
	tokenEndpoint: "https://tokens.idp.test/token",
	jwksUri: "https://keys.idp.test/certs",
	userinfoEndpoint: "https://api.idp.test/userinfo",
};

const post = (form: Record<string, string>): RequestInit => ({
	method: "POST",
	headers: { "content-type": "application/x-www-form-urlencoded" },
	body: new URLSearchParams(form).toString(),
});

const jwks = async (idp: Awaited<ReturnType<typeof createFakeIdp>>) =>
	createLocalJWKSet(await (await idp.fetch(ENDPOINTS.jwksUri)).json());

describe("createFakeIdp", () => {
	it("answers a code with tokens whose id_token verifies against the published JWKS", async () => {
		const idp = await createFakeIdp({ ...ENDPOINTS, clientId: "client-1", sub: "user-1" });
		idp.nonce = "n-1";
		const answer = await (
			await idp.fetch(ENDPOINTS.tokenEndpoint, post({ grant_type: "authorization_code" }))
		).json();
		expect(answer).toMatchObject({
			access_token: "at-1",
			token_type: "Bearer",
			expires_in: 3600,
			refresh_token: "rt-1",
		});
		const { payload } = await jwtVerify(answer.id_token, await jwks(idp), {
			issuer: ENDPOINTS.issuer,
			audience: "client-1",
		});
		expect(payload).toMatchObject({ sub: "user-1", nonce: "n-1" });
	});

	it("answers a refresh with rotated tokens and an id_token without a nonce", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.nonce = "n-1";
		const answer = await (
			await idp.fetch(ENDPOINTS.tokenEndpoint, post({ grant_type: "refresh_token" }))
		).json();
		expect(answer).toMatchObject({ access_token: "at-refreshed", refresh_token: "rt-2" });
		const { payload } = await jwtVerify(answer.id_token, await jwks(idp));
		expect(payload.nonce).toBeUndefined();
	});

	it("answers UserInfo for its subject, with the claims a test lays over it", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.userinfoClaims = { hd: "example.test" };
		const info = await (await idp.fetch(ENDPOINTS.userinfoEndpoint)).json();
		expect(info).toMatchObject({ sub: idp.sub, email: "alice@example.test", hd: "example.test" });
	});

	it("publishes no UserInfo when none is configured, and 404s what it does not serve", async () => {
		const idp = await createFakeIdp({ ...ENDPOINTS, userinfoEndpoint: undefined });
		expect((await idp.fetch(ENDPOINTS.userinfoEndpoint)).status).toBe(404);
		expect((await idp.fetch(`${ENDPOINTS.issuer}/elsewhere`)).status).toBe(404);
	});

	it("refuses at the token endpoint with the configured status", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.tokenStatus = 401;
		const refused = await idp.fetch(ENDPOINTS.tokenEndpoint, post({}));
		expect(refused.status).toBe(401);
		expect(await refused.json()).toEqual({ error: "invalid_client" });
	});

	it("lays codeAnswer and refreshAnswer over their answers, removing what they set to undefined", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.codeAnswer = { expires_in: undefined, scope: "openid email" };
		idp.refreshAnswer = { refresh_token: undefined, token_type: "DPoP" };
		const code = await (await idp.fetch(ENDPOINTS.tokenEndpoint, post({}))).json();
		expect("expires_in" in code).toBe(false);
		expect(code.scope).toBe("openid email");
		const refresh = await (
			await idp.fetch(ENDPOINTS.tokenEndpoint, post({ grant_type: "refresh_token" }))
		).json();
		expect("refresh_token" in refresh).toBe(false);
		expect(refresh.token_type).toBe("DPoP");
		expect(refresh.expires_in).toBe(1800);
	});

	it("leaves the id_token out when told to", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.omitIdToken = true;
		const answer = await (await idp.fetch(ENDPOINTS.tokenEndpoint, post({}))).json();
		expect(answer.id_token).toBeUndefined();
	});

	it("signs under an unpublished key or a claimed kid only when told to", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		idp.signWithUnpublishedKey = true;
		const forged = (await (await idp.fetch(ENDPOINTS.tokenEndpoint, post({}))).json()).id_token;
		await expect(jwtVerify(forged, await jwks(idp))).rejects.toThrow();

		idp.signWithUnpublishedKey = false;
		idp.signingKid = "kid-ghost";
		const ghost = (await (await idp.fetch(ENDPOINTS.tokenEndpoint, post({}))).json()).id_token;
		expect(decodeProtectedHeader(ghost).kid).toBe("kid-ghost");
	});

	it("rotates its signing key: the JWKS then holds only the new one", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		expect(idp.currentKid()).toBe("kid-1");
		expect(await idp.rotateKey()).toBe("kid-2");
		const published = await (await idp.fetch(ENDPOINTS.jwksUri)).json();
		expect(published.keys.map((k: { kid: string }) => k.kid)).toEqual(["kid-2"]);
	});

	it("records every request, and finds them by endpoint whatever the query string", async () => {
		const idp = await createFakeIdp(ENDPOINTS);
		await idp.fetch(`${ENDPOINTS.jwksUri}?cache=bust`);
		await idp.fetch(new Request(ENDPOINTS.tokenEndpoint, post({ code: "c-1" })));
		expect(idp.requests).toHaveLength(2);
		expect(idp.requestsTo(ENDPOINTS.jwksUri)).toHaveLength(1);
		const [token] = idp.requestsTo(ENDPOINTS.tokenEndpoint);
		expect(token?.method).toBe("POST");
	});
});
