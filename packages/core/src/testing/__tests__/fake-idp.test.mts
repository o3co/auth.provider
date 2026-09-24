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

import { createHash } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { createFakeIdp } from "#/testing/fake-idp.mjs";

const ENDPOINTS = {
	issuer: "https://idp.test",
	authorizationEndpoint: "https://idp.test/authorize",
	tokenEndpoint: "https://tokens.idp.test/token",
	jwksUri: "https://keys.idp.test/certs",
	userinfoEndpoint: "https://api.idp.test/userinfo",
};

const post = (form: Record<string, string>): RequestInit => ({
	method: "POST",
	headers: { "content-type": "application/x-www-form-urlencoded" },
	body: new URLSearchParams(form).toString(),
});

const jwksAt = async (idp: Awaited<ReturnType<typeof createFakeIdp>>, uri: string) =>
	createLocalJWKSet(await (await idp.fetch(uri)).json());
const jwks = (idp: Awaited<ReturnType<typeof createFakeIdp>>) => jwksAt(idp, ENDPOINTS.jwksUri);

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

	describe("authorize — the user agent and the user at the authorization endpoint", () => {
		const VERIFIER = "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef";
		const CALLBACK = "https://rp.test/callback";
		const request = (extra: Record<string, string> = {}): URL => {
			const url = new URL(ENDPOINTS.authorizationEndpoint);
			url.search = new URLSearchParams({
				client_id: "client-under-test",
				redirect_uri: CALLBACK,
				state: "s-1",
				nonce: "n-1",
				code_challenge: createHash("sha256").update(VERIFIER).digest("base64url"),
				code_challenge_method: "S256",
				...extra,
			}).toString();
			return url;
		};
		const redeem = async (
			idp: Awaited<ReturnType<typeof createFakeIdp>>,
			code: string,
			form: Record<string, string> = {},
		) =>
			idp.fetch(
				ENDPOINTS.tokenEndpoint,
				post({
					grant_type: "authorization_code",
					code,
					redirect_uri: CALLBACK,
					code_verifier: VERIFIER,
					...form,
				}),
			);

		it("answers a code, the state and its issuer, and binds that code's id_token to the nonce", async () => {
			const idp = await createFakeIdp(ENDPOINTS);
			const answer = idp.authorize(request());
			expect(answer).toEqual({ code: "authorized-code-1", state: "s-1", iss: ENDPOINTS.issuer });
			// The nonce is the authorization's, not a global another one overwrites.
			expect(idp.nonce).toBeUndefined();
			const token = await (await redeem(idp, answer.code)).json();
			const { payload } = await jwtVerify(token.id_token, await jwks(idp));
			expect(payload.nonce).toBe("n-1");
		});

		it("refuses a request for another endpoint or another client", async () => {
			const idp = await createFakeIdp(ENDPOINTS);
			expect(() => idp.authorize(`${ENDPOINTS.issuer}/elsewhere`)).toThrow(
				/authorization endpoint/,
			);
			expect(() => idp.authorize(request({ client_id: "stranger" }))).toThrow(/client_id/);
			// Its own is where it was told, and a request for any other is refused.
			const elsewhere = await createFakeIdp({
				...ENDPOINTS,
				authorizationEndpoint: "https://login.idp.test/auth",
			});
			expect(() => elsewhere.authorize(request())).toThrow(/authorization endpoint/);
		});

		it("holds the exchange to the request: one use, its redirect URI, a verifier matching its challenge", async () => {
			const idp = await createFakeIdp(ENDPOINTS);
			const { code } = idp.authorize(request());
			expect((await redeem(idp, code, { code_verifier: "wrong" })).status).toBe(400);
			const second = idp.authorize(request());
			expect(
				(await redeem(idp, second.code, { redirect_uri: "https://rp.test/other" })).status,
			).toBe(400);
			const third = idp.authorize(request());
			expect((await redeem(idp, third.code)).status).toBe(200);
			// Spent: a second exchange of the same code is refused, as RFC 6749
			// §4.1.2 requires — never answered as a code the fake never issued.
			const again = await redeem(idp, third.code);
			expect(again.status).toBe(400);
			expect(await again.json()).toEqual({ error: "invalid_grant" });
		});

		it("issues a distinct code for every authorization, including after one is exchanged", async () => {
			const idp = await createFakeIdp(ENDPOINTS);
			const first = idp.authorize(request());
			expect((await redeem(idp, first.code)).status).toBe(200);
			const second = idp.authorize(request());
			expect(second.code).not.toBe(first.code);
			expect((await redeem(idp, second.code)).status).toBe(200);
		});

		it("binds each code's id_token to the nonce of the authorization it came from", async () => {
			// Two transactions in flight: A's code must not come back carrying
			// B's nonce because B was authorized last.
			const idp = await createFakeIdp(ENDPOINTS);
			const a = idp.authorize(request({ nonce: "nonce-A" }));
			const b = idp.authorize(request({ nonce: "nonce-B" }));
			const tokenA = await (await redeem(idp, a.code)).json();
			const tokenB = await (await redeem(idp, b.code)).json();
			expect((await jwtVerify(tokenA.id_token, await jwks(idp))).payload.nonce).toBe("nonce-A");
			expect((await jwtVerify(tokenB.id_token, await jwks(idp))).payload.nonce).toBe("nonce-B");
		});

		it("with refreshTokenOnlyOnConsent, issues a refresh token only for offline access on a consent screen", async () => {
			const idp = await createFakeIdp(ENDPOINTS);
			idp.refreshTokenOnlyOnConsent = true;
			const offline = { access_type: "offline" };

			const first = idp.authorize(request(offline));
			expect((await (await redeem(idp, first.code)).json()).refresh_token).toBe("rt-1");
			// The user has consented: no screen, so no refresh token.
			const returning = idp.authorize(request(offline));
			expect((await (await redeem(idp, returning.code)).json()).refresh_token).toBeUndefined();
			// A consent screen asked for again brings one.
			const prompted = idp.authorize(request({ ...offline, prompt: "consent" }));
			expect((await (await redeem(idp, prompted.code)).json()).refresh_token).toBe("rt-1");
			// Online access never does, consent or not.
			const online = idp.authorize(request({ prompt: "consent" }));
			expect((await (await redeem(idp, online.code)).json()).refresh_token).toBeUndefined();
		});
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

describe("createFakeIdp as a discoverable OpenID Provider", () => {
	const ISSUER = "https://idp.test/realms/a";
	const DISCOVERY = `${ISSUER}/.well-known/openid-configuration`;

	it("serves its metadata at the issuer's discovery URL, its endpoints under the issuer by default", async () => {
		const idp = await createFakeIdp({
			issuer: ISSUER,
			discovery: true,
			userinfoEndpoint: `${ISSUER}/userinfo`,
			endSessionEndpoint: `${ISSUER}/logout`,
		});
		const metadata = await (await idp.fetch(DISCOVERY)).json();
		expect(metadata).toMatchObject({
			issuer: ISSUER,
			authorization_endpoint: `${ISSUER}/authorize`,
			token_endpoint: `${ISSUER}/token`,
			jwks_uri: `${ISSUER}/jwks`,
			userinfo_endpoint: `${ISSUER}/userinfo`,
			end_session_endpoint: `${ISSUER}/logout`,
			id_token_signing_alg_values_supported: ["RS256"],
			code_challenge_methods_supported: ["S256"],
		});
		// The default endpoints answer.
		expect((await idp.fetch(`${ISSUER}/jwks`)).status).toBe(200);
		expect((await idp.fetch(`${ISSUER}/token`, post({}))).status).toBe(200);
	});

	it("publishes no userinfo or end-session endpoint it was not given", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER, discovery: true });
		const metadata = await (await idp.fetch(DISCOVERY)).json();
		expect("userinfo_endpoint" in metadata).toBe(false);
		expect("end_session_endpoint" in metadata).toBe(false);
	});

	it("lets a test corrupt one field of the document, or refuse it with a status", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER, discovery: true });
		idp.metadata.authorization_response_iss_parameter_supported = true;
		expect(
			(await (await idp.fetch(DISCOVERY)).json()).authorization_response_iss_parameter_supported,
		).toBe(true);
		idp.discoveryStatus = 503;
		expect((await idp.fetch(DISCOVERY)).status).toBe(503);
	});

	it("serves no discovery document unless asked to", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER });
		expect((await idp.fetch(DISCOVERY)).status).toBe(404);
	});

	it("finds requests by a path under the issuer, and names the last token request", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER, discovery: true });
		await idp.fetch(DISCOVERY);
		await idp.fetch(`${ISSUER}/token`, post({ code: "c-1" }));
		await idp.fetch(`${ISSUER}/token`, post({ code: "c-2" }));
		expect(idp.requestsTo("/.well-known/openid-configuration")).toHaveLength(1);
		expect(idp.requestsTo("/token")).toHaveLength(2);
		expect(idp.lastTokenRequest()?.body?.get("code")).toBe("c-2");
	});

	it("routes a host spelled with the DNS root dot to itself", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER, discovery: true });
		const dotted = await idp.fetch("https://idp.test./realms/a/token", post({}));
		expect(dotted.status).toBe(200);
		expect(idp.requestsTo("/token")).toHaveLength(1);
	});

	it("answers a refusal with the body a test gives it", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER });
		idp.tokenStatus = 400;
		idp.refusal = { error: "invalid_grant", error_description: "revoked" };
		const refused = await idp.fetch(`${ISSUER}/token`, post({}));
		expect(refused.status).toBe(400);
		expect(await refused.json()).toEqual({ error: "invalid_grant", error_description: "revoked" });
	});

	it("puts an at_hash in the code exchange's id_token that is right, or wrong, when told to", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER });
		const atHash = async () => {
			const answer = await (await idp.fetch(`${ISSUER}/token`, post({}))).json();
			return (await jwtVerify(answer.id_token, await jwksAt(idp, `${ISSUER}/jwks`))).payload
				.at_hash;
		};
		expect(await atHash()).toBeUndefined();
		idp.atHash = "valid";
		const left = createHash("sha256").update(idp.accessToken).digest().subarray(0, 16);
		expect(await atHash()).toBe(left.toString("base64url"));
		idp.atHash = "wrong";
		expect(await atHash()).not.toBe(left.toString("base64url"));
	});

	it("leaves the id_token out of a refresh unless refreshWithIdToken is on", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER });
		idp.refreshWithIdToken = false;
		const plain = await (
			await idp.fetch(`${ISSUER}/token`, post({ grant_type: "refresh_token" }))
		).json();
		expect(plain.id_token).toBeUndefined();
	});

	it("delays its JWKS by the given milliseconds", async () => {
		const idp = await createFakeIdp({ issuer: ISSUER });
		idp.jwksDelayMs = 150;
		const started = Date.now();
		await idp.fetch(`${ISSUER}/jwks`);
		expect(Date.now() - started).toBeGreaterThanOrEqual(140);
	});
});
