import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene } from "../src/main.ts";
import { type Browser, browser as openBrowser } from "./browser.ts";
import { type Authorized, fakeUpstream } from "./upstream.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const callback = "https://app.example/cb";
const back = "https://app.example/after-logout";
const verifier = "w".repeat(43);
const pair = generateKeyPairSync("ed25519");
const upstreamClient = { id: "as-client", secret: "as-client-secret-0123456789" };
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const client = (id: string, receives: boolean): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	// Its own tokens name it, as a receiver's must.
	audiences: [id],
	redirectUris: [callback],
	firstParty: true,
	...(receives ? { upstreamTokens: { postLogoutRedirectUris: [back] } } : {}),
});

let corp: Awaited<ReturnType<typeof fakeUpstream>>;
let plain: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
beforeAll(async () => {
	corp = await fakeUpstream(upstreamClient, { endSession: true });
	plain = await fakeUpstream(upstreamClient);
	const idp = (name: string, issuer: string) => ({
		name,
		issuer,
		clientId: upstreamClient.id,
		clientSecret: upstreamClient.secret,
	});
	const scene = federationScene({
		origin,
		keys: {
			signing: {
				kid: "fed",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps: [idp("corp", corp.issuer), idp("plain", plain.issuer)],
		landing,
		returnTargets: [],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
			{
				identifier: "bob",
				password: "correct horse battery",
				upstream: { idp: "plain", subject: "u-bob" },
			},
		],
		clients: [client("fed-app", true), client("other-app", false)],
		keepsUpstreamTokens: true,
		userinfo: true,
	});
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await corp?.stop();
	await plain?.stop();
});

const headers = { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.40" };
async function post(path: string, form: Record<string, string>, more: Record<string, string> = {}) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		redirect: "manual",
		headers: { ...headers, "content-type": "application/x-www-form-urlencoded", ...more },
		body: new URLSearchParams(form),
	});
	const text = await res.text();
	return {
		status: res.status,
		location: res.headers.get("location") ?? "",
		retryAfter: res.headers.get("retry-after"),
		body: (text.startsWith("{") ? JSON.parse(text) : {}) as Record<string, unknown>,
	};
}

/** A browser logged in through `idp` as the user its subject names, with what the upstream hands over. */
async function loggedIn(
	idp: "corp" | "plain" = "corp",
	tokens: Authorized["tokens"] = {},
): Promise<Browser> {
	const b = openBrowser(() => base, origin);
	const upstream = idp === "corp" ? corp : plain;
	const started = await b.get(`/session/oauth/federation/${idp}`);
	const query = upstream.authorize(started.location, {
		subject: idp === "corp" ? "u-alice" : "u-bob",
		tokens,
	});
	const done = await b.get(`/session/oauth/federation/${idp}/callback?${query}`);
	expect([done.status, done.location]).toEqual([302, landing]);
	return b;
}

/** The access and refresh tokens a client gets by the code flow in the browser's session. */
async function clientTokens(b: Browser, as = "fed-app") {
	const asked = new URLSearchParams({
		response_type: "code",
		client_id: as,
		redirect_uri: callback,
		scope: "openid read",
		state: "s",
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
		code_challenge_method: "S256",
	});
	const answered = await b.get(`/oauth/authorize?${asked}`);
	const code = new URL(answered.location).searchParams.get("code") ?? "";
	const redeemed = await post("/oauth/token", {
		grant_type: "authorization_code",
		code,
		redirect_uri: callback,
		code_verifier: verifier,
		client_id: as,
		client_secret: secretOf(as),
	});
	expect(redeemed.status).toBe(200);
	return redeemed.body as { access_token: string; refresh_token: string };
}

/** Userinfo's answer to `token` as a Bearer token. */
async function userinfo(token: string) {
	const res = await fetch(`${base}/oauth/userinfo`, {
		headers: { ...headers, authorization: `Bearer ${token}` },
	});
	await res.text();
	return { status: res.status, challenge: res.headers.get("www-authenticate") ?? "" };
}

const upstreamToken = (access: string, idp = "corp") =>
	post(`/oauth/federation/${idp}/token`, {}, { authorization: `Bearer ${access}` });
const upstreamLogout = (access: string, form: Record<string, string> = {}, idp = "corp") =>
	post(`/oauth/federation/${idp}/logout`, form, { authorization: `Bearer ${access}` });

describe("federation tokens: handing over", () => {
	it("hands a receiving client the upstream access token of the session it was issued in", async () => {
		const b = await loggedIn("corp", { accessToken: "up-handed", scope: "openid email" });
		const mine = await clientTokens(b);
		const got = await upstreamToken(mine.access_token);
		expect(got.status).toBe(200);
		expect(got.body).toMatchObject({
			access_token: "up-handed",
			token_type: "Bearer",
			scope: "openid email",
		});
		expect(got.body.expires_in).toBeGreaterThan(290);
	});

	it("refreshes a token at its end, handing the new one with the scope the login gave", async () => {
		const b = await loggedIn("corp", { expiresIn: 0, scope: "openid email" });
		const got = await upstreamToken((await clientTokens(b)).access_token);
		expect(got.status).toBe(200);
		expect(got.body.access_token).toMatch(/^upstream-access-/);
		expect(got.body).toMatchObject({ scope: "openid email", expires_in: expect.any(Number) });
	});

	it("comes back to the scope the login gave after a refresh that narrowed it", async () => {
		const b = await loggedIn("corp", { expiresIn: 0, scope: "openid email" });
		const mine = await clientTokens(b);
		corp.answerRefresh({
			json: {
				access_token: "up-narrow",
				token_type: "Bearer",
				expires_in: 2,
				scope: "openid",
				refresh_token: "upstream-refresh-narrowed",
			},
		});
		expect((await upstreamToken(mine.access_token)).body).toMatchObject({
			access_token: "up-narrow",
			scope: "openid",
		});
		// Past half its short life, it is renewed again.
		await new Promise((resolve) => setTimeout(resolve, 1100));
		corp.answerRefresh({
			json: { access_token: "up-wide", token_type: "Bearer", expires_in: 300 },
		});
		expect((await upstreamToken(mine.access_token)).body).toMatchObject({
			access_token: "up-wide",
			scope: "openid email",
		});
	});

	it("cuts an end far off at the longest lifetime, and refuses a refresh that says it already ended", async () => {
		const b = await loggedIn("corp", { expiresIn: 0 });
		const mine = await clientTokens(b);
		corp.answerRefresh({
			json: { access_token: "up-far", token_type: "Bearer", expires_in: 1_000_000_000 },
		});
		const far = await upstreamToken(mine.access_token);
		expect(far.body.access_token).toBe("up-far");
		expect(far.body.expires_in).toBeLessThanOrEqual(86_400);
		expect(far.body.expires_in).toBeGreaterThan(86_000);

		const ended = await clientTokens(await loggedIn("corp", { expiresIn: 0 }));
		corp.answerRefresh({ json: { access_token: "up-zero", token_type: "Bearer", expires_in: 0 } });
		expect(await upstreamToken(ended.access_token)).toMatchObject({
			status: 500,
			body: { error: "refresh_failed" },
		});
	});
});

describe("federation tokens: refusals", () => {
	it("refuses a client the operator did not make a receiver", async () => {
		const b = await loggedIn();
		const got = await upstreamToken((await clientTokens(b, "other-app")).access_token);
		expect(got).toMatchObject({ status: 403, body: { error: "forbidden" } });
	});

	it("answers not linked for an IdP the session did not log in through", async () => {
		const b = await loggedIn();
		const got = await upstreamToken((await clientTokens(b)).access_token, "plain");
		expect(got).toMatchObject({ status: 404, body: { error: "federation_not_linked" } });
	});

	it("refuses a token whose refresh family ended, here and at userinfo alike [oidc-core-5.3-b] [rfc6750-2.1-a] [rfc6750-3-a] [rfc6750-3-f] [rfc6750-3.1-b]", async () => {
		const b = await loggedIn();
		const mine = await clientTokens(b);
		const refresh = (token: string) =>
			post("/oauth/token", {
				grant_type: "refresh_token",
				refresh_token: token,
				client_id: "fed-app",
				client_secret: secretOf("fed-app"),
			});
		const next = (await refresh(mine.refresh_token)).body as { access_token: string };
		expect((await userinfo(next.access_token)).status).toBe(200);
		expect((await upstreamToken(next.access_token)).status).toBe(200);
		// The spent refresh token again: the family ends, with every token it issued.
		await refresh(mine.refresh_token);
		expect(await upstreamToken(next.access_token)).toMatchObject({
			status: 401,
			body: { error: "invalid_token" },
		});
		const told = await userinfo(next.access_token);
		expect([told.status, told.challenge]).toEqual([
			401,
			expect.stringMatching(/error="invalid_token"/),
		]);
	});

	it("refuses a token once its session logged out", async () => {
		const b = await loggedIn();
		const mine = await clientTokens(b);
		const out = await fetch(`${base}/session/logout`, {
			method: "POST",
			headers: {
				...headers,
				origin,
				"x-forwarded-host": new URL(origin).host,
				"content-type": "application/x-www-form-urlencoded",
				cookie: b.cookies(),
			},
		});
		expect(out.status).toBeLessThan(400);
		expect((await upstreamToken(mine.access_token)).status).toBe(401);
	});

	it("hands no token that is not a bearer, and keeps it", async () => {
		const b = await loggedIn("corp", { tokenType: "DPoP" });
		const mine = await clientTokens(b);
		for (const _ of [1, 2]) {
			const got = await upstreamToken(mine.access_token);
			expect([got.status, got.body.error, got.retryAfter]).toEqual([
				502,
				"upstream_token_ineligible",
				"300",
			]);
		}
	});

	it("forgets the tokens when the upstream refuses the refresh token", async () => {
		const b = await loggedIn("corp", { expiresIn: 0 });
		const mine = await clientTokens(b);
		corp.answerRefresh({ status: 400, json: { error: "invalid_grant" } });
		expect(await upstreamToken(mine.access_token)).toMatchObject({
			status: 410,
			body: { error: "re_authentication_required" },
		});
		expect((await upstreamToken(mine.access_token)).status).toBe(404);
	});

	it("keeps the tokens while the upstream is down or limits, and hands them once it answers", async () => {
		const b = await loggedIn("corp", { expiresIn: 0 });
		const mine = await clientTokens(b);
		corp.answerRefresh({ status: 503, json: { error: "temporarily_unavailable" } });
		expect(await upstreamToken(mine.access_token)).toMatchObject({
			status: 503,
			body: { error: "temporarily_unavailable" },
		});
		corp.answerRefresh({
			status: 429,
			headers: { "retry-after": "7" },
			json: { error: "too_many_requests" },
		});
		const limited = await upstreamToken(mine.access_token);
		expect([limited.status, limited.body.error, limited.retryAfter]).toEqual([
			429,
			"rate_limited",
			"7",
		]);
		expect((await upstreamToken(mine.access_token)).status).toBe(200);
	});
});

describe("federation tokens: upstream logout", () => {
	it("sends the browser to the upstream's end of session with its hint and the registered return [oidc-rpinit-2-l] [oidc-rpinit-2-m]", async () => {
		const b = await loggedIn();
		const mine = await clientTokens(b);
		const out = await upstreamLogout(mine.access_token, {
			post_logout_redirect_uri: back,
			state: "st-1",
		});
		expect(out.status).toBe(303);
		const to = new URL(out.location);
		expect(`${to.origin}${to.pathname}`).toBe(`${corp.issuer}/logout`);
		expect(to.searchParams.get("id_token_hint")).toBe(corp.idTokens.at(-1));
		expect(to.searchParams.get("post_logout_redirect_uri")).toBe(back);
		expect(to.searchParams.get("state")).toBe("st-1");
		expect(await upstreamToken(mine.access_token)).toMatchObject({
			status: 404,
			body: { error: "federation_not_linked" },
		});
	});

	it("drops a return the client did not register", async () => {
		const mine = await clientTokens(await loggedIn());
		const out = await upstreamLogout(mine.access_token, {
			post_logout_redirect_uri: "https://elsewhere.example/",
		});
		expect(out.status).toBe(303);
		expect(new URL(out.location).searchParams.has("post_logout_redirect_uri")).toBe(false);
	});

	it("answers disconnected for an upstream without an end of session", async () => {
		const mine = await clientTokens(await loggedIn("plain"));
		expect(await upstreamLogout(mine.access_token, {}, "plain")).toMatchObject({
			status: 200,
			body: { disconnected: true },
		});
		expect((await upstreamToken(mine.access_token, "plain")).status).toBe(404);
	});

	it("answers not linked for an IdP the session did not log in through", async () => {
		const mine = await clientTokens(await loggedIn());
		expect(await upstreamLogout(mine.access_token, {}, "plain")).toMatchObject({
			status: 404,
			body: { error: "federation_not_linked" },
		});
	});
});
