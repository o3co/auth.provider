import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt, succeeded } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const user = { username: "alice", password: "correct horse battery" };
/** A user whose email holds a character outside ASCII. */
const wide = { username: "zoe", password: "correct horse battery" };
/** The one origin whose pages may read userinfo across origins. */
const page = "https://app.example";
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "profile", "email"],
	redirectUris: [callback],
	firstParty: true,
};

let running: Started;
let base = "";
const browser = browserAt(() => base, issuer, user);
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "ui",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app],
			users: [
				{ ...user, identifier: user.username, subject: "s-alice", email: "alice@example.com" },
				{ ...wide, identifier: wide.username, subject: "s-zoe", email: "zo\u00eb@example.com" },
			],
			discovery: true,
			revocation: true,
			refresh: {},
			userinfo: true,
			corsOrigins: [page],
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const sent = (path: string, as: string, form: Record<string, string>) =>
	fetch(`${base}${path}`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: as, client_secret: app.secret ?? "" }),
	});
async function post(path: string, as: string, form: Record<string, string>) {
	const text = await (await sent(path, as, form)).text();
	return (text ? JSON.parse(text) : {}) as Record<string, string>;
}
/** A fresh login's tokens for `scope`, by the code flow. */
async function codeTokens(scope: string, as = browser) {
	as.forget();
	const res = await as.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope,
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const answer = await sent("/oauth/token", app.id, {
		grant_type: "authorization_code",
		code: res.at?.searchParams.get("code") ?? "",
		redirect_uri: callback,
		code_verifier: verifier,
	});
	return (await succeeded(answer, "the token endpoint")) as Record<string, string>;
}
/** Userinfo's answer to `token` as a Bearer token, or to no token at all. */
async function userinfo(token?: string, method = "GET") {
	const res = await fetch(`${base}/oauth/userinfo`, {
		method,
		headers: { ...backChannel, ...(token ? { authorization: `Bearer ${token}` } : {}) },
	});
	const text = await res.text();
	return {
		status: res.status,
		challenge: res.headers.get("www-authenticate") ?? "",
		cache: res.headers.get("cache-control"),
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
	};
}

describe("OpenID Connect userinfo", () => {
	it("answers sub and the claims of the token's scope, by GET and by POST, never stored [oidc-core-5.3-a] [oidc-core-5.3-b] [oidc-core-5.3.2-a] [oidc-core-5.3.2-b] [oidc-core-5.3.2-d] [rfc6750-2.1-a]", async () => {
		const { access_token: token } = await codeTokens("openid email");
		for (const method of ["GET", "POST"]) {
			const answer = await userinfo(token, method);
			expect([method, answer.status, answer.cache]).toEqual([method, 200, "no-store"]);
			expect(answer.body).toMatchObject({ sub: "s-alice", email: "alice@example.com" });
			expect(answer.body).not.toHaveProperty("sid");
		}
		const narrow = await userinfo((await codeTokens("openid")).access_token);
		expect(narrow.body).toEqual({ sub: "s-alice" });
	});

	it("answers its JSON as application/json in UTF-8, a character outside ASCII intact [oidc-core-5.3.2-e] [oidc-core-5.3.2-f] [oidc-core-5.3.2-g] [oidc-core-5.3.2-h]", async () => {
		const { access_token: token } = await codeTokens(
			"openid email",
			browserAt(() => base, issuer, wide),
		);
		const res = await fetch(`${base}/oauth/userinfo`, {
			headers: { ...backChannel, authorization: `Bearer ${token}` },
		});
		expect(res.headers.get("content-type")).toMatch(/^application\/json(;\s*charset=utf-8)?$/i);
		const bytes = Buffer.from(await res.arrayBuffer());
		expect(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))).toEqual({
			sub: "s-zoe",
			email: "zo\u00eb@example.com",
		});
		expect(bytes.includes(Buffer.from("zo\u00eb", "utf8"))).toBe(true);
	});

	it("answers a token a refresh issued with its session's claims, and refuses it once the session has ended", async () => {
		const issued = await codeTokens("openid email");
		const refreshed = await post("/oauth/token", app.id, {
			grant_type: "refresh_token",
			refresh_token: issued.refresh_token ?? "",
		});
		const answer = await userinfo(refreshed.access_token);
		expect([answer.status, answer.body]).toEqual([
			200,
			expect.objectContaining({ sub: "s-alice", email: "alice@example.com" }),
		]);
		await browser.logout();
		expect((await userinfo(refreshed.access_token)).status).toBe(401);
	});

	it("refuses every access token of a refresh family once a spent refresh token comes again [rfc6750-3-a] [rfc6750-3-f] [rfc6750-3.1-b]", async () => {
		const issued = await codeTokens("openid email");
		const refreshed = await post("/oauth/token", app.id, {
			grant_type: "refresh_token",
			refresh_token: issued.refresh_token ?? "",
		});
		expect((await userinfo(refreshed.access_token)).status).toBe(200);
		// The first refresh token, spent by the rotation, comes again: the family ends.
		const reused = await post("/oauth/token", app.id, {
			grant_type: "refresh_token",
			refresh_token: issued.refresh_token ?? "",
		});
		expect(reused.error).toBe("invalid_grant");
		for (const token of [issued.access_token, refreshed.access_token]) {
			const answer = await userinfo(token);
			expect([answer.status, answer.challenge]).toEqual([
				401,
				expect.stringMatching(/error="invalid_token"/),
			]);
		}
	});

	it("refuses a token once its session has ended, and once it is revoked [rfc6750-3-a] [rfc6750-3-f] [rfc6750-3.1-b] [rfc7009-2-b]", async () => {
		const { access_token: ended } = await codeTokens("openid email");
		expect((await userinfo(ended)).status).toBe(200);
		await browser.logout();
		const afterLogout = await userinfo(ended);
		expect([afterLogout.status, afterLogout.challenge]).toEqual([
			401,
			expect.stringMatching(/error="invalid_token"/),
		]);
		const { access_token: revoked } = await codeTokens("openid");
		await post("/oauth/revoke", app.id, { token: revoked ?? "" });
		expect((await userinfo(revoked)).status).toBe(401);
	});

	it("refuses a refresh token and an ID token presented as an access token [rfc6750-3-a] [rfc6750-3-f] [rfc6750-3.1-b]", async () => {
		const issued = await codeTokens("openid email");
		for (const token of [issued.refresh_token, issued.id_token]) {
			const answer = await userinfo(token);
			expect([answer.status, answer.body]).toEqual([
				401,
				expect.not.objectContaining({ sub: expect.anything() }),
			]);
			expect(answer.challenge).toMatch(/error="invalid_token"/);
		}
	});

	it("challenges a request with no token, or a scheme with no token, without naming an error (RFC 6750 §3.1) [rfc6750-3-a] [rfc6750-3-b] [rfc6750-3.1-d] [rfc9449-7.2-b]", async () => {
		const empty = await fetch(`${base}/oauth/userinfo`, {
			headers: { ...backChannel, authorization: "Bearer" },
		});
		for (const answer of [
			await userinfo(),
			{ status: empty.status, challenge: empty.headers.get("www-authenticate") ?? "" },
		]) {
			expect(answer.status).toBe(401);
			expect(answer.challenge).toMatch(/^Bearer/);
			expect(answer.challenge).not.toMatch(/error=/);
		}
	});

	it("reads the token from the Authorization header only, never from the body or the query [rfc6750-3.1-d]", async () => {
		const { access_token: token = "" } = await codeTokens("openid email");
		const inBody = await fetch(`${base}/oauth/userinfo`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ access_token: token }),
		});
		const inQuery = await fetch(
			`${base}/oauth/userinfo?access_token=${encodeURIComponent(token)}`,
			{
				headers: backChannel,
			},
		);
		for (const res of [inBody, inQuery]) {
			expect(res.status).toBe(401);
			expect(res.headers.get("www-authenticate") ?? "").not.toMatch(/error=/);
		}
	});

	it("names itself in the metadata document [oidc-discovery-3-h]", async () => {
		const res = await fetch(`${base}/.well-known/openid-configuration`, { headers: backChannel });
		const doc = (await res.json()) as Record<string, unknown>;
		expect(doc.userinfo_endpoint).toBe(`${issuer}/oauth/userinfo`);
	});

	it("lets only a listed origin's page send its token and DPoP proof, and read the challenge, the nonce and the wait [oidc-core-5.3-c] [oidc-discovery-3-aj]", async () => {
		const asked = (origin: string, method = "GET", extra: Record<string, string> = {}) =>
			fetch(`${base}/oauth/userinfo`, { method, headers: { ...backChannel, origin, ...extra } });
		const preflight = await asked(page, "OPTIONS", {
			"access-control-request-method": "GET",
			"access-control-request-headers": "authorization, dpop",
		});
		expect(preflight.headers.get("access-control-allow-origin")).toBe(page);
		const allowed = (preflight.headers.get("access-control-allow-headers") ?? "").toLowerCase();
		expect(allowed).toContain("authorization");
		expect(allowed).toContain("dpop");
		const read = await asked(page);
		expect(read.headers.get("access-control-allow-origin")).toBe(page);
		expect(read.headers.get("access-control-allow-credentials")).toBeNull();
		const exposed = (read.headers.get("access-control-expose-headers") ?? "").toLowerCase();
		for (const name of ["www-authenticate", "dpop-nonce", "retry-after"])
			expect(exposed).toContain(name);
		const other = await asked("https://elsewhere.example");
		expect(other.headers.get("access-control-allow-origin")).toBeNull();
		expect((other.headers.get("vary") ?? "").toLowerCase()).toContain("origin");
	});

	it("allows a listed origin's preflight for a POST with both of userinfo's methods, and gives an unlisted origin's preflight no allowance [oidc-core-5.3-c] [oidc-discovery-3-aj]", async () => {
		const preflight = (origin: string) =>
			fetch(`${base}/oauth/userinfo`, {
				method: "OPTIONS",
				headers: {
					...backChannel,
					origin,
					"access-control-request-method": "POST",
					"access-control-request-headers": "authorization, content-type",
				},
			});
		const listed = await preflight(page);
		expect([listed.status, listed.headers.get("access-control-allow-origin")]).toEqual([204, page]);
		const methods = (listed.headers.get("access-control-allow-methods") ?? "").split(/\s*,\s*/);
		expect(methods.sort()).toEqual(["GET", "POST"]);
		expect((listed.headers.get("access-control-allow-headers") ?? "").toLowerCase()).toContain(
			"content-type",
		);
		expect(listed.headers.get("access-control-allow-credentials")).toBeNull();
		const unlisted = await preflight("https://elsewhere.example");
		expect(unlisted.status).toBe(204);
		for (const name of [
			"access-control-allow-origin",
			"access-control-allow-methods",
			"access-control-allow-headers",
		])
			expect(unlisted.headers.get(name)).toBeNull();
		const posted = (origin: string) =>
			fetch(`${base}/oauth/userinfo`, { method: "POST", headers: { ...backChannel, origin } });
		expect((await posted(page)).headers.get("access-control-allow-origin")).toBe(page);
		expect(
			(await posted("https://elsewhere.example")).headers.get("access-control-allow-origin"),
		).toBeNull();
	});
});
