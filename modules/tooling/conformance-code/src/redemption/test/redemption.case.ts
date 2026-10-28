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
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "read"],
	redirectUris: [callback],
	firstParty: true,
};
const pub: ClientScene = {
	id: "pub",
	kind: "public",
	method: "none",
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	redirectUris: [callback],
	firstParty: true,
};

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "rd",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app, pub],
			users: [{ identifier: "alice", password: "correct horse battery" }],
			refresh: {},
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
/** A request to the token endpoint with this form and these headers, its status, Cache-Control and body. */
async function token(form: Record<string, string>, headers: Record<string, string> = {}) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(form),
	});
	const body = (await res.json()) as Record<string, string>;
	return { status: res.status, cache: res.headers.get("cache-control"), body };
}
/** A fresh code for an OpenID request by `client`, and the form that redeems it, without credentials. */
async function codeFor(client: string) {
	browser.forget();
	const res = await browser.authorize({
		response_type: "code",
		client_id: client,
		redirect_uri: callback,
		state: "s1",
		scope: "openid read",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code") ?? "";
	return {
		grant_type: "authorization_code",
		code,
		redirect_uri: callback,
		code_verifier: verifier,
	};
}
const asApp = { client_id: app.id, client_secret: app.secret ?? "" };
const basic = (id: string, secret: string) => ({
	authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`,
});
/** The ways of presenting app's credentials that do not fit what it registered. */
const unfit: [string, Record<string, string>, Record<string, string>][] = [
	["no credentials", { client_id: app.id }, {}],
	["a wrong secret", { client_id: app.id, client_secret: "wrong-secret-0123456789" }, {}],
	["another method than the one registered", {}, basic(app.id, app.secret ?? "")],
];

describe("redeeming an OpenID Connect code", () => {
	it("authenticates a confidential client by the method it registered, checking the secret sent, the code kept for it [oidc-core-3.1.3.2-a] [rfc6749-4.1.3-a] [rfc6749-4.1.3-b]", async () => {
		const form = await codeFor(app.id);
		for (const [name, credentials, headers] of unfit) {
			const answer = await token({ ...form, ...credentials }, headers);
			expect([answer.status, answer.body.error], name).toEqual([401, "invalid_client"]);
		}
		expect((await token({ ...form, ...asApp })).status).toBe(200);
	});

	it("refuses a code a client that does not authenticate redeems without naming itself by client_id [rfc6749-3.2.1-b]", async () => {
		const form = await codeFor(pub.id);
		const unnamed = await token(form);
		expect([unnamed.status, unnamed.body.error]).toEqual([401, "invalid_client"]);
		expect((await token({ ...form, client_id: pub.id })).status).toBe(200);
	});

	it("answers its tokens never to be stored [oidc-core-3.1.3.3-d]", async () => {
		const answer = await token({ ...(await codeFor(app.id)), ...asApp });
		expect([answer.status, answer.cache, typeof answer.body.id_token]).toEqual([
			200,
			"no-store",
			"string",
		]);
	});
});

describe("refreshing what an OpenID Connect code gave", () => {
	const issued = async () =>
		(await succeeded(
			await fetch(`${base}/oauth/token`, {
				method: "POST",
				headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ ...(await codeFor(app.id)), ...asApp }),
			}),
			"the token endpoint",
		)) as Record<string, string>;

	it("authenticates the client by the method it registered, the refresh token kept for it [oidc-core-12.1-a] [rfc6749-6-b]", async () => {
		const { refresh_token: refreshToken = "" } = await issued();
		const form = { grant_type: "refresh_token", refresh_token: refreshToken };
		for (const [name, credentials, headers] of unfit) {
			const answer = await token({ ...form, ...credentials }, headers);
			expect([answer.status, answer.body.error], name).toEqual([401, "invalid_client"]);
		}
		const refreshed = await token({ ...form, ...asApp });
		expect([refreshed.status, refreshed.cache]).toEqual([200, "no-store"]);
	});

	it("refuses a refresh token it did not issue, one changed, and one already spent [oidc-core-12.1-b]", async () => {
		const { refresh_token: first = "" } = await issued();
		const refresh = (refreshToken: string) =>
			token({ grant_type: "refresh_token", refresh_token: refreshToken, ...asApp });
		const [family = "", secret = ""] = first.split(".");
		const changed = `${family}.${secret.startsWith("A") ? "B" : "A"}${secret.slice(1)}`;
		expect((await refresh("not-a-refresh-token")).body.error).toBe("invalid_grant");
		const { refresh_token: second = "" } = await issued();
		expect((await refresh(second)).status).toBe(200);
		expect((await refresh(second)).body.error).toBe("invalid_grant");
		expect((await refresh(changed)).body.error).toBe("invalid_grant");
	});
});
