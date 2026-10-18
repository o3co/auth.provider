import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { ledgerRevocation } from "@mod/conformance-identity";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const api = "https://api.example";
const credential = randomBytes(32).toString("base64url");
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
	defaultScopes: ["read"],
	redirectUris: [callback],
	firstParty: true,
	audiences: [api],
};
const bff: ClientScene = {
	id: "bff",
	kind: "confidential",
	method: "client_secret_post",
	secret: "bff-secret-0123456789abcdef",
	grants: ["session"],
	scopes: ["read"],
	defaultScopes: [],
	audiences: [api],
};
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "revoked",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [app, bff],
	users: [
		{ identifier: "alice", password: "correct horse battery", subject: "user-alice" },
		{ identifier: "bob", password: "battery staple horse", subject: "user-bob" },
	],
	refresh: {},
	sessionGrant: true,
	introspection: true,
	revocations: { credential, sources: ["198.51.100.0/24"] },
};

let running: Started;
let base = "";

const browserOf = (username: string, password: string) =>
	browserAt(() => base, issuer, { username, password });
async function post(path: string, as: ClientScene, form: Record<string, string>, cookie = "") {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			...(cookie ? { cookie, origin: issuer, "x-forwarded-host": new URL(issuer).host } : {}),
		},
		body: new URLSearchParams({ ...form, client_id: as.id, client_secret: as.secret ?? "" }),
	});
	const text = await res.text();
	return { status: res.status, body: (text ? JSON.parse(text) : {}) as Record<string, string> };
}
/** What a user's login holds: its cookie, the app's tokens from a code, and a session grant's token. */
async function signedIn(browser: ReturnType<typeof browserOf>) {
	const cookie = await browser.login();
	const asked = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid read",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = asked.at?.searchParams.get("code") ?? "";
	const { body: tokens } = await post("/oauth/token", app, {
		grant_type: "authorization_code",
		code,
		redirect_uri: callback,
		code_verifier: verifier,
	});
	const granted = await post("/oauth/token", bff, { grant_type: "session", scope: "read" }, cookie);
	return { cookie, tokens, sessionToken: granted.body.access_token ?? "" };
}
const active = async (token: string) =>
	(await post("/oauth/introspect", app, { token })).body.active;
/** The ledger's revocation of a subject, from its block over https, as its proxy forwards it. */
async function revoke(subject: string) {
	const res = await fetch(`${base}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject }),
	});
	return res.status;
}
/** Whether the session still lets its user in: a silent authorization answers a code or login_required. */
async function letsIn(browser: ReturnType<typeof browserOf>) {
	const asked = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s2",
		scope: "openid read",
		prompt: "none",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	return asked.at?.searchParams.get("code") ? "code" : asked.at?.searchParams.get("error");
}

describe.runIf(areaTarget().can(ledgerRevocation))("a subject the ledger revokes over HTTP", () => {
	beforeAll(async () => {
		running = await areaTarget().start(codeScene(fields));
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});

	it("ends the subject's session, its refresh tokens and its access tokens, and no other user's", async () => {
		const alice = browserOf("alice", "correct horse battery");
		const bob = browserOf("bob", "battery staple horse");
		const hers = await signedIn(alice);
		const his = await signedIn(bob);
		expect(await active(hers.tokens.access_token ?? "")).toBe(true);
		expect(await active(hers.sessionToken)).toBe(true);
		expect(await revoke("user-alice")).toBe(200);
		expect(await letsIn(alice)).toBe("login_required");
		const refreshed = await post("/oauth/token", app, {
			grant_type: "refresh_token",
			refresh_token: hers.tokens.refresh_token ?? "",
		});
		expect([refreshed.status, refreshed.body.error]).toEqual([400, "invalid_grant"]);
		expect(await active(hers.tokens.access_token ?? "")).toBe(false);
		expect(await active(hers.sessionToken)).toBe(false);
		const granted = await post(
			"/oauth/token",
			bff,
			{ grant_type: "session", scope: "read" },
			hers.cookie,
		);
		expect([granted.status, granted.body.error]).toEqual([401, "unauthorized"]);
		expect(await letsIn(bob)).toBe("code");
		expect(await active(his.tokens.access_token ?? "")).toBe(true);
		expect(await active(his.sessionToken)).toBe(true);
	});
});
