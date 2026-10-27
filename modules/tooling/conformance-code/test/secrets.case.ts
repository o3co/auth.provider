import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { backChannel, browserAt, succeeded } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const privatePem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const client = (id: string): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "email"],
	redirectUris: [callback],
	firstParty: true,
});
const app = client("app");
const other = client("other");
// Secrets of letters, digits and dashes alone, which no URL or HTML escaping changes.
const alice = { username: "alice", password: "alice-horse-battery-staple-4f1c" };
const bob = { username: "bob", password: "bob-battery-staple-horse-9d2e" };

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "sk",
					alg: "EdDSA",
					privatePem,
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app, other],
			users: [
				{
					identifier: alice.username,
					password: alice.password,
					email: "alice@example.com",
					emailVerified: true,
				},
				{
					identifier: bob.username,
					password: bob.password,
					email: "bob@example.com",
					emailVerified: true,
				},
			],
			discovery: true,
			refresh: {},
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const request = (as: ClientScene, extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: as.id,
	redirect_uri: callback,
	state: "s1",
	scope: "openid email",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});
/** An answer whole, its status, headers and body, as text a secret could be found in. */
async function whole(res: Response) {
	const headers = [...res.headers].map(([name, value]) => `${name}: ${value}`).join("\n");
	return { status: res.status, text: `${headers}\n${await res.text()}` };
}
const token = (as: ClientScene, form: Record<string, string>, secret = as.secret ?? "") =>
	fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: as.id, client_secret: secret }),
	});
/** A login's code, and the tokens it is redeemed for, for `as`. */
async function issued(user: typeof alice, as: ClientScene) {
	const browser = browserAt(() => base, issuer, user);
	const code = (await browser.authorize(request(as))).at?.searchParams.get("code") ?? "";
	const form = { grant_type: "authorization_code", code, redirect_uri: callback };
	const tokens = await succeeded(
		await token(as, { ...form, code_verifier: verifier }),
		"the token endpoint",
	);
	return { browser, code, tokens: tokens as Record<string, string> };
}

describe("authorization code: secrets kept out of answers", () => {
	it("answers no client's secret, no user's password or token, and no part of the signing key at discovery, the key set, authorize's refusals, the token endpoint's and userinfo's [guarantee-8-d]", async () => {
		const mine = await issued(alice, app);
		const theirs = await issued(bob, other);
		// A code still to redeem, which the token endpoint reads past the check for a used one.
		const waiting =
			(await browserAt(() => base, issuer, bob).authorize(request(other))).at?.searchParams.get(
				"code",
			) ?? "";
		const key = pair.privateKey.export({ format: "jwk" });
		const secrets: Record<string, string> = {
			"app's secret": app.secret ?? "",
			"other's secret": other.secret ?? "",
			"alice's password": alice.password,
			"bob's password": bob.password,
			"alice's code": mine.code,
			"bob's code": theirs.code,
			"bob's code still to redeem": waiting,
			"the signing key": String(key.d),
			...Object.fromEntries(
				privatePem
					.split("\n")
					.filter((line) => line && !line.startsWith("-----"))
					.map((line, i) => [`the signing key's PEM line ${i + 1}`, line]),
			),
			...Object.fromEntries(
				[
					["alice", mine.tokens],
					["bob", theirs.tokens],
				].flatMap(([who, tokens]) =>
					["access_token", "refresh_token", "id_token"].map((name) => [
						`${who}'s ${name}`,
						(tokens as Record<string, string>)[name] ?? "",
					]),
				),
			),
		};
		expect(Object.entries(secrets).filter(([, value]) => value === "")).toEqual([]);
		// What a careless answer could echo: a secret, a password and another user's token in the request.
		const carried = {
			client_secret: app.secret ?? "",
			password: alice.password,
			login_hint: theirs.tokens.access_token ?? "",
		};
		const authorize = async (params: Record<string, string>) =>
			whole(
				await fetch(`${base}/oauth/authorize?${new URLSearchParams(params)}`, {
					redirect: "manual",
					headers: mine.browser.headers({ cookie: await mine.browser.login() }),
				}),
			);
		const userinfo = async (bearer?: string) =>
			whole(
				await fetch(`${base}/oauth/userinfo`, {
					headers: { ...backChannel, ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
				}),
			);
		const answers: Record<string, () => Promise<{ status: number; text: string }>> = {
			discovery: async () =>
				whole(await fetch(`${base}/.well-known/openid-configuration`, { headers: backChannel })),
			"the key set": async () =>
				whole(await fetch(`${base}/.well-known/jwks.json`, { headers: backChannel })),
			"a refusal sent back": () => authorize(request(app, { ...carried, response_type: "token" })),
			"a refusal answered on the provider's page, an unknown client": () =>
				authorize(request(app, { ...carried, client_id: "nobody" })),
			"a refusal answered on the provider's page, an unregistered redirect URI": () =>
				authorize(request(app, { ...carried, redirect_uri: "https://evil.example/cb" })),
			"a used code": async () =>
				whole(
					await token(app, {
						grant_type: "authorization_code",
						code: mine.code,
						redirect_uri: callback,
						code_verifier: verifier,
					}),
				),
			"another client's code": async () =>
				whole(
					await token(app, {
						grant_type: "authorization_code",
						code: waiting,
						redirect_uri: callback,
						code_verifier: verifier,
					}),
				),
			"a wrong client secret": async () =>
				whole(
					await token(
						app,
						{ grant_type: "refresh_token", refresh_token: mine.tokens.refresh_token ?? "" },
						other.secret,
					),
				),
			"another client's refresh token": async () =>
				whole(
					await token(app, {
						grant_type: "refresh_token",
						refresh_token: theirs.tokens.refresh_token ?? "",
					}),
				),
			"userinfo without a token": () => userinfo(),
			"userinfo with an ID token": () => userinfo(theirs.tokens.id_token),
			"userinfo with a token altered": () => userinfo(`${theirs.tokens.access_token}x`),
		};
		const refusals = Object.keys(answers).filter(
			(name) => name !== "discovery" && name !== "the key set",
		);
		for (const [name, answer] of Object.entries(answers)) {
			const { status, text } = await answer();
			if (refusals.includes(name)) expect(status, name).not.toBe(200);
			else expect(status, name).toBe(200);
			const shown = Object.entries(secrets).filter(([, value]) => text.includes(value));
			expect(
				shown.map(([what]) => what),
				name,
			).toEqual([]);
		}
	});
});
