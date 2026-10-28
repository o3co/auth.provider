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
/** An origin whose pages the deployment lets read across origins, where a route takes them. */
const page = "https://app.example";
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

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "it",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [app],
			users: [{ identifier: "alice", password: "correct horse battery" }],
			refresh: {},
			discovery: true,
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

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
const claimsOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;
/** A fresh login's authorization response to an OpenID request with these parameters, and the tokens its code gives. */
async function signedIn(extra: Record<string, string> = {}) {
	browser.forget();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid read",
		code_challenge: challenge,
		code_challenge_method: "S256",
		...extra,
	});
	const tokens = (await succeeded(
		await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: app.id,
				client_secret: app.secret ?? "",
				code: res.at?.searchParams.get("code") ?? "",
				redirect_uri: callback,
				code_verifier: verifier,
			}),
		}),
		"the token endpoint",
	)) as Record<string, string>;
	return { at: res.at, tokens };
}

describe("OpenID Connect: the ID token", () => {
	it("carries auth_time where max_age, or auth_time as an essential claim, was asked [oidc-core-3.1.2.1-s] [oidc-core-2-h]", async () => {
		for (const extra of [
			{ max_age: "300" },
			{ claims: JSON.stringify({ id_token: { auth_time: { essential: true } } }) },
		]) {
			const { tokens } = await signedIn(extra);
			const claims = claimsOf(tokens.id_token);
			expect(typeof claims.auth_time, JSON.stringify(extra)).toBe("number");
			expect(claims.auth_time).toBeLessThanOrEqual(Number(claims.iat));
		}
	});

	it("carries the nonce asked in the ID token alone, in no access or refresh token and no other member of the answer [oidc-core-2-j]", async () => {
		const nonce = "n-only-in-the-id-token-0123";
		const { tokens } = await signedIn({ nonce });
		expect(claimsOf(tokens.id_token).nonce).toBe(nonce);
		const { id_token: _, ...others } = tokens;
		expect(JSON.stringify(others)).not.toContain(nonce);
		expect(JSON.stringify(claimsOf(tokens.access_token))).not.toContain(nonce);
		const refreshed = (await succeeded(
			await fetch(`${base}/oauth/token`, {
				method: "POST",
				headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: tokens.refresh_token ?? "",
					client_id: app.id,
					client_secret: app.secret ?? "",
				}),
			}),
			"the token endpoint",
		)) as Record<string, string>;
		expect(JSON.stringify(refreshed)).not.toContain(nonce);
		expect(JSON.stringify(claimsOf(refreshed.access_token))).not.toContain(nonce);
	});

	it("answers prompt=none with a code for the session it has, no id_token_hint asked [oidc-core-3.1.2.1-v] [oidc-core-15.1-b]", async () => {
		await signedIn();
		const quiet = await browser.authorize({
			response_type: "code",
			client_id: app.id,
			redirect_uri: callback,
			state: "s2",
			scope: "openid read",
			prompt: "none",
			code_challenge: challenge,
			code_challenge_method: "S256",
		});
		expect([quiet.at?.searchParams.has("code"), quiet.at?.searchParams.get("error")]).toEqual([
			true,
			null,
		]);
	});

	it("answers no CORS request at the authorization endpoint, a listed origin's included [oidc-discovery-3-ak] [rfc9700-2.6-e]", async () => {
		const query = new URLSearchParams({ response_type: "code", client_id: app.id });
		const asked = (method: string, extra: Record<string, string> = {}) =>
			fetch(`${base}/oauth/authorize?${query}`, {
				method,
				redirect: "manual",
				headers: { ...backChannel, origin: page, ...extra },
			});
		const preflight = await asked("OPTIONS", { "access-control-request-method": "GET" });
		const read = await asked("GET");
		for (const [name, res] of [
			["preflight", preflight],
			["GET", read],
		] as const) {
			for (const header of [...res.headers.keys()]) {
				expect(header, name).not.toMatch(/^access-control-/);
			}
		}
		// The same deployment answers the listed origin where a route takes it.
		const userinfo = await fetch(`${base}/oauth/userinfo`, {
			method: "OPTIONS",
			headers: { ...backChannel, origin: page, "access-control-request-method": "GET" },
		});
		expect(userinfo.headers.get("access-control-allow-origin")).toBe(page);
	});

	it("names as iss, as the authorization response does, exactly the issuer the metadata document publishes [oidc-core-16.15-a] [oidc-discovery-3-c] [rfc9207-2.3-b]", async () => {
		const published = (
			(await (await fetch(`${base}/.well-known/openid-configuration`)).json()) as {
				issuer: string;
			}
		).issuer;
		const { at, tokens } = await signedIn();
		expect(at?.searchParams.get("iss")).toBe(published);
		expect(claimsOf(tokens.id_token).iss).toBe(published);
	});
});
