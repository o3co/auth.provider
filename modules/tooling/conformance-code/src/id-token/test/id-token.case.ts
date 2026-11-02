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
	audiences: ["https://api.example"],
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
			users: [
				{ identifier: "alice", password: "correct horse battery" },
				{ identifier: "bob", password: "battery staple horse" },
			],
			refresh: {},
			discovery: true,
			userinfo: true,
			introspection: true,
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
/** Another person's browser, signed in as bob. */
const bobs = browserAt(() => base, issuer, { username: "bob", password: "battery staple horse" });
const claimsOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;
/** A fresh login's authorization response to an OpenID request with these parameters, and the tokens its code gives. */
async function signedIn(extra: Record<string, string> = {}, as = browser) {
	as.forget();
	const res = await as.authorize({
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

/** An OpenID request from the app's browser with these parameters added. */
const asked = (extra: Record<string, string>) => ({
	response_type: "code",
	client_id: app.id,
	redirect_uri: callback,
	state: "s2",
	scope: "openid read",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});

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

	it("carries the nonce asked in the ID token alone: in no access or refresh token, no other member of the answers, nor userinfo or introspection [oidc-core-2-j]", async () => {
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
		for (const [name, token] of [
			["first", tokens.access_token],
			["refreshed", refreshed.access_token],
		] as const) {
			const userinfo = await fetch(`${base}/oauth/userinfo`, {
				headers: { ...backChannel, authorization: `Bearer ${token}` },
			});
			expect(await succeeded(userinfo, "userinfo")).not.toHaveProperty("nonce");
			const introspected = await fetch(`${base}/oauth/introspect`, {
				method: "POST",
				headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					token: token ?? "",
					client_id: app.id,
					client_secret: app.secret ?? "",
				}),
			});
			const answer = await succeeded(introspected, "introspection");
			expect(answer.active, name).toBe(true);
			expect(JSON.stringify(answer)).not.toContain(nonce);
		}
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

	it("ignores offline_access in an OpenID Connect request, no offline access being offered: a code for the rest, the scope answered and carried without it [oidc-core-11-c]", async () => {
		const { at, tokens } = await signedIn({ scope: "openid offline_access read" });
		expect(at?.searchParams.get("error")).toBeNull();
		// The scope issued is not the one asked, so the answer must say it (RFC 6749 §5.1).
		expect(typeof tokens.scope).toBe("string");
		for (const [name, scope] of [
			["answer", tokens.scope],
			["access token", claimsOf(tokens.access_token).scope],
		] as const) {
			const words = String(scope).split(" ");
			expect(words, name).not.toContain("offline_access");
			expect(words, name).toEqual(expect.arrayContaining(["openid", "read"]));
		}
	});

	// The legacy build reads no id_token_hint at authorization, and gives a code for whoever is signed in.
	it.skipIf(areaTarget().differs("authorize-reads-id-token-hint"))(
		"issues a code under an id_token_hint only for the End-User it names: a code for the one signed in, prompt=none or not, and login_required for another, who has a session here [oidc-core-3.1.2.1-u] [oidc-core-3.1.2.2-d] [oidc-core-3.1.2.2-e]",
		async () => {
			const own = (await signedIn()).tokens.id_token ?? "";
			const others = (await signedIn({}, bobs)).tokens.id_token ?? "";
			for (const prompt of [{}, { prompt: "none" }]) {
				const mine = await browser.authorize(asked({ id_token_hint: own, ...prompt }));
				expect(mine.at?.searchParams.has("code"), JSON.stringify(prompt)).toBe(true);
				const theirs = await browser.authorize(asked({ id_token_hint: others, ...prompt }));
				expect(
					[theirs.at?.searchParams.get("error"), theirs.at?.searchParams.has("code")],
					JSON.stringify(prompt),
				).toEqual(["login_required", false]);
			}
		},
	);

	// The legacy build reads no id_token_hint at authorization, so one it did not issue gets a code too.
	it.skipIf(areaTarget().differs("authorize-reads-id-token-hint"))(
		"refuses an id_token_hint it did not issue as invalid_request, sent back with state and iss [oidc-core-3.1.2.2-f]",
		async () => {
			await signedIn();
			const forged = await browser.authorize(asked({ id_token_hint: "e30.e30.c2ln" }));
			expect(["error", "state", "iss"].map((name) => forged.at?.searchParams.get(name))).toEqual([
				"invalid_request",
				"s2",
				issuer,
			]);
		},
	);

	// The legacy build refuses select_account as a prompt word it does not know (invalid_request).
	it.skipIf(areaTarget().differs("select-account-refused"))(
		"refuses prompt=select_account as account_selection_required, with no page to choose an account by [oidc-core-3.1.2.1-q]",
		async () => {
			await signedIn();
			const res = await browser.authorize(asked({ prompt: "select_account" }));
			expect(res.at?.searchParams.get("error")).toBe("account_selection_required");
		},
	);

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
