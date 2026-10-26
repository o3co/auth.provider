import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, faultyTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";
import { backChannel, browserAt } from "../src/testing.ts";

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
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	redirectUris: [callback, "http://127.0.0.1:9000/cb"],
	firstParty: true,
	audiences: ["https://api.example"],
};
/** A client whose default scope holds openid, which a request must still name itself. */
const openidDefault: ClientScene = {
	...app,
	id: "openid-default",
	secret: "openid-default-secret-0123456789",
	defaultScopes: ["openid"],
};
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "cf",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [app, openidDefault],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	introspection: true,
};
const scene = codeScene(fields);

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(scene);
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
const request = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});

describe("authorization code: before the redirect URI is trusted", () => {
	it("answers an unknown client and an unregistered redirect URI locally [rfc6749-3.1.2.3-b] [rfc6749-3.1.2.3-c] [rfc6749-3.1.2.4-a] [rfc6749-3.1.2.4-b] [rfc6749-4.1.2.1-a] [rfc6749-4.1.2.1-b] [rfc9700-2.1-a] [oidc-core-3.1.2.6-b]", async () => {
		for (const params of [
			request({ client_id: "nobody" }),
			request({ redirect_uri: "https://evil.example/cb" }),
			request({ redirect_uri: `${callback}/` }),
		]) {
			const res = await browser.authorize(params);
			expect([res.status, res.at]).toEqual([400, undefined]);
		}
	});

	it("refuses textual variants of a loopback redirect URI, and ignores only its port [rfc6749-3.1.2.3-c] [rfc9700-2.1-a] [rfc9700-4.1.3-a]", async () => {
		expect(
			(await browser.authorize(request({ redirect_uri: "http://localhost:9000/cb" }))).status,
		).toBe(400);
		expect(
			(await browser.authorize(request({ redirect_uri: "http://127.0.0.1:9000/cb/" }))).status,
		).toBe(400);
		expect(
			(
				await browser.authorize(
					request({ redirect_uri: "http://127.0.0.1:9555/cb", response_type: "token" }),
				)
			).at?.origin,
		).toBe("http://127.0.0.1:9555");
	});
});

describe("authorization code: errors sent back", () => {
	it("sends refusals back with state and iss [rfc6749-3.1-f] [rfc6749-3.1.1-a] [rfc6749-4.1.2.1-c] [rfc6749-4.1.2.1-g] [rfc7636-4.4.1-c] [rfc7636-7.2-a] [rfc9207-2-a] [oidc-core-3.1.2.6-c] [oidc-core-3.1.2.6-d] [oidc-core-6.1-a]", async () => {
		const cases: [Record<string, string> | string, string][] = [
			[request({ response_type: "token" }), "unsupported_response_type"],
			[request({ code_challenge: "" }), "invalid_request"],
			[request({ code_challenge_method: "plain" }), "invalid_request"],
			[request({ request: "eyJhbGciOiJub25lIn0.e30." }), "request_not_supported"],
			[request({ response_mode: "fragment" }), "invalid_request"],
			[`${new URLSearchParams(request())}&code_challenge_method=S256`, "invalid_request"],
		];
		for (const [params, error] of cases) {
			const res = await browser.authorize(params);
			expect(res.status).toBe(302);
			expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
			expect([
				res.at?.searchParams.get("error"),
				res.at?.searchParams.get("state"),
				res.at?.searchParams.get("iss"),
			]).toEqual([error, "s1", issuer]);
		}
	});

	it("answers prompt=none without a session with login_required [oidc-core-3.1.2.1-k] [oidc-core-3.1.2.3-c] [oidc-core-3.1.2.3-d] [rfc9207-2-a]", async () => {
		const res = await browser.authorize(request({ prompt: "none" }), false);
		expect([res.at?.searchParams.get("error"), res.at?.searchParams.get("iss")]).toEqual([
			"login_required",
			issuer,
		]);
	});

	it("sends a request without a session to log in, coming back on the issuer's origin whatever the host says", async () => {
		const res = await fetch(`${base}/oauth/authorize?${new URLSearchParams(request())}`, {
			redirect: "manual",
			headers: browser.headers({ "x-forwarded-host": "evil.example" }),
		});
		const back = new URL(
			new URL(res.headers.get("location") ?? "", issuer).searchParams.get("redirect_to") ?? "",
		);
		expect(`${back.origin}${back.pathname}`).toBe(`${issuer}/oauth/authorize`);
	});
});

describe("authorization code: issuing and redeeming", () => {
	const token = async (form: Record<string, string>) => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: "app",
				client_secret: app.secret ?? "",
				...form,
			}),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};

	it("issues a code with state and iss, redeems it once, and a used code gets nothing [rfc6749-4.1.2-a] [rfc6749-4.1.2-d] [rfc6749-4.1.2-f] [rfc7636-4.6-a] [rfc9207-2-a] [oidc-core-3.1.3.2-d] [oidc-core-3.1.3.3-a] [oidc-core-3.1.3.3-b]", async () => {
		const res = await browser.authorize(request({ scope: "openid read" }));
		const code = res.at?.searchParams.get("code") ?? "";
		expect([res.at?.searchParams.get("state"), res.at?.searchParams.get("iss")]).toEqual([
			"s1",
			issuer,
		]);
		const first = await token({ code, redirect_uri: callback, code_verifier: verifier });
		expect([first.status, first.body.token_type]).toEqual([200, "Bearer"]);
		expect(
			(await token({ code, redirect_uri: callback, code_verifier: verifier })).body.error,
		).toBe("invalid_grant");
	});

	it("refuses a code after logout", async () => {
		const res = await browser.authorize(request({ scope: "openid read" }));
		const code = res.at?.searchParams.get("code") ?? "";
		await fetch(`${base}/session/logout`, {
			method: "POST",
			headers: browser.headers({ cookie: await browser.login(), origin: issuer }),
		});
		browser.forget();
		expect(
			(await token({ code, redirect_uri: callback, code_verifier: verifier })).body.error,
		).toBe("invalid_grant");
	});
});

describe("OpenID Connect: openid required by default", () => {
	const answer = (res: { at: URL | undefined }) =>
		["code", "error", "state", "iss"].map((name) =>
			name === "code" ? res.at?.searchParams.has(name) : res.at?.searchParams.get(name),
		);

	it("refuses a request whose own scope does not name openid with invalid_scope, sent back [oidc-core-3.1.2.2-a] [rfc6749-3.3-b] [rfc6749-4.1.2.1-c] [rfc6749-4.1.2.1-g] [rfc9207-2-a]", async () => {
		const { scope: _, ...unscoped } = request();
		const refused = [false, "invalid_scope", "s1", issuer];
		expect(answer(await browser.authorize(request({ scope: "read" })))).toEqual(refused);
		expect(answer(await browser.authorize(unscoped))).toEqual(refused);
		expect(answer(await browser.authorize({ ...unscoped, client_id: "openid-default" }))).toEqual(
			refused,
		);
	});

	it("gives a code to a request that names openid [rfc6749-4.1.2-a] [rfc6749-4.1.2-f] [rfc9207-2-a]", async () => {
		expect(answer(await browser.authorize(request({ scope: "openid read" })))).toEqual([
			true,
			null,
			"s1",
			issuer,
		]);
	});
});

describe("OpenID Connect: an ID token with the code", () => {
	const exchange = async (form: Record<string, string>) => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: "app",
				client_secret: app.secret ?? "",
				...form,
			}),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const claimsOf = (jwt: unknown) =>
		JSON.parse(Buffer.from(String(jwt).split(".")[1] ?? "", "base64url").toString()) as Record<
			string,
			unknown
		>;

	it("answers an openid request with a code, iss and state, and the exchange with an ID token for that client and nonce [oidc-core-2-a] [oidc-core-2-b] [oidc-core-2-d] [oidc-core-2-e] [oidc-core-2-i] [oidc-core-3.1.3.3-a] [oidc-core-3.1.3.3-c] [oidc-core-15.1-e] [rfc6749-4.1.2-a] [rfc6749-4.1.2-f] [rfc9207-2-a]", async () => {
		const res = await browser.authorize(request({ nonce: "n-123" }));
		expect([
			res.at?.searchParams.has("code"),
			res.at?.searchParams.get("state"),
			res.at?.searchParams.get("iss"),
		]).toEqual([true, "s1", issuer]);
		const answer = await exchange({
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		});
		expect([answer.status, answer.body.token_type]).toEqual([200, "Bearer"]);
		expect(claimsOf(answer.body.id_token)).toMatchObject({
			iss: issuer,
			sub: "alice",
			aud: "app",
			nonce: "n-123",
		});
		expect(typeof claimsOf(answer.body.id_token).auth_time).toBe("number");
	});

	it("refuses the same code a second time [rfc6749-4.1.2-d] [rfc6749-5.2-a] [oidc-core-3.1.3.2-d]", async () => {
		const res = await browser.authorize(request());
		const form = {
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		};
		expect((await exchange(form)).status).toBe(200);
		const again = await exchange(form);
		expect([again.status, again.body.error]).toEqual([400, "invalid_grant"]);
	});

	it.runIf(areaTarget().can(auditEvents.need))(
		"records the exchange of a code, and the refusal of a used one, never the code",
		async () => {
			const res = await browser.authorize(request());
			const code = res.at?.searchParams.get("code") ?? "";
			const form = { code, redirect_uri: callback, code_verifier: verifier };
			const trail = auditEvents.of(running);
			const first = await trail.during(() => exchange(form));
			const again = await trail.during(() => exchange(form));
			const by = { client: "app", source: expect.any(String), grant_type: "authorization_code" };
			expect(first.events).toEqual([
				{ kind: "token.issued", at: expect.any(Number), attributes: by },
			]);
			expect(again.events).toEqual([
				{
					kind: "token.issued.failure",
					at: expect.any(Number),
					attributes: { ...by, reason: "grant_refused", error: "invalid_grant" },
				},
			]);
			expect(JSON.stringify([first.events, again.events])).not.toContain(code);
		},
	);
});

describe("tokens and logout", () => {
	const post = async (path: string, form: Record<string, string>) => {
		const res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(form),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const asApp = { client_id: "app", client_secret: app.secret ?? "" };

	it("ends an access token handed out before logout", async () => {
		browser.forget();
		const res = await browser.authorize(request());
		const answer = await post("/oauth/token", {
			grant_type: "authorization_code",
			...asApp,
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		});
		const token = String(answer.body.access_token);
		expect((await post("/oauth/introspect", { ...asApp, token })).body.active).toBe(true);
		await fetch(`${base}/session/logout`, {
			method: "POST",
			headers: browser.headers({ cookie: await browser.login(), origin: issuer }),
		});
		browser.forget();
		expect((await post("/oauth/introspect", { ...asApp, token })).body.active).toBe(false);
	});

	it("signs ID tokens with the asymmetric key it publishes [oidc-core-2-o] [oidc-core-2-q]", async () => {
		browser.forget();
		const res = await browser.authorize(request());
		const answer = await post("/oauth/token", {
			grant_type: "authorization_code",
			...asApp,
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		});
		const header = JSON.parse(
			Buffer.from(String(answer.body.id_token).split(".")[0] ?? "", "base64url").toString(),
		);
		expect([header.alg, header.kid]).toEqual(["EdDSA", "cf"]);
	});

	it("types the ID token as the standard JWT, and never dates auth_time after iat", async () => {
		browser.forget();
		const res = await browser.authorize(request());
		const answer = await post("/oauth/token", {
			grant_type: "authorization_code",
			...asApp,
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		});
		const [header, claims] = String(answer.body.id_token)
			.split(".")
			.slice(0, 2)
			.map((part) => JSON.parse(Buffer.from(part, "base64url").toString()));
		expect(header.typ).toBe("JWT");
		expect(claims.auth_time).toBeLessThanOrEqual(claims.iat);
	});
});

describe.runIf(areaTarget().can("store-fault:codes"))(
	"authorization code: the store failing",
	() => {
		const faulty = faultyTarget(scene);
		let at = "";
		beforeAll(() => {
			at = base;
			base = faulty.base();
			browser.forget();
		});
		afterAll(() => {
			base = at;
			browser.forget();
		});

		it("answers 503 to a code redeemed while the store is unreachable, never invalid_grant", async () => {
			const res = await browser.authorize(request());
			const code = res.at?.searchParams.get("code") ?? "";
			expect(code).not.toBe("");
			const answer = await faulty.whileDown(async () => {
				const redeemed = await fetch(`${base}/oauth/token`, {
					method: "POST",
					headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({
						grant_type: "authorization_code",
						client_id: "app",
						client_secret: app.secret ?? "",
						code,
						redirect_uri: callback,
						code_verifier: verifier,
					}),
				});
				return {
					status: redeemed.status,
					body: (await redeemed.json()) as Record<string, unknown>,
				};
			});
			expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
		});
	},
);
