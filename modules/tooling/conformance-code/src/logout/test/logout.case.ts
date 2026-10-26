import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { areaTarget, type Fake, fakeHttp, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../../main.ts";
import { backChannel, browserAt, succeeded } from "../../testing.ts";

const issuer = "https://issuer.example";
const back = "https://app.example/after";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const user = { username: "alice", password: "correct horse battery" };
const client = (id: string, logout: ClientScene["logout"]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code"],
	scopes: ["openid"],
	redirectUris: [`https://${id}.example/cb`],
	firstParty: true,
	...(logout ? { logout } : {}),
});
const sceneWith = (clients: readonly ClientScene[], allowed: readonly string[]): CodeScene => ({
	issuer,
	keys: {
		signing: {
			kid: "lo",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients,
	users: [{ identifier: user.username, password: user.password }],
	discovery: true,
	logout: { allowed },
});

/** The back channel of an allowed client, and of one the operator did not allow. */
let told: Fake;
let unlisted: Fake;
let running: Started;
let base = "";
beforeAll(async () => {
	told = await fakeHttp(() => ({ status: 200 }));
	unlisted = await fakeHttp(() => ({ status: 200 }));
	const app = client("app", {
		postLogoutRedirectUris: [back],
		frontchannelLogoutUri: "https://app.example/fc",
		backchannelLogoutUri: `${told.base}/bc`,
	});
	// A second front channel, at another origin, that does not ask for the session.
	const side = client("side", {
		frontchannelLogoutUri: "https://side.example/fc",
		frontchannelLogoutSessionRequired: false,
	});
	// Clients that say outright whether their back channel needs the session.
	const keen = client("keen", {
		backchannelLogoutUri: `${told.base}/keen`,
		backchannelLogoutSessionRequired: true,
	});
	const lean = client("lean", {
		backchannelLogoutUri: `${told.base}/lean`,
		backchannelLogoutSessionRequired: false,
	});
	running = await areaTarget().start(codeScene(sceneWith([app, keen, lean, side], [told.base])));
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await told?.stop();
	await unlisted?.stop();
});

const claimsOf = (token: unknown) =>
	JSON.parse(Buffer.from(String(token).split(".")[1] ?? "", "base64url").toString());
/** A token signed with the provider's key unless another is given, as anyone holding it could make one. */
const signed = (header: object, claims: object, key = pair.privateKey) => {
	const encode = (part: object) => Buffer.from(JSON.stringify(part)).toString("base64url");
	const input = `${encode({ alg: "EdDSA", kid: "lo", ...header })}.${encode(claims)}`;
	return `${input}.${sign(null, Buffer.from(input), key).toString("base64url")}`;
};
/** Waits until the allowed back channel has had a request since `before`, for up to five seconds. */
const toldSince = async (before: number) => {
	for (let i = 0; i < 100 && told.received.length === before; i++) {
		await new Promise((resolve) => setTimeout(resolve, 50));
	}
};

/** An authorization request for a client's code, with openid. */
const codeRequest = (clientId: string) => ({
	response_type: "code",
	client_id: clientId,
	redirect_uri: `https://${clientId}.example/cb`,
	state: "s",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
});

/** A browser signed in afresh, and the ID token and access token a client's code gives in its session. */
async function signedIn(id = "app") {
	const browser = browserAt(() => base, issuer, user);
	const tokensFor = async (clientId: string) => {
		const answer = await browser.authorize(codeRequest(clientId));
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: clientId,
				client_secret: `${clientId}-secret-0123456789abcdef`,
				code: answer.at?.searchParams.get("code") ?? "",
				redirect_uri: `https://${clientId}.example/cb`,
				code_verifier: verifier,
			}),
		});
		const body = (await succeeded(res, "the token endpoint")) as {
			id_token?: string;
			access_token?: string;
		};
		return { idToken: String(body.id_token), accessToken: String(body.access_token) };
	};
	return { browser, ...(await tokensFor(id)), tokensFor };
}
type SignedIn = Awaited<ReturnType<typeof signedIn>>;

/** Asks for a logout as a browser, by GET with a query or POST with a form. */
async function logout(
	at: SignedIn,
	method: "GET" | "POST",
	/** The parameters, or their pairs in order where a name is sent more than once. */
	params: Record<string, string> | readonly (readonly [string, string])[],
	extra: Record<string, string> = {},
) {
	const query = new URLSearchParams(
		Array.isArray(params) ? params.map(([k, v]) => [k, v]) : (params as Record<string, string>),
	).toString();
	const res = await fetch(`${base}/oauth/logout${method === "GET" ? `?${query}` : ""}`, {
		method,
		redirect: "manual",
		headers: at.browser.headers({
			cookie: await at.browser.login(),
			...(method === "POST" ? { "content-type": "application/x-www-form-urlencoded" } : {}),
			...extra,
		}),
		...(method === "POST" ? { body: query } : {}),
	});
	const text = await res.text();
	const json = res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : undefined;
	return { status: res.status, headers: res.headers, text, json };
}
/** Whether the browser's session still gives a code. */
const stillSignedIn = async (at: SignedIn) =>
	(await at.browser.authorize(codeRequest("app"))).at?.searchParams.get("code") != null;

const unescaped = (text: string) =>
	text.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code))).replace(/&amp;/g, "&");
/** What a front-channel page frames, what it runs, where it moves on to, and its policy by directive. */
const pageOf = (page: Awaited<ReturnType<typeof logout>>) => ({
	frames: [...page.text.matchAll(/<iframe[^>]*\ssrc="([^"]+)"/g)].map(
		(m) => new URL(unescaped(m[1] ?? "")),
	),
	scripts: [...page.text.matchAll(/<script([^>]*)>([^<]*)<\/script>/g)].map((m) => ({
		attributes: m[1] ?? "",
		text: m[2] ?? "",
	})),
	target: unescaped(page.text.match(/\sdata-target="([^"]*)"/)?.[1] ?? "") || undefined,
	policy: new Map(
		(page.headers.get("content-security-policy") ?? "")
			.split(";")
			.map((directive) => directive.trim().split(/\s+/))
			.filter(([name]) => name)
			.map(([name = "", ...values]) => [name, values]),
	),
});
const hashOf = (script: string) =>
	`'sha256-${createHash("sha256").update(script).digest("base64")}'`;

describe("a logout the client starts", () => {
	it("ends the session the hint names and sends the browser back with its state, by GET or POST [oidc-rpinit-2-d]", async () => {
		for (const method of ["GET", "POST"] as const) {
			const at = await signedIn();
			expect(await stillSignedIn(at)).toBe(true);
			const params = { id_token_hint: at.idToken, post_logout_redirect_uri: back, state: "s 1" };
			const answer = await logout(at, method, params);
			expect([answer.status, answer.headers.get("location")]).toEqual([303, `${back}?state=s+1`]);
			expect(answer.headers.get("cache-control")).toContain("no-store");
			expect(await stillSignedIn(at)).toBe(false);
		}
	});

	it("answers a session already ended as logged out", async () => {
		const at = await signedIn();
		await logout(at, "POST", { id_token_hint: at.idToken });
		const again = await logout(at, "POST", { id_token_hint: at.idToken });
		expect([again.status, again.json]).toEqual([200, { logged_out: true }]);
	});

	// Open redirect: only a return the hint's client registered, compared exactly, is taken; any other
	// refuses the request, the session left as it was.
	it("refuses a return the client did not register, never sending the browser to it, and leaves the session [oidc-rpinit-2-b] [oidc-rpinit-3-b]", async () => {
		for (const asked of [`${back}/x`, `${back}?x=1`, "https://other.example/after"]) {
			const at = await signedIn();
			for (const accept of ["application/json", "text/html"]) {
				const answer = await logout(
					at,
					"GET",
					{ id_token_hint: at.idToken, post_logout_redirect_uri: asked },
					{ accept },
				);
				expect([asked, accept, answer.status, answer.json]).toEqual([
					asked,
					accept,
					400,
					{
						error: "invalid_request",
						error_description: "post_logout_redirect_uri is not registered for the client",
					},
				]);
				expect(answer.headers.get("location")).toBeNull();
			}
			expect(await stillSignedIn(at)).toBe(true);
		}
	});

	// A client_id beside the hint must be the client the ID token was issued to (RP-Initiated Logout 1.0 §2).
	it("refuses a client_id that is not the client the hint was issued to, leaving the session [oidc-rpinit-2-a]", async () => {
		const at = await signedIn();
		for (const method of ["GET", "POST"] as const) {
			const answer = await logout(at, method, { id_token_hint: at.idToken, client_id: "other" });
			expect([answer.status, answer.json]).toEqual([
				400,
				{
					error: "invalid_request",
					error_description: "client_id is not the client the id_token_hint was issued to",
				},
			]);
		}
		expect(await stillSignedIn(at)).toBe(true);
	});

	// A parameter sent twice reads as none: refused first, so neither the client_id check nor the
	// return's can be passed by sending it twice.
	it("refuses a client_id or a return sent twice, leaving the session", async () => {
		for (const [name, value] of [
			["client_id", "other"],
			["post_logout_redirect_uri", `${back}/x`],
		] as const) {
			const at = await signedIn();
			for (const method of ["GET", "POST"] as const) {
				const answer = await logout(at, method, [
					["id_token_hint", at.idToken],
					[name, value],
					[name, value],
				]);
				expect([name, method, answer.status, answer.json]).toEqual([
					name,
					method,
					400,
					{ error: "invalid_request", error_description: "repeated parameter" },
				]);
			}
			expect([name, await stillSignedIn(at)]).toEqual([name, true]);
		}
	});

	it("refuses a request without a hint [oidc-rpinit-3-a] [oidc-rpinit-4-c]", async () => {
		const at = await signedIn();
		for (const method of ["GET", "POST"] as const) {
			const answer = await logout(at, method, { post_logout_redirect_uri: back });
			expect([answer.status, answer.json?.error]).toEqual([400, "invalid_request"]);
		}
		expect(await stillSignedIn(at)).toBe(true);
	});

	// A hint naming no session cannot say which session to end.
	it("refuses a hint that names no session, leaving the session", async () => {
		const at = await signedIn();
		const { sid: _, ...claims } = claimsOf(at.idToken);
		const answer = await logout(at, "GET", { id_token_hint: signed({ typ: "JWT" }, claims) });
		expect([answer.status, answer.json?.error]).toEqual([400, "invalid_request"]);
		expect(await stillSignedIn(at)).toBe(true);
	});

	// Token confusion: only an ID token is taken as the hint, never another kind the provider signs.
	it("refuses as the hint a token of another kind, or one the provider did not sign [oidc-rpinit-2-e] [oidc-rpinit-4-a] [oidc-rpinit-4-b]", async () => {
		const at = await signedIn();
		const other = generateKeyPairSync("ed25519").privateKey;
		const foreign = signed({ typ: "JWT" }, claimsOf(at.idToken), other);
		for (const hint of [at.accessToken, foreign]) {
			const answer = await logout(at, "GET", { id_token_hint: hint });
			expect([answer.status, answer.json?.error]).toEqual([400, "invalid_token"]);
		}
		expect(await stillSignedIn(at)).toBe(true);
	});
});

describe("hints past their time", () => {
	/** The ID token re-signed with the provider's key, issued `ago` seconds ago and ended an hour ago. */
	const aged = (idToken: string, ago: number) => {
		const now = Math.floor(Date.now() / 1000);
		return signed({ typ: "JWT" }, { ...claimsOf(idToken), iat: now - ago, exp: now - 3600 });
	};
	it.runIf(!areaTarget().differs("expired-logout-hint"))(
		"ends the session for a hint past its end",
		async () => {
			const at = await signedIn();
			const answer = await logout(at, "GET", { id_token_hint: aged(at.idToken, 7200) });
			expect([answer.status, answer.json, await stillSignedIn(at)]).toEqual([
				200,
				{ logged_out: true },
				false,
			]);
		},
	);

	it.runIf(!areaTarget().differs("old-logout-hint"))(
		"refuses a hint issued over a day ago, by GET or POST, leaving the session open",
		async () => {
			const at = await signedIn();
			const hint = aged(at.idToken, 90_000);
			for (const method of ["GET", "POST"] as const) {
				const answer = await logout(at, method, { id_token_hint: hint });
				expect([answer.status, answer.json?.error], method).toEqual([400, "invalid_token"]);
			}
			expect(await stillSignedIn(at)).toBe(true);
		},
	);
});

describe("telling the session's clients", () => {
	it("frames each client's front channel with the issuer and session, on a page no one can frame", async () => {
		const at = await signedIn();
		const params = { id_token_hint: at.idToken, post_logout_redirect_uri: back, state: "s" };
		const page = await logout(at, "GET", params, { accept: "text/html" });
		expect(page.status).toBe(200);
		expect(page.headers.get("content-type")).toMatch(/^text\/html/);
		const src = (page.text.match(/<iframe[^>]*\ssrc="([^"]+)"/)?.[1] ?? "").replace(
			/&amp;|&#38;/g,
			"&",
		);
		const framed = new URL(src);
		expect([framed.origin + framed.pathname, framed.searchParams.get("iss")]).toEqual([
			"https://app.example/fc",
			issuer,
		]);
		expect(framed.searchParams.get("sid")).toBe(claimsOf(at.idToken).sid);
		const policy = page.headers.get("content-security-policy") ?? "";
		expect(policy).toMatch(/frame-src [^;]*https:\/\/app\.example/);
		expect(policy).toContain("frame-ancestors 'none'");
	});

	// Stored XSS through a front channel: the page frames only the URLs the session's clients registered,
	// and loads nothing but their origins and its one script.
	it("frames only the front channels the session's clients registered, under a policy naming their origins and the page's one script", async () => {
		const at = await signedIn();
		await at.tokensFor("side");
		await at.tokensFor("keen");
		const params = { id_token_hint: at.idToken, post_logout_redirect_uri: back, state: "s" };
		const answer = await logout(at, "GET", params, { accept: "text/html" });
		expect(answer.status).toBe(200);
		const page = pageOf(answer);
		const framed = page.frames.map((url) => url.origin + url.pathname).sort();
		expect(framed).toEqual(["https://app.example/fc", "https://side.example/fc"]);
		const sideFrame = page.frames.find((url) => url.origin === "https://side.example");
		expect(sideFrame?.searchParams.get("iss")).toBe(issuer);
		expect(sideFrame?.searchParams.has("sid")).toBe(false);
		expect(page.target).toBe(`${back}?state=s`);
		expect(page.scripts).toHaveLength(1);
		const [script] = page.scripts;
		expect(script?.attributes).not.toMatch(/\ssrc=/);
		expect(script?.text).not.toContain(back);
		expect([...(page.policy.get("frame-src") ?? [])].sort()).toEqual([
			"https://app.example",
			"https://side.example",
		]);
		expect(page.policy.get("script-src")).toEqual([hashOf(script?.text ?? "")]);
		expect(page.policy.get("default-src")).toEqual(["'none'"]);
		expect(page.policy.get("frame-ancestors")).toEqual(["'none'"]);
	});

	// Open redirect and XSS through a return: a page with no return to follow has no script and moves nowhere.
	it("gives a page with no script when there is no return to move on to", async () => {
		const at = await signedIn();
		const answer = await logout(at, "GET", { id_token_hint: at.idToken }, { accept: "text/html" });
		expect(answer.status).toBe(200);
		const page = pageOf(answer);
		expect(page.frames.map((url) => url.origin + url.pathname)).toEqual(["https://app.example/fc"]);
		expect([page.scripts, page.target, page.policy.has("script-src")]).toEqual([
			[],
			undefined,
			false,
		]);
		expect(page.policy.get("default-src")).toEqual(["'none'"]);
		expect(await stillSignedIn(at)).toBe(false);
	});

	it("posts each client of the session a logout token signed by the provider [oidc-bcl-2.4-a] [oidc-bcl-2.4-b] [oidc-bcl-2.4-f] [oidc-bcl-2.4-i] [oidc-bcl-2.4-j] [oidc-bcl-2.4-k] [oidc-bcl-2.4-m] [oidc-bcl-2.6-a]", async () => {
		const at = await signedIn();
		const before = told.received.length;
		await logout(at, "POST", { id_token_hint: at.idToken });
		await toldSince(before);
		const posted = told.received[before];
		expect([posted?.method, posted?.path, posted?.headers["content-type"]]).toEqual([
			"POST",
			"/bc",
			"application/x-www-form-urlencoded",
		]);
		const token = new URLSearchParams(posted?.body).get("logout_token") ?? "";
		const [header = "", body = "", signature = ""] = token.split(".");
		const key = createPublicKey(pair.publicKey.export({ format: "pem", type: "spki" }));
		const valid = verify(
			null,
			Buffer.from(`${header}.${body}`),
			key,
			Buffer.from(signature, "base64url"),
		);
		expect(valid).toBe(true);
		expect(JSON.parse(Buffer.from(header, "base64url").toString()).typ).toBe("logout+jwt");
		const claims = claimsOf(token);
		expect(claims).toMatchObject({ iss: issuer, aud: "app", sid: claimsOf(at.idToken).sid });
		expect(Object.keys(claims.events)).toEqual([
			"http://schemas.openid.net/event/backchannel-logout",
		]);
		expect(claims.nonce).toBeUndefined();
	});

	// OpenID Connect Back-Channel Logout 1.0 §2.4: a token without sid still names the subject.
	it("puts the session in the logout token of a client that requires it, and leaves it out, naming the subject, for one that does not [oidc-bcl-2.4-i]", async () => {
		const at = await signedIn();
		await at.tokensFor("keen");
		await at.tokensFor("lean");
		const before = told.received.length;
		await logout(at, "POST", { id_token_hint: at.idToken });
		for (let i = 0; i < 100 && told.received.length < before + 3; i++) {
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
		const tokenAt = (path: string) =>
			claimsOf(
				new URLSearchParams(told.received.slice(before).find((r) => r.path === path)?.body).get(
					"logout_token",
				),
			);
		const { sid, sub } = claimsOf(at.idToken);
		const event = "http://schemas.openid.net/event/backchannel-logout";
		expect(tokenAt("/keen")).toMatchObject({ iss: issuer, aud: "keen", sub, sid });
		const lean = tokenAt("/lean");
		expect(lean).toMatchObject({ iss: issuer, aud: "lean", sub });
		expect(lean).not.toHaveProperty("sid");
		expect(Object.keys(lean.events)).toEqual([event]);
	});

	// Outbound requests to client URLs: the back channel reaches only destinations the operator allows.
	describe.runIf(!areaTarget().differs("back-channel-by-host-and-port"))(
		"the back channel's destinations",
		() => {
			it("refuses to start with a client whose back channel the operator did not allow", async () => {
				const far = client("far", { backchannelLogoutUri: `${unlisted.base}/bc` });
				const started = await areaTarget().start(codeScene(sceneWith([far], [told.base])));
				try {
					expect(started.kind).toBe("refused");
					if (started.kind === "refused") {
						expect(started.output).toContain("backchannel-logout-uri");
						expect(started.output).not.toContain(unlisted.base);
					}
				} finally {
					if (started.kind === "running") await started.stop();
				}
				expect(unlisted.received).toEqual([]);
			});
		},
	);
});

it("names its endpoint and the channels it tells in the metadata document [oidc-rpinit-2.1-a] [oidc-bcl-2.1-a]", async () => {
	const res = await fetch(`${base}/.well-known/openid-configuration`, {
		headers: { "x-forwarded-proto": "https", "x-forwarded-host": new URL(issuer).host },
	});
	expect(await res.json()).toMatchObject({
		end_session_endpoint: `${issuer}/oauth/logout`,
		frontchannel_logout_supported: true,
		frontchannel_logout_session_supported: true,
		backchannel_logout_supported: true,
		backchannel_logout_session_supported: true,
	});
});

// Reserved names: a client's front channel may not carry the issuer or session names the provider adds.
it("refuses to start with a client whose return or front channel is not one it may register", async () => {
	for (const logout of [
		{ frontchannelLogoutUri: "https://app.example/fc?iss=x" },
		{ frontchannelLogoutUri: "https://app.example/fc?sid=x" },
		{ postLogoutRedirectUris: ["https://app.example/after#x"] },
	]) {
		const started = await areaTarget().start(codeScene(sceneWith([client("app", logout)], [])));
		if (started.kind === "running") await started.stop();
		expect(started.kind).toBe("refused");
	}
});

it.skipIf(areaTarget().differs("frontchannel-within-redirect-origins"))(
	"refuses to start with a client whose front channel is at none of its redirect URIs' origins (OpenID Connect Front-Channel Logout 1.0 §2)",
	async () => {
		const logout = { frontchannelLogoutUri: "https://elsewhere.example/fc" };
		const started = await areaTarget().start(codeScene(sceneWith([client("app", logout)], [])));
		if (started.kind === "running") await started.stop();
		expect(started.kind).toBe("refused");
	},
);
