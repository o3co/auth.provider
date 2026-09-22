/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The live-check front, against a fake provider: what it relays, what it
 * records of a callback, what it must never record, and what it renders as
 * text rather than markup. The real provider is not booted here —
 * `live-check.sh start` does that, and a person signs in.
 */
import { type ChildProcess, spawn } from "node:child_process";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const PROXY = fileURLToPath(new URL("../../proxy.mjs", import.meta.url));

async function freePort(): Promise<number> {
	const s = http.createServer();
	await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
	const port = (s.address() as AddressInfo).port;
	await new Promise((resolve) => s.close(resolve));
	return port;
}

type Seen = { method: string; url: string; host: string | undefined; body: string };

/**
 * A provider that answers the federation's two routes the way the real one
 * does — the start as a redirect to the IdP, the callback as a redirect to the
 * landing page or, with `fail=1`, as a JSON refusal — and echoes the rest.
 */
function fakeProvider(port: number, federation: string, landing: string) {
	const start = `/session/oauth/federation/${federation}`;
	const callback = `${start}/callback`;
	const seen: Seen[] = [];
	const server = http.createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			const body = Buffer.concat(chunks).toString("utf8");
			seen.push({ method: req.method ?? "", url: req.url ?? "", host: req.headers.host, body });
			const url = new URL(req.url ?? "/", "http://provider");
			if (url.pathname === start) {
				res.writeHead(302, {
					location: "https://idp.test/authorize?client_id=c&state=s",
					"set-cookie": "auth.session=pre; Path=/; HttpOnly",
				});
				return res.end();
			}
			if (url.pathname === callback) {
				if (url.searchParams.get("fail") === "1") {
					res.writeHead(400, { "content-type": "application/json" });
					return res.end(JSON.stringify({ error: "invalid_request", error_description: "no iss" }));
				}
				res.writeHead(302, {
					location: landing,
					"set-cookie": ["auth.session.csrf=x; Path=/", "auth.session=post; Path=/; HttpOnly"],
				});
				return res.end();
			}
			res.writeHead(200, { "content-type": "application/json", "x-echo": "yes" });
			res.end(JSON.stringify({ path: req.url, method: req.method, body }));
		});
	});
	return {
		seen,
		listen: () => new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve)),
		close: () => new Promise((resolve) => server.close(resolve)),
	};
}

async function startProxy(env: Record<string, string>): Promise<ChildProcess> {
	const child = spawn(process.execPath, [PROXY], {
		env: { ...process.env, ...env },
		stdio: ["ignore", "pipe", "pipe"],
	});
	await new Promise<void>((resolve, reject) => {
		let out = "";
		child.stdout?.on("data", (chunk) => {
			out += String(chunk);
			if (out.includes("live-check: http://")) resolve();
		});
		child.stderr?.on("data", (chunk) => reject(new Error(String(chunk))));
		child.on("exit", (code) => reject(new Error(`proxy exited with ${code}: ${out}`)));
	});
	return child;
}

const get = (base: string, path: string) => fetch(`${base}${path}`, { redirect: "manual" });
const post = (base: string, path: string, body: unknown) =>
	fetch(`${base}${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
		redirect: "manual",
	});
type State = {
	federation: string;
	expectedIss: string | null;
	start: { status: number; redirectedTo: string | null } | null;
	callback: {
		queryKeys: string[];
		iss: string | null;
		codeLength: number;
		stateLength: number;
		providerStatus: number;
		providerLocation: string | null;
		providerAnswer: unknown;
		sessionCookieSet: boolean;
	} | null;
	store: { accepted: boolean; token: string } | null;
	verdict: {
		issJudged: boolean;
		issPresent: boolean;
		issOk: boolean;
		loginOk: boolean;
		ok: boolean;
	} | null;
	report: string;
	fragment: string;
};
const state = async (base: string): Promise<State> =>
	(await (await get(base, "/__live-check/state")).json()) as State;

describe("tools/live-check proxy, judging the iss against an expected issuer", () => {
	const START = "/session/oauth/federation/google";
	const CALLBACK = `${START}/callback`;
	let proxyPort: number;
	let providerPort: number;
	let base: string;
	let provider: ReturnType<typeof fakeProvider>;
	let child: ChildProcess;

	beforeAll(async () => {
		proxyPort = await freePort();
		providerPort = await freePort();
		base = `http://127.0.0.1:${proxyPort}`;
		provider = fakeProvider(providerPort, "google", `http://localhost:${proxyPort}/`);
		await provider.listen();
		child = await startProxy({
			LIVE_CHECK_PORT: String(proxyPort),
			LIVE_CHECK_PROVIDER_PORT: String(providerPort),
			LIVE_CHECK_FEDERATION: "google",
			LIVE_CHECK_EXPECTED_ISS: "https://accounts.google.com",
			SESSION_NAME: "auth.session",
		});
	});
	afterAll(async () => {
		child?.kill();
		await provider?.close();
	});

	it("serves the page with the federation's sign-in link and the expected issuer", async () => {
		const res = await get(base, "/");
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toContain("text/html");
		const html = await res.text();
		expect(html).toContain(`href="${START}"`);
		expect(html).toContain("Sign in with google");
		expect(html).toContain("expecting <code>iss=https://accounts.google.com</code>");
	});

	it("is a Store that accepts every token of its federation and nothing else", async () => {
		const ok = await post(base, "/__store/authenticate-by-token", { token: "google:1234567890" });
		expect(ok.status).toBe(200);
		expect(await ok.json()).toMatchObject({ id: "live-check-1234567890", username: "google-7890" });
		expect((await state(base)).store).toEqual({
			at: expect.any(String),
			accepted: true,
			token: "google:••••••7890",
		});

		expect(
			(await post(base, "/__store/authenticate-by-token", { token: "github:1234567890" })).status,
		).toBe(401);
		// A 17-character token: the mask keeps at most twelve bullets before the last four.
		expect((await state(base)).store).toMatchObject({ accepted: false, token: "••••••••••••7890" });
		expect(
			(await post(base, "/__store/authenticate", { username: "a", password: "b" })).status,
		).toBe(401);
		expect((await get(base, "/__store/authenticate-by-token")).status).toBe(405);
		expect(
			(
				await fetch(`${base}/__store/authenticate-by-token`, {
					method: "POST",
					body: "not json",
				})
			).status,
		).toBe(400);
		// The Store is not the provider's: nothing above reached it.
		expect(provider.seen.filter((s) => s.url.startsWith("/__store/"))).toHaveLength(0);
	});

	it("relays any other request to the provider — method, path, query, body, status, headers", async () => {
		const res = await get(base, "/.well-known/openid-configuration?x=1");
		expect(res.status).toBe(200);
		expect(res.headers.get("x-echo")).toBe("yes");
		expect(await res.json()).toEqual({
			path: "/.well-known/openid-configuration?x=1",
			method: "GET",
			body: "",
		});
		expect(provider.seen.at(-1)).toEqual({
			method: "GET",
			url: "/.well-known/openid-configuration?x=1",
			host: `localhost:${providerPort}`,
			body: "",
		});

		const posted = await post(base, "/session/logout", { everything: "arrives" });
		expect(await posted.json()).toEqual({
			path: "/session/logout",
			method: "POST",
			body: '{"everything":"arrives"}',
		});
		expect(provider.seen.at(-1)).toMatchObject({
			method: "POST",
			url: "/session/logout",
			body: '{"everything":"arrives"}',
		});
	});

	it("records the start as a redirect to the IdP and clears the last callback", async () => {
		const res = await get(base, START);
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe("https://idp.test/authorize?client_id=c&state=s");
		expect(res.headers.getSetCookie()).toEqual(["auth.session=pre; Path=/; HttpOnly"]);
		const s = await state(base);
		expect(s.start).toMatchObject({ status: 302, redirectedTo: "https://idp.test/authorize" });
		expect(s.callback).toBeNull();
		expect(s.store).toBeNull();
		expect(s.verdict).toBeNull();
		expect(s.report).toContain("no callback recorded yet");
		expect(s.fragment).toContain(
			"Redirected to https://idp.test/authorize — waiting for the callback",
		);
	});

	it("records a callback the provider accepted: keys, iss, lengths, the redirect, the cookie — and no values", async () => {
		const res = await get(
			base,
			`${CALLBACK}?state=abcdef&code=secretcode123&iss=${encodeURIComponent("https://accounts.google.com")}&scope=openid&hd=example.com`,
		);
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(`http://localhost:${proxyPort}/`);
		expect(provider.seen.at(-1)?.url).toContain("code=secretcode123");

		const s = await state(base);
		expect(s.callback).toEqual({
			at: expect.any(String),
			queryKeys: ["state", "code", "iss", "scope", "hd"],
			iss: "https://accounts.google.com",
			codeLength: 13,
			stateLength: 6,
			providerStatus: 302,
			providerLocation: `http://localhost:${proxyPort}/`,
			providerAnswer: null,
			sessionCookieSet: true,
		});
		expect(s.verdict).toEqual({
			issJudged: true,
			issPresent: true,
			issOk: true,
			loginOk: true,
			ok: true,
		});
		expect(s.report).toContain(
			"iss: https://accounts.google.com (expected https://accounts.google.com) ✅",
		);
		expect(s.report).toContain("302 → http://localhost:");
		expect(s.report).toContain("callback query keys: state, code, iss, scope, hd");
		expect(s.fragment).toContain(
			"OK — the callback carried the expected iss and the login succeeded",
		);
		expect(s.fragment).toContain("code 13 chars, state 6 chars (values not recorded)");

		// Neither the record, nor the report, nor the rendered page carries a value.
		const everything = JSON.stringify(s);
		expect(everything).not.toContain("secretcode123");
		expect(everything).not.toContain("abcdef");
		const md = await (await get(base, "/__live-check/report")).text();
		expect(md).toBe(s.report);
		expect(md).not.toContain("secretcode123");
	});

	it("records a callback the provider refused: the status and its JSON answer, no cookie, not OK", async () => {
		const res = await get(base, `${CALLBACK}?state=abcdef&code=secretcode123&fail=1`);
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: "invalid_request", error_description: "no iss" });

		const s = await state(base);
		expect(s.callback).toMatchObject({
			iss: null,
			providerStatus: 400,
			providerLocation: null,
			providerAnswer: { error: "invalid_request", error_description: "no iss" },
			sessionCookieSet: false,
		});
		expect(s.verdict).toEqual({
			issJudged: true,
			issPresent: false,
			issOk: false,
			loginOk: false,
			ok: false,
		});
		expect(s.report).toContain("iss: (absent) (expected https://accounts.google.com) ❌");
		expect(s.fragment).toContain("NG — the callback carried no iss");
		expect(s.fragment).toContain("HTTP 400");
		expect(JSON.stringify(s)).not.toContain("secretcode123");
	});

	it("judges an iss that is not the expected issuer as present but not OK", async () => {
		await get(
			base,
			`${CALLBACK}?state=abcdef&code=c&iss=${encodeURIComponent("https://accounts.google.com.evil")}`,
		);
		const s = await state(base);
		expect(s.verdict).toEqual({
			issJudged: true,
			issPresent: true,
			issOk: false,
			loginOk: true,
			ok: false,
		});
		expect(s.fragment).toContain("NG — iss is not the expected issuer");
	});

	it("renders what the IdP or the provider sent as text, never as markup", async () => {
		const evil = "</code><script>alert(1)</script>";
		await get(base, `${CALLBACK}?state=s&code=c&iss=${encodeURIComponent(evil)}&<b>=1`);
		const s = await state(base);
		expect(s.callback?.iss).toBe(evil);
		expect(s.callback?.queryKeys).toEqual(["state", "code", "iss", "<b>"]);
		expect(s.fragment).not.toContain("<script>");
		expect(s.fragment).not.toContain("<b>");
		expect(s.fragment).toContain("&lt;/code&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
		expect(s.fragment).toContain("state, code, iss, &lt;b&gt;");
	});

	it("answers 502 when the provider is not there, rather than hanging", async () => {
		await provider.close();
		const res = await get(base, "/anything");
		expect(res.status).toBe(502);
		expect(await res.json()).toMatchObject({ error: "provider_unreachable" });
		provider = fakeProvider(providerPort, "google", `http://localhost:${proxyPort}/`);
		await provider.listen();
	});
});

describe("tools/live-check proxy without an expected issuer", () => {
	const START = "/session/oauth/federation/oidc";
	const CALLBACK = `${START}/callback`;
	let child: ChildProcess;
	let provider: ReturnType<typeof fakeProvider>;
	let base: string;

	beforeAll(async () => {
		const proxyPort = await freePort();
		const providerPort = await freePort();
		base = `http://127.0.0.1:${proxyPort}`;
		provider = fakeProvider(providerPort, "oidc", `http://localhost:${proxyPort}/`);
		await provider.listen();
		child = await startProxy({
			LIVE_CHECK_PORT: String(proxyPort),
			LIVE_CHECK_PROVIDER_PORT: String(providerPort),
			LIVE_CHECK_FEDERATION: "oidc",
			LIVE_CHECK_EXPECTED_ISS: "",
		});
	});
	afterAll(async () => {
		child?.kill();
		await provider?.close();
	});

	it("names its federation in the paths it watches and in the page", async () => {
		const html = await (await get(base, "/")).text();
		expect(html).toContain(`href="${START}"`);
		expect(html).toContain("iss recorded, not judged");
		expect((await state(base)).expectedIss).toBeNull();
	});

	it("records an iss that arrives without judging it — a login is OK on its own", async () => {
		await get(
			base,
			`${CALLBACK}?state=s&code=c&iss=${encodeURIComponent("https://idp.example.com")}`,
		);
		const s = await state(base);
		expect(s.callback?.providerStatus).toBe(302);
		expect(s.verdict).toEqual({
			issJudged: false,
			issPresent: true,
			issOk: true,
			loginOk: true,
			ok: true,
		});
		expect(s.report).toContain(
			"iss: https://idp.example.com (not judged: the profile names no expected issuer)",
		);
		expect(s.fragment).toContain("OK — the login succeeded (iss recorded, not judged)");
	});

	it("does not fail a callback without an iss — the provider did not require one", async () => {
		await get(base, `${CALLBACK}?state=s&code=c`);
		const s = await state(base);
		expect(s.verdict).toEqual({
			issJudged: false,
			issPresent: false,
			issOk: true,
			loginOk: true,
			ok: true,
		});
		expect(s.report).toContain("iss: (absent) (not judged: the profile names no expected issuer)");
		expect(s.fragment).toContain("OK — the login succeeded (iss absent, not judged)");
	});

	it("still reports a refused login as not OK", async () => {
		await get(base, `${CALLBACK}?state=s&code=c&fail=1`);
		const s = await state(base);
		expect(s.verdict).toMatchObject({ issJudged: false, loginOk: false, ok: false });
		expect(s.fragment).toContain("iss absent, but the login failed (HTTP 400)");
	});
});
