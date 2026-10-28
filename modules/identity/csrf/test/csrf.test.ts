import { type Cookies, cookies } from "@mod/cookies";
import cookiesModule from "@mod/cookies/module";
import { listening, routes, site, use } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	type Assembly,
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { carried, checking } from "../src/check.ts";
import { csrfChecked, formTokens, originEvidence } from "../src/contract.ts";
import csrfModule from "../src/module.ts";
import { csrfStandIn } from "../src/testing.ts";

/** The request cookie that carries a csrf token, named the way cookies names it here. */
const cookieOf = (jar: Cookies, value: string) =>
	jar.write(carried.cookie, value, 1).split(";")[0] ?? "";
const runtime = quietRuntime();
const boot = (origin = "https://as.example", modules: readonly Module[] = [csrfModule]) =>
	assemble({
		modules: [http, cookiesModule, ...modules],
		config: {
			// A plain-http origin is one only a development deployment takes.
			...kernelConfig({ environment: origin.startsWith("http:") ? "development" : "production" }),
			...httpConfig({
				"trusted-proxies": ["127.0.0.1"],
				...(origin ? { "public-origin": origin } : {}),
				"insecure-origin": origin.startsWith("http:"),
			}),
		},
		runtime,
	});

/** The check as the module builds it, from the assembled http. */
const checkOf = (app: Assembly) => {
	const { origin, secureCookies } = app.get(site);
	return checking(origin ?? "", secureCookies, app.get(cookies));
};
const token = "t".repeat(43);

describe("the check", () => {
	it("passes on same-origin evidence or a matching token, and refuses any foreign evidence [guarantee-9-a]", async () => {
		const app = await boot();
		const check = checkOf(app);
		const named = (value: string) => cookieOf(app.get(cookies), value);
		type Sent = [headers: Record<string, string>, form?: Record<string, string[]>];
		const at = ([headers, form = {}]: Sent, scheme: "http" | "https" = "https") =>
			check(
				testRequest({
					method: "POST",
					headers: new Map(Object.entries(headers)),
					form: new Map(Object.entries(form)),
					source: { scheme },
				}),
			);
		const cookie = named(token);
		const long = "t".repeat(44);
		const passed: Record<string, Sent> = {
			"Origin is ours": [{ origin: "https://as.example" }],
			"Referer is ours": [{ referer: "https://as.example/login" }],
			"Origin: null falls through to the token": [
				{ origin: "null", cookie, "x-csrf-token": token },
			],
			"an unreadable Referer falls through to the token": [
				{ referer: "::not a url::", cookie, "x-csrf-token": token },
			],
			"the header token matches the cookie": [{ cookie, "x-csrf-token": token }],
			"the field token, sent once": [{ cookie }, { csrf_token: [token] }],
			"the header wins over the field": [
				{ cookie, "x-csrf-token": token },
				{ csrf_token: ["other"] },
			],
		};
		const refused: Record<string, Sent> = {
			"a foreign Origin, even with the token": [
				{ origin: "https://evil.example", cookie, "x-csrf-token": token },
			],
			"a foreign Referer beside our Origin": [
				{ origin: "https://as.example", referer: "https://evil.example/" },
			],
			"Origin: null and no token": [{ origin: "null" }],
			"the field token sent twice": [{ cookie }, { csrf_token: [token, token] }],
			"a wrong header beside a right field": [
				{ cookie, "x-csrf-token": "other" },
				{ csrf_token: [token] },
			],
			"the cookie sent twice": [{ cookie: `${cookie}; ${cookie}`, "x-csrf-token": token }],
			"a token too short": [{ cookie: named("short"), "x-csrf-token": "short" }],
			"a token too long": [{ cookie: named(long), "x-csrf-token": long }],
			"a cookie and no token": [{ cookie }],
			"a token and no cookie": [{ "x-csrf-token": token }],
			"a token that differs from the cookie": [{ cookie, "x-csrf-token": "other" }],
			"a token of the same length that differs": [{ cookie, "x-csrf-token": "u".repeat(43) }],
			"no evidence and no token": [{}],
		};
		for (const [name, sent] of Object.entries(passed)) expect(at(sent), name).toBe("passed");
		for (const [name, sent] of Object.entries(refused)) expect(at(sent), name).toBe("refused");
		expect(at([{ origin: "https://as.example" }], "http"), "plain http").toBe("refused");
	});

	it("reads the field token from a JSON body only as a string [guarantee-9-a]", async () => {
		const app = await boot();
		const check = checkOf(app);
		const cookie = cookieOf(app.get(cookies), token);
		const sentAsJson = (json: Record<string, unknown>) =>
			check(testRequest({ method: "POST", headers: new Map([["cookie", cookie]]), json }));
		expect(sentAsJson({ csrf_token: token })).toBe("passed");
		expect(sentAsJson({ csrf_token: [token] })).toBe("refused");
		expect(sentAsJson({ csrf_token: "other" })).toBe("refused");
	});

	it("takes the token over plain http only where http says cookies cannot be secure", async () => {
		const app = await boot("http://as.example");
		const request = testRequest({
			method: "POST",
			headers: new Map([
				["cookie", cookieOf(app.get(cookies), token)],
				["x-csrf-token", token],
			]),
			source: { scheme: "http" },
		});
		expect(checkOf(app)(request)).toBe("passed");
	});
});

describe("the route", () => {
	it("hands out a token with its cookie, uncached, and keeps a valid one sent over HTTPS", async () => {
		const app = await boot();
		await app.start();
		try {
			const url = `http://127.0.0.1:${app.get(listening).port()}/session/csrf`;
			const https = { "x-forwarded-proto": "https" };
			const handedOut = async (headers: Record<string, string>) => {
				const res = await fetch(url, { headers });
				const body = (await res.json()) as Record<string, unknown> & { csrf_token: string };
				return { res, body, token: body.csrf_token };
			};
			const first = await handedOut(https);
			expect(first.res.headers.get("cache-control")).toBe("no-store");
			expect(first.body).toMatchObject({
				header_name: "x-csrf-token",
				body_field: "csrf_token",
				expires_in: 7200,
			});
			const jar = app.get(cookies);
			expect(first.res.headers.getSetCookie()[0]).toBe(jar.write("csrf", first.token, 7200));
			const kept = cookieOf(jar, first.token);
			expect((await handedOut({ ...https, cookie: kept })).token).toBe(first.token);
			expect((await handedOut({ cookie: kept })).token).not.toBe(first.token);
			const renewed = await handedOut({ ...https, cookie: cookieOf(jar, "short") });
			expect(renewed.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
		} finally {
			await app.stop(1000);
		}
	});

	it("is not served by the stand-in", async () => {
		const app = await boot("https://as.example", [csrfStandIn]);
		await app.start();
		try {
			const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/session/csrf`);
			expect(res.status).toBe(404);
		} finally {
			await app.stop(1000);
		}
	});
});

const guarded = defineModule({ name: "guarded", takes: [] }, (m) =>
	(["GET", "POST", "DELETE"] as const).map((method) =>
		m.contribute(routes).by(() => ({
			method,
			path: "/guarded",
			uses: [use(csrfChecked)],
			...(method === "GET" ? { changesState: false } : { unlimited: "a test route" }),
			handle: () => ({ status: 204 }),
		})),
	),
);

describe("without a public origin", () => {
	it("refuses to start the module, as there is nothing to compare evidence with", async () => {
		await expect(
			assemble({
				modules: [http, cookiesModule, csrfModule],
				config: { ...kernelConfig(), ...httpConfig({}) },
				runtime,
			}),
		).rejects.toMatchObject({ name: "BootRefused", refusals: [{ where: "csrf" }] });
	});

	it("starts the stand-in, which then refuses every unsafe request [guarantee-9-a]", async () => {
		const app = await boot("", [csrfStandIn, guarded]);
		await app.start();
		try {
			const base = `http://127.0.0.1:${app.get(listening).port()}/guarded`;
			const headers = {
				"x-forwarded-proto": "https",
				origin: "https://as.example",
				"sec-fetch-site": "same-origin",
				cookie: cookieOf(app.get(cookies), token),
				"x-csrf-token": token,
			};
			const post = async (sent: Record<string, string>) =>
				(await fetch(base, { method: "POST", headers: sent })).status;
			expect(await post({ "x-forwarded-proto": "https" })).toBe(403);
			expect(await post(headers)).toBe(403);
			expect((await fetch(base)).status).toBe(204);
			const request = testRequest({ method: "POST", headers: new Map(Object.entries(headers)) });
			expect(app.get(originEvidence).sameOrigin(request)).toBe(false);
		} finally {
			await app.stop(1000);
		}
	});
});

describe.each([
	["the module", csrfModule],
	["the stand-in", csrfStandIn],
])("the contract, as %s keeps it", (_, module) => {
	it("offers the policy to routes: a GET passes, any other method only on evidence or the token [guarantee-9-a] [oidc-core-3.1.2.3-e]", async () => {
		const app = await boot("https://as.example", [module, guarded]);
		await app.start();
		try {
			const base = `http://127.0.0.1:${app.get(listening).port()}/guarded`;
			const post = (headers: Record<string, string>) =>
				fetch(base, { method: "POST", headers: { "x-forwarded-proto": "https", ...headers } });
			const refused = await post({});
			expect([refused.status, refused.headers.get("cache-control"), await refused.json()]).toEqual([
				403,
				"no-store",
				{ error: "csrf" },
			]);
			expect((await fetch(base)).status).toBe(204);
			expect((await fetch(base, { method: "DELETE" })).status).toBe(403);
			const cookie = cookieOf(app.get(cookies), token);
			const statuses = {
				"Origin is ours": await post({ origin: "https://as.example" }),
				"the token matches its cookie": await post({ cookie, "x-csrf-token": token }),
				"a foreign Referer beside our Origin": await post({
					origin: "https://as.example",
					referer: "https://evil.example/",
				}),
				"plain http where cookies can be secure": await fetch(base, {
					method: "POST",
					headers: { "x-forwarded-proto": "http", origin: "https://as.example" },
				}),
			};
			expect(Object.fromEntries(Object.entries(statuses).map(([k, r]) => [k, r.status]))).toEqual({
				"Origin is ours": 204,
				"the token matches its cookie": 204,
				"a foreign Referer beside our Origin": 403,
				"plain http where cookies can be secure": 403,
			});
		} finally {
			await app.stop(1000);
		}
	});

	it("marks the policy own-site for every method but GET", async () => {
		const declared = (method: "GET" | "POST" | "PUT" | "DELETE") =>
			defineModule({ name: "declared", takes: [] }, (m) => [
				m.contribute(routes).by(() => ({
					method,
					path: "/declared",
					changesState: true,
					uses: [use(csrfChecked)],
					unlimited: "a test route",
					handle: () => ({ status: 204 }),
				})),
			]);
		for (const method of ["POST", "PUT", "DELETE"] as const) {
			const app = await boot("https://as.example", [module, declared(method)]);
			expect(app.get(listening), method).toBeDefined();
		}
		await expect(boot("https://as.example", [module, declared("GET")])).rejects.toThrow(
			BootRefused,
		);
	});

	it("answers same origin only on positive evidence: Origin is ours, or Sec-Fetch-Site says same-origin", async () => {
		const evidence = (await boot("https://as.example", [module])).get(originEvidence);
		const sameOrigin = (headers: Record<string, string>, scheme: "http" | "https" = "https") =>
			evidence.sameOrigin(
				testRequest({
					method: "POST",
					headers: new Map(Object.entries(headers)),
					source: { scheme },
				}),
			);
		const ours = "https://as.example";
		const evil = "https://evil.example";
		const cases: [string, Record<string, string>, boolean, ("http" | "https")?][] = [
			["Origin is ours", { origin: ours }, true],
			["Sec-Fetch-Site is same-origin", { "sec-fetch-site": "same-origin" }, true],
			[
				"all three agree",
				{ origin: ours, "sec-fetch-site": "same-origin", referer: `${ours}/x` },
				true,
			],
			["no evidence", {}, false],
			["only a Referer of ours", { referer: `${ours}/login` }, false],
			["Origin: null", { origin: "null" }, false],
			["a foreign Origin", { origin: evil }, false],
			["Origin sent twice", { origin: `${ours}, ${ours}` }, false],
			[
				"a foreign Origin beside same-origin",
				{ origin: evil, "sec-fetch-site": "same-origin" },
				false,
			],
			["our Origin beside cross-site", { origin: ours, "sec-fetch-site": "cross-site" }, false],
			["our Origin beside a foreign Referer", { origin: ours, referer: `${evil}/` }, false],
			["Sec-Fetch-Site is same-site", { "sec-fetch-site": "same-site" }, false],
			["Sec-Fetch-Site is none", { "sec-fetch-site": "none" }, false],
			["plain http where cookies can be secure", { origin: ours }, false, "http"],
		];
		for (const [name, headers, expected, scheme] of cases) {
			expect(sameOrigin(headers, scheme), name).toBe(expected);
		}
		const plain = (await boot("http://as.example", [module])).get(originEvidence);
		const overHttp = testRequest({
			method: "POST",
			headers: new Map([["origin", "http://as.example"]]),
			source: { scheme: "http" },
		});
		expect(plain.sameOrigin(overHttp)).toBe(true);
	});
});

it("takes every handle its takes name, the module and its stand-in alike, at a public origin", async () => {
	const config = { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) };
	for (const module of [csrfModule, csrfStandIn]) {
		expect(
			(await takesUnused({ modules: [http, cookiesModule, module], config })).csrf,
		).toBeUndefined();
	}
});

it("takes cookies in its stand-in without a public origin too, for the form tokens it hands out", async () => {
	// The policy refuses every unsafe request without an origin; the form tokens still need the cookie.
	const config = { ...kernelConfig(), ...httpConfig() };
	const unused = await takesUnused({ modules: [http, cookiesModule, csrfStandIn], config });
	expect(unused.csrf).toBeUndefined();
});

describe("a token for a form the server draws", () => {
	for (const [name, module] of [
		["the module", csrfModule],
		["the stand-in", csrfStandIn],
	] as const) {
		it(`is handed out by ${name} with its cookie, a valid one the request holds kept, and passes the policy from a form`, async () => {
			const app = await boot("https://as.example", [module, guarded]);
			await app.start();
			try {
				const jar = app.get(cookies);
				const issued = app.get(formTokens).issue(testRequest({ method: "GET", path: "/page" }));
				expect(issued.field).toBe("csrf_token");
				expect(issued.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
				expect(issued.cookies).toEqual([jar.write("csrf", issued.token, 7200)]);
				const cookie = cookieOf(jar, issued.token);
				const again = app
					.get(formTokens)
					.issue(
						testRequest({ method: "GET", path: "/page", headers: new Map([["cookie", cookie]]) }),
					);
				expect(again.token).toBe(issued.token);
				// A form posted from a page under no-referrer: Origin null, no Referer; the token carries it.
				const base = `http://127.0.0.1:${app.get(listening).port()}/guarded`;
				const form = (body: string) =>
					fetch(base, {
						method: "POST",
						headers: {
							"x-forwarded-proto": "https",
							origin: "null",
							cookie,
							"content-type": "application/x-www-form-urlencoded",
						},
						body,
					});
				expect((await form(`csrf_token=${issued.token}`)).status).toBe(204);
				expect((await form("")).status).toBe(403);
				expect((await form(`csrf_token=${"x".repeat(43)}`)).status).toBe(403);
			} finally {
				await app.stop(1000);
			}
		});
	}
});
