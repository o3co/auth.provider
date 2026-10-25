import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import {
	quietRuntime,
	recordingLog,
	switchedModule,
	takesUnused,
	unavailableSwitch,
} from "@mod/kernel/testing";
import { loginGates, logins, returnPaths } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import rateLimitModule from "@mod/rate-limit/module";
import secretHashModule from "@mod/secret-hash/module";
import { type Sessions, sessions } from "@mod/session";
import { sessionStandIn, stubSessions } from "@mod/session/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { type Users, users } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { afterEach, describe, expect, it } from "vitest";
import loginModule from "../src/module.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

interface Setup {
	readonly login?: Record<string, unknown>;
	readonly gates?: Record<string, unknown>;
	/** In place of login-gates, a `logins` answering as a test needs. */
	readonly logins?: Module;
	readonly trusted?: string[];
	readonly origin?: string;
	readonly sessions?: Module;
	readonly users?: Module;
	readonly extra?: Module[];
	/** A log in place of the quiet one. */
	readonly log?: ReturnType<typeof recordingLog>;
}

async function serve(setup: Setup = {}) {
	const simulated = simulatedStore();
	const audit = auditStandIn();
	const origin = setup.origin ?? "https://as.example";
	const app = await assemble({
		modules: [
			http,
			setup.logins ?? gatesModule,
			csrfStandIn,
			cookiesModule,
			setup.users ?? usersModule,
			secretHashModule,
			memoryUsersStores().module,
			setup.sessions ?? sessionStandIn,
			subjectRevocationStandIn,
			rateLimitModule,
			simulated.module,
			loginModule,
			audit.module,
			...(setup.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({
				"trusted-proxies": setup.trusted ?? ["127.0.0.1"],
				"public-origin": origin,
				"insecure-origin": origin.startsWith("http:"),
			}),
			// bob's subject differs from his identifier, so an event can show which one it carries.
			...usersConfig([
				testUser("alice", "correct horse"),
				testUser("bob", "battery staple", { subject: "s-bob" }),
				testUser("carol", "pw", { attributes: carol }),
			]),
			"login-password": setup.login ?? {},
			...(setup.logins ? {} : { "login-gates": setup.gates ?? {} }),
		},
		runtime: setup.log ? quietRuntime({ log: setup.log.log }) : runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const login = async (
		form: Record<string, string> | string,
		headers: Record<string, string> = {},
	) => {
		const res = await fetch(`${base}/session/login`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.9",
				origin,
				...headers,
			},
			body: typeof form === "string" ? form : new URLSearchParams(form),
		});
		const text = await res.text();
		return {
			status: res.status,
			headers: res.headers,
			body: (text ? JSON.parse(text) : undefined) as Record<string, unknown>,
		};
	};
	return { app, simulated, login, events: audit.events };
}
const right = { username: "alice", password: "correct horse" };
const carol = {
	email: "carol@example.com",
	email_verified: true,
	name: "Carol",
	picture: "https://pictures.example/carol",
	groups: ["staff"],
	role: "admin",
};
const json = { "content-type": "application/json" };
const from = (address: string) => ({ "x-forwarded-for": address });

describe("login-password answers", () => {
	it("opens a session for the right password with an empty body, and answers every failure alike", async () => {
		const { login } = await serve();
		const ok = await login(right);
		expect([ok.status, ok.body]).toEqual([200, {}]);
		expect(ok.headers.get("cache-control")).toBe("no-store");
		expect(ok.headers.getSetCookie()[0]).toMatch(/^__Host-session=/);
		for (const form of [
			{ username: "alice", password: "nope" },
			{ username: "nobody", password: "correct horse" },
		]) {
			const failed = await login(form);
			expect([failed.status, failed.body], form.username).toEqual([
				401,
				{ error: "invalid_credentials" },
			]);
			expect(failed.headers.get("cache-control")).toBe("no-store");
			expect(failed.headers.getSetCookie()).toEqual([]);
		}
	});

	it("refuses a missing or empty credential as a malformed request, and opens no session", async () => {
		const { login } = await serve();
		for (const form of [
			{},
			{ username: "alice" },
			{ password: "correct horse" },
			{ username: "", password: "correct horse" },
			{ username: "alice", password: "" },
		]) {
			const res = await login(form);
			expect([res.status, res.body], JSON.stringify(form)).toEqual([
				400,
				{ error: "invalid_request" },
			]);
			expect(res.headers.get("cache-control")).toBe("no-store");
			expect(res.headers.getSetCookie()).toEqual([]);
		}
	});

	it("takes the same fields as JSON strings, a credential of another type counting as absent", async () => {
		const { login } = await serve({ gates: { "return-targets": ["https://app.example/"] } });
		const ok = await login(JSON.stringify(right), json);
		expect([ok.status, ok.body]).toEqual([200, {}]);
		expect(ok.headers.getSetCookie()[0]).toMatch(/^__Host-session=/);
		const back = await login(
			JSON.stringify({ ...right, redirect_to: "https://app.example/" }),
			json,
		);
		expect([back.status, back.body]).toEqual([200, { redirect_to: "https://app.example/" }]);
		const none = await login(JSON.stringify({ ...right, redirect_to: null }), json);
		expect([none.status, none.body]).toEqual([200, {}]);
		for (const typed of [{ password: ["correct horse"] }, { username: 1 }, { password: null }]) {
			const res = await login(JSON.stringify({ ...right, ...typed }), json);
			expect([res.status, res.body], JSON.stringify(typed)).toEqual([
				400,
				{ error: "invalid_request" },
			]);
			expect(res.headers.getSetCookie()).toEqual([]);
		}
		expect((await login("username=alice", { "content-type": "text/plain" })).status).toBe(415);
	});

	it("refuses without CSRF evidence, and with a repeated field", async () => {
		const { login } = await serve();
		expect((await login(right, { origin: "" })).status).toBe(403);
		expect((await login(right, { origin: "https://evil.example" })).status).toBe(403);
		const twice = await login("username=alice&username=alice&password=correct+horse");
		expect([twice.status, twice.body]).toEqual([400, { error: "repeated_parameter" }]);
	});

	it("replaces the session the request carried, and closes it", async () => {
		const { app, login } = await serve();
		const first = (await login(right)).headers.getSetCookie()[0]?.split(";")[0] ?? "";
		const second =
			(await login(right, { cookie: first })).headers.getSetCookie()[0]?.split(";")[0] ?? "";
		expect(second).not.toBe(first);
		const enter = (cookie: string) =>
			app.get(sessions).enter(testRequest({ headers: new Map([["cookie", cookie]]) }));
		expect(await enter(first)).toBeUndefined();
		expect(await enter(second)).toBeDefined();
	});

	it("gives no cookie when the session cannot be opened after a match", async () => {
		const down = unavailableSwitch<Sessions>("session");
		down.unavailable("complete");
		const failing = defineModule({ name: "session", takes: [] }, (m) => [
			m.provide(sessions).by(() => down.wrap(stubSessions())),
		]);
		const { login, events } = await serve({ sessions: failing });
		const res = await login(right);
		expect([res.status, res.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(res.headers.getSetCookie()).toEqual([]);
		expect(events).toEqual([]);
	});
});

describe("login-password when users cannot answer", () => {
	it("answers 503 without a cookie, and records nothing", async () => {
		const down = unavailableSwitch<Users>("users");
		down.unavailable("verify");
		const { login, events } = await serve({ users: switchedModule(usersModule, users, down) });
		const res = await login(right);
		expect([res.status, res.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(res.headers.getSetCookie()).toEqual([]);
		expect(events).toEqual([]);
	});
});

describe("login-password return targets", () => {
	it("sends the user back only to a listed https target, exactly, and nowhere when none is listed", async () => {
		const none = await serve();
		expect((await none.login({ ...right, redirect_to: "https://app.example/" })).body).toEqual({
			error: "invalid_redirect",
		});
		await stop();
		const listed = await serve({ gates: { "return-targets": ["https://app.example/"] } });
		const back = await listed.login({ ...right, redirect_to: "https://app.example/" });
		expect([back.status, back.body]).toEqual([200, { redirect_to: "https://app.example/" }]);
		for (const near of [
			"https://app.example",
			"https://app.example/?",
			"HTTPS://app.example/",
			"https://app.example/#x",
			"https://app.example/x",
		]) {
			expect((await listed.login({ ...right, redirect_to: near })).status, near).toBe(400);
		}
	});

	it("refuses a JSON destination of another type than a string or null, before the credentials", async () => {
		const { login } = await serve({ gates: { "return-targets": ["https://app.example/"] } });
		for (const redirect_to of [1, {}, ["https://app.example/"], true]) {
			for (const password of ["correct horse", "nope", ""]) {
				const body = JSON.stringify({ username: "alice", password, redirect_to });
				const res = await login(body, json);
				expect([res.status, res.body], body).toEqual([400, { error: "invalid_redirect" }]);
				expect(res.headers.getSetCookie()).toEqual([]);
			}
		}
	});

	it("refuses to start with limits looser than its bounds, or a window that names no unit", async () => {
		for (const login of [
			{ attempts: 101 },
			{ window: "59s" },
			{ window: 900 },
			{ window: "900" },
		]) {
			const refused = await serve({ login }).catch((error) => error);
			expect(refused, JSON.stringify(login)).toBeInstanceOf(BootRefused);
			expect(refused.refusals.map((r: { where: string }) => r.where).join()).toMatch(
				/login-password/,
			);
		}
	});

	it("refuses an empty destination in a form, before the credentials", async () => {
		const { login } = await serve({ gates: { "return-targets": ["https://app.example/"] } });
		const res = await login({ ...right, redirect_to: "" });
		expect([res.status, res.body]).toEqual([400, { error: "invalid_redirect" }]);
	});
});

describe("login-password attempts", () => {
	it("counts every attempt before checking it, successful or not, known user or not", async () => {
		const { login } = await serve({ login: { attempts: 2, window: "1m" } });
		await login(right, from("198.51.100.1"));
		await login({ username: "nobody", password: "x" }, from("198.51.100.1"));
		const limited = await login(right, from("198.51.100.1"));
		expect([limited.status, limited.body]).toEqual([429, { error: "too_many_attempts" }]);
		const wait = Number(limited.headers.get("retry-after"));
		expect(wait).toBeGreaterThan(0);
		expect(wait).toBeLessThanOrEqual(60);
		expect((await login(right, from("198.51.100.2"))).status).toBe(200);
	});

	it("counts a malformed request too, after CSRF and before anything else is checked", async () => {
		const { login } = await serve({ login: { attempts: 2, window: "1m" } });
		const sender = from("198.51.100.3");
		expect((await login(right, { ...sender, origin: "" })).status).toBe(403);
		expect((await login("username=a&username=b&password=c", sender)).status).toBe(400);
		expect(
			(await login({ ...right, redirect_to: "https://elsewhere.example/" }, sender)).status,
		).toBe(400);
		expect((await login(right, sender)).status).toBe(429);
	});

	it("counts a request without credentials too", async () => {
		const { login } = await serve({ login: { attempts: 1, window: "1m" } });
		const sender = from("198.51.100.4");
		expect((await login({ username: "alice" }, sender)).status).toBe(400);
		expect((await login(right, sender)).status).toBe(429);
	});

	it("counts an IPv6 sender by its /64, and a sender with a port as the sender", async () => {
		const { login } = await serve({ login: { attempts: 1, window: "1m" } });
		await login(right, from("2001:db8::1"));
		expect((await login(right, from("2001:DB8:0:0::2"))).status).toBe(429);
		expect((await login(right, from("2001:db8:0:1::1"))).status).toBe(200);
		await login(right, from("198.51.100.7:1111"));
		expect((await login(right, from("198.51.100.7:2222"))).status).toBe(429);
	});

	it("ignores forwarded senders from an untrusted peer", async () => {
		const { login } = await serve({
			trusted: [],
			origin: "http://as.example",
			login: { attempts: 1, window: "1m" },
		});
		await login(right, from("198.51.100.1"));
		expect((await login(right, from("198.51.100.2"))).status).toBe(429);
	});

	it("refuses with 503 when a trusted proxy does not say who sent the request", async () => {
		const { login } = await serve();
		for (const headers of [
			{ "x-forwarded-for": "" },
			{ "x-forwarded-for": "", forwarded: "for=198.51.100.1" },
		]) {
			const res = await login(right, headers);
			expect([res.status, res.body], JSON.stringify(headers)).toEqual([
				503,
				{ error: "service_unavailable" },
			]);
		}
	});

	it("answers 503 when it cannot count", async () => {
		const { simulated, login } = await serve();
		simulated.unreachable(true);
		const res = await login(right, from("198.51.100.1"));
		expect([res.status, res.body]).toEqual([503, { error: "service_unavailable" }]);
		expect(res.headers.getSetCookie()).toEqual([]);
	});
});

it("sends the user back to a contributed path on the public origin, with any query, and nowhere near it", async () => {
	const authorize = defineModule({ name: "return-path", takes: [] }, (m) => [
		m.contribute(returnPaths).by(() => ({ path: "/oauth/authorize" })),
	]);
	const device = defineModule({ name: "another-return-path", takes: [] }, (m) => [
		m.contribute(returnPaths).by(() => ({ path: "/device" })),
	]);
	const { login } = await serve({ extra: [authorize, device] });
	const back = "https://as.example/oauth/authorize?client_id=app&state=x";
	expect((await login({ ...right, redirect_to: back })).body).toEqual({ redirect_to: back });
	const page = "https://as.example/device?user_code=x";
	expect((await login({ ...right, redirect_to: page })).body).toEqual({ redirect_to: page });
	for (const near of [
		"https://as.example/oauth/authorize/x?y=1",
		"https://as.example/oauth/other?y=1",
		"https://as.example/oauth/authorize?x=1#frag",
		"https://u:p@as.example/oauth/authorize?x=1",
		"https://as.example/oauth/x/../authorize?x=1",
		"https://as.example:8443/oauth/authorize?x=1",
		"http://as.example/oauth/authorize?x=1",
		"https://evil.example/oauth/authorize?x=1",
		"/oauth/authorize?x=1",
	]) {
		expect((await login({ ...right, redirect_to: near })).status, near).toBe(400);
	}
});

it("answers a login a gate holds with 403, the gate's answer and its cookies, and opens no session", async () => {
	const carried: unknown[] = [];
	const gate = defineModule({ name: "gate", takes: [] }, (m) => [
		m.contribute(loginGates).by(() => ({
			name: "second",
			hold: async (_request, _facts, done) => {
				carried.push(done);
				return { kind: "held" as const, answer: { step: "next" }, cookies: ["step=1; Path=/"] };
			},
		})),
	]);
	const { login, events } = await serve({
		extra: [gate],
		gates: { "return-targets": ["https://app.example/back"] },
	});
	const held = await login({
		username: "alice",
		password: "correct horse",
		redirect_to: "https://app.example/back",
	});
	expect([held.status, held.body]).toEqual([403, { step: "next" }]);
	expect(held.headers.get("cache-control")).toBe("no-store");
	expect(held.headers.getSetCookie()).toEqual(["step=1; Path=/"]);
	expect(carried).toEqual([{ redirect_to: "https://app.example/back" }]);
	expect(events).toEqual([
		{
			kind: "login.held",
			subject: "alice",
			attributes: { method: "password", source: "198.51.100.9" },
			at: expect.any(Number),
		},
	]);
});

it("records each login that opens a session or fails on credentials, with its source and no identifier on failure", async () => {
	const { login, events } = await serve();
	await login(right);
	await login({ username: "alice", password: "nope" });
	await login({ username: "nobody", password: "correct horse" });
	await login({ username: "alice" });
	const at = expect.any(Number);
	const attributes = { method: "password", source: "198.51.100.9" };
	const failed = { kind: "login.failed", attributes, at };
	expect(events).toEqual([
		{ kind: "login.succeeded", subject: "alice", attributes, at },
		failed,
		failed,
	]);
});

it("records the subject, never the username, and a password too long to check as a failure", async () => {
	const { login, events } = await serve();
	await login({ username: "bob", password: "battery staple" });
	await login({ username: "bob", password: "x".repeat(2000) });
	const attributes = { method: "password", source: "198.51.100.9" };
	expect(events).toEqual([
		{ kind: "login.succeeded", subject: "s-bob", attributes, at: expect.any(Number) },
		{ kind: "login.failed", attributes, at: expect.any(Number) },
	]);
	expect(JSON.stringify(events)).not.toMatch(/"bob"/);
});

it("declares the password as an amr it can prove", async () => {
	const { app } = await serve();
	expect(app.get(logins).achievable(["pwd"])).toBe(true);
});

it("holds no return targets of its own", async () => {
	await expect(
		serve({ login: { "return-targets": ["https://app.example/"] } }),
	).rejects.toBeInstanceOf(BootRefused);
});

it("passes the user's attributes from users' answer to the session, under the source users and users' names", async () => {
	const { app, login } = await serve();
	const attributesOf = async (username: string) => {
		const cookie = (await login({ username, password: "pw" })).headers.getSetCookie()[0] ?? "";
		const request = testRequest({ headers: new Map([["cookie", cookie.split(";")[0] ?? ""]]) });
		return (await app.get(sessions).enter(request))?.context.attributes;
	};
	const { role: _, ...named } = carol;
	expect(await attributesOf("carol")).toEqual({ source: "users", values: named });
	const cookie = (await login(right)).headers.getSetCookie()[0] ?? "";
	const request = testRequest({ headers: new Map([["cookie", cookie.split(";")[0] ?? ""]]) });
	expect((await app.get(sessions).enter(request))?.context).not.toHaveProperty("attributes");
});

it("reports the time it verified the password as the login's authentication time", async () => {
	const seen: unknown[] = [];
	const gate = defineModule({ name: "gate", takes: [] }, (m) => [
		m.contribute(loginGates).by(() => ({
			name: "watching",
			hold: async (_request, facts) => {
				seen.push(facts.authenticatedAt);
				return { kind: "pass" as const };
			},
		})),
	]);
	const { login } = await serve({ extra: [gate] });
	const before = Date.now();
	expect((await login(right)).status).toBe(200);
	const after = Date.now();
	const [at] = seen;
	expect(typeof at).toBe("number");
	expect(at as number).toBeGreaterThanOrEqual(before);
	expect(at as number).toBeLessThanOrEqual(after);
});

describe("login-password attempts per account", () => {
	const budget = {
		"account-attempts": 2,
		"account-window": "1h",
		"account-max-wait": "1m",
	};
	/** A sender of its own for each attempt, so only the attempts per account hold one back. */
	let sender = 10;
	const elsewhere = () => from(`198.51.100.${sender++}`);
	const wrong = (username: string) => ({ username, password: "wrong" });

	it("makes an identifier wait after its attempts, from any source, and answers alike whether its account exists", async () => {
		for (const username of ["alice", "nobody"]) {
			const { login } = await serve({ login: budget });
			expect((await login(wrong(username), elsewhere())).status, username).toBe(401);
			expect((await login(wrong(username), elsewhere())).status, username).toBe(401);
			const held = await login(wrong(username), elsewhere());
			expect([held.status, held.body], username).toEqual([429, { error: "too_many_attempts" }]);
			const wait = Number(held.headers.get("retry-after"));
			expect(wait, username).toBeGreaterThan(0);
			expect(wait, username).toBeLessThanOrEqual(60);
			await stop();
		}
	});

	it("checks no password while an identifier waits, and records nothing for it", async () => {
		const { login, events } = await serve({ login: budget });
		await login(wrong("alice"), elsewhere());
		await login(wrong("alice"), elsewhere());
		const before = events.length;
		const held = await login(right, elsewhere());
		expect([held.status, held.body]).toEqual([429, { error: "too_many_attempts" }]);
		expect(held.headers.getSetCookie()).toEqual([]);
		expect(events.length).toBe(before);
	});

	it("counts an identifier folded in case and width, and holds back no other identifier", async () => {
		const { login } = await serve({ login: budget });
		await login(wrong("alice"), elsewhere());
		await login(wrong("ALICE"), elsewhere());
		expect((await login(wrong("Ａｌｉｃｅ"), elsewhere())).status).toBe(429);
		expect((await login({ username: "bob", password: "battery staple" }, elsewhere())).status).toBe(
			200,
		);
	});

	it("never makes an identifier wait longer than the longest wait, and lets it through once that has passed", async () => {
		const { login, simulated } = await serve({ login: budget });
		for (let i = 0; i < 12; i++) {
			const res = await login(wrong("alice"), elsewhere());
			if (res.status === 429) {
				expect(Number(res.headers.get("retry-after"))).toBeLessThanOrEqual(60);
				simulated.shiftClock(60_000);
			}
		}
		simulated.shiftClock(60_000);
		expect((await login(right, elsewhere())).status).toBe(200);
	});

	it("hands back the attempt of a guess users could not judge", async () => {
		const down = unavailableSwitch<Users>("users");
		const { login } = await serve({
			login: { ...budget, "account-attempts": 1 },
			users: switchedModule(usersModule, users, down),
		});
		down.unavailable("verify");
		expect((await login(wrong("alice"), elsewhere())).status).toBe(503);
		down.restore();
		expect((await login(wrong("alice"), elsewhere())).status).toBe(401);
		expect((await login(wrong("alice"), elsewhere())).status).toBe(429);
	});

	it("starts its count again after the right password", async () => {
		const { login } = await serve({ login: budget });
		await login(wrong("alice"), elsewhere());
		expect((await login(right, elsewhere())).status).toBe(200);
		expect((await login(wrong("alice"), elsewhere())).status).toBe(401);
		expect((await login(wrong("alice"), elsewhere())).status).toBe(401);
		expect((await login(wrong("alice"), elsewhere())).status).toBe(429);
	});

	it("refuses to boot on attempts, a window or a longest wait out of bounds, or a wait that names no unit", async () => {
		for (const login of [
			{ "account-attempts": 0 },
			{ "account-attempts": 101 },
			{ "account-window": "59s" },
			{ "account-max-wait": "0s" },
			{ "account-max-wait": "1.5s" },
			{ "account-max-wait": 60 },
			{ "account-window": "10m", "account-max-wait": "15m" },
		]) {
			await expect(serve({ login }), JSON.stringify(login)).rejects.toBeInstanceOf(BootRefused);
		}
	});
});

describe("login-password under a gate that refuses", () => {
	/** A `logins` whose login answers `outcome`, or throws it. */
	const answering = (outcome: () => Promise<unknown>) =>
		defineModule({ name: "logins-stand-in", takes: [] }, (m) => [
			m.provide(logins).by(() => ({
				login: outcome as never,
				resume: outcome as never,
				achievable: () => true,
				returnAllowed: () => true,
			})),
		]);
	const budget = { "account-attempts": 2, "account-window": "1h", "account-max-wait": "1m" };
	let sender = 60;
	const elsewhere = () => from(`198.51.100.${sender++}`);

	it("answers a refused login as a wrong password, in its answer, its record and its count", async () => {
		const refused = async () => ({ kind: "refused", gate: "credential-policy", cookies: [] });
		const { login, events } = await serve({ login: budget, logins: answering(refused) });
		const wrong = await login({ username: "bob", password: "wrong" }, elsewhere());
		const refusedOne = await login({ username: "alice", password: "correct horse" }, elsewhere());
		expect([refusedOne.status, refusedOne.body]).toEqual([wrong.status, wrong.body]);
		expect(refusedOne.headers.getSetCookie()).toEqual([]);
		expect(events.map((e) => [e.kind, e.subject])).toEqual([
			["login.failed", undefined],
			["login.failed", undefined],
		]);
		// Counted as a failed guess: the identifier waits after its attempts.
		await login({ username: "alice", password: "correct horse" }, elsewhere());
		const held = await login({ username: "alice", password: "correct horse" }, elsewhere());
		expect([held.status, held.body]).toEqual([429, { error: "too_many_attempts" }]);
	});

	it("hands back the guess where a gate cannot tell, answering unavailable", async () => {
		const down = async () => {
			throw new Unavailable("login-gates");
		};
		const { login } = await serve({
			login: { ...budget, "account-attempts": 1 },
			logins: answering(down),
		});
		for (let i = 0; i < 3; i++) {
			const res = await login({ username: "alice", password: "correct horse" }, elsewhere());
			expect([res.status, res.body], String(i)).toEqual([
				503,
				{ error: "temporarily_unavailable" },
			]);
		}
	});

	it("answers a login the gates opened or held though its run cannot be ended then, the attempt staying counted", async () => {
		let down = () => {};
		const outcomes = {
			opened: { kind: "opened", session: { id: "h1" }, cookies: ["__Host-session=s1; Path=/"] },
			held: {
				kind: "held",
				gate: "mfa",
				answer: { error: "mfa_required" },
				cookies: ["mfa=t1; Path=/"],
			},
		};
		let next: keyof typeof outcomes = "opened";
		const logged = recordingLog();
		const { login, simulated, events } = await serve({
			log: logged,
			login: budget,
			logins: answering(async () => {
				// The store goes down once the login is made, before its run is ended.
				down();
				return outcomes[next];
			}),
		});
		down = () => simulated.unreachable(true);
		const answers = [];
		for (const kind of ["opened", "held"] as const) {
			next = kind;
			simulated.unreachable(false);
			const res = await login({ username: "alice", password: "correct horse" }, elsewhere());
			answers.push([res.status, res.body, res.headers.getSetCookie()]);
		}
		expect(answers).toEqual([
			[200, {}, [expect.stringMatching(/^__Host-session=s1/)]],
			[403, { error: "mfa_required" }, [expect.stringMatching(/^mfa=t1/)]],
		]);
		expect(events.map((e) => [e.kind, e.subject])).toEqual([
			["login.succeeded", "alice"],
			["login.held", "alice"],
		]);
		expect(logged.lines().filter((l) => l.level === "warn")).toEqual([
			{ level: "warn", event: "login-password.run_unended", fields: {} },
			{ level: "warn", event: "login-password.run_unended", fields: {} },
		]);
		// Both left counted: the identifier, past its two attempts, waits.
		simulated.unreachable(false);
		down = () => {};
		const held = await login({ username: "alice", password: "correct horse" }, elsewhere());
		expect([held.status, held.body]).toEqual([429, { error: "too_many_attempts" }]);
	});
});

it("takes every handle its takes name, every module beside it as it boots", async () => {
	const modules = [
		http,
		gatesModule,
		csrfStandIn,
		cookiesModule,
		usersModule,
		secretHashModule,
		memoryUsersStores().module,
		sessionStandIn,
		subjectRevocationStandIn,
		rateLimitModule,
		simulatedStore().module,
		loginModule,
		auditStandIn().module,
	];
	const config = {
		...kernelConfig(),
		...httpConfig({ "public-origin": "https://as.example" }),
		...usersConfig([testUser("alice", "correct horse")]),
		"login-password": {},
		"login-gates": {},
	};
	expect(await takesUnused({ modules, config })).toEqual({});
});
