import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, faultyTarget, type Started, sceneOf } from "@mod/conformance";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type IdentityPart, identityArea, type UserScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const long = "x".repeat(72);
const pair = generateKeyPairSync("ed25519");
const sceneWith = (users: UserScene[], more: Partial<NonNullable<IdentityPart["login"]>> = {}) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "login",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users,
			login: {
				returnTargets: ["https://app.example/back"],
				attempts: 3,
				windowSeconds: 600,
				...more,
			},
		}),
	);
const scene = sceneWith([{ identifier: "alice", password: "correct horse battery" }]);

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

let sender = 0;
/** Each test sends from its own address, so the attempt limit is per test. */
const nextSender = () => `198.51.100.${++sender}`;
const sessionCookie = (cookies: string[]) =>
	cookies
		.map((c) => c.split(";")[0] ?? "")
		.find((c) => /^__Host-[^=]*session=/.test(c) && !/csrf/.test(c));

async function post(
	path: string,
	form: Record<string, string>,
	from: string,
	headers: Record<string, string> = {},
) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": from,
			origin: issuer,
			// Some targets judge the origin by the forwarded host.
			"x-forwarded-host": new URL(issuer).host,
			...headers,
		},
		body: new URLSearchParams(form),
		redirect: "manual",
	});
	return { status: res.status, cookies: res.headers.getSetCookie(), text: await res.text() };
}
const login = (form: Record<string, string>, from: string, headers?: Record<string, string>) =>
	post("/session/login", form, from, headers);
/** The same request with a JSON body, as a deployment's own pages may send it. */
async function postJson(
	path: string,
	json: Record<string, unknown>,
	from: string,
	headers: Record<string, string | undefined> = {},
) {
	const sent = {
		"content-type": "application/json",
		"x-forwarded-proto": "https",
		"x-forwarded-for": from,
		origin: issuer,
		"x-forwarded-host": new URL(issuer).host,
		...headers,
	};
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		// A header given as undefined is not sent.
		headers: Object.fromEntries(
			Object.entries(sent).filter((h): h is [string, string] => h[1] !== undefined),
		),
		body: JSON.stringify(json),
		redirect: "manual",
	});
	return { status: res.status, cookies: res.headers.getSetCookie(), text: await res.text() };
}
const right = { username: "alice", password: "correct horse battery" };

describe("password login", () => {
	it("opens a session behind a __Host- cookie for the right password", async () => {
		const ok = await login(right, nextSender());
		expect(ok.status).toBe(200);
		const cookie = ok.cookies.find((c) => /^__Host-[^=]*session=/.test(c) && !/csrf/.test(c)) ?? "";
		expect(cookie).toMatch(/; *Secure/i);
		expect(cookie).toMatch(/; *HttpOnly/i);
		expect(cookie).toMatch(/; *Path=\//i);
	});

	it("answers a wrong password and an unknown user alike, without a session", async () => {
		const from = nextSender();
		const wrong = await login({ username: "alice", password: "nope" }, from);
		const unknown = await login({ username: "nobody", password: "correct horse battery" }, from);
		expect(wrong.status).toBe(401);
		expect([unknown.status, unknown.text]).toEqual([wrong.status, wrong.text]);
		expect(sessionCookie(wrong.cookies)).toBeUndefined();
	});

	it("refuses a login without same-origin evidence or token, and from a foreign origin [guarantee-9-a]", async () => {
		const from = nextSender();
		expect((await login(right, from, { origin: "" })).status).toBe(403);
		expect((await login(right, from, { origin: "https://evil.example" })).status).toBe(403);
	});

	it("gives every login a new session, even when the request carried one", async () => {
		const from = nextSender();
		const first = sessionCookie((await login(right, from)).cookies) ?? "";
		const second = sessionCookie((await login(right, from, { cookie: first })).cookies) ?? "";
		expect(second).not.toBe("");
		expect(second).not.toBe(first);
	});

	it("sends the user back only to a listed target", async () => {
		const from = nextSender();
		expect((await login({ ...right, redirect_to: "https://app.example/back" }, from)).status).toBe(
			200,
		);
		expect((await login({ ...right, redirect_to: "https://app.example/other" }, from)).status).toBe(
			400,
		);
	});

	it("limits attempts per sender, counting successes too [rfc6749-10.10-d] [guarantee-10-a]", async () => {
		const from = nextSender();
		for (let i = 0; i < 3; i++) await login(right, from);
		expect((await login(right, from)).status).toBe(429);
		expect((await login(right, nextSender())).status).toBe(200);
	});

	it("counts a malformed login toward its sender's attempts", async () => {
		const from = nextSender();
		for (let i = 0; i < 3; i++) {
			const res = await login({ ...right, redirect_to: "https://app.example/other" }, from);
			expect(res.status).toBe(400);
		}
		expect((await login(right, from)).status).toBe(429);
	});

	it("takes a login sent as JSON as it takes a form", async () => {
		const from = nextSender();
		const ok = await postJson("/session/login", right, from);
		expect(ok.status).toBe(200);
		expect(sessionCookie(ok.cookies)).toMatch(/^__Host-/);
		const wrong = await postJson("/session/login", { ...right, password: "nope" }, from);
		const form = await login({ ...right, password: "nope" }, nextSender());
		expect([wrong.status, wrong.text]).toEqual([form.status, form.text]);
		expect(sessionCookie(wrong.cookies)).toBeUndefined();
	});

	it("refuses a JSON login whose destination is a number, without a session", async () => {
		const res = await postJson("/session/login", { ...right, redirect_to: 1 }, nextSender());
		expect([res.status, JSON.parse(res.text).error]).toEqual([400, "invalid_redirect"]);
		expect(sessionCookie(res.cookies)).toBeUndefined();
	});

	it("refuses a login without a password, or with a number as one, as a malformed request", async () => {
		const missing = await login({ username: "alice" }, nextSender());
		const number = await postJson("/session/login", { ...right, password: 1 }, nextSender());
		for (const res of [missing, number]) {
			expect([res.status, JSON.parse(res.text).error]).toEqual([400, "invalid_request"]);
			expect(sessionCookie(res.cookies)).toBeUndefined();
		}
	});

	it("takes the double-submit token from a JSON body [guarantee-9-a]", async () => {
		const from = nextSender();
		const https = { "x-forwarded-proto": "https", "x-forwarded-host": new URL(issuer).host };
		const issued = await fetch(`${base}/session/csrf`, { headers: https });
		const cookie = issued.headers.getSetCookie().map((c) => c.split(";")[0] ?? "")[0] ?? "";
		const { csrf_token: token = "" } = (await issued.json()) as { csrf_token?: string };
		const sent = (json: Record<string, unknown>) =>
			postJson("/session/login", json, from, { origin: undefined, cookie });
		expect((await sent(right)).status).toBe(403);
		expect((await sent({ ...right, csrf_token: token })).status).toBe(200);
	});

	it.skipIf(areaTarget().differs("repeated-field-login-400"))(
		"refuses a login that repeats a field as a malformed request",
		async () => {
			const res = await fetch(`${base}/session/login`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					"x-forwarded-proto": "https",
					"x-forwarded-for": nextSender(),
					origin: issuer,
				},
				body: "username=alice&username=alice&password=correct+horse+battery",
			});
			expect([res.status, await res.json()]).toEqual([400, { error: "repeated_parameter" }]);
		},
	);
});

// A scene of its own: an app taking users from a ledger holds no bcrypt hash in the settings.
describe.skipIf(areaTarget().differs("bcrypt-all-bytes"))("password login: a bcrypt hash", () => {
	let bcrypt: Started;
	let at = "";
	beforeAll(async () => {
		// Kept first, so the blocks after this one get their target back where it is left out.
		at = base;
		bcrypt = await areaTarget().start(
			sceneWith([{ identifier: "long", password: long, bcrypt: true }]),
		);
		if (bcrypt.kind !== "running") throw new Error(`refused:\n${bcrypt.output}`);
		base = bcrypt.baseUrl;
	});
	afterAll(async () => {
		base = at;
		if (bcrypt?.kind === "running") await bcrypt.stop();
	});

	it("matches a bcrypt password on all its bytes, past the 72nd too", async () => {
		const from = nextSender();
		expect((await login({ username: "long", password: long }, from)).status).toBe(200);
		expect((await login({ username: "long", password: `${long}more` }, from)).status).toBe(401);
	});
});

// A scene of its own: a small budget per identifier, which the shared scene's tests would run into.
describe.skipIf(areaTarget().differs("login-attempts-per-account"))(
	"password login: the attempts per identifier",
	() => {
		let budgeted: Started;
		let at = "";
		beforeAll(async () => {
			at = base;
			budgeted = await areaTarget().start(
				sceneWith([{ identifier: "dana", password: "correct horse battery" }], {
					accountAttempts: 2,
					accountWindowSeconds: 3600,
					accountMaxWaitSeconds: 60,
				}),
			);
			if (budgeted.kind !== "running") throw new Error(`refused:\n${budgeted.output}`);
			base = budgeted.baseUrl;
		});
		afterAll(async () => {
			base = at;
			if (budgeted?.kind === "running") await budgeted.stop();
		});

		it("makes an identifier wait after its failed attempts from many senders, alike whether its account exists [rfc6749-10.10-d]", async () => {
			for (const username of ["dana", "nobody"]) {
				const wrong = { username, password: "wrong" };
				expect((await login(wrong, nextSender())).status, username).toBe(401);
				expect((await login(wrong, nextSender())).status, username).toBe(401);
				const res = await fetch(`${base}/session/login`, {
					method: "POST",
					headers: {
						"content-type": "application/x-www-form-urlencoded",
						"x-forwarded-proto": "https",
						"x-forwarded-for": nextSender(),
						origin: issuer,
						"x-forwarded-host": new URL(issuer).host,
					},
					body: new URLSearchParams({ username, password: "correct horse battery" }),
				});
				expect([res.status, await res.json()], username).toEqual([
					429,
					{ error: "too_many_attempts" },
				]);
				const wait = Number(res.headers.get("retry-after"));
				expect(wait, username).toBeGreaterThan(0);
				expect(wait, username).toBeLessThanOrEqual(60);
			}
		});
	},
);

describe.runIf(areaTarget().can(auditEvents.need))("password login: audit events", () => {
	it("records a login that succeeded with its subject, and one that failed without", async () => {
		const trail = auditEvents.of(running);
		const from = nextSender();
		const ok = await trail.during(() => login(right, from));
		const wrong = await trail.during(() => login({ username: "alice", password: "nope" }, from));
		expect([ok.result.status, wrong.result.status]).toEqual([200, 401]);
		// The source, when a target records one, is the sender's.
		const by = { method: "password" };
		const attributes = expect.toBeOneOf([by, { ...by, source: from }]);
		expect(ok.events).toEqual([
			{
				kind: "login.succeeded",
				at: expect.any(Number),
				subject: expect.stringMatching(/./),
				attributes,
			},
		]);
		expect(wrong.events).toEqual([{ kind: "login.failed", at: expect.any(Number), attributes }]);
		expect(JSON.stringify([ok.events, wrong.events])).not.toMatch(/correct horse|nope/);
	});

	it("records nothing for a refusal over the attempt limit", async () => {
		const trail = auditEvents.of(running);
		const from = nextSender();
		for (let i = 0; i < 3; i++) await login(right, from);
		const limited = await trail.during(() => login(right, from));
		expect([limited.result.status, limited.events]).toEqual([429, []]);
	});

	it("records a logout answered as done, with the session's subject and sid, and its source", async () => {
		const trail = auditEvents.of(running);
		const from = nextSender();
		const cookie = sessionCookie((await login(right, from)).cookies) ?? "";
		const out = await trail.during(() => post("/session/logout", {}, from, { cookie }));
		expect(out.result.status).toBe(200);
		expect(out.events).toEqual([
			{
				kind: "logout.succeeded",
				at: expect.any(Number),
				subject: "alice",
				attributes: { source: from, sid: expect.any(String) },
			},
		]);
		expect(JSON.stringify(out.events)).not.toContain(cookie.split("=")[1]);
	});
});

describe("logout", () => {
	it("needs CSRF evidence, then ends the session [guarantee-9-a]", async () => {
		const from = nextSender();
		const cookie = sessionCookie((await login(right, from)).cookies) ?? "";
		expect((await post("/session/logout", {}, from, { cookie, origin: "" })).status).toBe(403);
		expect((await post("/session/logout", {}, from, { cookie })).status).toBe(200);
	});

	it("takes a logout sent as JSON", async () => {
		const from = nextSender();
		const cookie = sessionCookie((await postJson("/session/login", right, from)).cookies) ?? "";
		expect((await postJson("/session/logout", {}, from, { cookie })).status).toBe(200);
	});
});

describe.runIf(areaTarget().can("store-fault:login"))("password login: the store failing", () => {
	const faulty = faultyTarget(scene);
	let at = "";
	beforeAll(() => {
		at = base;
		base = faulty.base();
	});
	afterAll(() => {
		base = at;
	});

	it("answers 503 without a session while the store is unreachable, never as wrong credentials", async () => {
		const from = nextSender();
		const answer = await faulty.whileDown(() => login(right, from));
		expect(answer.status).toBe(503);
		expect(sessionCookie(answer.cookies)).toBeUndefined();
		expect((await login(right, from)).status).toBe(200);
	});
});

describe.runIf(areaTarget().can("store-fault:login") && areaTarget().can(auditEvents.need))(
	"password login: audit events while the store fails",
	() => {
		let faulty: Started;
		let at = "";
		beforeAll(async () => {
			faulty = await areaTarget().start({ ...scene, storeFaults: true });
			if (faulty.kind !== "running") throw new Error(`refused:\n${faulty.output}`);
			at = base;
			base = faulty.baseUrl;
		});
		afterAll(async () => {
			base = at;
			if (faulty?.kind === "running") await faulty.stop();
		});

		it("records that the attempt limit could not count, with the source", async () => {
			const down = faulty.kind === "running" ? faulty : undefined;
			const from = nextSender();
			const failed = await auditEvents.of(faulty).during(async () => {
				await down?.fault?.(true);
				try {
					return await login(right, from);
				} finally {
					await down?.fault?.(false);
				}
			});
			expect(failed.result.status).toBe(503);
			expect(failed.events).toEqual([
				{
					kind: "rate_limit.unavailable",
					at: expect.any(Number),
					attributes: {
						name: expect.stringMatching(/./),
						limit: "attempts",
						source: from,
						outcome: "refused",
					},
				},
			]);
		});
	},
);
