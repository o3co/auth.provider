import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { participants, type Sessions, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, expect, it } from "vitest";
import logoutModule from "../src/module.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

async function serve() {
	const failing = { on: false };
	const down = unavailableSwitch<Sessions>("sessions");
	const audit = auditStandIn();
	const participant = defineModule({ name: "participant" }, (m) => [
		m.contribute(participants).by(() => ({
			name: "test",
			closing: async () => {
				if (failing.on) throw new Error("not yet");
			},
		})),
	]);
	const app = await assemble({
		modules: [
			csrfStandIn,
			cookiesModule,
			audit.module,
			http,
			switchedModule(sessionStandIn, sessions, down),
			subjectRevocationStandIn,
			logoutModule,
			participant,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": "https://as.example" }),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const s = app.get(sessions);
	const completed = await s.complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const cookie = completed.cookies[0]?.split(";")[0] ?? "";
	const sid = completed.session.id;
	const inside = () => s.enter(testRequest({ headers: new Map([["cookie", cookie]]) }));
	const logout = async (headers: Record<string, string>, body?: string) => {
		const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/session/logout`, {
			method: "POST",
			headers: { "x-forwarded-proto": "https", ...headers },
			...(body === undefined ? {} : { body }),
		});
		const text = await res.text();
		return {
			status: res.status,
			cache: res.headers.get("cache-control"),
			cookies: res.headers.getSetCookie(),
			body: text && JSON.parse(text),
		};
	};
	return { cookie, sid, inside, logout, failing, down, events: audit.events };
}

it("closes the request's session and clears its cookie, only with CSRF evidence", async () => {
	const { cookie, inside, logout } = await serve();
	expect((await logout({ cookie })).status).toBe(403);
	expect(await inside()).toBeDefined();
	const out = await logout({ cookie, origin: "https://as.example" });
	expect([out.status, out.cache]).toEqual([200, "no-store"]);
	expect(out.cookies[0]).toMatch(/^__Host-session=; .*Max-Age=0$/);
	expect(await inside()).toBeUndefined();
	expect((await logout({ cookie, origin: "https://as.example" })).status).toBe(200);
});

it("answers 503 while a participant has not finished, with the session already shut", async () => {
	const { cookie, inside, logout, failing } = await serve();
	failing.on = true;
	const pending = await logout({ cookie, origin: "https://as.example" });
	expect([pending.status, pending.body, pending.cache]).toEqual([
		503,
		{ error: "temporarily_unavailable" },
		"no-store",
	]);
	expect(pending.cookies[0]).toMatch(/^__Host-session=; .*Max-Age=0$/);
	expect(await inside()).toBeUndefined();
});

it("answers 503 when the session cannot tell, leaving the session as it was", async () => {
	const { cookie, inside, logout, down } = await serve();
	down.unavailable("closeRequest");
	const out = await logout({ cookie, origin: "https://as.example" });
	expect([out.status, out.body, out.cache]).toEqual([
		503,
		{ error: "temporarily_unavailable" },
		"no-store",
	]);
	down.restore();
	expect(await inside()).toBeDefined();
});

it("clears the cookie of a session that is already closing", async () => {
	const { cookie, inside, logout, failing } = await serve();
	failing.on = true;
	await logout({ cookie, origin: "https://as.example" });
	failing.on = false;
	const out = await logout({ cookie, origin: "https://as.example" });
	expect(out.status).toBe(200);
	expect(out.cookies[0]).toMatch(/^__Host-session=; .*Max-Age=0$/);
	expect(await inside()).toBeUndefined();
});

it("takes a form, a JSON body or none, and no other", async () => {
	const origin = "https://as.example";
	for (const [type, body] of [
		["application/x-www-form-urlencoded", "a=1"],
		["application/json", "{}"],
	]) {
		const { cookie, inside, logout } = await serve();
		expect((await logout({ cookie, origin, "content-type": type ?? "" }, body)).status).toBe(200);
		expect(await inside()).toBeUndefined();
	}
	const { cookie, inside, logout } = await serve();
	expect((await logout({ cookie, origin, "content-type": "text/plain" }, "x")).status).toBe(415);
	expect(await inside()).toBeDefined();
});

it("records a logout answered as done, and one whose close is pending, with the source", async () => {
	const { cookie, sid, logout, failing, events } = await serve();
	const sent = { origin: "https://as.example", "x-forwarded-for": "198.51.100.7" };
	failing.on = true;
	expect((await logout({ cookie, ...sent })).status).toBe(503);
	failing.on = false;
	expect((await logout({ cookie, ...sent })).status).toBe(200);
	expect((await logout({ cookie })).status).toBe(403);
	expect(events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
		["logout.close_pending", "alice", { source: "198.51.100.7", sid }],
		["logout.succeeded", "alice", { source: "198.51.100.7", sid }],
	]);
	expect(JSON.stringify(events)).not.toContain(cookie.split("=")[1]);
});
