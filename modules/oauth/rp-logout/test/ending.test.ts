import { type Clients, clientSources } from "@mod/clients";
import { use } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { requestsPerSource } from "@mod/rate-limit";
import { type Sessions, sessions } from "@mod/session";
import { sessionStandIn, stubSessions } from "@mod/session/testing";
import { participants } from "@mod/session-participants";
import { entryRequirements } from "@mod/session-requirements";
import { describe, expect, it } from "vitest";
import { upstreamEnds } from "../src/contract.ts";
import type { SessionClients } from "../src/store.ts";
import { back, issuer, servedEach } from "./harness.ts";

const serve = servedEach();
const noCache = { "cache-control": "no-store", pragma: "no-cache" };

/**
 * Sessions in memory whose read ends one past its lifetime calling no participants, and whose close
 * calls them for any record it finds open, past its lifetime too: as session-lifecycle keeps them
 * while a record outlives its end (a host's clock behind another's, or a lifetime shortened since).
 */
function readEndingSessions(lifetimeMs: number) {
	return defineModule({ takes: [participants], name: "session" }, (m) => [
		m.provide(sessions).by(async (c) => {
			const closers = await c.collect(participants);
			type Kept = { subject: string; openedAt: number; state: "open" | "closing" | "closed" };
			const kept = new Map<string, Kept>();
			const sessionOf = (id: string, r: Kept) => ({
				id,
				context: { subject: r.subject, amr: ["pwd"], authenticatedAt: r.openedAt },
			});
			return stubSessions({
				complete: async (_request, facts) => {
					const id = `s${kept.size + 1}`;
					const r: Kept = { subject: facts.subject, openedAt: c.clock.now(), state: "open" };
					kept.set(id, r);
					return { session: sessionOf(id, r), cookies: [`session=${id}`] };
				},
				entryOf: async (id) => {
					const r = kept.get(id);
					if (r?.state !== "open") return { kind: "absent" };
					if (r.openedAt + lifetimeMs <= c.clock.now()) {
						r.state = "closed";
						return { kind: "absent" };
					}
					return { kind: "entered", session: sessionOf(id, r), endsAt: r.openedAt + lifetimeMs };
				},
				close: async (id) => {
					const r = kept.get(id);
					if (!r) return { kind: "closed", cookies: [] };
					const from = r.state;
					if (r.state !== "closed") {
						r.state = "closing";
						for (const closer of closers) await closer.closing(sessionOf(id, r));
						r.state = "closed";
					}
					return { kind: "closed", cookies: [], session: { id, subject: r.subject }, from };
				},
			});
		}),
	]);
}

describe("the logout a client starts", () => {
	it("ends the session the hint names and clears the cookie of a browser in it", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		const hint = await h.hintFor(session.id);
		const out = await h.call("POST", { id_token_hint: hint }, { cookie, "user-agent": "ua/1" });
		expect([out.status, out.json]).toEqual([200, { logged_out: true }]);
		expect(out.headers).toMatchObject(noCache);
		expect(out.cookies.length).toBeGreaterThan(0);
		expect(await h.stillOpen(session.id)).toBe(false);
		expect(h.events).toEqual([
			{
				kind: "logout.success",
				subject: "alice",
				attributes: { sid: session.id, source: "127.0.0.1", userAgent: "ua/1" },
				at: expect.any(Number),
			},
		]);
	});

	it("ends it from a GET too, leaving another browser's cookie", async () => {
		const h = await serve();
		const { session } = await h.login();
		const other = await h.login();
		const out = await h.call(
			"GET",
			{ id_token_hint: await h.hintFor(session.id) },
			{
				cookie: other.cookie,
			},
		);
		expect([out.status, out.cookies]).toEqual([200, []]);
		expect([await h.stillOpen(session.id), await h.stillOpen(other.session.id)]).toEqual([
			false,
			true,
		]);
	});

	it("refuses a request without a hint, with a hint it cannot verify, or one that names no session [oidc-rpinit-2-e] [oidc-rpinit-4-a] [oidc-rpinit-4-b]", async () => {
		const h = await serve();
		const { session } = await h.login();
		const forged = (await h.hintFor(session.id)).replace(/\.[^.]+$/, ".AAAA");
		const cases = [
			["no hint", "POST", {}, "invalid_request"],
			["a forged hint", "GET", { id_token_hint: forged }, "invalid_token"],
			[
				"another issuer's",
				"GET",
				{ id_token_hint: await h.hintFor(session.id, { iss: "https://x" }) },
				"invalid_token",
			],
			[
				"one naming no session",
				"POST",
				{ id_token_hint: await h.hintFor(session.id, { sid: undefined }) },
				"invalid_request",
			],
		] as const;
		for (const [name, method, params, error] of cases) {
			const out = await h.call(method, params);
			expect([name, out.status, out.json?.error]).toEqual([name, 400, error]);
		}
		expect(await h.stillOpen(session.id)).toBe(true);
		expect(h.events).toEqual([]);
	});

	it("takes a hint past its end [oidc-rpinit-2-f]", async () => {
		const h = await serve();
		const { session } = await h.login();
		const iat = 1_800_000_000 - 7200;
		const hint = await h.hintFor(session.id, { iat, exp: iat + 3600 });
		expect((await h.call("GET", { id_token_hint: hint })).status).toBe(200);
		expect(await h.stillOpen(session.id)).toBe(false);
	});

	it("refuses a hint issued more than a day ago, by GET or POST, and closes nothing [oidc-rpinit-2-d]", async () => {
		const h = await serve();
		const { session } = await h.login();
		const iat = 1_800_000_000 - 86_401;
		const hint = await h.hintFor(session.id, { iat, exp: iat + 86_400 });
		for (const method of ["GET", "POST"] as const) {
			const out = await h.call(method, { id_token_hint: hint });
			expect([out.status, out.json?.error], method).toEqual([400, "invalid_token"]);
		}
		expect(await h.stillOpen(session.id)).toBe(true);
	});

	it("sends the browser back with its state only to a return the hint's client registered [oidc-rpinit-2-b] [oidc-rpinit-3-b]", async () => {
		const h = await serve();
		const go = async (asked: string, over: Record<string, unknown> = {}) => {
			const { session } = await h.login();
			const hint = await h.hintFor(session.id, over);
			const params = { id_token_hint: hint, post_logout_redirect_uri: asked, state: "s 1" };
			return h.call("GET", params);
		};
		const sent = await go(back);
		expect([sent.status, sent.headers.location]).toEqual([303, `${back}?state=s+1`]);
		expect(sent.headers).toMatchObject(noCache);
	});

	it("refuses a parameter sent twice, whichever it is, by GET or POST, and closes nothing", async () => {
		const h = await serve();
		const twice = (name: string, value: string) => [name, [value, value]] as const;
		for (const [name, value] of [
			["client_id", "other"],
			["post_logout_redirect_uri", `${back}/`],
			["state", "s"],
			["ui_locales", "en"],
		] as const) {
			const { session } = await h.login();
			const hint = await h.hintFor(session.id);
			for (const method of ["GET", "POST"] as const) {
				const out = await h.call(method, {
					id_token_hint: hint,
					...Object.fromEntries([twice(name, value)]),
				});
				expect([name, method, out.status, out.json]).toEqual([
					name,
					method,
					400,
					{ error: "invalid_request", error_description: "repeated parameter" },
				]);
			}
			expect([name, await h.stillOpen(session.id)]).toEqual([name, true]);
		}
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		const out = await h.call("GET", { id_token_hint: [hint, hint] });
		expect([out.status, out.json]).toEqual([
			400,
			{ error: "invalid_request", error_description: "repeated parameter" },
		]);
		expect(await h.stillOpen(session.id)).toBe(true);
		expect(h.events).toEqual([]);
	});

	it("refuses a client_id that is not the one the hint was issued to, and closes nothing", async () => {
		const h = await serve();
		const refused = [
			["another client", "other", {}],
			["a hint naming no one client", "app", { aud: ["app", "api"], azp: undefined }],
		] as const;
		for (const [name, clientId, over] of refused) {
			const { session } = await h.login();
			const hint = await h.hintFor(session.id, over);
			for (const method of ["GET", "POST"] as const) {
				const out = await h.call(method, { id_token_hint: hint, client_id: clientId });
				expect([name, method, out.status, out.json]).toEqual([
					name,
					method,
					400,
					{
						error: "invalid_request",
						error_description: "client_id is not the client the id_token_hint was issued to",
					},
				]);
			}
			expect([name, await h.stillOpen(session.id)]).toEqual([name, true]);
		}
		expect(h.events).toEqual([]);
		// The client the hint was issued to, named as client_id too, logs out.
		const { session } = await h.login();
		const named = await h.call("GET", {
			id_token_hint: await h.hintFor(session.id),
			client_id: "app",
		});
		expect([named.status, named.json]).toEqual([200, { logged_out: true }]);
		expect(await h.stillOpen(session.id)).toBe(false);
	});

	it("refuses a return the hint's client did not register, and closes nothing", async () => {
		const h = await serve();
		const refused = [
			["a return it did not register", `${back}/`, {}],
			["a hint naming no one client", back, { aud: ["app", "api"], azp: undefined }],
			["another client's hint", back, { aud: "other", azp: undefined }],
		] as const;
		for (const [name, asked, over] of refused) {
			const { session } = await h.login();
			const hint = await h.hintFor(session.id, over);
			for (const method of ["GET", "POST"] as const) {
				const out = await h.call(method, {
					id_token_hint: hint,
					post_logout_redirect_uri: asked,
					state: "s",
				});
				expect([name, method, out.status, out.json]).toEqual([
					name,
					method,
					400,
					{
						error: "invalid_request",
						error_description: "post_logout_redirect_uri is not registered for the client",
					},
				]);
				expect(out.headers).toMatchObject(noCache);
			}
			expect([name, await h.stillOpen(session.id)]).toEqual([name, true]);
		}
		expect(h.events).toEqual([]);
	});

	it("answers 503 where the client a return is judged by cannot be read, and closes nothing", async () => {
		const down = unavailableSwitch<Clients>("clients");
		const h = await serve({ clientRecordsDown: down });
		const { session } = await h.login();
		down.failNext("find");
		const out = await h.call("GET", {
			id_token_hint: await h.hintFor(session.id),
			post_logout_redirect_uri: back,
		});
		expect([out.status, out.json]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(h.logs().filter((l) => l.event === "rp-logout.unavailable")).toEqual([
			{ level: "warn", event: "rp-logout.unavailable", fields: { what: "clients" } },
		]);
		expect(await h.stillOpen(session.id)).toBe(true);
	});

	it("answers a close left pending 503, clearing the cookie and recording it by its sid and source alone, never as a logout", async () => {
		const unfinished = defineModule({ takes: [], name: "unfinished" }, (m) => [
			m.contribute(participants).by(() => ({
				name: "unfinished",
				closing: async () => {
					throw new Error("left for later");
				},
			})),
		]);
		const h = await serve({ extra: [unfinished] });
		const { session, cookie } = await h.login();
		const hint = await h.hintFor(session.id);
		const answered = await h.call(
			"POST",
			{ id_token_hint: hint },
			{ cookie, "user-agent": "ua/1" },
		);
		// The session is closing, but tokens it holds live until the close is swept: no success yet.
		expect([answered.status, answered.json]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(answered.cookies.length).toBeGreaterThan(0);
		expect(h.events.map((e) => [e.kind, e.attributes])).toEqual([
			["logout.close_pending", { sid: session.id, source: "127.0.0.1" }],
		]);
		// Sent again while the close is still pending: still 503, never a logout answered done.
		const again = await h.call("POST", { id_token_hint: hint }, { "user-agent": "ua/1" });
		expect([again.status, again.json]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(h.events.map((e) => e.kind)).toEqual(["logout.close_pending", "logout.close_pending"]);
	});

	it("closes a session past its lifetime through its participants when its logout comes, as any close does", async () => {
		const closing: string[] = [];
		const watcher = defineModule({ takes: [], name: "watcher" }, (m) => [
			m.contribute(participants).by(() => ({
				name: "watcher",
				closing: async (session) => {
					closing.push(session.id);
				},
			})),
		]);
		const h = await serve({ sessionsModule: readEndingSessions(60_000), extra: [watcher] });
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		h.advance(60_000);
		const answered = await h.call("POST", { id_token_hint: hint });
		expect(answered.status).toBe(200);
		expect(closing).toEqual([session.id]);
		// Its record was still open: this close is the logout.
		expect(h.events.map((e) => e.kind)).toEqual(["logout.success"]);
	});

	it("answers a session already gone as logged out, with no event", async () => {
		const h = await serve();
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		await h.call("POST", { id_token_hint: hint });
		h.events.length = 0;
		expect((await h.call("POST", { id_token_hint: hint })).json).toEqual({ logged_out: true });
		expect(h.events).toEqual([]);
	});

	it("logs out a session short of a requirement to be used as any live one: recorded, closed, sent back", async () => {
		const short = { now: false };
		const requirement = defineModule({ takes: [], name: "short-to-use" }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "mfa",
				judges: ["use"],
				admits: async () =>
					short.now ? { kind: "short", answer: { error: "mfa_required" } } : { kind: "admit" },
			})),
		]);
		const h = await serve({ extra: [requirement] });
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		short.now = true;
		const sent = await h.call("GET", { id_token_hint: hint, post_logout_redirect_uri: back });
		expect([sent.status, sent.headers.location]).toEqual([303, back]);
		expect(h.events.map((e) => [e.kind, e.subject, e.attributes?.sid])).toEqual([
			["logout.success", "alice", session.id],
		]);
		short.now = false;
		expect(await h.stillOpen(session.id)).toBe(false);
	});

	it("answers 503 when a check cannot tell, logging what failed", async () => {
		const down = unavailableSwitch<SessionClients>("rp-logout");
		const h = await serve({ clientsDown: down });
		const { session } = await h.login();
		down.failNext("members");
		const out = await h.call("POST", { id_token_hint: await h.hintFor(session.id) });
		expect([out.status, out.json]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(h.logs().filter((l) => l.event === "rp-logout.unavailable")).toEqual([
			{ level: "warn", event: "rp-logout.unavailable", fields: { what: "rp-logout" } },
		]);
		// Nothing was closed: the session still enters.
		expect(await h.stillOpen(session.id)).toBe(true);
	});

	it("passes on an error of the close's that is not Unavailable, recording no failed close", async () => {
		const broken = defineModule({ takes: [], name: "session" }, (m) => [
			m.provide(sessions).by(() =>
				stubSessions({
					complete: async (_request, facts) => ({
						session: {
							id: "s1",
							context: { subject: facts.subject, amr: ["pwd"], authenticatedAt: 0 },
						},
						cookies: ["session=s1"],
					}),
					close: async () => {
						throw new TypeError("a mistake in the close");
					},
				}),
			),
		]);
		const h = await serve({ sessionsModule: broken });
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		await expect(h.call("POST", { id_token_hint: hint })).rejects.toThrow(TypeError);
		expect(h.events).toEqual([]);
	});

	it("answers 503 and records the failed close when the session cannot be closed", async () => {
		const down = unavailableSwitch<Sessions>("session");
		const h = await serve({ sessionsModule: switchedModule(sessionStandIn, sessions, down) });
		const { session } = await h.login();
		down.failNext("close");
		const out = await h.call("POST", { id_token_hint: await h.hintFor(session.id) });
		expect([out.status, out.json]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(h.events.map((e) => [e.kind, e.attributes])).toEqual([
			["logout.cascade_failed", { sid: session.id, source: "127.0.0.1", store: "session" }],
		]);
	});
});

describe("the front-channel page", () => {
	it("frames each client of the session with iss and sid, in a sandbox keeping scripts and its own origin, then moves on to the return", async () => {
		const h = await serve();
		const { session } = await h.login();
		await h.redeemed(session.id, "app");
		const hint = await h.hintFor(session.id);
		const params = { id_token_hint: hint, post_logout_redirect_uri: back, state: "s" };
		const out = await h.call("GET", params, { accept: "text/html" });
		expect(out.status).toBe(200);
		expect(out.headers["content-type"]).toBe("text/html; charset=utf-8");
		const frame = `https://app.example/fc?iss=${encodeURIComponent(issuer)}&#38;sid=${session.id}`;
		expect(out.text).toContain(`<iframe src="${frame}"`);
		// Scripts and the frame's own origin stay, so the client's page can clear its own cookies.
		const iframe = /<iframe [^>]*>/.exec(out.text ?? "")?.[0];
		expect(iframe).toContain(' sandbox="allow-scripts allow-same-origin"');
		expect(out.text).toContain(`data-target="${back}?state=s"`);
		const script = /<script>([^<]*)<\/script>/.exec(out.text ?? "")?.[1];
		expect(out.loads).toEqual({ frames: ["https://app.example"], scripts: [script] });
	});

	it("sends no page when no client of the session can be framed", async () => {
		const h = await serve({
			sections: { app: { "post-logout-redirect-uris": [back] } },
		});
		const { session } = await h.login();
		await h.redeemed(session.id, "app");
		const params = { id_token_hint: await h.hintFor(session.id), post_logout_redirect_uri: back };
		expect((await h.call("GET", params, { accept: "text/html" })).status).toBe(303);
	});

	it("sends no page to a browser that does not prefer HTML", async () => {
		const h = await serve();
		const { session } = await h.login();
		await h.redeemed(session.id, "app");
		const hint = await h.hintFor(session.id);
		const out = await h.call("GET", { id_token_hint: hint }, { accept: "*/*" });
		expect(out.json).toEqual({ logged_out: true });
	});

	it("leaves out the session for a client that did not ask for it, and stays without a place to go", async () => {
		const h = await serve({
			sections: {
				app: {
					"frontchannel-logout-uri": "https://app.example/fc?x=1",
					"frontchannel-logout-session-required": false,
				},
			},
		});
		const { session } = await h.login();
		await h.redeemed(session.id, "app");
		const out = await h.call(
			"GET",
			{ id_token_hint: await h.hintFor(session.id) },
			{
				accept: "text/html,application/json;q=0.5",
			},
		);
		expect(out.text).toContain(`src="https://app.example/fc?x=1&#38;iss=`);
		expect(out.text).not.toContain("sid=");
		expect(out.text).not.toContain("<script>");
		expect(out.loads).toEqual({ frames: ["https://app.example"], scripts: [] });
	});
});

it("leaves out a frame whose origin the page's policy cannot name, logging how many", async () => {
	const h = await serve({
		sections: {
			app: { "frontchannel-logout-uri": "https://app.example/fc" },
			under: { "frontchannel-logout-uri": "https://under_score.example/fc" },
		},
		redirects: { under: ["https://under_score.example/cb"] },
	});
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.redeemed(session.id, "under");
	const hint = await h.hintFor(session.id);
	const out = await h.call("GET", { id_token_hint: hint }, { accept: "text/html" });
	expect(out.loads?.frames).toEqual(["https://app.example"]);
	expect(h.logs().filter((l) => l.event === "rp-logout.frames_skipped")).toEqual([
		expect.objectContaining({ level: "warn", fields: { count: 1 } }),
	]);
});

describe("the upstream's end of session", () => {
	const ending = (seen: { open?: boolean }) =>
		defineModule({ takes: [sessions], name: "upstream-end" }, (m) => [
			m.contribute(upstreamEnds).by(async (c) => {
				const kept = await c.late(sessions);
				return {
					name: "upstream",
					at: async (session, at) => {
						seen.open = (await kept().entryOf(session)).kind === "entered";
						const url = new URL("https://idp.example/logout");
						for (const [k, v] of Object.entries(at)) url.searchParams.set(k, String(v));
						return url.href;
					},
				};
			}),
		]);

	it("sends the browser to the upstream first, with the return and state, asked before the close", async () => {
		const seen: { open?: boolean } = {};
		const h = await serve({ extra: [ending(seen)] });
		const { session } = await h.login();
		const hint = await h.hintFor(session.id);
		const params = { id_token_hint: hint, post_logout_redirect_uri: back, state: "s" };
		const out = await h.call("POST", params);
		expect(out.status).toBe(303);
		expect(Object.fromEntries(new URL(String(out.headers.location)).searchParams)).toEqual({
			postLogoutRedirectUri: back,
			state: "s",
		});
		expect(seen.open).toBe(true);
	});

	it("refuses to start with two", async () => {
		const twice = defineModule({ takes: [], name: "upstream-end-2" }, (m) => [
			m.contribute(upstreamEnds).by(() => ({ name: "other", at: async () => undefined })),
		]);
		await expect(serve({ extra: [ending({}), twice] })).rejects.toMatchObject({
			refusals: [expect.objectContaining({ reason: "more than one upstream end of session" })],
		});
	});
});

it("publishes its endpoint and the front-channel and back-channel support [oidc-rpinit-2.1-a] [oidc-bcl-2.1-a]", async () => {
	const h = await serve();
	expect(Object.fromEntries(h.items.map((i) => [i.name, i.value]))).toMatchObject({
		end_session_endpoint: `${issuer}/oauth/logout`,
		frontchannel_logout_supported: true,
		frontchannel_logout_session_supported: true,
		backchannel_logout_supported: true,
		backchannel_logout_session_supported: true,
	});
});

it("publishes its endpoint on the issuer's origin where no public origin is written [oidc-rpinit-2.1-a]", async () => {
	const h = await serve({ noPublicOrigin: true });
	expect(h.items.find((i) => i.name === "end_session_endpoint")?.value).toBe(
		`${issuer}/oauth/logout`,
	);
});

it("refuses to start with a client whose return, front-channel or back-channel URL does not fit", async () => {
	const cases = [
		["a return with a fragment", "post-logout-redirect-uris", ["https://app.example/after#x"]],
		["iss in a front channel", "frontchannel-logout-uri", "https://app.example/fc?ISS=1"],
		["sid spelled otherwise", "frontchannel-logout-uri", "https://app.example/fc?s_i-d=1"],
		["a front channel not on the web", "frontchannel-logout-uri", "javascript:alert(1)"],
		["a back channel not on the web", "backchannel-logout-uri", "ftp://app.example/bc"],
		["a back channel with a space", "backchannel-logout-uri", " https://app.example/bc"],
	] as const;
	for (const [name, field, value] of cases) {
		const refused = await serve({ sections: { app: { [field]: value } } }).catch((error) => error);
		const where = refused?.refusals?.map((r: { where: string }) => r.where);
		expect([name, where]).toEqual([
			name,
			[expect.stringMatching(new RegExp(`sections\\.rp-logout\\.${field}`))],
		]);
	}
});

it("refuses to start with a client whose front channel is at none of its redirect URIs' origins", async () => {
	for (const uri of [
		"https://other.example/fc",
		"https://app.example:8443/fc",
		"http://app.example/fc",
	]) {
		const refused = await serve({ sections: { app: { "frontchannel-logout-uri": uri } } }).catch(
			(error) => error,
		);
		expect(refused?.refusals, uri).toEqual([
			{
				where: "clients.registered.0.sections.rp-logout",
				// rp-logout's own words, however clients words the refusal around them.
				reason: expect.stringMatching(
					/frontchannel-logout-uri is at none of its redirect URIs' origins$/,
				),
			},
		]);
	}
	// At one of them, it starts.
	const h = await serve({
		sections: { app: { "frontchannel-logout-uri": "https://app.example/fc" } },
	});
	expect(h.items.length).toBeGreaterThan(0);
});

it("leaves out the frame of a client a source names whose front channel is at none of its redirect URIs' origins, logging it", async () => {
	const remote = (id: string, frontChannel: string) => ({
		id,
		kind: "public" as const,
		method: "none",
		sections: {
			"rp-logout": { "frontchannel-logout-uri": frontChannel },
			authorize: { "redirect-uris": ["https://remote.example/cb"] },
		},
	});
	const records = [
		remote("https://remote.example/off", "https://elsewhere.example/fc"),
		remote("https://remote.example/on", "https://remote.example/fc"),
	];
	const source = defineModule({ takes: [], name: "remote-clients" }, (m) => [
		m.contribute(clientSources).by(() => ({
			find: async (id) => records.find((r) => r.id === id),
		})),
	]);
	const h = await serve({ sections: {}, extra: [source] });
	const { session } = await h.login();
	for (const { id } of records) await h.redeemed(session.id, id);
	const hint = await h.hintFor(session.id, { aud: "https://remote.example/on" });
	const out = await h.call("GET", { id_token_hint: hint }, { accept: "text/html" });
	expect(out.loads?.frames).toEqual(["https://remote.example"]);
	expect(h.logs().filter((l) => l.event === "rp-logout.frontchannel_off_redirects")).toEqual([
		expect.objectContaining({ level: "warn", fields: { client: "https://remote.example/off" } }),
	]);
});

it("limits its requests per source, a GET and a POST together, by the section's window [guarantee-10-a]", async () => {
	const window = (h: Awaited<ReturnType<typeof serve>>, method: string) =>
		h.routes.find((r) => r.path === "/oauth/logout" && r.method === method)?.uses;
	const given = await serve({ settings: { requests: 5, window: "10s" } });
	for (const method of ["GET", "POST"]) {
		expect(window(given, method), method).toEqual([
			use(requestsPerSource, { name: "rp-logout", window: { limit: 5, ms: 10_000 } }),
		]);
	}
	await given.stop();
	const byDefault = await serve();
	expect(window(byDefault, "POST")).toEqual([
		use(requestsPerSource, { name: "rp-logout", window: { limit: 60, ms: 60_000 } }),
	]);
});
