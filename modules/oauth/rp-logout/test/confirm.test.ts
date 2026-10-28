import { csrfChecked } from "@mod/csrf";
import { use } from "@mod/http";
import { defineModule, Unavailable } from "@mod/kernel";
import { keys } from "@mod/keys";
import { requestsPerSource } from "@mod/rate-limit";
import { sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { participants } from "@mod/session-participants";
import { describe, expect, it } from "vitest";
import { upstreamEnds } from "../src/contract.ts";
import { issuer, readEndingSessions, servedEach, until } from "./harness.ts";

const serve = servedEach();
const path = "/oauth/logout/confirm";
const confirmationOf = (text: string | undefined) =>
	/name="confirmation" value="([^"]+)"/.exec(text ?? "")?.[1] ?? "";

describe("the confirmation's routes", () => {
	it("are a GET that changes nothing and a POST under the CSRF check, both counted per source, as each may sign a confirmation", async () => {
		const h = await serve();
		const route = (method: string) => h.routes.find((r) => r.path === path && r.method === method);
		const counted = use(requestsPerSource, {
			name: "rp-logout",
			window: { limit: 60, ms: 60_000 },
		});
		expect(route("GET")?.changesState).toBe(false);
		expect(route("GET")?.uses).toEqual([counted]);
		expect(route("POST")?.uses).toEqual([use(csrfChecked), counted]);
		expect(route("POST")?.takes).toEqual(["form"]);
		expect(route("POST")?.unlimited).toBeUndefined();
	});

	it("bind the page to the session, signed by the provider's keys with the claims it holds", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		const shown = await h.confirming("GET", {}, { cookie });
		expect(shown.status).toBe(200);
		// The form's CSRF token comes with its cookie, named as cookies names it where they are secure.
		expect(shown.cookies.some((c) => c.startsWith("__Host-csrf="))).toBe(true);
		const verified = await h.app.get(keys).verify(confirmationOf(shown.text), "logout-confirm+jwt");
		expect(verified).toEqual({
			kind: "valid",
			claims: { iss: issuer, aud: `${issuer}${path}`, sid: session.id, exp: 1_800_000_000 + 300 },
		});
	});

	it("close the session once agreed, recording the logout", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		const confirmation = confirmationOf((await h.confirming("GET", {}, { cookie })).text);
		const taken = await h.confirming("POST", { confirmation }, { cookie, "user-agent": "ua/1" });
		expect(taken.status).toBe(200);
		expect(taken.text).toContain("You are logged out.");
		expect(await h.stillOpen(session.id)).toBe(false);
		expect(h.events.map((e) => [e.kind, e.subject])).toEqual([["logout.success", "alice"]]);
	});

	it("hold a confirmation to its end by the provider's own keys: at its exp it asks again, a second before it closes", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		const late = confirmationOf((await h.confirming("GET", {}, { cookie })).text);
		h.advance(300_000);
		const asked = await h.confirming("POST", { confirmation: late }, { cookie });
		expect(asked.text).toContain("Do you want to log out");
		expect(await h.stillOpen(session.id)).toBe(true);
		const fresh = confirmationOf(asked.text);
		h.advance(299_000);
		await h.confirming("POST", { confirmation: fresh }, { cookie });
		expect(await h.stillOpen(session.id)).toBe(false);
	});

	it("ask again, closing nothing, where the confirmation was shown for another session", async () => {
		const h = await serve();
		const first = await h.login();
		const second = await h.login();
		const forFirst = confirmationOf((await h.confirming("GET", {}, { cookie: first.cookie })).text);
		const asked = await h.confirming("POST", { confirmation: forFirst }, { cookie: second.cookie });
		expect(asked.text).toContain("Do you want to log out");
		expect(await h.stillOpen(first.session.id)).toBe(true);
		expect(await h.stillOpen(second.session.id)).toBe(true);
	});

	it("ask again, closing nothing, for a token the provider's own keys signed of another kind or with claims that do not hold", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		const signer = h.app.get(keys);
		const right = {
			iss: issuer,
			aud: `${issuer}${path}`,
			sid: session.id,
			exp: 1_800_000_000 + 300,
		};
		const kind = "logout-confirm+jwt";
		const tokens: Record<string, string> = {
			"an ID token": await signer.sign(right, "JWT"),
			"a back-channel logout token": await signer.sign(right, "logout+jwt"),
			"no exp": await signer.sign({ ...right, exp: undefined }, kind),
			"an exp in words": await signer.sign({ ...right, exp: String(right.exp) }, kind),
			"an empty sid": await signer.sign({ ...right, sid: "" }, kind),
			"another issuer": await signer.sign({ ...right, iss: "https://other.example" }, kind),
			"another audience": await signer.sign({ ...right, aud: `${issuer}/other` }, kind),
			"no token": "not-a-token",
		};
		for (const [label, confirmation] of Object.entries(tokens)) {
			const asked = await h.confirming("POST", { confirmation }, { cookie });
			expect(asked.text, label).toContain("Do you want to log out");
		}
		expect(await h.stillOpen(session.id)).toBe(true);
		expect(h.events).toEqual([]);
	});

	it("log out once for a confirmation sent again in the same session, recording no second logout", async () => {
		const h = await serve();
		const { cookie } = await h.login();
		const confirmation = confirmationOf((await h.confirming("GET", {}, { cookie })).text);
		await h.confirming("POST", { confirmation }, { cookie });
		const again = await h.confirming("POST", { confirmation }, { cookie });
		expect(again.status).toBe(200);
		expect(again.text).not.toContain("Do you want to log out");
		expect(h.events.map((e) => e.kind)).toEqual(["logout.success"]);
	});

	it("answer 503, closing nothing, where the session index cannot tell whose the browser is", async () => {
		const failing = defineModule({ takes: [], name: "session" }, (m) => [
			m.provide(sessions).by(() =>
				stubSessions({
					handleOf: async () => {
						throw new Unavailable("session");
					},
				}),
			),
		]);
		const h = await serve({ sessionsModule: failing });
		const shown = await h.confirming("GET", {}, { cookie: "session=s1" });
		const taken = await h.confirming("POST", { confirmation: "x" }, { cookie: "session=s1" });
		expect([shown.status, taken.status]).toEqual([503, 503]);
		expect(h.events).toEqual([]);
	});

	it("close a session past its lifetime through its participants, recording the logout and moving on to the upstream, as the hinted logout does", async () => {
		const closing: string[] = [];
		const watcher = defineModule({ takes: [], name: "watcher" }, (m) => [
			m.contribute(participants).by(() => ({
				name: "watcher",
				closing: async (session) => {
					closing.push(session.id);
				},
			})),
		]);
		const upstream = defineModule({ takes: [], name: "upstream-end" }, (m) => [
			m.contribute(upstreamEnds).by(() => ({
				name: "upstream",
				at: async () => "https://idp.example/logout",
			})),
		]);
		const h = await serve({
			sessionsModule: readEndingSessions(60_000),
			extra: [watcher, upstream],
		});
		const { session, cookie } = await h.login();
		const confirmation = confirmationOf((await h.confirming("GET", {}, { cookie })).text);
		h.advance(60_000);
		const taken = await h.confirming("POST", { confirmation }, { cookie });
		expect(closing).toEqual([session.id]);
		expect(h.events.map((e) => e.kind)).toEqual(["logout.success"]);
		expect(taken.text).toContain('data-target="https://idp.example/logout"');
	});

	it("frame each client of the session and send its back-channel notice, on the confirmed logout too", async () => {
		const h = await serve();
		const { session, cookie } = await h.login();
		await h.redeemed(session.id, "app");
		const confirmation = confirmationOf((await h.confirming("GET", {}, { cookie })).text);
		const taken = await h.confirming("POST", { confirmation }, { cookie });
		const frame = `https://app.example/fc?iss=${encodeURIComponent(issuer)}&#38;sid=${session.id}`;
		expect(taken.text).toContain(`<iframe src="${frame}"`);
		await until(() => h.sent.length > 0);
		expect(h.sent.map((s) => [s.url, s.request?.method])).toEqual([
			["https://app.example/bc", "POST"],
		]);
	});
});
