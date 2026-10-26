import { csrfChecked } from "@mod/csrf";
import { use } from "@mod/http";
import { keys } from "@mod/keys";
import { requestsPerSource } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import { issuer, servedEach } from "./harness.ts";

const serve = servedEach();
const path = "/oauth/logout/confirm";
const confirmationOf = (text: string | undefined) =>
	/name="confirmation" value="([^"]+)"/.exec(text ?? "")?.[1] ?? "";

describe("the confirmation's routes", () => {
	it("are a GET that changes nothing, counted per source, and a POST under the CSRF check, uncounted", async () => {
		const h = await serve();
		const route = (method: string) => h.routes.find((r) => r.path === path && r.method === method);
		expect(route("GET")?.changesState).toBe(false);
		expect(route("GET")?.uses).toEqual([
			use(requestsPerSource, { name: "rp-logout", window: { limit: 60, ms: 60_000 } }),
		]);
		expect(route("POST")?.uses).toEqual([use(csrfChecked)]);
		expect(route("POST")?.takes).toEqual(["form"]);
		expect(route("POST")?.unlimited).toBeDefined();
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
});
