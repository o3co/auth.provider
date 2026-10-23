import { areaTarget } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser as openBrowser } from "../../../test/browser.ts";
import { grantsLoginPage } from "../../area.ts";
import { type GrantsTarget, grantsTarget, origin, page } from "./grants.ts";

const loginPage = `${origin}/sign-in`;

describe.runIf(areaTarget().can(grantsLoginPage))(
	"federation grants: a browser with no session logs in, then goes on with the connect",
	() => {
		let t: GrantsTarget;
		beforeAll(async () => {
			t = await grantsTarget({ loginPage });
		});
		afterAll(async () => {
			await t?.stop();
		});

		/** A connect opened in a browser with no session: where it is sent, and the target to come back to. */
		const sentToLogIn = async () => {
			const lodged = await t.lodge();
			const connect = new URL(String(lodged.body.connect_uri));
			const b = openBrowser(() => t.base, origin);
			const opened = await b.get(`${connect.pathname}${connect.search}`);
			expect(opened.status).toBe(303);
			const sent = new URL(opened.location);
			expect(`${sent.origin}${sent.pathname}`).toBe(loginPage);
			const back = sent.searchParams.get("redirect_to") ?? "";
			expect(back).toBe(connect.href);
			return { b, back };
		};
		/** The connect, opened again once logged in: it goes on to the page that asks the user. */
		const goesOn = async (b: ReturnType<typeof openBrowser>, back: string) => {
			const at = new URL(back);
			const opened = await b.get(`${at.pathname}${at.search}`);
			expect(opened.status).toBe(303);
			expect(opened.location.startsWith(`${page}?challenge=`)).toBe(true);
		};

		it("comes back from a login through the upstream to the connect it was sent from", async () => {
			const { b, back } = await sentToLogIn();
			const started = await b.get(
				`/session/oauth/federation/corp?redirect_to=${encodeURIComponent(back)}`,
			);
			expect(started.status).toBe(302);
			const done = await b.get(
				`/session/oauth/federation/corp/callback?${t.corp.authorize(started.location, { subject: "u-alice" })}`,
			);
			expect(done.location).toBe(back);
			await goesOn(b, back);
		});

		it("comes back from a password login to the connect it was sent from", async () => {
			const { b, back } = await sentToLogIn();
			const logged = await b.submit("/session/login", {
				username: "alice",
				password: "correct horse battery",
				redirect_to: back,
			});
			expect(logged.status).toBe(200);
			expect(logged.body).toMatchObject({ redirect_to: back });
			await goesOn(b, back);
		});

		it("refuses to come back to a connect on another origin", async () => {
			const { b, back } = await sentToLogIn();
			const elsewhere = back.replace(origin, "https://other.example");
			const logged = await b.submit("/session/login", {
				username: "alice",
				password: "correct horse battery",
				redirect_to: elsewhere,
			});
			expect([logged.status, logged.body]).toEqual([400, { error: "invalid_redirect" }]);
		});
	},
);
