import { testRequest } from "@mod/http/testing";
import { afterEach, describe, expect, it } from "vitest";
import { advance, eventsDeclared, request, serve, stopServed } from "../../../test/harness.ts";

afterEach(() => stopServed());
afterEach(() => eventsDeclared());

describe("the flow: the session's freshness, held across the trip to raise it", () => {
	const raised = async (s: Awaited<ReturnType<typeof serve>>, cookie: string) => {
		const done = await s.opened.raise(testRequest({ headers: new Map([["cookie", cookie]]) }), [
			"otp",
			"mfa",
		]);
		return done?.cookies[0]?.split(";")[0] ?? "";
	};
	const table = {
		acr: { "urn:test:mfa": [["mfa"]] },
		authorize: { "step-up-page": "https://as.example/mfa" },
	};

	it("checks max_age immediately before the code is issued, back from raising it, so a record never lets a login past it through [guarantee-2-b]", async () => {
		const s = await serve(table);
		const stepUpBack = async (lateMs: number) => {
			const old = await s.login();
			advance(120_000);
			const asked = await s.authorize(request({ acr_values: "urn:test:mfa", max_age: "60" }), old);
			const resume = new URL(asked.at?.searchParams.get("redirect_to") ?? "");
			const fresh = await s.login();
			const sent = await s.authorize(resume.search.slice(1), fresh);
			expect(`${sent.at?.origin}${sent.at?.pathname}`).toBe("https://as.example/mfa");
			const back = new URL(sent.at?.searchParams.get("redirect_to") ?? "");
			advance(lateMs);
			return (await s.authorize(back.search.slice(1), await raised(s, fresh))).at?.searchParams;
		};
		expect((await stepUpBack(59_000))?.has("code")).toBe(true);
		// Raised more than max_age after the login: refused, its record taken all the same.
		expect((await stepUpBack(61_000))?.get("error")).toBe("login_required");
	});
});
