import { BootRefused } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { connector, origin } from "../src/connect/test/harness.ts";
import { section, settingsOf } from "../src/section.ts";

const legacy = { identityCheck: "required" } as const;

describe("the browser half's section", () => {
	it("takes https pages, http only on a loopback host, and refuses an unknown key", () => {
		expect(section.parse({ page: `${origin}/ask` }).page).toBe(`${origin}/ask`);
		expect(section.parse({ "login-page": "http://127.0.0.1:8080/login" })["login-page"]).toBe(
			"http://127.0.0.1:8080/login",
		);
		for (const wrong of [
			{ page: "http://pages.example/ask" },
			{ "step-up-page": "/raise" },
			{ "identity-check": "maybe" },
			{ connections: {} },
		])
			expect(section.safeParse(wrong).success, JSON.stringify(wrong)).toBe(false);
	});

	it("reads its own settings first, else those federation-grants' section still holds", () => {
		const old = {
			page: `${origin}/old-ask`,
			loginPage: `${origin}/old-login`,
			stepUpPage: `${origin}/old-raise`,
			identityCheck: "none",
		} as const;
		expect(settingsOf(section.parse({ page: `${origin}/ask` }), old)).toEqual({
			page: `${origin}/ask`,
			"login-page": `${origin}/old-login`,
			"step-up-page": `${origin}/old-raise`,
			"identity-check": "none",
		});
		expect(settingsOf(section.parse({ "identity-check": "required" }), old)["identity-check"]).toBe(
			"required",
		);
		expect(settingsOf(section.parse({}), legacy)).toEqual({ "identity-check": "required" });
	});
});

describe("composed beside federation-grants", () => {
	it("asks on its own page, else on the one federation-grants' section still names, and refuses boot with neither", async () => {
		const own = await connector();
		expect(own.location((await own.started()).opened).pathname).toBe("/consent-page");
		const old = await connector({
			settings: { page: undefined },
			grants: { page: `${origin}/old-ask` },
		});
		expect(old.location((await old.started()).opened).pathname).toBe("/old-ask");
		const neither = await connector({ settings: { page: undefined } }).catch((e: unknown) => e);
		expect(neither).toBeInstanceOf(BootRefused);
	});
});
