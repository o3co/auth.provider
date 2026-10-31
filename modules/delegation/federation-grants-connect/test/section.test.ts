import { BootRefused } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { connector, origin } from "../src/connect/test/harness.ts";
import connectModule from "../src/module.ts";
import { section } from "../src/section.ts";

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

	it("refuses in production each page on a loopback host, by its key", () => {
		const refused = connectModule.refusedInProduction?.(
			section.parse({
				page: "http://localhost:8080/ask",
				"login-page": `${origin}/login`,
				"step-up-page": "http://127.0.0.1:8080/raise",
			}),
		);
		expect(refused?.map((r) => r.key)).toEqual(["page", "step-up-page"]);
	});

	it("checks the upstream account unless its section says none", () => {
		expect(section.parse({})["identity-check"]).toBe("required");
		expect(section.parse({ "identity-check": "none" })["identity-check"]).toBe("none");
	});
});

describe("composed beside federation-grants", () => {
	it("asks on its own page, and refuses boot without one, whatever federation-grants' section names", async () => {
		const own = await connector();
		expect(own.location((await own.started()).opened).pathname).toBe("/consent-page");
		const old = await connector({
			settings: { page: undefined },
			grants: { page: `${origin}/old-ask` },
		}).catch((e: unknown) => e);
		expect(old).toBeInstanceOf(BootRefused);
	});
});

it("warns at every start where the section says none, and not where it says required", async () => {
	const warned = async (check?: string) =>
		(await connector(check ? { settings: { "identity-check": check } } : {}))
			.logs()
			.filter((line) => line.event === "federation-grants-connect.identity_unchecked");
	expect(await warned("none")).toEqual([
		{
			level: "warn",
			event: "federation-grants-connect.identity_unchecked",
			fields: { reason: "a callback whose upstream account another user holds is not refused" },
		},
	]);
	expect(await warned()).toEqual([]);
});
