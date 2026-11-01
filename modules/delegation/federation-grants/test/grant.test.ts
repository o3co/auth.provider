import { BootRefused } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import { clientSection } from "../src/grant/grant.ts";
import { section } from "../src/section.ts";
import { bootCases, sectionCases } from "./fixtures/settings.ts";
import { harness } from "./harness.ts";

describe("the operator's section and the boot", () => {
	for (const c of sectionCases) {
		it(`takes ${c.name}: ${c.ok}`, () => expect(section.safeParse(c.settings).success).toBe(c.ok));
	}
	for (const c of bootCases) {
		it(`refuses ${c.name}`, async () => {
			const refused = (e: unknown) =>
				e instanceof BootRefused && e.refusals.some((r) => `${r.where}: ${r.reason}` === c.refused);
			await expect(harness(c)).rejects.toSatisfy(refused);
		});
	}

	it("refuses to boot on a browser setting still written here, naming the key and never its value", async () => {
		const error = await harness({
			settings: { "login-page": "https://issuer.example/secret-login" } as never,
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect(JSON.stringify((error as BootRefused).refusals)).toContain("login-page");
		expect(JSON.stringify((error as BootRefused).refusals)).not.toContain("secret-login");
	});

	it("counts every route's requests per source in the operator's window", async () => {
		const h = await harness({ settings: { requests: 7, window: "9s" } });
		const own = h.routes.filter((r) => r.path.includes("federation-grants"));
		for (const route of own) {
			const limited = route.uses?.find((u) => u.policy === requestsPerSource);
			expect(limited?.options, route.path).toMatchObject({ window: { limit: 7, ms: 9000 } });
		}
		expect(own.length).toBe(6);
	});

	it("holds a grant to the longest life allowed now, after a restart that shortened it", async () => {
		const before = await harness();
		const { id } = await before.connected();
		const after = await harness({ stores: before.stores, settings: { "max-lifetime": "1m" } });
		after.advance(60_000);
		expect((await after.grantCall(id, "token")).json?.error).toBe("grant_expired");
	});
});

describe("a client's returns", () => {
	it("refuses a return URI holding any name the end of a connection adds", () => {
		for (const name of ["grant_id", "state", "error"]) {
			const checked = clientSection.schema["~standard"].validate({
				"return-uris": [`https://worker.example/back?${name}=x`],
			});
			expect("issues" in checked && checked.issues, name).toBeTruthy();
		}
	});

	it("takes only a return URI a client may register to be sent back to, as redirect-uris says", () => {
		const takes = (uri: string) =>
			!("issues" in clientSection.schema["~standard"].validate({ "return-uris": [uri] }));
		for (const uri of [
			"https://worker.example/back",
			"http://127.0.0.1:8080/back",
			"http://localhost/back",
			"com.example.worker:/back",
		]) {
			expect(takes(uri), uri).toBe(true);
		}
		for (const uri of [
			"javascript:alert(1)",
			"data:text/html,x",
			"http://worker.example/back",
			"ftp://worker.example/back",
			"https://worker.example/back#here",
			"https://user:pass@worker.example/back",
		]) {
			expect(takes(uri), uri).toBe(false);
		}
	});
});
