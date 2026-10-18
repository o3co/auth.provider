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

	it("boots with its pages at http on a loopback host", async () => {
		const local = {
			page: "http://localhost:3000/page",
			"login-page": "http://127.0.0.1:3000/login",
			"step-up-page": "http://[::1]:3000/raise",
		};
		await expect(harness({ settings: local })).resolves.toBeDefined();
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
});
