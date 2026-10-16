import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GrantsTarget, grantsTarget } from "./grants.ts";

let t: GrantsTarget;
beforeAll(async () => {
	t = await grantsTarget({ lodges: { limit: 3, windowSeconds: 60 } });
});
afterAll(async () => {
	await t?.stop();
});

describe("federation grants: the lodging limit", () => {
	it("counts a client's lodgings whatever user each names, and answers 429 past the limit", async () => {
		for (const sub of ["u1", "u2", "u3"]) expect((await t.lodge({ sub })).status).toBe(201);
		const over = await t.lodge({ sub: "u4" });
		expect([over.status, over.body.error]).toEqual([429, "rate_limited"]);
		// Another client's lodgings are its own.
		expect((await t.lodge({ sub: "u4" }, "other-worker")).status).toBe(201);
	});
});
