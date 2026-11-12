import { expect, it } from "vitest";
import { harness, said } from "../../../test/harness.ts";

it("refuses a lodging for a subject erased here as unknown, keeping nothing and auditing it without the subject", async () => {
	const h = await harness();
	h.stores.erased.add("gone");
	const lodged = await h.lodge({ sub: "gone" });
	expect(said(lodged)).toBe("403 access_denied subject_unknown");
	const denied = h.events.filter((e) => e.kind === "federation.grant.request.denied");
	expect(denied.map((e) => [e.subject, e.attributes])).toEqual([
		[
			undefined,
			{ client: "worker", outcome: "subject_unknown", withheld: "erased", source: "127.0.0.1" },
		],
	]);
	expect(h.events.some((e) => e.kind === "federation.grant.requested")).toBe(false);
});
