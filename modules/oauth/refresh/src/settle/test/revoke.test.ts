import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { FamilyStore } from "../../store.ts";
import { settling } from "../settle.ts";

/** A family store with no record, whose `unowned` answers as given; what it was asked. */
function revokerOver(answer: "created" | "exists" | "closed" | undefined) {
	const asked: string[] = [];
	const families: Partial<FamilyStore> = {
		update: async () => undefined,
		save: async () => {
			asked.push("save");
			return "created";
		},
		...(answer === undefined
			? {}
			: {
					unowned: async () => {
						asked.push("unowned");
						return answer;
					},
				}),
	};
	const revoker = settling({ families } as never, {} as never, () => 0, 1000);
	return { revoke: () => revoker.revokeFamily("fam"), asked };
}

describe("revoking a family with no record", () => {
	it("marks it through the store's unowned where offered, closed marking nothing", async () => {
		for (const answer of ["created", "closed"] as const) {
			const r = revokerOver(answer);
			await r.revoke();
			expect(r.asked).toEqual(["unowned"]);
		}
	});

	it("is unavailable where a record was placed meanwhile, so the revocation is tried again", async () => {
		await expect(revokerOver("exists").revoke()).rejects.toBeInstanceOf(Unavailable);
	});

	it("saves the mark with no subject on a store offering no unowned, which keeps none", async () => {
		const r = revokerOver(undefined);
		await r.revoke();
		expect(r.asked).toEqual(["save"]);
	});
});
