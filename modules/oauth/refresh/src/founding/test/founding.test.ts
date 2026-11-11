import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { StoredRedemption } from "../../store.ts";
import { starting, takingBack } from "../founding.ts";

/** Redemptions kept create-if-absent, as the store keeps them; the revoker and the founding as stand-ins. */
function parts(opts: { readonly entered?: boolean } = {}) {
	const kept = new Map<string, StoredRedemption>();
	const redemptions = {
		save: async (name: string, record: StoredRedemption) => {
			if (kept.has(name)) return "exists" as const;
			kept.set(name, record);
			return "created" as const;
		},
		read: async (name: string) => kept.get(name),
	};
	const stores = { redemptions } as never;
	const revoked: string[] = [];
	const revoker = { revokeFamily: async (id: string) => void revoked.push(id) } as never;
	let during: (() => Promise<void>) | undefined;
	const founded: string[] = [];
	const found = {
		name: () => "fam",
		bindingFor: () => undefined,
		endsAt: () => 1000,
		found: async (id: string) => {
			founded.push(id);
			await during?.();
			return `${id}.secret`;
		},
	} as never;
	const selections = { follow: async () => {} };
	const entered = {
		entryOf: async () => ({ kind: opts.entered === false ? "absent" : "entered" }),
	} as never;
	const start = starting(stores, revoker, found, 1000, selections, entered);
	const takeBack = takingBack(stores, revoker, 1000);
	const redeemed = {
		redemption: "r",
		// A client allowed the refresh grant, as `client-allowance` reads its section.
		client: { id: "app", kind: "confidential", section: () => ({ grants: ["refresh_token"] }) },
		session: "s",
		access: { id: "a", expiresAt: 1000 },
	} as never;
	return {
		kept,
		revoked,
		founded,
		start: () => start(redeemed),
		takeBack: () => takeBack("r"),
		during: (step: () => Promise<void>) => {
			during = step;
		},
	};
}

describe("a family's founding against a take-back of its redemption", () => {
	it("decides a take-back before the link by the link's create: the family is revoked and hands out no token", async () => {
		const p = parts();
		// The record is written; the code is taken back before the redemption's link.
		p.during(() => p.takeBack());
		await expect(p.start()).rejects.toBeInstanceOf(Unavailable);
		expect(p.kept.get("r")).toEqual({ format: 1, taken: true });
		expect(p.revoked).toEqual(["fam"]);
	});

	it("revokes the family a take-back after the link finds", async () => {
		const p = parts();
		expect(await p.start()).toBe("fam.secret");
		await p.takeBack();
		expect(p.revoked).toEqual(["fam"]);
	});

	it("writes no record and no link for a session closed before the family starts", async () => {
		const p = parts({ entered: false });
		await expect(p.start()).rejects.toBeInstanceOf(Unavailable);
		expect([p.founded, [...p.kept.keys()], p.revoked]).toEqual([[], [], []]);
	});
});
