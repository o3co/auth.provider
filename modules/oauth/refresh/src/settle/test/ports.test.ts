import type { BuildContext } from "@mod/kernel";
import { tokens } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import type { Settings } from "../../section.ts";
import { type FamilyStore, familyStore, redemptionStore, tokenFamilies } from "../../store.ts";
import { portsOf, portsRefused } from "../ports.ts";
import { settlingIn } from "../settle.ts";

const nothing = async () => undefined;
const base = { save: async () => "created" as const, read: nothing, update: nothing };
const ports = {
	erase: async () => ({}) as never,
	migrate: async () => ({}) as never,
	unowned: async () => "created" as const,
};
const names = ["erase", "migrate", "unowned"] as const;
const storeWith = (offered: readonly (keyof typeof ports)[]) =>
	({ ...base, ...Object.fromEntries(offered.map((name) => [name, ports[name]])) }) as FamilyStore;
/** Every part of the set that is neither none nor whole. */
const [erase, migrate, unowned] = names;
const parts = [
	[erase],
	[migrate],
	[unowned],
	[erase, migrate],
	[erase, unowned],
	[migrate, unowned],
];

/** `settlingIn` over a family store, its refusal thrown as the boot's. */
const built = (families: FamilyStore) => {
	const given = new Map<unknown, unknown>([
		[familyStore, families],
		[redemptionStore, base],
		[tokenFamilies, base],
		[tokens, { revocable: () => true }],
	]);
	const c = {
		get: async (contract: unknown) => given.get(contract),
		refuse: (_module: string, reason: string) => {
			throw new Error(reason);
		},
		section: { lifetime: 60 },
		clock: { now: () => 0 },
	};
	return settlingIn(c as unknown as BuildContext<Settings>);
};

describe("the family store's ports", () => {
	it("are one set: none or all of erase, migrate and unowned", () => {
		expect(portsRefused(storeWith([]))).toBeUndefined();
		expect(portsRefused(storeWith(names))).toBeUndefined();
		expect(portsOf(storeWith([]))).toBeUndefined();
		expect(portsOf(storeWith(names))).toBeDefined();
		for (const part of parts) {
			expect(portsRefused(storeWith(part))).toBe(
				"the family store offers part of erase, migrate and unowned: it offers all three, or none",
			);
			expect(portsOf(storeWith(part))).toBeUndefined();
		}
	});

	it("refuse the boot when only part of the set is offered, and build with none or all", async () => {
		await expect(built(storeWith([]))).resolves.toBeDefined();
		await expect(built(storeWith(names))).resolves.toBeDefined();
		for (const part of parts) {
			await expect(built(storeWith(part))).rejects.toThrow(
				"offers part of erase, migrate and unowned",
			);
		}
	});
});
