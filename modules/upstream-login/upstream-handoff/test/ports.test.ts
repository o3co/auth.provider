import { describe, expect, it } from "vitest";
import { handoffIn } from "../src/handoff.ts";
import { portsOf, portsRefused } from "../src/ports.ts";
import { type HeldLoginStore, heldLoginStore } from "../src/store.ts";

const nothing = async () => undefined;
const base = {
	save: async () => "created" as const,
	update: nothing,
	remove: nothing,
};
const ports = { erase: async () => ({}) as never, migrate: async () => ({}) as never };
const storeWith = (offered: readonly ("erase" | "migrate")[]) =>
	({
		...base,
		...Object.fromEntries(offered.map((name) => [name, ports[name]])),
	}) as unknown as HeldLoginStore;
const refusal = "the held login store offers one of erase and migrate: it offers both, or neither";

describe("the held login store's ports", () => {
	it("are one pair: both or neither of erase and migrate", () => {
		expect(portsRefused(storeWith([]))).toBeUndefined();
		expect(portsRefused(storeWith(["erase", "migrate"]))).toBeUndefined();
		expect(portsOf(storeWith([]))).toBeUndefined();
		expect(portsOf(storeWith(["erase", "migrate"]))).toBeDefined();
		for (const half of [["erase"], ["migrate"]] as const) {
			expect(portsRefused(storeWith(half))).toBe(refusal);
			expect(portsOf(storeWith(half))).toBeUndefined();
		}
	});

	it("refuse the boot at handoffIn when only one of the pair is offered, whether or not a module receives tokens", async () => {
		for (const half of [["erase"], ["migrate"]] as const) {
			const c = {
				collect: async () => [],
				get: async (contract: unknown) => (contract === heldLoginStore ? storeWith(half) : {}),
				refuse: (_module: string, reason: string) => {
					throw new Error(reason);
				},
			};
			await expect(handoffIn(c as never)).rejects.toThrow(refusal);
		}
	});
});
