import type { BuildContext } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Settings } from "../../section.ts";
import { type UpstreamTokenStore, upstreamTokenStore } from "../../store.ts";
import { portsOf, portsRefused } from "../ports.ts";
import { renewalIn } from "../renewal.ts";

const nothing = async () => undefined;
const base = {
	save: async () => "created" as const,
	read: nothing,
	update: nothing,
	remove: nothing,
	scan: async () => ({ keys: [] }),
};
const ports = { erase: async () => ({}) as never, migrate: async () => ({}) as never };
const storeWith = (offered: readonly ("erase" | "migrate")[]) =>
	({
		...base,
		...Object.fromEntries(offered.map((name) => [name, ports[name]])),
	}) as UpstreamTokenStore;
const refusal =
	"the upstream token store offers one of erase and migrate: it offers both, or neither";

describe("the upstream token store's ports", () => {
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

	it("refuse the boot at renewalIn when only one of the pair is offered", async () => {
		for (const half of [["erase"], ["migrate"]] as const) {
			const c = {
				late: () => () => ({}),
				get: async (contract: unknown) => (contract === upstreamTokenStore ? storeWith(half) : {}),
				refuse: (_module: string, reason: string) => {
					throw new Error(reason);
				},
			};
			await expect(renewalIn(c as unknown as BuildContext<Settings>)).rejects.toThrow(refusal);
		}
	});
});
