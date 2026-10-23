import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { expect, it, vi } from "vitest";

const stopped: string[] = [];
// The outside party's helper never starts: the deployment's own, started, is ended before boot is refused.
vi.mock("../src/resolver-process/contract.ts", async (actual) => ({
	...(await actual<object>()),
	resolverPool: ({ pool }: { pool: string }) => ({
		start: () => (pool === "outside" ? Promise.reject(new Error("no")) : Promise.resolve()),
		stop: async () => {
			stopped.push(pool);
		},
		run: () => undefined,
	}),
}));

it("refuses boot where a helper does not start, ending every pool first", async () => {
	const { default: outboundModule } = await import("../src/module.ts");
	const refused = await assemble({
		modules: [outboundModule],
		config: { ...kernelConfig(), outbound: {} },
	}).catch((error: unknown) => error);
	expect(BootRefused.is(refused)).toBe(true);
	expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["outbound.resolution"]);
	expect(stopped.sort()).toEqual(["outside", "own"]);
});
