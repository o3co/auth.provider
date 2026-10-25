import { acrEntries, isAmrSets } from "@mod/acr";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { secondFactorAmr } from "@mod/mfa-extensions";
import { type FactorReading, factorReading } from "@mod/mfa-reading";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const runtime = quietRuntime();
const offered = contract<() => unknown>("test.offered");
const reader = defineModule({ name: "reader", takes: [acrEntries] }, (m) => [
	m.provide(offered).by(async (c) => {
		const entries = await c.collect(acrEntries);
		return () => entries;
	}),
]);
const secondFactors = defineModule({ name: "factors-stand-in", takes: [] }, (m) => [
	m.provide(factorReading).by(() => ({}) as FactorReading),
]);

it("offers the acr met by a second factor, only where second factors are composed", async () => {
	const app = await assemble({
		modules: [secondFactors, bridge, reader],
		config: kernelConfig(),
		runtime,
	});
	expect(app.get(offered)()).toEqual([{ acr: "urn:o3co:acr:mfa", sets: [[secondFactorAmr]] }]);
	// The entry passes acr's own rule for the sets an entry may hold.
	expect(isAmrSets([[secondFactorAmr]])).toBe(true);
	await expect(
		assemble({ modules: [bridge, reader], config: kernelConfig(), runtime }),
	).rejects.toThrow(BootRefused);
});

it("takes all it names", async () => {
	const input = { modules: [secondFactors, bridge, reader], config: kernelConfig(), runtime };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["mfa-acr"]).toBeUndefined();
});
