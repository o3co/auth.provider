import { acrEntries, isAmrSets } from "@mod/acr";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Factors, factors, secondFactorAmr } from "@mod/mfa";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const runtime = quietRuntime();
const offered = contract<() => unknown>("test.offered");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(offered).by(async (c) => {
		const entries = await c.collect(acrEntries);
		return () => entries;
	}),
]);
const secondFactors = defineModule({ name: "factors-stand-in" }, (m) => [
	m.provide(factors).by(() => ({}) as Factors),
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
