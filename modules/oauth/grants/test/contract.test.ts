import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { grants, tokenTies } from "../src/contract.ts";

const echo = (name: string, grantType = "urn:test:echo") =>
	defineModule({ name }, (m) => [
		m.contribute(grants).by(() => ({
			grantType,
			readsAmbient: "none",
			handle: async () => ({ kind: "error", error: "invalid_grant" }),
		})),
	]);
const types = contract<readonly string[]>("types");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(types).by(async (c) => (await c.collect(grants)).map((g) => g.grantType)),
]);

it("takes one grant for each grant type, and refuses boot when two name the same", async () => {
	const boot = (...modules: ReturnType<typeof echo>[]) =>
		assemble({ modules: [...modules, reader], config: kernelConfig() });
	const two = await boot(echo("a"), echo("b", "urn:test:other"));
	expect([...two.get(types)].sort()).toEqual(["urn:test:echo", "urn:test:other"]);
	await expect(boot(echo("a"), echo("b"))).rejects.toBeInstanceOf(BootRefused);
});

it("takes any number of token ties, one for each name, and refuses boot when two share one", async () => {
	const tie = (module: string, name: string) =>
		defineModule({ name: module }, (m) => [
			m.contribute(tokenTies).by(() => ({ name, tieOf: async () => ({ kind: "none" as const }) })),
		]);
	const names = contract<readonly string[]>("names");
	const read = defineModule({ name: "tie-reader" }, (m) => [
		m.provide(names).by(async (c) => (await c.collect(tokenTies)).map((t) => t.name)),
	]);
	const boot = (...modules: ReturnType<typeof tie>[]) =>
		assemble({ modules: [...modules, read], config: kernelConfig() });
	expect((await boot()).get(names)).toEqual([]);
	expect([...(await boot(tie("a", "session"), tie("b", "family"))).get(names)].sort()).toEqual([
		"family",
		"session",
	]);
	await expect(boot(tie("a", "family"), tie("b", "family"))).rejects.toBeInstanceOf(BootRefused);
});
