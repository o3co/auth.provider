import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { grants } from "../src/contract.ts";

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
