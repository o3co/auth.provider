import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { type Grant, type GrantInput, grants, tokenTies } from "../src/contract.ts";

const echo = (name: string, grantType = "urn:test:echo") =>
	defineModule({ name, takes: [] }, (m) => [
		m.contribute(grants).by(() => ({
			grantType,
			readsAmbient: "none",
			handle: async () => ({ kind: "error", error: "invalid_grant" }),
		})),
	]);
const types = contract<readonly string[]>("types");
const reader = defineModule({ name: "reader", takes: [grants] }, (m) => [
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
		defineModule({ name: module, takes: [] }, (m) => [
			m.contribute(tokenTies).by(() => ({ name, tieOf: async () => ({ kind: "none" as const }) })),
		]);
	const names = contract<readonly string[]>("names");
	const read = defineModule({ name: "tie-reader", takes: [tokenTies] }, (m) => [
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

it("lets a grant identify the client of a request naming none, and hands what it identified back to it", async () => {
	// What the grant checked, as it would carry it: the endpoint never reads it.
	const checked = { signer: "s" };
	const identifying = defineModule({ name: "identifying", takes: [] }, (m) => [
		m.contribute(grants).by(() => ({
			grantType: "urn:test:identifying",
			readsAmbient: "none",
			identify: async ({ param }) =>
				param("assertion") === "known"
					? { kind: "client", client: "registered", identified: checked }
					: { kind: "error", error: "invalid_grant", description: "untrusted signer" },
			handle: async ({ identified }) =>
				identified === checked
					? { kind: "issued", body: {} }
					: { kind: "error", error: "invalid_grant" },
		})),
	]);
	const found = contract<Grant>("found");
	const read = defineModule({ name: "identifying-reader", takes: [grants] }, (m) => [
		m.provide(found).by(async (c) => (await c.collect(grants))[0] as Grant),
	]);
	const grant = (await assemble({ modules: [identifying, read], config: kernelConfig() })).get(
		found,
	);
	const asked = (assertion: string) => ({
		request: {} as GrantInput["request"],
		param: (name: string) => (name === "assertion" ? assertion : undefined),
		value: () => undefined,
	});
	expect(await grant.identify?.(asked("known"))).toEqual({
		kind: "client",
		client: "registered",
		identified: checked,
	});
	expect(await grant.identify?.(asked("other"))).toMatchObject({
		kind: "error",
		error: "invalid_grant",
	});
	const input = { identified: checked } as GrantInput;
	expect(await grant.handle(input)).toEqual({ kind: "issued", body: {} });
	// A grant that cannot tell has no `identify`: the endpoint answers such a request as it does today.
	expect(
		"identify" in
			(await assemble({ modules: [echo("a"), read], config: kernelConfig() })).get(found),
	).toBe(false);
});
