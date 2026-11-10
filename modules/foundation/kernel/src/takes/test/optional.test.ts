import { expect, it } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig, optional } from "../../contract.ts";
import { takesUnused } from "../../testing.ts";

const single = kernelConfig();
const control = contract<{ readonly read: () => string }>("store.control");
const answer = contract<string>("answer");

/** A module taking `control` optionally, answering what `find` gives it. */
const finder = defineModule(
	{ name: "finder", replicaSafe: true, takes: [optional(control)] },
	(m) => [m.provide(answer).by(async (c) => (await c.find(control))?.read() ?? "none")],
);
const provider = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
	m.provide(control).by(() => ({ read: () => "read" })),
]);

it("finds a contract taken optionally where a module provides it, and none where none does, refusing no boot", async () => {
	const provided = await assemble({ modules: [finder, provider], config: single });
	expect(provided.get(answer)).toBe("read");
	const missing = await assemble({ modules: [finder], config: single });
	expect(missing.get(answer)).toBe("none");
});

it("holds an optional take to its contract's takenBy", async () => {
	const named = contract<string>("named", { takenBy: ["other"] });
	const refusals = await refusalsOf(
		assemble({
			modules: [
				defineModule({ name: "taker", replicaSafe: true, takes: [optional(named)] }, (m) => [
					m.provide(answer).by(async (c) => (await c.find(named)) ?? "none"),
				]),
				defineModule({ name: "giver", replicaSafe: true, takes: [] }, (m) => [
					m.provide(named).by(() => "x"),
				]),
			],
			config: single,
		}),
	);
	expect(refusals).toContainEqual({ where: "taker", reason: "named is taken by other alone" });
});

it("refuses a find its takes do not name, and a get of an optional take none provides", async () => {
	const unnamed = await refusalsOf(
		assemble({
			modules: [
				provider,
				defineModule({ name: "taker", replicaSafe: true, takes: [] }, (m) => [
					m.provide(answer).by(async (c) => (await c.find(control))?.read() ?? "none"),
				]),
			],
			config: single,
		}),
	);
	expect(unnamed).toEqual([
		{ where: "taker", reason: "takes store.control, which its takes do not name" },
	]);
	const strict = await refusalsOf(
		assemble({
			modules: [
				defineModule({ name: "taker", replicaSafe: true, takes: [optional(control)] }, (m) => [
					m.provide(answer).by(async (c) => (await c.get(control)).read()),
				]),
			],
			config: single,
		}),
	);
	expect(strict).toEqual([{ where: "taker", reason: "no module provides store.control" }]);
});

it("counts an optional take found as used", async () => {
	expect(
		(await takesUnused({ modules: [finder, provider], config: single })).finder,
	).toBeUndefined();
	expect((await takesUnused({ modules: [finder], config: single })).finder).toBeUndefined();
});

it("refuses a find of a contract its takes name plainly, once, even where the taker catches it", async () => {
	const refusals = await refusalsOf(
		assemble({
			modules: [
				provider,
				defineModule({ name: "taker", replicaSafe: true, takes: [control] }, (m) => [
					m.provide(answer).by(async (c) => {
						await c.find(control).catch(() => undefined);
						return (await c.find(control).catch(() => undefined))?.read() ?? "none";
					}),
				]),
			],
			config: single,
		}),
	);
	expect(refusals).toEqual([
		{
			where: "taker",
			reason: "finds store.control, which its takes name plainly: take it optionally or get it",
		},
	]);
});
