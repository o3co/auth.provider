import { expect, it } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig, optional } from "../../contract.ts";
import { takesUnused } from "../../testing.ts";

const single = kernelConfig();
/** A contract its owner lets go unprovided. */
const control = contract<{ readonly read: () => string }>("store.control", { optional: true });
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

it("lets a contract be taken optionally only where its owner lets it go unprovided", async () => {
	const required = contract<string>("required");
	const refusals = await refusalsOf(
		assemble({
			modules: [
				defineModule({ name: "taker", replicaSafe: true, takes: [optional(required)] }, (m) => [
					m.provide(answer).by(async (c) => (await c.find(required)) ?? "none"),
				]),
				defineModule({ name: "owner", replicaSafe: true, takes: [] }, (m) => [
					m.provide(required).by(() => "x"),
				]),
			],
			config: single,
		}),
	);
	expect(refusals).toEqual([{ where: "taker", reason: "required may not be taken optionally" }]);
});

it("holds an optional take to its contract's takenBy", async () => {
	const named = contract<string>("named", { takenBy: ["other"], optional: true });
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

it("refuses a find its takes do not name, and a get or late of a contract taken optionally, provided or not", async () => {
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
	for (const how of ["get", "late"] as const) {
		const required = await refusalsOf(
			assemble({
				modules: [
					provider,
					defineModule({ name: "taker", replicaSafe: true, takes: [optional(control)] }, (m) => [
						m
							.provide(answer)
							.by(async (c) =>
								how === "get" ? (await c.get(control)).read() : (c.late(control), "late"),
							),
					]),
				],
				config: single,
			}),
		);
		expect(required, how).toEqual([
			{ where: "taker", reason: "takes store.control optionally: find it" },
		]);
	}
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

it("refuses the boot where a provider of a contract taken optionally fails, never reading it as missing", async () => {
	const failing = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(control).by((c) => c.refuse("store", "cannot open")),
	]);
	const refusals = await refusalsOf(assemble({ modules: [finder, failing], config: single }));
	expect(refusals).toEqual([{ where: "store", reason: "cannot open" }]);
});

it("counts an optional take found as used", async () => {
	expect(
		(await takesUnused({ modules: [finder, provider], config: single })).finder,
	).toBeUndefined();
	expect((await takesUnused({ modules: [finder], config: single })).finder).toBeUndefined();
});
