import { describe, expect, it } from "vitest";
import { z } from "zod";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";

const single = kernelConfig();

describe("a module's section, as the kernel reads it", () => {
	it("converts a string as the HOCON library's typed getters do, a number or a boolean as the schema asks", async () => {
		const read = contract<unknown>("read");
		const m = defineModule(
			{
				name: "m",
				replicaSafe: true,
				section: z.strictObject({ n: z.number(), b: z.boolean() }),
				takes: [],
			},
			(m) => [m.provide(read).by((c) => c.section)],
		);
		const app = await assemble({ modules: [m], config: { ...single, m: { n: "5", b: "true" } } });
		expect(app.get(read)).toEqual({ n: 5, b: true });
		const refusals = await refusalsOf(
			assemble({ modules: [m], config: { ...single, m: { n: "five", b: "true" } } }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["m.n"]);
	});

	it("refuses two modules of one name, naming it", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "same", replicaSafe: true, takes: [] }),
					defineModule({ name: "same", replicaSafe: true, takes: [] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "same", reason: "duplicate module name" }]);
	});

	it("refuses a section whose schema throws a schema error with no issue it can read, in production too, building nothing", async () => {
		const empty = new z.ZodError([]);
		// A schema error whose issues are no list.
		const holed = new Proxy(new z.ZodError([]), {
			get: (target, key) => (key === "issues" ? "none" : Reflect.get(target, key)),
		});
		const malformed = new z.ZodError([{ code: "custom", message: 42, path: "x" } as never]);
		for (const thrown of [empty, holed, malformed]) {
			let built = false;
			let asked = false;
			const m = defineModule(
				{
					name: "m",
					replicaSafe: false,
					section: z.object({}).transform(() => {
						throw thrown;
					}),
					takes: [],
					refusedInProduction: () => {
						asked = true;
						return [];
					},
				},
				(m) => [
					m.provide(contract<object>("m-out")).by(() => {
						built = true;
						return {};
					}),
				],
			);
			const refusals = await refusalsOf(
				assemble({
					modules: [m],
					config: { ...kernelConfig({ environment: "production" }), m: {} },
				}),
			);
			expect(refusals).toEqual([
				{ where: "m", reason: "its schema failed as it read the section" },
			]);
			expect([built, asked]).toEqual([false, false]);
		}
	});

	it("reads a section left out of the configuration as an empty one, its defaults filled in", async () => {
		const read = contract<unknown>("read");
		const m = defineModule(
			{
				name: "m",
				replicaSafe: true,
				section: z.strictObject({ n: z.number().default(3) }),
				takes: [],
			},
			(m) => [m.provide(read).by((c) => c.section)],
		);
		const app = await assemble({ modules: [m], config: single });
		expect(app.get(read)).toEqual({ n: 3 });
	});

	it("reads a module's section from the configuration's own keys only", async () => {
		const read = contract<unknown>("read");
		const app = await assemble({
			modules: [
				defineModule({ name: "constructor", replicaSafe: true, takes: [] }),
				defineModule(
					{
						name: "toString",
						replicaSafe: true,
						section: z.strictObject({}).default({}),
						takes: [],
					},
					(m) => [m.provide(read).by((c) => c.section)],
				),
			],
			config: single,
		});
		expect(app.get(read)).toEqual({});
	});
});
