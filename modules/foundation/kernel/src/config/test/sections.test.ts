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

describe("the kernel's own section, refused", () => {
	/** A module refusing a plain-http URL in production, and declaring itself unsafe on many instances. */
	const strict = defineModule({
		name: "strict",
		replicaSafe: false,
		section: z.strictObject({ url: z.string().default("http://a.example") }),
		refusedInProduction: (section) =>
			section.url.startsWith("http:") ? [{ key: "url", reason: "is plain http" }] : [],
		takes: [],
	});
	const refusedWith = async (kernel: Record<string, unknown>) =>
		refusalsOf(assemble({ modules: [strict], config: { kernel } }));

	it("keeps the environment and deployment written beside a refused key, asking their checks as written", async () => {
		const development = { deployment: "single", environment: "development", "stop-deadline": "30" };
		expect(await refusedWith(development)).toEqual([
			{ where: "kernel.stop-deadline", reason: expect.any(String) },
		]);
		// No environment written is production, its default, so its check is asked.
		const unwritten = { deployment: "multi", "stop-deadline": "30" };
		expect((await refusedWith(unwritten)).map((r) => r.where)).toEqual([
			"kernel.stop-deadline",
			"strict",
			"strict.url",
		]);
	});

	it("asks no production check where the environment is refused, and no replica check where the deployment is", async () => {
		const refused = await refusedWith({ deployment: "one", environment: "staging" });
		expect(refused.map((r) => r.where).sort()).toEqual(["kernel.deployment", "kernel.environment"]);
	});

	it("says an unset deployment is required, with its choices, and a wrong one by its choices", async () => {
		const alone = async (kernel: Record<string, unknown>) =>
			refusalsOf(assemble({ modules: [], config: { kernel } }));
		expect(await alone({})).toEqual([
			{ where: "kernel.deployment", reason: "required, and not set: single or multi" },
		]);
		expect(await alone({ deployment: "one" })).toEqual([
			{ where: "kernel.deployment", reason: "single or multi" },
		]);
	});
});

it("refuses a section for a module that is not loaded, saying to take it out or compose the module", async () => {
	expect(await refusalsOf(assemble({ modules: [], config: { ...single, ghost: {} } }))).toEqual([
		{
			where: "ghost",
			reason: "section for a module that is not loaded: take it out, or compose the module",
		},
	]);
});
