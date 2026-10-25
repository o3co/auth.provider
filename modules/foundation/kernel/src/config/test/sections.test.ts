import { describe, expect, it } from "vitest";
import { z } from "zod";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";

const single = kernelConfig();

describe("a module's section, as the kernel reads it", () => {
	it("converts a string as the HOCON library's typed getters do, a number or a boolean as the schema asks", async () => {
		const read = contract<unknown>("read");
		const m = defineModule(
			{ name: "m", section: z.strictObject({ n: z.number(), b: z.boolean() }), takes: [] },
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
					defineModule({ name: "same", takes: [] }),
					defineModule({ name: "same", takes: [] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "same", reason: "duplicate module name" }]);
	});
});
