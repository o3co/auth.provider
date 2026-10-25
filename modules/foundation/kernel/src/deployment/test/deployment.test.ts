import { describe, expect, it } from "vitest";
import { z } from "zod";
import { refusalsOf, unreadable } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";
import { recordingLog } from "../../testing.ts";

const production = kernelConfig();
const development = kernelConfig({ environment: "development" });
const secret = "s3cr3t-value";

/** A module whose section holds a URL, refusing a plain-http one in production. */
const origin = defineModule({
	name: "origin",
	section: z.strictObject({ url: z.string() }),
	refusedInProduction: (section) =>
		section.url.startsWith("http:") ? [{ key: "url", reason: "is plain http" }] : [],
	takes: [],
});

describe("the deployment's environment", () => {
	it("is production unless the kernel's section says development, and nothing else", async () => {
		const plain = { origin: { url: "http://a.example" } };
		const refused = await refusalsOf(
			assemble({ modules: [origin], config: { ...production, ...plain } }),
		);
		expect(refused).toEqual([{ where: "origin.url", reason: "is plain http" }]);
		await expect(
			assemble({ modules: [origin], config: { ...development, ...plain } }),
		).resolves.toBeDefined();
		const other = await refusalsOf(
			assemble({ modules: [], config: kernelConfig({ environment: "staging" as never }) }),
		);
		expect(other.map((r) => r.where)).toEqual(["kernel.environment"]);
	});

	it("refuses in production with every other refusal before anything is built", async () => {
		const built: string[] = [];
		const missing = contract<string>("missing");
		const taker = defineModule({ name: "taker", takes: [missing] });
		const unsafe = defineModule({ name: "unsafe", replicaSafe: false, takes: [] }, (m) => [
			m.provide(contract<string>("unsafe")).by(() => {
				built.push("unsafe");
				return "";
			}),
		]);
		const refused = await refusalsOf(
			assemble({
				modules: [origin, taker, unsafe],
				config: {
					...kernelConfig({ deployment: "multi" }),
					origin: { url: "http://a.example" },
				},
			}),
		);
		expect(refused.map((r) => r.where).sort()).toEqual(["origin.url", "taker", "unsafe"]);
		expect(built).toEqual([]);
	});

	it("asks a module's production check only with a section that passed, and never in development", async () => {
		const asked: unknown[] = [];
		const m = defineModule({
			name: "m",
			section: z.strictObject({ n: z.number() }),
			refusedInProduction: (section) => {
				asked.push(section);
				return [];
			},
			takes: [],
		});
		await refusalsOf(assemble({ modules: [m], config: { ...production, m: { n: "x" } } }));
		await assemble({ modules: [m], config: { ...development, m: { n: 1 } } });
		expect(asked).toEqual([]);
		await assemble({ modules: [m], config: { ...production, m: { n: 1 } } });
		expect(asked).toEqual([{ n: 1 }]);
	});

	it("holds a check that throws to its module, with a fixed reason, never the thrown value, and goes on", async () => {
		const recorded = recordingLog();
		const throwing = (name: string, thrown: unknown) =>
			defineModule({
				name,
				refusedInProduction: () => {
					throw thrown;
				},
				replicaSafe: () => {
					throw thrown;
				},
				takes: [],
			});
		const modules = [
			throwing("one", new Error(`holds ${secret}`)),
			...unreadable().map((value, i) => throwing(`odd${i}`, value)),
			origin,
		];
		const refused = await refusalsOf(
			assemble({
				modules,
				config: { ...kernelConfig({ deployment: "multi" }), origin: { url: "http://x" } },
				runtime: {
					clock: { now: () => 0 },
					random: { bytes: (n) => new Uint8Array(n) },
					log: recorded.log,
				},
			}),
		);
		for (const name of ["one", "odd0", "odd1"]) {
			expect(refused).toContainEqual({ where: name, reason: "its production check failed" });
			expect(refused).toContainEqual({ where: name, reason: "its multi-instance check failed" });
		}
		expect(refused).toContainEqual({ where: "origin.url", reason: "is plain http" });
		expect(JSON.stringify([refused, recorded.lines()])).not.toContain(secret);
	});
});
