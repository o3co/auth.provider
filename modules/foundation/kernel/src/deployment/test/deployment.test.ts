import { describe, expect, it } from "vitest";
import { z } from "zod";
import { refusalsOf, unreadable } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig, type Module } from "../../contract.ts";
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
		// In the order the preflight asks: replicas, production, then takes.
		expect(refused.map((r) => r.where)).toEqual(["unsafe", "origin.url", "taker"]);
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

	it("holds an answer that is no list of key and reason strings, or that throws as it is read, to its module", async () => {
		const throwing = () => {
			throw new Error(secret);
		};
		const answers: unknown[] = [
			"",
			new Set([{ key: "k", reason: "r" }]),
			[{}],
			[{ key: 1, reason: "r" }],
			[{ key: "k", reason: "" }],
			[null],
			{ length: 1, 0: { key: "k", reason: "r" } },
			new Proxy([{ key: "k", reason: "r" }], { get: throwing }),
			[
				{
					get key() {
						return throwing();
					},
					reason: "r",
				},
			],
			{ [Symbol.iterator]: throwing },
		];
		const modules = answers.map((answer, i) =>
			defineModule({ name: `a${i}`, refusedInProduction: () => answer as never, takes: [] }),
		);
		const refused = await refusalsOf(assemble({ modules, config: production }));
		expect(refused).toEqual(
			answers.map((_, i) => ({ where: `a${i}`, reason: "its production check failed" })),
		);
		expect(JSON.stringify(refused)).not.toContain(secret);
	});

	it("holds a declaration whose very reading throws to its module, keeping nothing of it", async () => {
		const getter = (key: string) =>
			({
				name: `get-${key}`,
				takes: [],
				get [key]() {
					throw new Error(secret);
				},
			}) as unknown as Module;
		const refused = await refusalsOf(
			assemble({
				modules: [getter("refusedInProduction"), getter("replicaSafe"), origin],
				config: { ...kernelConfig({ deployment: "multi" }), origin: { url: "http://x" } },
			}),
		);
		expect(refused).toEqual([
			{ where: "get-replicaSafe", reason: "its multi-instance check failed" },
			{ where: "get-refusedInProduction", reason: "its production check failed" },
			{ where: "origin.url", reason: "is plain http" },
		]);
		expect(JSON.stringify(refused)).not.toContain(secret);
	});

	it("asks a declaration as its module's method, and with no section, or the section its defaults fill", async () => {
		const asked: unknown[] = [];
		const methods = {
			name: "methods",
			takes: [],
			replicaSafe(this: { name: string }) {
				return this.name === "methods";
			},
			refusedInProduction(this: { name: string }, section: unknown) {
				asked.push(section);
				return this.name === "methods" ? [] : [{ key: "this", reason: "lost" }];
			},
		} as unknown as Module;
		const filled = defineModule({
			name: "filled",
			section: z.strictObject({ n: z.number().prefault(7) }),
			refusedInProduction: (section) => {
				asked.push(section);
				return [];
			},
			takes: [],
		});
		await assemble({
			modules: [methods, filled],
			config: kernelConfig({ deployment: "multi" }),
		});
		expect(asked).toEqual([undefined, { n: 7 }]);
	});

	it("gives a factory an environment it cannot change", async () => {
		const outcome = contract<readonly unknown[]>("outcome");
		const changer = defineModule({ name: "changer", takes: [] }, (m) => [
			m
				.provide(outcome)
				.by((c) => [
					Reflect.set(c, "environment", "development"),
					Reflect.defineProperty(c, "environment", { value: "development" }),
					c.environment,
				]),
		]);
		const app = await assemble({ modules: [changer], config: production });
		expect(app.get(outcome)).toEqual([false, false, "production"]);
	});

	it("reads an answer by index alone, never by its iterator", async () => {
		const answer = Object.defineProperty([{ key: "k", reason: "r" }], Symbol.iterator, {
			get: () => {
				throw new Error(secret);
			},
		});
		const indexed = defineModule({ name: "indexed", refusedInProduction: () => answer, takes: [] });
		const refused = await refusalsOf(assemble({ modules: [indexed], config: production }));
		expect(refused).toEqual([{ where: "indexed.k", reason: "r" }]);
	});

	it("holds a replica declaration answering anything but a boolean to its module", async () => {
		const answers: unknown[] = [1, "yes", undefined, null, {}];
		const modules = answers.map((answer, i) =>
			defineModule({ name: `r${i}`, replicaSafe: () => answer as boolean, takes: [] }),
		);
		const refused = await refusalsOf(
			assemble({ modules, config: kernelConfig({ deployment: "multi" }) }),
		);
		expect(refused).toEqual(
			answers.map((_, i) => ({ where: `r${i}`, reason: "its multi-instance check failed" })),
		);
	});
});
