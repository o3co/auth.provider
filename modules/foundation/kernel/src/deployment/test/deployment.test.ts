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
	replicaSafe: true,
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
		const taker = defineModule({ name: "taker", replicaSafe: true, takes: [missing] });
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

	it("asks a module's production check only with a section that passed, in either environment", async () => {
		const asked: unknown[] = [];
		const m = defineModule({
			name: "m",
			replicaSafe: true,
			section: z.strictObject({ n: z.number() }),
			refusedInProduction: (section) => {
				asked.push(section);
				return [];
			},
			takes: [],
		});
		await refusalsOf(assemble({ modules: [m], config: { ...production, m: { n: "x" } } }));
		expect(asked).toEqual([]);
		await assemble({ modules: [m], config: { ...development, m: { n: 1 } } });
		await assemble({ modules: [m], config: { ...production, m: { n: 2 } } });
		expect(asked).toEqual([{ n: 1 }, { n: 2 }]);
	});

	it("warns in development each value production would refuse, by its key and the module's reason, never the value", async () => {
		const recorded = recordingLog();
		const runtime = {
			clock: { now: () => 0 },
			random: { bytes: (n: number) => new Uint8Array(n) },
			log: recorded.log,
		};
		const twice = defineModule({
			name: "twice",
			replicaSafe: true,
			section: z.strictObject({ a: z.string(), b: z.string() }),
			refusedInProduction: () => [
				{ key: "a", reason: "is plain http" },
				{ key: "b.c", reason: "is on loopback" },
			],
			takes: [],
		});
		const plain = { origin: { url: `http://${secret}.example` }, twice: { a: secret, b: secret } };
		await assemble({ modules: [origin, twice], config: { ...development, ...plain }, runtime });
		const warned = recorded.lines().filter((l) => l.event === "kernel.allowed_in_development");
		expect(warned).toEqual([
			{
				level: "warn",
				event: "kernel.allowed_in_development",
				fields: { key: "origin.url", reason: "is plain http" },
			},
			{
				level: "warn",
				event: "kernel.allowed_in_development",
				fields: { key: "twice.a", reason: "is plain http" },
			},
			{
				level: "warn",
				event: "kernel.allowed_in_development",
				fields: { key: "twice.b.c", reason: "is on loopback" },
			},
		]);
		// A sink writes the line's own level, event and at beside its fields, so none may take those names.
		const own = ["level", "event", "at"];
		for (const line of warned)
			expect(Object.keys(line.fields).filter((k) => own.includes(k))).toEqual([]);
		expect(JSON.stringify(recorded.lines())).not.toContain(secret);
		// Production refuses the same, and warns none of it.
		const before = recorded.lines().length;
		await refusalsOf(assemble({ modules: [origin], config: { ...production, ...plain }, runtime }));
		expect(
			recorded
				.lines()
				.slice(before)
				.filter((l) => l.event === "kernel.allowed_in_development"),
		).toEqual([]);
	});

	it("refuses in development too a production check that cannot be read", async () => {
		const broken = defineModule({
			name: "broken",
			replicaSafe: true,
			refusedInProduction: () => [{ key: "", reason: "r" }],
			takes: [],
		});
		const refused = await refusalsOf(assemble({ modules: [broken], config: development }));
		expect(refused).toEqual([{ where: "broken", reason: "its production check failed" }]);
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
			defineModule({
				name: `a${i}`,
				replicaSafe: true,
				refusedInProduction: () => answer as never,
				takes: [],
			}),
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
				...(key === "replicaSafe" ? {} : { replicaSafe: true }),
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
			replicaSafe: true,
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
		const changer = defineModule({ name: "changer", replicaSafe: false, takes: [] }, (m) => [
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
		const indexed = defineModule({
			name: "indexed",
			replicaSafe: true,
			refusedInProduction: () => answer,
			takes: [],
		});
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

	it("tells each factory the deployment's environment, production unless set", async () => {
		const told = contract<string>("told");
		const telling = defineModule({ name: "telling", replicaSafe: true, takes: [] }, (m) => [
			m.provide(told).by((c) => c.environment),
		]);
		const asTold = async (config: object) =>
			(await assemble({ modules: [telling], config })).get(told);
		expect(await asTold(production)).toBe("production");
		expect(await asTold(kernelConfig({ environment: "development" }))).toBe("development");
	});
});

/** A module that takes an id once: in its own process, or in the place it is given. */
const once = contract<{ use(id: string): boolean }>("once");
const taking = (name: string, replicaSafe: boolean | "unsaid", kept = new Set<string>()) =>
	defineModule(
		replicaSafe === "unsaid"
			? // The type requires the declaration; left out here on purpose, as a JavaScript module may.
				({ name, takes: [] } as never)
			: { name, replicaSafe, takes: [] },
		(m) => [m.provide(once).by(() => ({ use: (id) => !kept.has(id) && Boolean(kept.add(id)) }))],
	);
/** Two instances of an app composing the module, on many instances; each takes `id-1` once. */
async function twoInstances(module: () => Module) {
	const multi = kernelConfig({ deployment: "multi" });
	const apps = [
		await assemble({ modules: [module()], config: multi }),
		await assemble({ modules: [module()], config: multi }),
	];
	return apps.map((app) => app.get(once).use("id-1"));
}

describe("the deployment's instances", () => {
	it("refuses, on many instances only, a module that declares nothing of them", async () => {
		const refused = await refusalsOf(
			assemble({
				modules: [taking("silent", "unsaid")],
				config: kernelConfig({ deployment: "multi" }),
			}),
		);
		expect(refused).toEqual([
			{ where: "silent", reason: "declares nothing about multiple instances: say replicaSafe" },
		]);
		await expect(
			assemble({ modules: [taking("silent", "unsaid")], config: production }),
		).resolves.toBeDefined();
	});

	it("refuses a module keeping a used id in its own process that declares nothing, before two instances take it twice", async () => {
		await expect(twoInstances(() => taking("once-in-memory", "unsaid"))).rejects.toMatchObject({
			refusals: [{ where: "once-in-memory" }],
		});
	});

	// The kernel reads the declaration and never what a module keeps: a module that keeps a used id in
	// its own process and declares itself safe boots, and two instances take one id twice. Human review
	// required; no automated detection demonstrated.
	it("boots a module keeping a used id in its own process that falsely declares itself safe, and two instances take it twice: human review required; no automated detection demonstrated", async () => {
		expect(await twoInstances(() => taking("once-in-memory", true))).toEqual([true, true]);
	});

	it("takes an id once across two instances where the module keeps it in the place they share", async () => {
		const shared = new Set<string>();
		expect(await twoInstances(() => taking("once-shared", true, shared))).toEqual([true, false]);
	});

	it("refuses replica-unsafe modules only when deployed on multiple replicas", async () => {
		const unsafe = defineModule({ name: "mem", replicaSafe: false, takes: [] });
		await expect(assemble({ modules: [unsafe], config: production })).resolves.toBeDefined();
		const refusals = await refusalsOf(
			assemble({ modules: [unsafe], config: kernelConfig({ deployment: "multi" }) }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["mem"]);
	});

	it("asks a module whether it is replica-safe only with a section that passed", async () => {
		const asked: unknown[] = [];
		const m = defineModule({
			name: "m",
			section: z.strictObject({ shared: z.boolean() }),
			replicaSafe: (section) => {
				asked.push(section);
				return section.shared;
			},
			takes: [],
		});
		const multi = kernelConfig({ deployment: "multi" });
		const bad = await refusalsOf(
			assemble({ modules: [m], config: { ...multi, m: { shared: 1 } } }),
		);
		expect([bad.map((r) => r.where), asked]).toEqual([["m.shared"], []]);
		const unsafe = await refusalsOf(
			assemble({ modules: [m], config: { ...multi, m: { shared: false } } }),
		);
		expect([unsafe.map((r) => r.where), asked]).toEqual([["m"], [{ shared: false }]]);
	});
});
