import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
	assemble,
	contract,
	defineModule,
	extensionPoint,
	kernelConfig,
	kernelSection,
} from "../src/contract.ts";
import { quietRuntime, recordingLog } from "../src/testing.ts";
import { refusalsOf } from "./refusals.ts";

const single = kernelConfig();

describe("assemble", () => {
	it("refuses a missing or wrong kernel section", async () => {
		expect(await refusalsOf(assemble({ modules: [], config: {} }))).toEqual([
			{ where: "kernel", reason: expect.any(String) },
		]);
		const wrong = await refusalsOf(
			assemble({ modules: [], config: { kernel: { deployment: "many" } } }),
		);
		expect(wrong.map((r) => r.where)).toEqual(["kernel.deployment"]);
	});

	it("builds its own section: a single deployment, unless the settings say otherwise", async () => {
		expect(kernelConfig()).toEqual({ kernel: { deployment: "single" } });
		const multi = kernelConfig({ deployment: "multi", logging: { level: "warn" } });
		expect(multi).toEqual({ kernel: { deployment: "multi", logging: { level: "warn" } } });
		await expect(assemble({ modules: [], config: multi })).resolves.toBeDefined();
	});

	it("exports its section's schema, with the defaults and a description on each key", () => {
		expect(kernelSection.parse({ deployment: "multi" })).toEqual({
			deployment: "multi",
			logging: { level: "info" },
			"stop-seconds": 30,
		});
		const { deployment, logging, "stop-seconds": stopSeconds } = kernelSection.shape;
		for (const key of [deployment, logging, logging.unwrap().shape.level, stopSeconds]) {
			expect(key.description).toMatch(/\w/);
		}
	});

	it("refuses sections of modules that are not loaded", async () => {
		const refusals = await refusalsOf(assemble({ modules: [], config: { ...single, ghost: {} } }));
		expect(refusals.map((r) => r.where)).toEqual(["ghost"]);
	});

	it("refuses a key that names an object's prototype in a section, by the section's path", async () => {
		const m = defineModule({
			name: "m",
			section: z.strictObject({ limits: z.record(z.string(), z.number()) }),
		});
		// As the configuration loader hands it over: an own key, as JSON and HOCON both make one.
		const section = JSON.parse('{"limits":{"__proto__":5,"ok":1}}');
		const refusals = await refusalsOf(
			assemble({ modules: [m], config: { ...single, m: section } }),
		);
		expect(refusals).toEqual([
			{ where: expect.stringMatching(/^m\.limits/), reason: expect.stringContaining("__proto__") },
		]);
	});

	it("reports every section issue by path, never the value", async () => {
		const m = defineModule({
			name: "m",
			section: z.strictObject({ secret: z.string().min(32), n: z.number() }),
		});
		const refusals = await refusalsOf(
			assemble({ modules: [m], config: { ...single, m: { secret: "short-value", extra: 1 } } }),
		);
		expect(refusals.map((r) => r.where).sort()).toEqual(["m", "m.n", "m.secret"]);
		expect(JSON.stringify(refusals)).not.toContain("short-value");
	});

	it("takes a field set to undefined as absent, and refuses values configuration cannot hold", async () => {
		const m = defineModule({
			name: "m",
			section: z.strictObject({ n: z.number(), note: z.string().optional() }),
		});
		const config = (section: unknown) => ({ ...single, m: section });
		await expect(
			assemble({ modules: [m], config: config({ n: 1, note: undefined }) }),
		).resolves.toBeDefined();
		for (const n of [Number.NaN, new Date(0), () => 1]) {
			const refusals = await refusalsOf(assemble({ modules: [m], config: config({ n }) }));
			expect(refusals).toEqual([{ where: "m.n", reason: expect.any(String) }]);
		}
	});

	it("refuses a value configuration cannot hold by its key path, inside lists too", async () => {
		const m = defineModule({ name: "m", section: z.strictObject({ a: z.unknown() }) });
		const deep = { a: { list: [1, { at: new Date(0) }], n: Number.POSITIVE_INFINITY } };
		const refusals = await refusalsOf(assemble({ modules: [m], config: { ...single, m: deep } }));
		expect(refusals.map((r) => r.where)).toEqual(["m.a.list.1.at"]);
		const infinite = await refusalsOf(
			assemble({ modules: [m], config: { ...single, m: { a: { n: Number.POSITIVE_INFINITY } } } }),
		);
		expect(infinite.map((r) => r.where)).toEqual(["m.a.n"]);
	});

	it("takes a section schema written with zod only, the library that reads sections", () => {
		const other = {
			"~standard": { version: 1, vendor: "other", validate: (value: unknown) => ({ value }) },
		} as const;
		// @ts-expect-error a schema of another library is not read
		expect(defineModule({ name: "m", section: other }).section).toBe(other);
	});

	it("hands each module its own frozen section", async () => {
		const seen = contract<{ list: string[] }>("seen");
		const m = defineModule(
			{ name: "m", section: z.strictObject({ list: z.array(z.string()) }) },
			(m) => [m.provide(seen).by((c) => c.section)],
		);
		const app = await assemble({ modules: [m], config: { ...single, m: { list: ["a"] } } });
		expect(Object.isFrozen(app.get(seen).list)).toBe(true);
	});

	it("hands contributions over frozen one level, leaving the values they hold alone", async () => {
		type Point = { name: string; held: { state: number } };
		const seen = contract<readonly Point[]>("seen");
		const points = extensionPoint<Point>("points", { multiplicity: "many" });
		const owner = defineModule({ name: "owner" }, (m) => [
			m.provide(seen).by((c) => c.collect(points)),
		]);
		const a = defineModule({ name: "a" }, (m) => [
			m.contribute(points).by(() => ({ name: "a", held: { state: 0 } })),
		]);
		const app = await assemble({ modules: [owner, a], config: single });
		const [only] = app.get(seen);
		expect(Object.isFrozen(only)).toBe(true);
		expect(Object.isFrozen(only?.held)).toBe(false);
	});

	it("resolves contracts across modules and collects contributions", async () => {
		const greeting = contract<string>("greeting");
		const names = extensionPoint<string>("names", { multiplicity: "many" });
		const owner = defineModule({ name: "owner" }, (m) => [
			m.provide(greeting).by(async (c) => `hello ${(await c.collect(names)).join(",")}`),
		]);
		const a = defineModule({ name: "a" }, (m) => [m.contribute(names).by(() => "a")]);
		const b = defineModule({ name: "b" }, (m) => [m.contribute(names).by(() => "b")]);
		const app = await assemble({ modules: [owner, a, b], config: single });
		expect(app.get(greeting)).toBe("hello a,b");
	});

	const x = contract<number>("x");
	const y = contract<number>("y");

	it("refuses a contract two modules provide", async () => {
		const dup = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [m.provide(x).by(() => 1)]),
					defineModule({ name: "b" }, (m) => [m.provide(x).by(() => 2)]),
				],
				config: single,
			}),
		);
		expect(dup.map((r) => r.where)).toEqual(["x"]);
	});

	it("refuses a contract no module provides, naming it", async () => {
		const missing = await refusalsOf(
			assemble({
				modules: [defineModule({ name: "a" }, (m) => [m.provide(x).by((c) => c.get(y))])],
				config: single,
			}),
		);
		expect(missing).toEqual([{ where: "a", reason: expect.stringContaining("y") }]);
	});

	it("refuses a dependency cycle", async () => {
		const cycle = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [m.provide(x).by((c) => c.get(y))]),
					defineModule({ name: "b" }, (m) => [m.provide(y).by((c) => c.get(x))]),
				],
				config: single,
			}),
		);
		expect(cycle.map((r) => r.reason)).toEqual([expect.stringContaining("cycle")]);
	});

	it("refuses a cycle between branches built side by side, rather than waiting forever", async () => {
		const top = contract<number>("top");
		const b = contract<number>("b");
		const c = contract<number>("c");
		const cycle = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "top" }, (m) => [
						m.provide(top).by(async (ctx) => (await Promise.all([ctx.get(b), ctx.get(c)]))[0]),
					]),
					// Each asks after a pause, so the two branches start before either asks the other.
					defineModule({ name: "b" }, (m) => [
						m.provide(b).by(async (ctx) => {
							await Promise.resolve();
							return ctx.get(c);
						}),
					]),
					defineModule({ name: "c" }, (m) => [
						m.provide(c).by(async (ctx) => {
							await Promise.resolve();
							return ctx.get(b);
						}),
					]),
				],
				config: single,
			}),
		);
		expect(cycle.map((r) => r.reason)).toContainEqual(expect.stringContaining("cycle"));
	}, 2000);

	it("refuses duplicate keys at a keyed extension point even when nothing collects it", async () => {
		const routes = extensionPoint<{ path: string }>("routes", {
			multiplicity: "keyed",
			keyOf: (r) => r.path,
		});
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [m.contribute(routes).by(() => ({ path: "/p" }))]),
					defineModule({ name: "b" }, (m) => [m.contribute(routes).by(() => ({ path: "/p" }))]),
				],
				config: single,
			}),
		);
		expect(refusals.map((r) => r.where)).toEqual(["routes:/p"]);
	});

	it("refuses boot when a point nothing collects cannot be checked", async () => {
		const routes = extensionPoint<{ path: string }>("routes", {
			multiplicity: "keyed",
			keyOf: () => {
				throw new Error("broken");
			},
		});
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [m.contribute(routes).by(() => ({ path: "/p" }))]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "routes", reason: "failed during assembly" }]);
	});

	it("refuses only the failed contribution at a point nothing collects", async () => {
		const steps = extensionPoint<string>("steps", { multiplicity: "some" });
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [
						m.contribute(steps).by(() => {
							throw new Error("broken");
						}),
					]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "a", reason: "failed during assembly" }]);
	});

	it("reports every duplicated key at a keyed point, once however many modules collect it", async () => {
		const routes = extensionPoint<{ path: string }>("routes", {
			multiplicity: "keyed",
			keyOf: (r) => r.path,
		});
		const route = (name: string, path: string) =>
			defineModule({ name }, (m) => [m.contribute(routes).by(() => ({ path }))]);
		const collecting = (name: string) =>
			defineModule({ name }, (m) => [
				m.provide(contract<number>(name)).by(async (c) => (await c.collect(routes)).length),
			]);
		const refusals = await refusalsOf(
			assemble({
				modules: [
					collecting("one"),
					collecting("other"),
					route("a", "/p"),
					route("b", "/p"),
					route("c", "/q"),
					route("d", "/q"),
					route("e", "/q"),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{ where: "routes:/p", reason: "more than one contribution for the same key" },
			{ where: "routes:/q", reason: "more than one contribution for the same key" },
		]);
	});

	it("refuses an extension point that needs at least one contribution when it has none, naming it", async () => {
		const steps = extensionPoint<string>("proof steps", { multiplicity: "some" });
		const counted = contract<number>("counted");
		const owner = defineModule({ name: "owner" }, (m) => [
			m.provide(counted).by(async (c) => (await c.collect(steps)).length),
		]);
		const refusals = await refusalsOf(assemble({ modules: [owner], config: single }));
		expect(refusals.map((r) => [r.where, r.reason])).toEqual([
			["proof steps", "needs at least one contribution"],
		]);
		const app = await assemble({
			modules: [
				owner,
				defineModule({ name: "a" }, (m) => [m.contribute(steps).by(() => "a")]),
				defineModule({ name: "b" }, (m) => [m.contribute(steps).by(() => "b")]),
			],
			config: single,
		});
		expect(app.get(counted)).toBe(2);
	});

	it("collects refusals from independent factories together", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [
						m.provide(contract("p")).by((c) => c.refuse("a.k", "bad")),
					]),
					defineModule({ name: "b" }, (m) => [
						m.provide(contract("q")).by((c) => c.refuse("b.k", "bad")),
					]),
				],
				config: single,
			}),
		);
		expect(refusals.map((r) => r.where)).toEqual(["a.k", "b.k"]);
	});

	it("takes several refusals from one factory at once", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [
						m.provide(contract("p")).by((c) =>
							c.refuseAll([
								{ where: "a.x", reason: "bad" },
								{ where: "a.y", reason: "bad" },
							]),
						),
					]),
				],
				config: single,
			}),
		);
		expect(refusals.map((r) => r.where)).toEqual(["a.x", "a.y"]);
	});

	it("hides unexpected factory errors behind a generic reason", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a" }, (m) => [
						m.provide(contract("p")).by(() => {
							throw new Error("token=abc");
						}),
					]),
				],
				config: single,
			}),
		);
		expect(JSON.stringify(refusals)).not.toContain("abc");
	});

	it("refuses replica-unsafe modules only when deployed on multiple replicas", async () => {
		const unsafe = defineModule({ name: "mem", replicaSafe: false });
		await expect(assemble({ modules: [unsafe], config: single })).resolves.toBeDefined();
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

	it("refuses a kernel section without a deployment, which has no default", async () => {
		const refusals = await refusalsOf(assemble({ modules: [], config: { kernel: {} } }));
		expect(refusals.map((r) => r.where)).toEqual(["kernel.deployment"]);
	});

	it("tells contracts apart by value, never by their name", async () => {
		const [one, other] = [contract<string>("same"), contract<string>("same")];
		const app = await assemble({
			modules: [
				defineModule({ name: "a" }, (m) => [m.provide(one).by(() => "a")]),
				defineModule({ name: "b" }, (m) => [m.provide(other).by(() => "b")]),
			],
			config: single,
		});
		expect([app.get(one), app.get(other)]).toEqual(["a", "b"]);
	});

	it("refuses an extension point that needs exactly one contribution when it has two", async () => {
		const only = extensionPoint<string>("only", { multiplicity: "one" });
		const used = contract<string>("used");
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "owner" }, (m) => [
						m.provide(used).by(async (c) => (await c.collect(only))[0] ?? ""),
					]),
					defineModule({ name: "a" }, (m) => [m.contribute(only).by(() => "a")]),
					defineModule({ name: "b" }, (m) => [m.contribute(only).by(() => "b")]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "only", reason: "needs exactly one contribution (2)" }]);
	});

	it("refuses a module named kernel, the kernel's own section's name", async () => {
		// A section taking anything, so only the name can refuse it.
		const named = defineModule({ name: "kernel", section: z.looseObject({}) });
		const refusals = await refusalsOf(assemble({ modules: [named], config: single }));
		expect(refusals).toEqual([{ where: "kernel", reason: "duplicate module name" }]);
	});

	it("refuses a section given to a module that takes none", async () => {
		const refusals = await refusalsOf(
			assemble({ modules: [defineModule({ name: "m" })], config: { ...single, m: {} } }),
		);
		expect(refusals).toEqual([{ where: "m", reason: "module without a section" }]);
	});

	it("reads a section left out of the configuration as an empty one, its defaults filled in", async () => {
		const read = contract<unknown>("read");
		const m = defineModule(
			{ name: "m", section: z.strictObject({ n: z.number().default(3) }) },
			(m) => [m.provide(read).by((c) => c.section)],
		);
		const app = await assemble({ modules: [m], config: single });
		expect(app.get(read)).toEqual({ n: 3 });
	});

	it("reads a module's section from the configuration's own keys only", async () => {
		const read = contract<unknown>("read");
		const app = await assemble({
			modules: [
				defineModule({ name: "constructor" }),
				defineModule({ name: "toString", section: z.strictObject({}).default({}) }, (m) => [
					m.provide(read).by((c) => c.section),
				]),
			],
			config: single,
		});
		expect(app.get(read)).toEqual({});
	});

	it("refuses a configuration whose root is not an object", async () => {
		for (const config of [[], "kernel", null]) {
			expect(await refusalsOf(assemble({ modules: [], config }))).toEqual([
				{ where: "config", reason: "the configuration root is not an object" },
			]);
		}
	});

	it("takes a module that says nothing of replicas as safe on multiple instances", async () => {
		const multi = kernelConfig({ deployment: "multi" });
		await expect(
			assemble({ modules: [defineModule({ name: "m" })], config: multi }),
		).resolves.toBeDefined();
	});

	it("reports the sections' refusals alone, before looking at what the modules provide", async () => {
		const twice = contract<number>("twice");
		const providing = (name: string) =>
			defineModule({ name }, (m) => [m.provide(twice).by(() => 1)]);
		const refusals = await refusalsOf(
			assemble({ modules: [providing("a"), providing("b")], config: { ...single, ghost: {} } }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["ghost"]);
	});

	it("refuses with the module's name when a factory refuses with an empty list", async () => {
		const m = defineModule({ name: "m" }, (m) => [
			m.provide(contract<number>("x")).by((c) => c.refuseAll([])),
		]);
		expect(await refusalsOf(assemble({ modules: [m], config: single }))).toEqual([
			{ where: "m", reason: "refused" },
		]);
	});

	it("throws when asked for a contract the assembly does not provide", async () => {
		const app = await assemble({ modules: [], config: single });
		expect(() => app.get(contract<number>("absent"))).toThrow("absent is not provided");
	});

	it("refuses an extension point that needs exactly one contribution when it has none, collected or not", async () => {
		const only = extensionPoint<string>("only", { multiplicity: "one" });
		const used = contract<string>("used");
		const owner = defineModule({ name: "owner" }, (m) => [
			m.provide(used).by(async (c) => (await c.collect(only))[0] ?? ""),
		]);
		expect(await refusalsOf(assemble({ modules: [owner], config: single }))).toEqual([
			{ where: "only", reason: "needs exactly one contribution (0)" },
		]);
	});

	it("hands a collected list over frozen", async () => {
		const many = extensionPoint<string>("many", { multiplicity: "many" });
		const list = contract<readonly string[]>("list");
		const app = await assemble({
			modules: [
				defineModule({ name: "owner" }, (m) => [m.provide(list).by((c) => c.collect(many))]),
				defineModule({ name: "a" }, (m) => [m.contribute(many).by(() => "a")]),
			],
			config: single,
		});
		expect(Object.isFrozen(app.get(list))).toBe(true);
	});

	it("starts hooks in the order they were registered and stops in reverse", async () => {
		const order: string[] = [];
		const handles = {
			base: contract<void>("base"),
			top: contract<void>("top"),
			leaf: contract<void>("leaf"),
		};
		const chain = (name: keyof typeof handles, after?: keyof typeof handles) =>
			defineModule({ name }, (m) => [
				m.provide(handles[name]).by(async (c) => {
					if (after) await c.get(handles[after]);
					c.onStart(() => {
						order.push(`start ${name}`);
					});
					c.onStop(() => {
						order.push(`stop ${name}`);
					});
				}),
			]);
		const modules = [chain("leaf", "top"), chain("top", "base"), chain("base")];
		const app = await assemble({ modules, config: single });
		await app.start();
		await app.stop(1000);
		expect(order).toEqual([
			"start base",
			"start top",
			"start leaf",
			"stop leaf",
			"stop top",
			"stop base",
		]);
	});
});

describe("late", () => {
	const greeter = contract<{ greet(name: string): string }>("greeter");
	const greetings = extensionPoint<{ say(): string }>("greetings", { multiplicity: "many" });
	const owner = defineModule({ name: "owner" }, (m) => [
		m.provide(greeter).by(async (c) => {
			const all = await c.collect(greetings);
			return { greet: (name: string) => `hello ${name} (${all.length})` };
		}),
	]);

	it("lets a contributor hold its owner's interface and use it once assembly is done", async () => {
		const contributor = defineModule({ name: "contributor" }, (m) => [
			m.contribute(greetings).by((c) => {
				const later = c.late(greeter);
				return { say: () => later().greet("late") };
			}),
		]);
		let said: (() => string) | undefined;
		const keeper = defineModule({ name: "keeper" }, (m) => [
			m.provide(contract<object>("keeper")).by(async (c) => {
				said = (await c.collect(greetings))[0]?.say;
				return {};
			}),
		]);
		await assemble({ modules: [owner, contributor, keeper], config: single });
		expect(said?.()).toBe("hello late (1)");
	});

	it("throws when a late reference is used during assembly, refusing boot", async () => {
		const eager = defineModule({ name: "eager" }, (m) => [
			m.contribute(greetings).by((c) => {
				const later = c.late(greeter);
				return { say: () => later().greet("now"), now: later() };
			}),
		]);
		const refusals = await refusalsOf(assemble({ modules: [owner, eager], config: single }));
		expect(refusals).toEqual([{ where: "eager", reason: "failed during assembly" }]);
	});

	it("refuses boot when nothing provides what a late reference names", async () => {
		const missing = contract<object>("missing");
		const asking = defineModule({ name: "asking" }, (m) => [
			m.provide(contract<object>("asking")).by((c) => ({ later: c.late(missing) })),
		]);
		expect(await refusalsOf(assemble({ modules: [asking], config: single }))).toEqual([
			{ where: "asking", reason: "no module provides missing" },
		]);
	});

	it("never hands over an interface from an assembly that was refused", async () => {
		let later: (() => unknown) | undefined;
		const holder = defineModule({ name: "holder" }, (m) => [
			m.provide(contract<object>("holder")).by((c) => {
				later = c.late(greeter);
				return {};
			}),
		]);
		const broken = defineModule({ name: "broken" }, (m) => [
			m.provide(contract<object>("broken")).by(() => {
				throw new Error("broken");
			}),
		]);
		await refusalsOf(assemble({ modules: [owner, holder, broken], config: single }));
		expect(() => later?.()).toThrow("before assembly is done");
	});
});

describe("every", () => {
	const probe = contract<object>("probe");
	const recorded = recordingLog();
	let from = 0;
	/** The events warned since this test began. */
	const warned = () =>
		recorded
			.lines()
			.slice(from)
			.filter((line) => line.level === "warn")
			.map((line) => line.event);
	const runtime = quietRuntime({ log: recorded.log });
	const withTask = (intervalMs: number, task: (signal: AbortSignal) => Promise<void>) =>
		defineModule({ name: "p" }, (m) => [
			m.provide(probe).by((c) => {
				c.every(intervalMs, task);
				return {};
			}),
		]);

	beforeEach(() => {
		from = recorded.lines().length;
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("logs a task that throws before it returns a promise, as one that rejects, and runs it again", async () => {
		let runs = 0;
		const app = await assemble({
			modules: [
				withTask(100, () => {
					runs++;
					throw new Error("at once");
				}),
			],
			config: single,
			runtime,
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(200);
		expect([runs, warned()]).toEqual([2, ["kernel.every_failed", "kernel.every_failed"]]);
		await app.stop(1000);
	});

	it("runs a task on its interval only once started, never two runs at once, and on after a failure", async () => {
		let runs = 0;
		let release = () => {};
		const app = await assemble({
			modules: [
				withTask(100, async () => {
					runs++;
					if (runs === 1) throw new Error("once");
					if (runs === 2) await new Promise<void>((resolve) => (release = resolve));
				}),
			],
			config: single,
			runtime,
		});
		await vi.advanceTimersByTimeAsync(500);
		expect(runs).toBe(0);
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		expect([runs, warned()]).toEqual([1, ["kernel.every_failed"]]);
		await vi.advanceTimersByTimeAsync(500);
		expect(runs).toBe(2);
		release();
		await vi.advanceTimersByTimeAsync(100);
		expect(runs).toBe(3);
		await app.stop(1000);
	});

	it("aborts the running run on stop and waits for it", async () => {
		const seen: string[] = [];
		const app = await assemble({
			modules: [
				withTask(
					100,
					(signal) =>
						new Promise<void>((resolve) => {
							seen.push("running");
							// The run takes a while to wind down once aborted, so stop has to wait for it.
							signal.addEventListener("abort", () => {
								seen.push("aborted");
								setTimeout(() => {
									seen.push("ended");
									resolve();
								}, 50);
							});
						}),
				),
			],
			config: single,
			runtime,
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		const stopped = app.stop(1000).then(() => seen.push("stopped"));
		await vi.advanceTimersByTimeAsync(10);
		expect(seen).toEqual(["running", "aborted"]);
		await vi.advanceTimersByTimeAsync(50);
		await stopped;
		expect(seen).toEqual(["running", "aborted", "ended", "stopped"]);
		await vi.advanceTimersByTimeAsync(1000);
		expect(seen).toEqual(["running", "aborted", "ended", "stopped"]);
	});

	it.each([0, -1, 1.5, 2 ** 31])(
		"refuses the interval %s, no whole number of ms from 1 to 2^31-1",
		async (bad) => {
			const refusals = await refusalsOf(
				assemble({ modules: [withTask(bad, async () => {})], config: single, runtime }),
			);
			expect(refusals.map((r) => r.where)).toContain("p");
		},
	);

	it("takes the longest interval a timer holds", async () => {
		await expect(
			assemble({ modules: [withTask(2 ** 31 - 1, async () => {})], config: single, runtime }),
		).resolves.toBeDefined();
	});
});

describe("stop", () => {
	afterEach(() => {
		vi.useRealTimers();
	});
	/** A module whose stop hook does what `hook` does, after noting its name in `order`. */
	const stopping = (
		name: string,
		order: string[],
		hook: (signal: AbortSignal) => Promise<void> | void = () => {},
	) =>
		defineModule({ name }, (m) => [
			m.provide(contract<object>(name)).by((c) => {
				c.onStop((signal) => {
					order.push(name);
					return hook(signal);
				});
				return {};
			}),
		]);

	it("runs the earlier stop hooks when one fails, logging the failure", async () => {
		const order: string[] = [];
		const recorded = recordingLog();
		const app = await assemble({
			modules: [
				stopping("store", order),
				stopping("broken", order, () => {
					throw new Error("at db.internal");
				}),
			],
			config: single,
			runtime: quietRuntime({ log: recorded.log }),
		});
		await app.stop(1000);
		expect(order).toEqual(["broken", "store"]);
		expect(recorded.lines()).toEqual([
			{
				level: "warn",
				event: "kernel.stop_failed",
				fields: { module: "broken", outcome: "failed", kind: "Error" },
			},
		]);
	});

	it("refuses a deadline that is no whole number from 1 to 2^31-1, stopping nothing", async () => {
		const order: string[] = [];
		const app = await assemble({ modules: [stopping("store", order)], config: single });
		for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 31]) {
			await expect(app.stop(bad)).rejects.toThrow(TypeError);
		}
		expect(order).toEqual([]);
		await app.stop(2 ** 31 - 1);
		expect(order).toEqual(["store"]);
	});

	it("stops by kernel.stop-seconds when given no deadline, 30 s unless set", async () => {
		vi.useFakeTimers();
		const hung = (signals: AbortSignal[]) =>
			stopping("hung", [], (signal) => {
				signals.push(signal);
				return new Promise<void>(() => {});
			});
		const at = async (config: object, ms: number) => {
			const signals: AbortSignal[] = [];
			const app = await assemble({ modules: [hung(signals)], config });
			const stop = app.stop();
			await vi.advanceTimersByTimeAsync(ms - 1);
			const before = signals[0]?.aborted;
			await vi.advanceTimersByTimeAsync(1);
			await stop;
			return [before, signals[0]?.aborted];
		};
		expect(await at(single, 30_000)).toEqual([false, true]);
		expect(await at(kernelConfig({ "stop-seconds": 5 }), 5_000)).toEqual([false, true]);
		expect(await at({ kernel: { deployment: "single", "stop-seconds": "7" } }, 7_000)).toEqual([
			false,
			true,
		]);
	});

	it("refuses a stop-seconds that is no whole number from 1 to 3600", async () => {
		for (const bad of [0, 3601, 1.5, "x", true]) {
			const refusals = await refusalsOf(
				assemble({
					modules: [],
					config: { kernel: { deployment: "single", "stop-seconds": bad } },
				}),
			);
			expect(refusals.map((r) => r.where)).toEqual(["kernel.stop-seconds"]);
		}
	});

	it("calls the hooks left at the deadline with the aborted signal, without waiting for them", async () => {
		vi.useFakeTimers();
		const order: string[] = [];
		const signals: AbortSignal[] = [];
		const hang = (signal: AbortSignal) => {
			signals.push(signal);
			return new Promise<void>(() => {});
		};
		const app = await assemble({
			modules: [stopping("first", order, hang), stopping("last", order, hang)],
			config: single,
			runtime: quietRuntime(),
		});
		let stopped = false;
		const stop = app.stop(500).then(() => {
			stopped = true;
		});
		await vi.advanceTimersByTimeAsync(500);
		await stop;
		expect([stopped, order]).toEqual([true, ["last", "first"]]);
		expect(signals.map((signal) => signal.aborted)).toEqual([true, true]);
	});

	it("runs the stop hooks only once the periodic tasks have ended", async () => {
		vi.useFakeTimers();
		const seen: string[] = [];
		const app = await assemble({
			modules: [
				defineModule({ name: "p" }, (m) => [
					m.provide(contract<object>("p")).by((c) => {
						c.every(100, (signal) => {
							return new Promise<void>((resolve) => {
								signal.addEventListener("abort", () =>
									setTimeout(() => {
										seen.push("task ended");
										resolve();
									}, 50),
								);
							});
						});
						c.onStop(() => void seen.push("hook"));
						return {};
					}),
				]),
			],
			config: single,
			runtime: quietRuntime(),
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		const stop = app.stop(1000);
		await vi.advanceTimersByTimeAsync(50);
		await stop;
		expect(seen).toEqual(["task ended", "hook"]);
	});

	it("aborts a hung stop hook at the deadline, and still calls the earlier ones", async () => {
		vi.useFakeTimers();
		const order: string[] = [];
		const signals: AbortSignal[] = [];
		const recorded = recordingLog();
		const app = await assemble({
			modules: [
				stopping("store", order, (signal) => void signals.push(signal)),
				stopping("hung", order, (signal) => {
					signals.push(signal);
					return new Promise<void>(() => {});
				}),
			],
			config: single,
			runtime: quietRuntime({ log: recorded.log }),
		});
		let stopped = false;
		const stop = app.stop(500).then(() => {
			stopped = true;
		});
		await vi.advanceTimersByTimeAsync(499);
		expect([stopped, order, signals[0]?.aborted]).toEqual([false, ["hung"], false]);
		await vi.advanceTimersByTimeAsync(1);
		await stop;
		expect(order).toEqual(["hung", "store"]);
		expect(signals.map((signal) => signal.aborted)).toEqual([true, true]);
		expect(recorded.lines().map((line) => line.fields)).toEqual([
			{ module: "hung", outcome: "late" },
		]);
	});
});
