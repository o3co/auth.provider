import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	assemble,
	BuildRefused,
	contract,
	defineModule,
	extensionPoint,
	kernelConfig,
	kernelSection,
} from "../src/contract.ts";
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

	it("refuses a section its schema throws on, by the module's name, keeping none of what it threw", async () => {
		const thrown: (() => unknown)[] = [
			() => new TypeError("token=abc"),
			() => ({ secret: "token=abc" }),
			() =>
				new Proxy(
					{},
					{
						getPrototypeOf() {
							throw new Error("token=abc");
						},
					},
				),
		];
		for (const [i, value] of thrown.entries()) {
			const section = z.object({ n: z.number() }).transform(() => {
				throw value();
			});
			const refusals = await refusalsOf(
				assemble({
					modules: [defineModule({ name: "m", replicaSafe: true, section, takes: [] })],
					config: { ...single, m: { n: 1 } },
				}),
			);
			expect(refusals, String(i)).toEqual([
				{ where: "m", reason: "its schema failed as it read the section" },
			]);
		}
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
			environment: "production",
			logging: { level: "info" },
			"stop-deadline": 30,
		});
		const { deployment, environment, logging, "stop-deadline": stopDeadline } = kernelSection.shape;
		for (const key of [
			deployment,
			environment,
			logging,
			logging.unwrap().shape.level,
			stopDeadline,
		]) {
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
			replicaSafe: true,
			section: z.strictObject({ limits: z.record(z.string(), z.number()) }),
			takes: [],
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

	it("reports every section issue by path, never the value: a needed key not set as required, any other in the schema's words [guarantee-8-a]", async () => {
		const m = defineModule({
			name: "m",
			replicaSafe: true,
			section: z.strictObject({ secret: z.string().min(32), n: z.number(), e: z.enum(["a"]) }),
			takes: [],
		});
		const refined = defineModule({
			name: "r",
			replicaSafe: true,
			section: z.strictObject({ w: z.string({ error: "kept" }) }),
			takes: [],
		});
		const refusals = await refusalsOf(
			assemble({
				modules: [m, refined],
				config: { ...single, m: { secret: "short-value", extra: 1 } },
			}),
		);
		expect(refusals.map((r) => r.where).sort()).toEqual(["m", "m.e", "m.n", "m.secret", "r.w"]);
		expect(JSON.stringify(refusals)).not.toContain("short-value");
		const notSet = refusals.filter((r) => r.reason === "required, and not set");
		expect(notSet.map((r) => r.where)).toEqual(["m.n", "m.e"]);
	});

	it("takes a field set to undefined as absent, and refuses values configuration cannot hold", async () => {
		const m = defineModule({
			name: "m",
			replicaSafe: true,
			section: z.strictObject({ n: z.number(), note: z.string().optional() }),
			takes: [],
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

	it("refuses a value configuration cannot hold by its key path, inside lists too [guarantee-8-a]", async () => {
		const m = defineModule({
			name: "m",
			replicaSafe: true,
			section: z.strictObject({ a: z.unknown() }),
			takes: [],
		});
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
		expect(defineModule({ name: "m", replicaSafe: true, section: other, takes: [] }).section).toBe(
			other,
		);
	});

	it("hands each module its own frozen section", async () => {
		const seen = contract<{ list: string[] }>("seen");
		const m = defineModule(
			{
				name: "m",
				replicaSafe: true,
				section: z.strictObject({ list: z.array(z.string()) }),
				takes: [],
			},
			(m) => [m.provide(seen).by((c) => c.section)],
		);
		const app = await assemble({ modules: [m], config: { ...single, m: { list: ["a"] } } });
		expect(Object.isFrozen(app.get(seen).list)).toBe(true);
	});

	it("hands contributions over frozen one level, leaving the values they hold alone", async () => {
		type Point = { name: string; held: { state: number } };
		const seen = contract<readonly Point[]>("seen");
		const points = extensionPoint<Point>("points", { multiplicity: "many" });
		const owner = defineModule({ name: "owner", replicaSafe: false, takes: [points] }, (m) => [
			m.provide(seen).by((c) => c.collect(points)),
		]);
		const a = defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
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
		const owner = defineModule({ name: "owner", replicaSafe: false, takes: [names] }, (m) => [
			m.provide(greeting).by(async (c) => `hello ${(await c.collect(names)).join(",")}`),
		]);
		const a = defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(names).by(() => "a"),
		]);
		const b = defineModule({ name: "b", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(names).by(() => "b"),
		]);
		const app = await assemble({ modules: [owner, a, b], config: single });
		expect(app.get(greeting)).toBe("hello a,b");
	});

	const x = contract<number>("x");
	const y = contract<number>("y");

	it("refuses a contract two modules provide", async () => {
		const dup = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
						m.provide(x).by(() => 1),
					]),
					defineModule({ name: "b", replicaSafe: true, takes: [] }, (m) => [
						m.provide(x).by(() => 2),
					]),
				],
				config: single,
			}),
		);
		expect(dup.map((r) => r.where)).toEqual(["x"]);
	});

	it("refuses a contract no module provides, naming it", async () => {
		const missing = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [y] }, (m) => [
						m.provide(x).by((c) => c.get(y)),
					]),
				],
				config: single,
			}),
		);
		expect(missing).toEqual([{ where: "a", reason: expect.stringContaining("y") }]);
	});

	it("refuses a dependency cycle", async () => {
		const cycle = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [y] }, (m) => [
						m.provide(x).by((c) => c.get(y)),
					]),
					defineModule({ name: "b", replicaSafe: true, takes: [x] }, (m) => [
						m.provide(y).by((c) => c.get(x)),
					]),
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
					defineModule({ name: "top", replicaSafe: true, takes: [b, c] }, (m) => [
						m.provide(top).by(async (ctx) => (await Promise.all([ctx.get(b), ctx.get(c)]))[0]),
					]),
					// Each asks after a pause, so the two branches start before either asks the other.
					defineModule({ name: "b", replicaSafe: true, takes: [c] }, (m) => [
						m.provide(b).by(async (ctx) => {
							await Promise.resolve();
							return ctx.get(c);
						}),
					]),
					defineModule({ name: "c", replicaSafe: true, takes: [b] }, (m) => [
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
					defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(routes).by(() => ({ path: "/p" })),
					]),
					defineModule({ name: "b", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(routes).by(() => ({ path: "/p" })),
					]),
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
					defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(routes).by(() => ({ path: "/p" })),
					]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "routes", reason: "failed during assembly" }]);
	});

	it("refuses a build a library refuses with its where and reason, beside the other refusals", async () => {
		const opened = contract<string>("opened");
		// A library called in a factory, with no build context to refuse through.
		const open = (space: string): string => {
			throw new BuildRefused(space, "a space holds records or secret records, not both");
		};
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
						m.provide(opened).by(() => open("a.cookies")),
					]),
					defineModule({ name: "b", replicaSafe: true, takes: [opened] }, (m) => [
						m.provide(contract<string>("built-on")).by((c) => c.get(opened)),
					]),
					defineModule({ name: "c", replicaSafe: true, takes: [] }, (m) => [
						m.provide(contract<string>("secretive")).by(() => {
							throw new Error("token=abc");
						}),
					]),
				],
				config: single,
			}),
		);
		// b only waited on a: what refused it is a's, recorded once; c's own text never shows.
		expect(refusals).toEqual([
			{ where: "a.cookies", reason: "a space holds records or secret records, not both" },
			{ where: "c", reason: "failed during assembly" },
		]);
	});

	it("refuses a build that throws a value it cannot read as a refusal as failed, never letting it pass", async () => {
		const mark = Symbol.for("@mod/kernel.build-refused");
		const thrown: unknown[] = [
			Object.defineProperty({}, mark, {
				get() {
					throw new Error("mark");
				},
			}),
			Object.defineProperty({ [mark]: true, reason: "r" }, "where", {
				get() {
					throw new Error("where");
				},
			}),
			{ [mark]: true },
			{ [mark]: true, where: "w", reason: "token=abc\nrefused invented: forged" },
			new Proxy(
				{},
				{
					getPrototypeOf() {
						throw new Error("prototype");
					},
				},
			),
		];
		for (const [i, value] of thrown.entries()) {
			const refusals = await refusalsOf(
				assemble({
					modules: [
						defineModule({ name: `odd${i}`, replicaSafe: true, takes: [] }, (m) => [
							m.provide(contract<string>(`odd${i}`)).by(() => {
								throw value;
							}),
						]),
					],
					config: single,
				}),
			);
			expect(refusals, String(i)).toEqual([{ where: `odd${i}`, reason: "failed during assembly" }]);
		}
	});

	it("refuses only the failed contribution at a point nothing collects", async () => {
		const steps = extensionPoint<string>("steps", { multiplicity: "some" });
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
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
			defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
				m.contribute(routes).by(() => ({ path })),
			]);
		const collecting = (name: string) =>
			defineModule({ name, replicaSafe: false, takes: [routes] }, (m) => [
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
		const owner = defineModule({ name: "owner", replicaSafe: false, takes: [steps] }, (m) => [
			m.provide(counted).by(async (c) => (await c.collect(steps)).length),
		]);
		const refusals = await refusalsOf(assemble({ modules: [owner], config: single }));
		expect(refusals.map((r) => [r.where, r.reason])).toEqual([
			["proof steps", "needs at least one contribution"],
		]);
		const app = await assemble({
			modules: [
				owner,
				defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
					m.contribute(steps).by(() => "a"),
				]),
				defineModule({ name: "b", replicaSafe: false, takes: [] }, (m) => [
					m.contribute(steps).by(() => "b"),
				]),
			],
			config: single,
		});
		expect(app.get(counted)).toBe(2);
	});

	it("collects refusals from independent factories together", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
						m.provide(contract("p")).by((c) => c.refuse("a.k", "bad")),
					]),
					defineModule({ name: "b", replicaSafe: true, takes: [] }, (m) => [
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
					defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
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
					defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
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

	it("refuses a kernel section without a deployment, which has no default", async () => {
		const refusals = await refusalsOf(assemble({ modules: [], config: { kernel: {} } }));
		expect(refusals.map((r) => r.where)).toEqual(["kernel.deployment"]);
	});

	it("tells contracts apart by value, never by their name", async () => {
		const [one, other] = [contract<string>("same"), contract<string>("same")];
		const app = await assemble({
			modules: [
				defineModule({ name: "a", replicaSafe: true, takes: [] }, (m) => [
					m.provide(one).by(() => "a"),
				]),
				defineModule({ name: "b", replicaSafe: false, takes: [] }, (m) => [
					m.provide(other).by(() => "b"),
				]),
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
					defineModule({ name: "owner", replicaSafe: false, takes: [only] }, (m) => [
						m.provide(used).by(async (c) => (await c.collect(only))[0] ?? ""),
					]),
					defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(only).by(() => "a"),
					]),
					defineModule({ name: "b", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(only).by(() => "b"),
					]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "only", reason: "needs exactly one contribution (2)" }]);
	});

	it("refuses a module named kernel, the kernel's own section's name", async () => {
		// A section taking anything, so only the name can refuse it.
		const named = defineModule({
			name: "kernel",
			replicaSafe: true,
			section: z.looseObject({}),
			takes: [],
		});
		const refusals = await refusalsOf(assemble({ modules: [named], config: single }));
		expect(refusals).toEqual([{ where: "kernel", reason: "duplicate module name" }]);
	});

	it("refuses a section given to a module that takes none", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [defineModule({ name: "m", replicaSafe: true, takes: [] })],
				config: { ...single, m: {} },
			}),
		);
		expect(refusals).toEqual([{ where: "m", reason: "module without a section" }]);
	});

	it("refuses a configuration whose root is not an object", async () => {
		for (const config of [[], "kernel", null]) {
			expect(await refusalsOf(assemble({ modules: [], config }))).toEqual([
				{ where: "config", reason: "the configuration root is not an object" },
			]);
		}
	});

	it("reports the sections' refusals with a contract provided twice, building nothing", async () => {
		const twice = contract<number>("twice");
		const providing = (name: string) =>
			defineModule({ name, replicaSafe: true, takes: [] }, (m) => [m.provide(twice).by(() => 1)]);
		const refusals = await refusalsOf(
			assemble({ modules: [providing("a"), providing("b")], config: { ...single, ghost: {} } }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["ghost", "twice"]);
	});

	it("refuses with the module's name when a factory refuses with an empty list", async () => {
		const m = defineModule({ name: "m", replicaSafe: true, takes: [] }, (m) => [
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
		const owner = defineModule({ name: "owner", replicaSafe: false, takes: [only] }, (m) => [
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
				defineModule({ name: "owner", replicaSafe: false, takes: [many] }, (m) => [
					m.provide(list).by((c) => c.collect(many)),
				]),
				defineModule({ name: "a", replicaSafe: false, takes: [] }, (m) => [
					m.contribute(many).by(() => "a"),
				]),
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
			defineModule({ name, replicaSafe: false, takes: after ? [handles[after]] : [] }, (m) => [
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
	const owner = defineModule({ name: "owner", replicaSafe: false, takes: [greetings] }, (m) => [
		m.provide(greeter).by(async (c) => {
			const all = await c.collect(greetings);
			return { greet: (name: string) => `hello ${name} (${all.length})` };
		}),
	]);

	it("lets a contributor hold its owner's interface and use it once assembly is done", async () => {
		const contributor = defineModule(
			{ name: "contributor", replicaSafe: false, takes: [greeter] },
			(m) => [
				m.contribute(greetings).by((c) => {
					const later = c.late(greeter);
					return { say: () => later().greet("late") };
				}),
			],
		);
		let said: (() => string) | undefined;
		const keeper = defineModule({ name: "keeper", replicaSafe: false, takes: [greetings] }, (m) => [
			m.provide(contract<object>("keeper")).by(async (c) => {
				said = (await c.collect(greetings))[0]?.say;
				return {};
			}),
		]);
		await assemble({ modules: [owner, contributor, keeper], config: single });
		expect(said?.()).toBe("hello late (1)");
	});

	it("throws when a late reference is used during assembly, refusing boot", async () => {
		const eager = defineModule({ name: "eager", replicaSafe: false, takes: [greeter] }, (m) => [
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
		const asking = defineModule({ name: "asking", replicaSafe: true, takes: [missing] }, (m) => [
			m.provide(contract<object>("asking")).by((c) => ({ later: c.late(missing) })),
		]);
		expect(await refusalsOf(assemble({ modules: [asking], config: single }))).toEqual([
			{ where: "asking", reason: "no module provides missing" },
		]);
	});

	it("never hands over an interface from an assembly that was refused", async () => {
		let later: (() => unknown) | undefined;
		const holder = defineModule({ name: "holder", replicaSafe: false, takes: [greeter] }, (m) => [
			m.provide(contract<object>("holder")).by((c) => {
				later = c.late(greeter);
				return {};
			}),
		]);
		const broken = defineModule({ name: "broken", replicaSafe: true, takes: [] }, (m) => [
			m.provide(contract<object>("broken")).by(() => {
				throw new Error("broken");
			}),
		]);
		await refusalsOf(assemble({ modules: [owner, holder, broken], config: single }));
		expect(() => later?.()).toThrow("before assembly is done");
	});
});

describe("takenBy", () => {
	const signer = contract<{ sign(): string }>("signer", { takenBy: ["issuer"] });
	const keys = defineModule({ name: "keys", replicaSafe: true, takes: [] }, (m) => [
		m.provide(signer).by(() => ({ sign: () => "signed" })),
	]);
	/** A module named `name` providing `out`, which takes the signer as `how` says. */
	const taker = (name: string, how: "get" | "late" | "caught" | "late-caught") => {
		const out = contract<object>(`${name}-out`);
		return defineModule({ name, replicaSafe: true, takes: [signer] }, (m) => [
			m.provide(out).by(async (c) => {
				if (how === "late") c.late(signer);
				else if (how === "get") await c.get(signer);
				else if (how === "caught") await c.get(signer).catch(() => undefined);
				else
					try {
						c.late(signer);
					} catch {}
				return {};
			}),
		]);
	};
	const refusal = (where: string) => ({ where, reason: "signer is taken by issuer alone" });

	it("lets a module the contract names take it, by get or late, and the composition root besides", async () => {
		const app = await assemble({ modules: [keys, taker("issuer", "get")], config: single });
		expect(app.get(signer).sign()).toBe("signed");
		const signs = contract<{ sign(): string }>("signs");
		const late = defineModule({ name: "issuer", replicaSafe: true, takes: [signer] }, (m) => [
			m.provide(signs).by((c) => {
				const later = c.late(signer);
				return { sign: () => later().sign() };
			}),
		]);
		const lateApp = await assemble({ modules: [keys, late], config: single });
		expect(lateApp.get(signs).sign()).toBe("signed");
	});

	it("refuses boot when a module it does not name takes it, by get or late, even when the taker catches the throw", async () => {
		for (const how of ["get", "late", "caught", "late-caught"] as const) {
			const refused = await refusalsOf(
				assemble({ modules: [keys, taker("tokens", how)], config: single }),
			);
			expect(refused, how).toEqual([refusal("tokens")]);
		}
	});

	it("binds the contract object, never its label: a lookalike reaches no provider", async () => {
		for (const lookalike of [
			contract<{ sign(): string }>("signer"),
			contract<{ sign(): string }>("signer", { takenBy: ["tokens"] }),
		]) {
			for (const how of ["get", "late"] as const) {
				// It names what it takes, the lookalike: one label, another contract.
				const tokens = defineModule(
					{ name: "tokens", replicaSafe: true, takes: [lookalike] },
					(m) => [
						m.provide(contract<object>("tokens-out")).by(async (c) => {
							if (how === "get") await c.get(lookalike);
							else c.late(lookalike);
							return {};
						}),
					],
				);
				const refused = await refusalsOf(assemble({ modules: [keys, tokens], config: single }));
				expect(refused, how).toEqual([{ where: "tokens", reason: "no module provides signer" }]);
			}
		}
	});

	it("lets no module take a contract whose takenBy is empty", async () => {
		const sealed = contract<object>("sealed", { takenBy: [] });
		const holder = defineModule({ name: "holder", replicaSafe: true, takes: [] }, (m) => [
			m.provide(sealed).by(() => ({})),
		]);
		const reader = defineModule({ name: "reader", replicaSafe: true, takes: [sealed] }, (m) => [
			m.provide(contract<object>("read")).by(async (c) => c.get(sealed)),
		]);
		expect(await refusalsOf(assemble({ modules: [holder, reader], config: single }))).toEqual([
			{ where: "reader", reason: "sealed is taken by no module" },
		]);
	});

	it("keeps the takers it was given, whatever later becomes of the list", async () => {
		const takers = ["issuer"];
		const kept = contract<{ sign(): string }>("kept", { takenBy: takers });
		takers.push("tokens");
		expect(kept.takenBy).toEqual(["issuer"]);
		expect(Object.isFrozen(kept.takenBy)).toBe(true);
		const holder = defineModule({ name: "holder", replicaSafe: false, takes: [] }, (m) => [
			m.provide(kept).by(() => ({ sign: () => "signed" })),
		]);
		const tokens = defineModule({ name: "tokens", replicaSafe: false, takes: [kept] }, (m) => [
			m.provide(contract<object>("tokens-out")).by(async (c) => c.get(kept)),
		]);
		expect(await refusalsOf(assemble({ modules: [holder, tokens], config: single }))).toEqual([
			{ where: "tokens", reason: "kept is taken by issuer alone" },
		]);
	});

	it("binds only the contracts that name their takers", async () => {
		const open = contract<object>("open");
		const anyone = defineModule({ name: "anyone", replicaSafe: true, takes: [] }, (m) => [
			m.provide(open).by(() => ({})),
		]);
		const reader = defineModule({ name: "reader", replicaSafe: true, takes: [open] }, (m) => [
			m.provide(contract<object>("read")).by(async (c) => c.get(open)),
		]);
		await assemble({ modules: [anyone, reader], config: single });
	});
});
