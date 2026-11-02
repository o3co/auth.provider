import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	assemble,
	contract,
	defineModule,
	extensionPoint,
	type Handle,
	kernelConfig,
} from "../src/contract.ts";
import { refusalsOf, unreadable } from "./refusals.ts";

const single = kernelConfig();
const none = (label: string) => ({ where: "", reason: `no module provides ${label}` });

describe("a module's takes, checked before anything is built", () => {
	it("names every contract no module provides, each taker's second and third too, in one refusal", async () => {
		const keys = contract<string>("keys");
		const site = contract<string>("http.site");
		const binding = contract<string>("sender-binding");
		const audit = contract<string>("audit");
		const store = contract<string>("store");
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "tokens", replicaSafe: true, takes: [keys, site, binding] }),
					defineModule({ name: "token-endpoint", replicaSafe: true, takes: [site, audit] }),
					defineModule({ name: "tokens-store", replicaSafe: true, takes: [store] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{ ...none("keys"), where: "tokens" },
			{ ...none("http.site"), where: "tokens" },
			{ ...none("sender-binding"), where: "tokens" },
			{ ...none("http.site"), where: "token-endpoint" },
			{ ...none("audit"), where: "token-endpoint" },
			{ ...none("store"), where: "tokens-store" },
		]);
	});

	it("names a taker's own gaps beside the failing provider it waits on", async () => {
		const tokens = contract<string>("tokens");
		const audit = contract<string>("audit");
		const keys = contract<string>("keys");
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "tokens", replicaSafe: true, takes: [keys] }, (m) => [
						m.provide(tokens).by(async (c) => c.get(keys)),
					]),
					defineModule({ name: "token-endpoint", replicaSafe: true, takes: [tokens, audit] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{ ...none("keys"), where: "tokens" },
			{ ...none("audit"), where: "token-endpoint" },
		]);
	});

	it("gives a section's, a replica's and a provider's refusals together with the takes' gaps", async () => {
		const shared = contract<string>("shared");
		const missing = contract<string>("missing");
		const asked: string[] = [];
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule(
						{
							name: "sectioned",
							replicaSafe: true,
							section: z.object({ size: z.number() }),
							// Not asked: its section did not pass.
							takes: (s) => {
								asked.push(`sectioned ${s.size}`);
								return [missing];
							},
						},
						(m) => [m.provide(shared).by(() => "a")],
					),
					defineModule({
						name: "fixed",
						replicaSafe: true,
						section: z.object({ on: z.boolean() }),
						takes: [missing],
					}),
					defineModule({ name: "unsafe", replicaSafe: false, takes: [] }, (m) => [
						m.provide(shared).by(() => "b"),
					]),
				],
				config: { ...kernelConfig({ deployment: "multi" }), sectioned: { size: "big" }, fixed: {} },
			}),
		);
		expect(asked).toEqual([]);
		expect(refusals.map((r) => r.where)).toEqual([
			"sectioned.size",
			"fixed.on",
			"unsafe",
			"shared",
			"fixed",
		]);
		expect(refusals.at(-1)).toEqual({ ...none("missing"), where: "fixed" });
	});

	it("builds nothing where a gap is found: no factory runs and no stop hook is left", async () => {
		const missing = contract<string>("missing");
		const pool = contract<string>("pool");
		const ran: string[] = [];
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "pool-owner", replicaSafe: false, takes: [] }, (m) => [
						m.provide(pool).by((c) => {
							ran.push("pool opened");
							c.onStop(() => {
								ran.push("pool closed");
							});
							return "pool";
						}),
					]),
					defineModule({ name: "needy", replicaSafe: true, takes: [missing] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ ...none("missing"), where: "needy" }]);
		expect(ran).toEqual([]);
	});

	it("holds a contract's takenBy to a declared taker, and lets a module take its own contract undeclared", async () => {
		const kept = contract<string>("kept", { takenBy: ["owner"] });
		const own = contract<string>("own");
		const after = contract<string>("after");
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "owner", replicaSafe: true, takes: [] }, (m) => [
						m.provide(kept).by(() => "k"),
					]),
					defineModule({ name: "outsider", replicaSafe: true, takes: [kept] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "outsider", reason: "kept is taken by owner alone" }]);
		const assembly = await assemble({
			modules: [
				defineModule({ name: "self", replicaSafe: true, takes: [] }, (m) => [
					m.provide(own).by(() => "o"),
					m.provide(after).by(async (c) => `${await c.get(own)}!`),
				]),
			],
			config: single,
		});
		expect(assembly.get(after)).toBe("o!");
	});

	it("holds a module taking its own contract undeclared to the contract's takenBy, as its factory runs", async () => {
		const signer = contract<object>("signer", { takenBy: ["issuer"] });
		for (const how of ["get", "late", "caught", "late-caught"] as const) {
			let ran = false;
			const tokens = defineModule({ name: "tokens", replicaSafe: false, takes: [] }, (m) => [
				m.provide(signer).by(() => ({})),
				m.provide(contract<object>("tokens-out")).by(async (c) => {
					ran = true;
					if (how === "get") await c.get(signer);
					else if (how === "late") c.late(signer);
					else if (how === "caught") await c.get(signer).catch(() => undefined);
					else
						try {
							c.late(signer);
						} catch {}
					return {};
				}),
			]);
			const refusals = await refusalsOf(assemble({ modules: [tokens], config: single }));
			expect(refusals, how).toEqual([
				{ where: "tokens", reason: "signer is taken by issuer alone" },
			]);
			expect(ran, how).toBe(true);
		}
	});

	it("counts every registered contribution, a failing one too, against a point's rule", async () => {
		const one = extensionPoint<string>("one", { multiplicity: "one" });
		const some = extensionPoint<string>("some", { multiplicity: "some" });
		const empty = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "owner", replicaSafe: true, takes: [one, some] }),
					defineModule({ name: "two", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(one).by(() => "a"),
						m.contribute(one).by(() => "b"),
					]),
				],
				config: single,
			}),
		);
		expect(empty).toEqual([
			{ where: "one", reason: "needs exactly one contribution (2)" },
			{ where: "some", reason: "needs at least one contribution" },
		]);
		// One contribution that fails as it builds is still one: its failure is its own refusal.
		const failing = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "owner", replicaSafe: false, takes: [some] }, (m) => [
						m.provide(contract<readonly string[]>("all")).by((c) => c.collect(some)),
					]),
					defineModule({ name: "broken", replicaSafe: false, takes: [] }, (m) => [
						m.contribute(some).by(() => {
							throw new Error("broken");
						}),
					]),
				],
				config: single,
			}),
		);
		expect(failing).toEqual([{ where: "broken", reason: "failed during assembly" }]);
	});

	it("checks a point by its identity: two of one label each, one point named by two modules once", async () => {
		const first = extensionPoint<string>("steps", { multiplicity: "some" });
		const second = extensionPoint<string>("steps", { multiplicity: "some" });
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "a", replicaSafe: true, takes: [first, second] }),
					// The same point again, by another module and twice in one list: still checked once.
					defineModule({ name: "b", replicaSafe: true, takes: [first, first] }),
				],
				config: single,
			}),
		);
		// Two points of one label, both empty: each refused, never one taken for the other.
		expect(refusals).toEqual([
			{ where: "steps", reason: "needs at least one contribution" },
			{ where: "steps", reason: "needs at least one contribution" },
		]);
	});

	it("takes no point handle without its rule, and one written by hand with it", async () => {
		// @ts-expect-error A point's handle carries its rule: the preflight reads its multiplicity.
		const bare: Handle = { kind: "extension-point", label: "bare" };
		expect(bare.label).toBe("bare");
		const handmade: Handle = {
			kind: "extension-point",
			label: "handmade",
			rule: { multiplicity: "some" },
		};
		expect(
			await refusalsOf(
				assemble({
					modules: [defineModule({ name: "a", replicaSafe: true, takes: [handmade] })],
					config: single,
				}),
			),
		).toEqual([{ where: "handmade", reason: "needs at least one contribution" }]);
	});

	it("takes a typed point of any rule as a handle, without a cast", () => {
		const keyed = extensionPoint<{ readonly name: string }>("keyed", {
			multiplicity: "keyed",
			keyOf: (part) => part.name,
		});
		const many = extensionPoint<number>("many", { multiplicity: "many" });
		const handles: readonly Handle[] = [keyed, many, contract<string>("c")];
		expect(defineModule({ name: "typed", replicaSafe: true, takes: handles }).takes).toEqual(
			handles,
		);
	});
});

describe("a module's takes, held while it is built", () => {
	it("refuses a contract or a point taken beyond them, by get, late or collect, caught or not", async () => {
		const declared = contract<string>("declared");
		const undeclared = contract<string>("undeclared");
		const later = contract<string>("later");
		const point = extensionPoint<string>("point", { multiplicity: "many" });
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "provider", replicaSafe: true, takes: [] }, (m) => [
						m.provide(declared).by(() => "d"),
						m.provide(undeclared).by(() => "u"),
						m.provide(later).by(() => "l"),
					]),
					defineModule({ name: "taker", replicaSafe: false, takes: [declared] }, (m) => [
						m.provide(contract<string>("built")).by(async (c) => {
							await c.get(declared);
							try {
								await c.get(undeclared);
							} catch {}
							return "built";
						}),
						m.contribute(point).by((c) => {
							c.late(later);
							return "p";
						}),
						m.provide(contract<readonly string[]>("collected")).by((c) => c.collect(point)),
					]),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{ where: "taker", reason: "takes undeclared, which its takes do not name" },
			{ where: "taker", reason: "takes point, which its takes do not name" },
			{ where: "taker", reason: "takes later, which its takes do not name" },
		]);
	});

	it("refuses a module that declares no takes, as one written without the types may be", async () => {
		// A module's definition from plain JavaScript, or one cast past its type: no takes at all.
		const untyped = { name: "untyped" } as unknown as Parameters<typeof defineModule>[0];
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule(untyped, (m) => [m.provide(contract<string>("v")).by(() => "v")]),
					defineModule({ name: "declared", replicaSafe: true, takes: [] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "untyped", reason: "declares no takes" }]);
	});

	it("refuses a module whose takes throw by its name, its text never kept, beside the other gaps", async () => {
		const missing = contract<string>("missing");
		for (const thrown of [new Error("private detail"), { private: "detail" }, ...unreadable()]) {
			const refusals = await refusalsOf(
				assemble({
					modules: [
						defineModule({
							name: "thrower",
							replicaSafe: true,
							takes: () => {
								throw thrown;
							},
						}),
						defineModule({ name: "gap", replicaSafe: true, takes: [missing] }),
					],
					config: single,
				}),
			);
			expect(refusals).toEqual([
				{ where: "thrower", reason: "its takes failed as they were asked" },
				{ where: "gap", reason: "no module provides missing" },
			]);
		}
	});
});

describe("the boot of #1974's hand-assembled app", () => {
	it("names every structural gap of the modules composed in one boot", async () => {
		const handle = (label: string) => contract<string>(label);
		const [site, keys, store, binding, audit] = [
			"http.site",
			"keys",
			"store",
			"sender-binding",
			"audit",
		].map(handle) as [Handle, Handle, Handle, Handle, Handle];
		const checkers = extensionPoint<string>("secret-hash.checkers", { multiplicity: "some" });
		const tokens = contract<string>("tokens");
		const refusals = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "issuer", replicaSafe: true, takes: [site] }),
					defineModule({ name: "tokens", replicaSafe: true, takes: [site, keys, binding] }, (m) => [
						m.provide(tokens).by(() => "t"),
					]),
					defineModule({ name: "token-endpoint", replicaSafe: true, takes: [site, tokens, audit] }),
					defineModule({ name: "clients", replicaSafe: true, takes: [checkers] }),
					defineModule({ name: "tokens-store", replicaSafe: true, takes: [store] }),
				],
				config: single,
			}),
		);
		expect(new Set(refusals.map((r) => r.reason.replace("no module provides ", "")))).toEqual(
			new Set([
				"http.site",
				"keys",
				"sender-binding",
				"audit",
				"needs at least one contribution",
				"store",
			]),
		);
	});
});
