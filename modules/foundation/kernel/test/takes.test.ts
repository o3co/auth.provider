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
import { refusalsOf } from "./refusals.ts";

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
					defineModule({ name: "tokens", takes: [keys, site, binding] }),
					defineModule({ name: "token-endpoint", takes: [site, audit] }),
					defineModule({ name: "tokens-store", takes: [store] }),
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
					defineModule({ name: "tokens", takes: [keys] }, (m) => [
						m.provide(tokens).by(async (c) => c.get(keys)),
					]),
					defineModule({ name: "token-endpoint", takes: [tokens, audit] }),
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
							section: z.object({ size: z.number() }),
							// Not asked: its section did not pass.
							takes: (s) => {
								asked.push(`sectioned ${s.size}`);
								return [missing];
							},
						},
						(m) => [m.provide(shared).by(() => "a")],
					),
					defineModule({ name: "fixed", section: z.object({ on: z.boolean() }), takes: [missing] }),
					defineModule({ name: "unsafe", replicaSafe: false }, (m) => [
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
					defineModule({ name: "pool-owner" }, (m) => [
						m.provide(pool).by((c) => {
							ran.push("pool opened");
							c.onStop(() => {
								ran.push("pool closed");
							});
							return "pool";
						}),
					]),
					defineModule({ name: "needy", takes: [missing] }),
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
					defineModule({ name: "owner" }, (m) => [m.provide(kept).by(() => "k")]),
					defineModule({ name: "outsider", takes: [kept] }),
				],
				config: single,
			}),
		);
		expect(refusals).toEqual([{ where: "outsider", reason: "kept is taken by owner alone" }]);
		const assembly = await assemble({
			modules: [
				defineModule({ name: "self", takes: [] }, (m) => [
					m.provide(own).by(() => "o"),
					m.provide(after).by(async (c) => `${await c.get(own)}!`),
				]),
			],
			config: single,
		});
		expect(assembly.get(after)).toBe("o!");
	});

	it("counts every registered contribution, a failing one too, against a point's rule", async () => {
		const one = extensionPoint<string>("one", { multiplicity: "one" });
		const some = extensionPoint<string>("some", { multiplicity: "some" });
		const empty = await refusalsOf(
			assemble({
				modules: [
					defineModule({ name: "owner", takes: [one, some] }),
					defineModule({ name: "two" }, (m) => [
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
					defineModule({ name: "owner", takes: [some] }, (m) => [
						m.provide(contract<readonly string[]>("all")).by((c) => c.collect(some)),
					]),
					defineModule({ name: "broken" }, (m) => [
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
					defineModule({ name: "a", takes: [first, second] }),
					// The same point again, by another module and twice in one list: still checked once.
					defineModule({ name: "b", takes: [first, first] }),
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
				assemble({ modules: [defineModule({ name: "a", takes: [handmade] })], config: single }),
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
		expect(defineModule({ name: "typed", takes: handles }).takes).toEqual(handles);
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
					defineModule({ name: "provider" }, (m) => [
						m.provide(declared).by(() => "d"),
						m.provide(undeclared).by(() => "u"),
						m.provide(later).by(() => "l"),
					]),
					defineModule({ name: "taker", takes: [declared] }, (m) => [
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

	it("lets a module without takes take as before", async () => {
		const value = contract<string>("value");
		const assembly = await assemble({
			modules: [
				defineModule({ name: "older" }, (m) => [m.provide(value).by(() => "v")]),
				defineModule({ name: "oldest" }, (m) => [
					m.provide(contract<string>("again")).by((c) => c.get(value)),
				]),
			],
			config: single,
		});
		expect(assembly.get(value)).toBe("v");
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
					defineModule({ name: "issuer", takes: [site] }),
					defineModule({ name: "tokens", takes: [site, keys, binding] }, (m) => [
						m.provide(tokens).by(() => "t"),
					]),
					defineModule({ name: "token-endpoint", takes: [site, tokens, audit] }),
					defineModule({ name: "clients", takes: [checkers] }),
					defineModule({ name: "tokens-store", takes: [store] }),
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
