import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { completedOf, composedWith, neededWith } from "../src/composed.ts";
import { type Declared, declaredIn, type Package } from "../src/declared.ts";
import { type Declaration, declaredWith } from "../src/outside.ts";

// Reading a workspace spawns pnpm, slow on a loaded machine.
vi.setConfig({ testTimeout: 60_000 });

const fixture = declaredIn(join(import.meta.dirname, "composition"));

const feature = (name: string, needs: string[] = []): Declaration => ({
	name,
	kind: "feature",
	needs,
});

/** A workspace of the packages given, each as composing reads it. */
const workspaceOf = (packages: Partial<Package>[]): Declared => ({
	wirings: new Map(),
	bridges: [],
	packages: new Map(
		packages.map((p) => [
			p.name as string,
			{
				module: true,
				needs: [],
				optIn: false,
				default: false,
				forWiring: false,
				outside: false,
				...p,
			} as Package,
		]),
	),
});

describe("what is declared outside the workspace, composed with it", () => {
	it("composes an outside feature with what it needs, and the axis defaults that come with that", () => {
		const declared = declaredWith(fixture, [feature("@x/grant", ["@c/users"])]);
		expect(composedWith(declared, { features: { login: ["@x/grant"] } })).toEqual([
			"@x/grant",
			"@c/users",
			"@c/users-http",
			"@c/outbound",
		]);
		expect(neededWith(declared, ["@x/grant"])).toEqual(["@x/grant", "@c/users"]);
	});

	it("keeps an axis's only adapter in the workspace its default, beside an outside adapter of it", () => {
		const declared = declaredWith(fixture, [
			{ name: "@x/users-db", kind: "adapter", adapts: "@c/users", needs: [] },
		]);
		const selection = { features: { login: ["@c/users"] } };
		expect(composedWith(declared, selection)).toContain("@c/users-http");
		const chosen = composedWith(declared, { ...selection, axes: { "@c/users": "@x/users-db" } });
		expect(chosen).toContain("@x/users-db");
		expect(chosen).not.toContain("@c/users-http");
	});

	it("brings an outside wiring with the outside feature it wires", () => {
		const declared = declaredWith(fixture, [
			feature("@x/grant"),
			{ name: "@x/grant-store", kind: "wiring", wires: "@x/grant", needs: ["@x/grant"] },
		]);
		expect(composedWith(declared, { features: { login: ["@x/grant"] } })).toEqual([
			"@x/grant",
			"@x/grant-store",
		]);
	});

	it("lets an outside adapter join what it bridges", () => {
		const declared = declaredWith(fixture, [
			{
				name: "@x/audit-users",
				kind: "adapter",
				adapts: "@c/audit",
				joins: ["@c/audit", "@c/users"],
				needs: [],
			},
		]);
		expect(completedOf(declared, ["@c/audit", "@c/users"])).toContain("@x/audit-users");
	});

	it("gives an outside axis the default its adapters declare", () => {
		const declared = declaredWith(fixture, [
			feature("@x/registry"),
			{ name: "@x/registry-a", kind: "adapter", adapts: "@x/registry", default: true, needs: [] },
			{ name: "@x/registry-b", kind: "adapter", adapts: "@x/registry", needs: [] },
		]);
		expect(composedWith(declared, { features: { login: ["@x/registry"] } })).toEqual([
			"@x/registry",
			"@x/registry-a",
		]);
	});

	it("refuses nothing in the workspace itself: its packages' npm dependencies are no edges", () => {
		const root = join(import.meta.dirname, "..", "..", "..", "..");
		expect(() => declaredWith(declaredIn(root), [])).not.toThrow();
		expect(() => declaredWith(fixture, [])).not.toThrow();
	});
});

describe("refusing an outside declaration, naming it", () => {
	const refused = (outside: Declaration[], why: RegExp, declared = fixture) =>
		expect(() => declaredWith(declared, outside)).toThrow(why);

	it("refuses a name the workspace declares, or one declared twice", () => {
		refused([feature("@c/users")], /@c\/users: declared in the workspace/);
		refused([feature("@x/a"), feature("@x/a")], /@x\/a: declared twice/);
	});

	it("refuses a kind an outside package may not be", () => {
		refused(
			[{ name: "@x/a", kind: "foundation", needs: [] }],
			/@x\/a: kind foundation is not one of feature, adapter, wiring/,
		);
	});

	it("refuses a need that is neither in the workspace nor declared beside it", () => {
		refused([feature("@x/a", ["@c/nope"])], /@x\/a: needs @c\/nope, which is not declared/);
	});

	it("refuses a need against the direction of the kinds", () => {
		refused([feature("@x/a", ["@c/redis"])], /@x\/a: a feature may not need @c\/redis, an adapter/);
	});

	it("keeps an outside feature off a capability and off what declares forWiring", () => {
		const declared = workspaceOf([
			{ name: "@w/http-kit", kind: "capability" },
			{ name: "@w/store", kind: "foundation", forWiring: true },
		]);
		refused(
			[feature("@x/a", ["@w/http-kit"])],
			/@x\/a: a feature may not need @w\/http-kit, a capability/,
			declared,
		);
		refused(
			[feature("@x/a", ["@w/store"])],
			/@x\/a: a feature may not need @w\/store, which declares forWiring/,
			declared,
		);
	});

	it("lets an outside wiring need what declares forWiring: the refusal is a feature's alone", () => {
		const declared = workspaceOf([{ name: "@w/store", kind: "foundation", forWiring: true }]);
		const outside: Declaration[] = [
			feature("@x/a"),
			{ name: "@x/a-store", kind: "wiring", wires: "@x/a", needs: ["@x/a", "@w/store"] },
		];
		expect(() => declaredWith(declared, outside)).not.toThrow();
	});

	it("refuses a need composing would never bring: an adapter of another axis, or a wiring", () => {
		refused(
			[
				feature("@x/f"),
				feature("@x/g"),
				{ name: "@x/a", kind: "adapter", adapts: "@x/f", needs: ["@x/b"] },
				{ name: "@x/b", kind: "adapter", adapts: "@x/g", needs: [] },
			],
			/@x\/a: needs @x\/b, an adapter, which a need never brings: need what it adapts or wires/,
		);
		refused(
			[
				feature("@x/f"),
				feature("@x/g"),
				{ name: "@x/f-store", kind: "wiring", wires: "@x/f", needs: ["@x/f"] },
				{ name: "@x/g-store", kind: "wiring", wires: "@x/g", needs: ["@x/g", "@x/f-store"] },
			],
			/@x\/g-store: needs @x\/f-store, a wiring, which a need never brings/,
		);
	});

	it("lets an outside module need an axis owner, whose axis then brings its choice", () => {
		const declared = declaredWith(fixture, [
			feature("@x/g"),
			{ name: "@x/b", kind: "adapter", adapts: "@x/g", needs: [] },
			feature("@x/f", ["@x/g"]),
		]);
		expect(composedWith(declared, { features: { login: ["@x/f"] } })).toEqual([
			"@x/f",
			"@x/g",
			"@x/b",
		]);
	});

	it("refuses an empty joins, as the workspace's manifests are", () => {
		refused([{ ...feature("@x/a"), joins: [] }], /@x\/a: joins names no module/);
	});

	it("refuses a field its kind does not take", () => {
		refused([{ ...feature("@x/a"), replaces: "@c/mail" }], /@x\/a: replaces is an adapter's/);
		refused([{ ...feature("@x/a"), wires: "@x/b" }], /@x\/a: wires is a wiring's/);
		refused(
			[{ name: "@x/a", kind: "adapter", adapts: "@c/users", optIn: true, needs: [] }],
			/@x\/a: optIn is a feature's/,
		);
		refused(
			[
				{ name: "@x/a", kind: "wiring", wires: "@x/b", joins: ["@c/users"], needs: [] },
				feature("@x/b"),
			],
			/@x\/a: joins is a feature's or an adapter's/,
		);
	});

	it("refuses an adapter declaring both replaces and adapts, or neither", () => {
		refused(
			[{ name: "@x/a", kind: "adapter", replaces: "@c/mail", adapts: "@c/mail", needs: [] }],
			/@x\/a: declares replaces and adapts/,
		);
		refused(
			[{ name: "@x/a", kind: "adapter", needs: [] }],
			/@x\/a: declares neither replaces nor adapts/,
		);
	});

	it("refuses a wiring of no outside feature declared beside it", () => {
		refused([{ name: "@x/a", kind: "wiring", needs: [] }], /@x\/a: wires no feature/);
		refused(
			[{ name: "@x/a", kind: "wiring", wires: "@c/wired", needs: [] }],
			/@x\/a: wires @c\/wired, which is not an outside feature/,
		);
	});

	it("refuses an outside default for an axis the workspace owns: choosing one is the selection's", () => {
		refused(
			[{ name: "@x/a", kind: "adapter", adapts: "@c/users", default: true, needs: [] }],
			/@x\/a: declares the default of @c\/users, an axis the workspace owns/,
		);
	});

	it("refuses an owner, a join or a wired feature that is not declared", () => {
		refused(
			[{ name: "@x/a", kind: "adapter", adapts: "@c/nope", needs: [] }],
			/@x\/a: adapts @c\/nope, which is not declared/,
		);
		refused(
			[{ ...feature("@x/a"), joins: ["@c/users", "@c/nope"] }],
			/@x\/a: joins @c\/nope, which is not declared/,
		);
	});

	it("refuses an outside axis with several adapters and no default, or several defaults", () => {
		const adapter = (name: string, extra: Partial<Declaration> = {}): Declaration => ({
			name,
			kind: "adapter",
			adapts: "@x/o",
			needs: [],
			...extra,
		});
		refused(
			[feature("@x/o"), adapter("@x/a"), adapter("@x/b")],
			/@x\/o: no default among its 2 adapters/,
		);
		refused(
			[feature("@x/o"), adapter("@x/a", { default: true }), adapter("@x/b", { default: true })],
			/@x\/o: 2 defaults among its adapters/,
		);
	});

	it("refuses a cycle of needs and joins, naming it", () => {
		refused(
			[feature("@x/a", ["@x/b"]), feature("@x/b", ["@x/a"])],
			/a cycle: @x\/a -> @x\/b -> @x\/a/,
		);
	});

	it("names every refusal at once", () => {
		refused(
			[feature("@c/users"), feature("@x/a", ["@c/nope"])],
			/@c\/users: declared in the workspace; @x\/a: needs @c\/nope/,
		);
	});
});
