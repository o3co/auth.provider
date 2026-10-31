import { mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { importViolations, type Rules } from "../src/contract.ts";
import type { Pkg } from "../src/workspace.ts";
import { budget, pkg } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const check = (packages: Pkg[], rules: Rules) => importViolations(packages, rules);
const rules = (packages: Pkg[]) => check(packages, budget).map((v) => v.rule.split(" ")[0]);

describe("guard-imports", () => {
	// The first syntax tree loads the parser, which under a full parallel run takes longer than a test may.
	beforeAll(() => {
		check([pkg("@t/warm", { "src/contract.ts": "export const n = 1;\n" })], budget);
	}, 60_000);

	it("G10 refuses a lower kind depending on a higher one, and an unknown kind", () => {
		// Without exports, so no contract surface is built: these rules read only kinds and dependencies.
		const dep = (name: string) => ({ dependencies: { [name]: "workspace:*" } });
		const feature = pkg("@x/feature", { "src/contract.ts": "export const f = 1;\n" }, {});
		const base = pkg(
			"@x/base",
			{ "src/contract.ts": "export const b = 1;\n" },
			dep("@x/feature"),
			"foundation",
		);
		expect(rules([feature, base])).toContain("G10");
		const upward = pkg("@x/up", { "src/contract.ts": "export const u = 1;\n" }, dep("@x/base2"));
		const base2 = pkg("@x/base2", { "src/contract.ts": "export const b = 1;\n" }, {}, "foundation");
		expect(rules([upward, base2])).not.toContain("G10");
		const stray = pkg("@x/stray", { "src/contract.ts": "export const s = 1;\n" }, {}, "unknown");
		expect(rules([stray])).toContain("G10");
	});

	it("passes a clean pair", () => {
		const a = pkg("@t/a", { "src/contract.ts": "export const a = 1;\n" });
		const b = pkg(
			"@t/b",
			{ "src/contract.ts": 'import { a } from "@t/a";\nexport const b = a;\n' },
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/a": "workspace:*" } },
		);
		expect(check([a, b], budget)).toEqual([]);
	});

	it("finds cycles and undeclared runtime imports", () => {
		const a = pkg(
			"@t/c1",
			{ "src/contract.ts": 'export { x } from "@t/c2";\n' },
			{
				exports: { ".": "./src/contract.ts", "./internal": "./src/x.ts" },
				dependencies: { "@t/c2": "*" },
			},
		);
		const b = pkg(
			"@t/c2",
			{
				"src/contract.ts":
					'import type { y } from "@t/c1";\nimport z from "lib";\nexport const x = z;\n',
			},
			{ exports: { ".": "./src/contract.ts" }, devDependencies: { "@t/c1": "*" } },
		);
		expect(rules([a, b]).sort()).toEqual(["G1", "G8"]);
	});

	it("keeps assembly definitions and contract tests out of product code only", () => {
		const m = pkg(
			"@t/m",
			{
				"src/module.ts":
					'import other from "@t/o/module";\nimport { suite } from "@t/o/testing";\nexport default [other, suite];\n',
				"test/m.test.ts": 'import other from "@t/o/module";\nexport default other;\n',
			},
			{ exports: { "./module": "./src/module.ts" }, dependencies: { "@t/o": "*" } },
		);
		const o = pkg("@t/o", { "src/contract.ts": "export const o = 1;\n" });
		expect(rules([m, o]).sort()).toEqual(["G3", "G4"]);
	});

	it("checks a published contract test suite's imports as shipped code", () => {
		const p = pkg(
			"@t/suite",
			{
				"src/contract.ts": "export const a = 1;\n",
				"src/testing.ts": 'import { x } from "undeclared";\nexport const t = x;\n',
			},
			{ exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" } },
		);
		const violations = check([p], budget);
		expect(violations.map((v) => `${v.rule.split(" ")[0]} ${v.detail}`)).toEqual(["G8 undeclared"]);
	});

	it("G8 asks a declared run-time dependency of an import that loads its module, types alone named or not", () => {
		const x = pkg("@v/x", { "src/contract.ts": "export type T = 1;\n" }, {});
		const user = pkg(
			"@v/user",
			{
				"src/a.ts": 'import { type T } from "@v/x";\nexport type A = T;\n',
				"src/b.ts": 'import type { T } from "@v/x";\nexport type B = T;\n',
				"src/c.ts": 'import {} from "@v/x";\n',
				// A declaration loads nothing, whatever form names the module.
				"src/d.d.ts": 'export declare class Pool extends (require("@v/x").Pool) {}\n',
			},
			{ devDependencies: { "@v/x": "*" } },
		);
		expect(
			check([x, user], budget)
				.filter((v) => v.rule.startsWith("G8"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@v/user/src/a.ts @v/x (it still loads the module: import type { … } binds types alone)",
			"@v/user/src/c.ts @v/x",
		]);
	});

	it("G2 holds the bottom level to no workspace dependency, a peer, a dev one or one beside it included", () => {
		// Without exports, so no contract surface is built: these rules read only kinds and dependencies.
		const kernel = pkg("@b/kernel", { "src/contract.ts": "export const k = 1;\n" }, {}, "common");
		const feature = pkg("@b/feature", { "src/contract.ts": "export const f = 1;\n" }, {});
		const on = (field: string, name: string, at: string) =>
			pkg(
				at,
				{ "src/contract.ts": "export const w = 1;\n" },
				{ [field]: { [name]: "workspace:*" } },
				"protocol",
			);
		const found = (packages: Pkg[]) =>
			check(packages, budget)
				.filter((v) => v.rule.startsWith("G2 "))
				.map((v) => `${v.where} ${v.detail}`);
		expect(found([kernel, on("dependencies", "@b/kernel", "@b/beside")])).toEqual([
			"@b/beside @b/kernel",
		]);
		expect(found([feature, on("peerDependencies", "@b/feature", "@b/peer")])).toEqual([
			"@b/peer @b/feature",
		]);
		expect(found([kernel, on("devDependencies", "@b/kernel", "@b/dev")])).toEqual([
			"@b/dev @b/kernel",
		]);
		const alone = pkg("@b/wire", { "src/contract.ts": "export const w = 1;\n" }, {}, "protocol");
		expect(found([kernel, alone])).toEqual([]);
	});

	it("G10 and G14 let every kind, a verification base included, depend on protocol", () => {
		const deps = (...names: string[]) => ({
			dependencies: Object.fromEntries(names.map((n) => [n, "workspace:*"])),
		});
		const wire = pkg("@p/wire", { "src/contract.ts": "export const w = 1;\n" }, {}, "protocol");
		const kinds = ["foundation", "capability", "feature", "adapter", "wiring", "assembly"];
		const users = kinds.map((kind) =>
			pkg(`@p/${kind}`, { "src/contract.ts": "export const u = 1;\n" }, deps("@p/wire"), kind),
		);
		const base = pkg(
			"@p/base",
			{ "src/contract.ts": "export const b = 1;\n" },
			deps("@p/wire"),
			"verification",
		);
		const area = pkg(
			"@p/area",
			{ "src/contract.ts": "export const a = 1;\n" },
			deps("@p/base"),
			"verification",
		);
		expect(rules([wire, ...users, base, area]).filter((r) => r === "G10" || r === "G14")).toEqual(
			[],
		);
	});

	it("reads a workspace peer as a dependency, as G8 takes it at run time", () => {
		const feature = pkg("@q/feature", { "src/contract.ts": "export const f = 1;\n" }, {});
		const base = pkg(
			"@q/base",
			{ "src/contract.ts": "export const b = 1;\n" },
			{ peerDependencies: { "@q/feature": "workspace:*" } },
			"foundation",
		);
		expect(rules([feature, base])).toContain("G10");
		const check2 = pkg(
			"@q/check",
			{ "src/contract.ts": "export const c = 1;\n" },
			{ peerDependencies: { "@q/feature": "workspace:*" } },
			"verification",
		);
		const area = pkg(
			"@q/area",
			{ "src/contract.ts": "export const a = 1;\n" },
			{ dependencies: { "@q/check": "workspace:*" } },
			"verification",
		);
		expect(rules([feature, check2, area])).toContain("G14");
	});

	it("G34 holds a relative import to its own package, a climb within it let through", () => {
		const other = pkg("@r/other", { "src/contract.ts": "export const o = 1;\n" }, {});
		const within = pkg(
			"@r/within",
			{
				"src/contract.ts": 'import { l } from "../lib/l.ts";\nexport const w = l;\n',
				"lib/l.ts": "export const l = 1;\n",
				"test/w.test.ts": 'import { w } from "../src/contract.ts";\nexport const t = w;\n',
			},
			{},
		);
		const out = pkg(
			"@r/out",
			{
				"src/contract.ts":
					'import { o } from "../../@r_other/src/contract.ts";\nexport { o };\nexport * from "../../@r_other/src/contract.ts";\nexport const d = () => import("../../@r_other/src/contract.ts");\n',
				"test/o.test.ts":
					'import { o } from "../../@r_other/src/contract.ts";\nexport const t = o;\n',
			},
			{},
		);
		expect(
			check([other, within, out], budget)
				.filter((v) => v.rule.startsWith("G34"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@r/out/src/contract.ts ../../@r_other/src/contract.ts",
			"@r/out/src/contract.ts ../../@r_other/src/contract.ts",
			"@r/out/src/contract.ts ../../@r_other/src/contract.ts",
			"@r/out/test/o.test.ts ../../@r_other/src/contract.ts",
		]);
	});

	it("G34 reads a template's import and an import type, and refuses a relative import named at run time", () => {
		const other = pkg("@s/other", { "src/contract.ts": "export const o = 1;\n" }, {});
		const out = pkg(
			"@s/out",
			{
				"src/contract.ts": [
					"export const t = () => import(`../../@s_other/src/contract.ts`);",
					'export type O = import("../../@s_other/src/contract.ts").O;',
					"export const n = (name: string) => import(`../${name}.ts`);",
					"export const i = () => import(`./in.ts`);",
					'import O = require("../../@s_other/src/contract.ts");',
					"export const r = O;",
					"",
				].join("\n"),
				"src/in.ts": "export const i = 1;\n",
			},
			{},
		);
		expect(
			check([other, out], budget)
				.filter((v) => v.rule.startsWith("G34"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@s/out/src/contract.ts ../../@s_other/src/contract.ts",
			"@s/out/src/contract.ts ../../@s_other/src/contract.ts",
			"@s/out/src/contract.ts ../${…}: a relative import named at run time",
			"@s/out/src/contract.ts ../../@s_other/src/contract.ts",
		]);
	});

	it("G34 follows a link out of the package, as the import would", () => {
		const other = pkg("@l/other", { "src/contract.ts": "export const o = 1;\n" }, {});
		const linked = pkg(
			"@l/linked",
			{ "src/contract.ts": 'export { o } from "../lib/contract.ts";\n' },
			{},
		);
		symlinkSync(join(other.dir, "src"), join(linked.dir, "lib"));
		expect(
			check([other, linked], budget)
				.filter((v) => v.rule.startsWith("G34"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@l/linked/src/contract.ts ../lib/contract.ts"]);
	});

	it("G34 resolves a specifier as Node's loader does: encoded dots, a query, and the file's own place", () => {
		const other = pkg(
			"@u/other",
			{
				"src/helper.mjs": "export const h = 1;\n",
				"src/linked.ts": 'export { h } from "./helper.mjs";\n',
			},
			{},
		);
		const own = pkg(
			"@u/own",
			{
				"src/contract.ts": [
					'export const e = () => import("./%2e%2e/%2e%2e/@u_other/src/helper.mjs");',
					'export { h } from "../lib/helper.mjs?v=1";',
					'export const inner = () => import("./inner.mjs?v=1");',
					"",
				].join("\n"),
				"src/inner.mjs": "export const i = 1;\n",
			},
			{},
		);
		mkdirSync(join(own.dir, "lib"));
		symlinkSync(join(other.dir, "src", "helper.mjs"), join(own.dir, "lib", "helper.mjs"));
		symlinkSync(join(other.dir, "src", "linked.ts"), join(own.dir, "src", "linked.ts"));
		const reading = { ...own, files: [...own.files, "src/linked.ts"] };
		expect(
			check([other, reading], budget)
				.filter((v) => v.rule.startsWith("G34"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@u/own/src/contract.ts ./%2e%2e/%2e%2e/@u_other/src/helper.mjs",
			"@u/own/src/contract.ts ../lib/helper.mjs?v=1",
			"@u/own/src/linked.ts ./helper.mjs",
		]);
	});

	it("G34 reads a require too, and leaves a resolve, which names a file and takes no dependency", () => {
		const other = pkg("@q/other", { "src/contract.ts": "export const o = 1;\n" }, {});
		const out = pkg(
			"@q/out",
			{
				"src/contract.ts": [
					'export const r = require("../../@q_other/src/contract.ts");',
					'export const at = import.meta.resolve("../../@q_other/src/contract.ts");',
					"",
				].join("\n"),
			},
			{},
		);
		expect(
			check([other, out], budget)
				.filter((v) => v.rule.startsWith("G34"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@q/out/src/contract.ts ../../@q_other/src/contract.ts"]);
	});

	it("G14 keeps a check package that others build on free of the product's modules", () => {
		// Without exports, so no contract surface is built: these rules read only kinds and dependencies.
		const deps = (...names: string[]) => ({
			dependencies: Object.fromEntries(names.map((n) => [n, "workspace:*"])),
		});
		const feature = pkg("@t/feature", { "src/contract.ts": "export const n = 1;\n" }, {});
		const base = pkg(
			"@t/base",
			{ "src/contract.ts": "export const n = 1;\n" },
			deps("@t/feature"),
			"verification",
		);
		const area = pkg(
			"@t/area",
			{ "src/contract.ts": "export const n = 1;\n" },
			deps("@t/base", "@t/feature"),
			"verification",
		);
		expect(
			check([feature, base, area], budget).map(
				(v) => `${v.rule.split(" ")[0]} ${v.where} ${v.detail}`,
			),
		).toEqual(["G14 @t/base @t/feature"]);
		const alone = pkg(
			"@t/alone",
			{ "src/contract.ts": "export const n = 1;\n" },
			deps("@t/feature"),
			"verification",
		);
		expect(rules([feature, alone])).not.toContain("G14");
	});

	/** Packages for the kind rules: a capability, a feature on it, wiring over both, and tests reaching up. */
	const kinds = () => {
		const deps = (...names: string[]) => ({
			dependencies: Object.fromEntries(names.map((n) => [n, "workspace:*"])),
		});
		const capability = pkg(
			"@t/cap",
			{ "src/contract.ts": "export const n = 1;\n" },
			{},
			"capability",
		);
		const feature = pkg("@t/feat", { "src/contract.ts": "export const n = 1;\n" }, deps("@t/cap"));
		const wired = pkg(
			"@t/wired",
			{ "src/contract.ts": "export const n = 1;\n" },
			deps("@t/cap", "@t/feat"),
			"wiring",
		);
		const tested = pkg(
			"@t/tested",
			{ "src/contract.ts": "export const n = 1;\n" },
			{ devDependencies: { "@t/wired": "workspace:*" } },
		);
		const shipped = pkg(
			"@t/shipped",
			{ "src/contract.ts": "export const n = 1;\n" },
			deps("@t/wired"),
		);
		const testedUp = pkg(
			"@t/tested-up",
			{ "src/contract.ts": "export const n = 1;\n" },
			{ devDependencies: { "@t/tool": "workspace:*" } },
		);
		const tool = pkg("@t/tool", { "src/contract.ts": "export const n = 1;\n" }, {}, "verification");
		const standIn = pkg(
			"@t/stand-in",
			{
				"src/contract.ts": "export const n = 1;\n",
				"test/x.test.ts": 'import { m } from "@t/cap/testing";\nexport const k = m;\n',
			},
			{ devDependencies: { "@t/cap": "workspace:*" } },
		);
		const reaching = pkg(
			"@t/reaching",
			{
				"src/contract.ts": "export const n = 1;\n",
				"test/x.test.ts": 'import { m } from "@t/cap";\nexport const k = m;\n',
			},
			{ devDependencies: { "@t/cap": "workspace:*" } },
		);
		return { capability, feature, wired, tested, shipped, testedUp, tool, standIn, reaching };
	};

	it("G16 refuses a feature depending on a capability, save its tests using the capability's stand-in", () => {
		const { capability, feature, wired, standIn, reaching } = kinds();
		expect(
			check([capability, feature, wired], budget).map(
				(v) => `${v.rule.split(" ")[0]} ${v.where} ${v.detail}`,
			),
		).toEqual(["G16 @t/feat @t/cap"]);
		const g16 = (packages: Pkg[]) =>
			check(packages, budget)
				.filter((v) => v.rule.startsWith("G16"))
				.map((v) => v.where);
		expect(g16([capability, standIn])).toEqual([]);
		expect(g16([capability, reaching])).toEqual(["@t/reaching"]);
	});

	it("G16 refuses a feature depending on what declares forWiring, as on a capability, save its tests using the stand-in", () => {
		const files = {
			"src/contract.ts": "export const s = 1;\n",
			"src/testing.ts": "export const t = 1;\n",
		};
		const exports = { ".": "./src/contract.ts", "./testing": "./src/testing.ts" };
		const storage = pkg("@w/store", files, { exports, forWiring: true }, "foundation");
		const on = (name: string, kind: string, file: string, text: string, deps: object) =>
			pkg(name, { [file]: text }, { exports: { ".": "./src/contract.ts" }, ...deps }, kind);
		const runtime = on(
			"@w/feat",
			"feature",
			"src/contract.ts",
			`import { s } from "@w/store";\nexport const f = s;\n`,
			{ dependencies: { "@w/store": "*" } },
		);
		const standIn = on(
			"@w/tested",
			"feature",
			"test/a.test.ts",
			`import { t } from "@w/store/testing";\nexport const x = t;\n`,
			{ devDependencies: { "@w/store": "*" } },
		);
		const whole = on(
			"@w/whole",
			"feature",
			"test/a.test.ts",
			`import { s } from "@w/store";\nexport const x = s;\n`,
			{ devDependencies: { "@w/store": "*" } },
		);
		const wiring = on(
			"@w/feat-store",
			"wiring",
			"src/module.ts",
			`import { s } from "@w/store";\nexport const w = s;\n`,
			{ dependencies: { "@w/store": "*" } },
		);
		const loose = pkg("@w/loose", files, { exports, forWiring: "yes" }, "foundation");
		expect(
			check([storage, runtime, standIn, whole, wiring, loose], budget)
				.filter((v) => v.rule.startsWith("G16"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@w/feat @w/store", "@w/whole @w/store", "@w/loose forWiring is true only"]);
	});

	it("G10 lets only tests reach up to a wiring module, and no other higher kind", () => {
		const { capability, feature, wired, tested, shipped, testedUp, tool } = kinds();
		const g10 = (packages: Pkg[]) =>
			check(packages, budget)
				.filter((v) => v.rule.startsWith("G10"))
				.map((v) => v.where);
		expect(g10([capability, feature, wired, tested])).toEqual([]);
		expect(g10([capability, feature, wired, shipped])).toEqual(["@t/shipped"]);
		expect(g10([tool, testedUp])).toEqual(["@t/tested-up"]);
	});

	it("reads a kind only from the manifest, never from the card", () => {
		const old = pkg("@t/old", { "src/contract.ts": "export const n = 1;\n" });
		const carded = {
			...old,
			manifest: { exports: { ".": "./src/contract.ts" } },
			card: "# old\n\nKind: verification\n",
		};
		expect(rules([carded])).toContain("G10");
	});

	it("G22 refuses a feature that declares storeWiring with no wiring naming it in wires", () => {
		// Without exports, so no contract surface is built: this rule reads only manifests.
		const files = { "src/contract.ts": "export const n = 1;\n" };
		const bare = pkg("@t/bare", files, { storeWiring: true });
		const wired = pkg("@t/wired", files, { storeWiring: true });
		const wiring = pkg("@t/wired-store", files, { wires: "@t/wired" }, "wiring");
		const plain = pkg("@t/unwired", files, { storeWiring: false });
		// A package of another kind naming a feature in wires neither wires it nor passes.
		const faked = pkg("@t/faked", files, { storeWiring: true });
		const fake = pkg("@t/fake-store", files, { wires: "@t/faked" });
		expect(
			check([bare, wired, wiring, plain, faked, fake], budget)
				.filter((v) => v.rule.startsWith("G22"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@t/bare no package wires it",
			"@t/faked no package wires it",
			"@t/fake-store kind feature",
		]);
	});

	it("G25 holds each adapter to one axis, each axis to one default, and optIn to features", () => {
		// Without exports, so no contract surface is built: this rule reads only manifests.
		const files = { "src/contract.ts": "export const n = 1;\n" };
		const adapter = (name: string, manifest: Record<string, unknown>) =>
			pkg(name, files, manifest as Pkg["manifest"], "adapter");
		const packages = [
			pkg("@t/store", files, {}, "foundation"),
			pkg("@t/audit", files, {}, "foundation"),
			pkg("@t/mail", files, {}, "foundation"),
			adapter("@t/redis", { replaces: "@t/store" }),
			adapter("@t/http-audit", { adapts: "@t/audit", default: true }),
			adapter("@t/stdout-audit", { adapts: "@t/audit" }),
			adapter("@t/both", { replaces: "@t/store", adapts: "@t/audit" }),
			adapter("@t/neither", {}),
			adapter("@t/elsewhere", { adapts: "@t/nowhere" }),
			adapter("@t/smtp", { replaces: "@t/mail" }),
			adapter("@t/file-mail", { replaces: "@t/mail" }),
			adapter("@t/loud", { replaces: "@t/mail", default: "yes" }),
			pkg(
				"@t/wording",
				{ "src/module.ts": "export const t = (m) => m.contribute(mailTemplates);\n" },
				{ adapts: "@t/mail", joins: ["@t/mail"] },
				"adapter",
			),
			// Only a wording adapter is held to it: another may still join its owner.
			adapter("@t/bridged", { adapts: "@t/audit", joins: ["@t/audit"] }),
			pkg("@t/log", files, {}, "foundation"),
			adapter("@t/log-a", { adapts: "@t/log", default: true }),
			adapter("@t/log-b", { adapts: "@t/log", default: true }),
			pkg("@t/extra", files, { optIn: true }),
			pkg("@t/odd", files, { optIn: false }),
			pkg("@t/base", files, { optIn: true }, "foundation"),
			pkg("@t/feature-default", files, { default: true }),
		];
		expect(
			check(packages, budget)
				.filter((v) => v.rule.startsWith("G25"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@t/both declares replaces and adapts",
			"@t/neither declares neither replaces nor adapts",
			"@t/elsewhere names no workspace package: @t/nowhere",
			"@t/loud default is not true",
			"@t/wording joins the owner it adapts",
			"@t/odd optIn is not true",
			"@t/base optIn on kind foundation",
			"@t/feature-default default on kind feature",
			"@t/mail no default among its 4 adapters",
			"@t/log 2 defaults among its adapters",
		]);
	});

	it("G24 refuses a wiring that keys no guarantee by the needs its feature declares", () => {
		// Without exports, so no contract surface is built: this rule reads the wiring's source alone.
		const needs = "export const fNeeds = { neverEvicted: true } as const;\n";
		const feature = pkg("@t/f", { "src/store.ts": needs }, { storeWiring: true });
		const keyed = pkg(
			"@t/f-store",
			{
				"src/module.ts": `import { type fNeeds } from "@t/f";\nexport const g: Record<keyof typeof fNeeds, string> = { neverEvicted: "no-eviction" };\n`,
			},
			{ wires: "@t/f" },
			"wiring",
		);
		const bare = pkg("@t/g", { "src/store.ts": "export const n = 1;\n" }, { storeWiring: true });
		const unkeyed = pkg(
			"@t/g-store",
			{
				// Each falls short: no keyof, a name from elsewhere, and a test file.
				"src/module.ts": `import { type gNeeds } from "@t/g";\nimport { type other } from "@t/f";\nexport const a: typeof gNeeds = { n: 1 };\nexport const b: Record<keyof typeof other, 1> = {};\n`,
				"src/module.test.ts": `import { type gNeeds } from "@t/g";\nexport const c: Record<keyof typeof gNeeds, 1> = {};\n`,
			},
			{ wires: "@t/g" },
			"wiring",
		);
		const named = pkg("@t/h", { "src/store.ts": needs }, { storeWiring: true });
		const byDefault = pkg(
			"@t/h-store",
			{
				// The default taken by name keys as any name does.
				"src/module.ts": `import { default as hNeeds } from "@t/h";\nexport const g: Record<keyof typeof hNeeds, string> = {};\n`,
			},
			{ wires: "@t/h" },
			"wiring",
		);
		const ambientFeature = pkg("@t/k", { "src/store.ts": needs }, { storeWiring: true });
		const ambient = pkg(
			"@t/k-store",
			{
				// An import inside a declared module keys nothing the wiring runs.
				"src/module.ts": `declare module "other" {\n\timport { kNeeds } from "@t/k";\n\ttype A = keyof typeof kNeeds;\n}\nexport {};\n`,
			},
			{ wires: "@t/k" },
			"wiring",
		);
		expect(
			check([feature, keyed, bare, unkeyed, named, byDefault, ambientFeature, ambient], budget)
				.filter((v) => v.rule.startsWith("G24"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@t/g @t/g-store keys no guarantee by them",
			"@t/k @t/k-store keys no guarantee by them",
		]);
	});

	it("G28 refuses a contract or an extension point imported from a dependency named as helpers", () => {
		const mail = pkg("@t/mail", {
			"src/contract.ts": `import { contract, extensionPoint } from "@t/kernel";\nexport { senders } from "./points.ts";\nexport const isAddress = (s: string) => s.includes("@");\nexport const mailer = contract<Mailer>("mail");\nexport interface Mailer { send(): void }\n`,
			"src/points.ts": `import { extensionPoint } from "@t/kernel";\nexport const senders = extensionPoint<string>("mail.senders", { multiplicity: "many" });\n`,
		});
		const users = pkg(
			"@t/users",
			{
				"src/contract.ts": `import { isAddress, type Mailer } from "@t/mail";\nexport const ok = (m: Mailer) => isAddress(String(m));\n`,
				"src/module.ts": `import { mailer as m, senders } from "@t/mail";\nimport * as all from "@t/mail";\nexport const used = [m, senders, all];\n`,
				"src/module.test.ts": `import { mailer } from "@t/mail";\nexport const t = mailer;\n`,
				// An import inside a declared module's types takes no value at run time.
				"src/types.ts": `declare module "@t/other" {\n\timport { mailer } from "@t/mail";\n}\nexport {};\n`,
			},
			{
				exports: { ".": "./src/contract.ts" },
				dependencies: { "@t/mail": "*" },
				helpers: ["@t/mail"],
			},
		);
		// A dependency not named as helpers lends its contracts as ever.
		const session = pkg(
			"@t/session",
			{ "src/contract.ts": `import { mailer } from "@t/mail";\nexport const s = mailer;\n` },
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/mail": "*" } },
		);
		expect(
			check([mail, users, session], budget)
				.filter((v) => v.rule.startsWith("G28"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@t/users/src/module.ts mailer (@t/mail)",
			"@t/users/src/module.ts senders (@t/mail)",
			"@t/users/src/module.ts * (@t/mail)",
		]);
	});

	it("G29 refuses a test composing a feature bridge's modules and a module contributing to it, without the bridge", () => {
		const session = pkg(
			"@b/session",
			{
				"src/contract.ts": "export const session = 1;\n",
				"src/testing.ts": "export const sessionStandIn = 1;\nexport const sessionRecords = 2;\n",
			},
			{ exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" } },
		);
		const reqs = pkg(
			"@b/reqs",
			{
				"src/contract.ts": `import { extensionPoint } from "@b/kernel";\nexport const entryRequirements = extensionPoint("r");\nexport const helper = 1;\n`,
				"src/module.ts": "export default 1;\n",
			},
			{
				exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
				joins: ["@b/session"],
			},
		);
		const lifecycle = pkg(
			"@b/lifecycle",
			{ "src/module.ts": "export default 1;\n" },
			{ exports: { "./module": "./src/module.ts" }, replaces: "@b/session" },
			"adapter",
		);
		const entry = pkg(
			"@b/entry",
			{
				"src/module.ts": `import { entryRequirements } from "@b/reqs";\nexport default entryRequirements;\n`,
				// Its own test composes it by path, beside a stand-in for the bridge's module.
				"test/own.test.ts": `import { sessionStandIn } from "@b/session/testing";\nimport entry from "../src/module.ts";\nexport const m = [entry, sessionStandIn];\n`,
				// An import type of its module, as resolving its path, composes nothing.
				"test/typed.test.ts": `import { sessionStandIn } from "@b/session/testing";\nexport type M = typeof import("../src/module.ts");\nexport const m = [sessionStandIn];\n`,
				// Resolving its module's path composes nothing.
				"test/resolved.test.ts": `import { sessionStandIn } from "@b/session/testing";\nexport const at = import.meta.resolve("../src/module.ts");\nexport const m = [sessionStandIn];\n`,
			},
			{ exports: { "./module": "./src/module.ts" }, dependencies: { "@b/reqs": "*" } },
		);
		// A foundation bridge collects what decides no answer a test reads, such as counts.
		const meter = pkg(
			"@b/meter",
			{
				"src/contract.ts": `import { extensionPoint } from "@b/kernel";\nexport const meters = extensionPoint("m");\n`,
				"src/module.ts": "export default 1;\n",
			},
			{
				exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
				joins: ["@b/session"],
			},
			"foundation",
		);
		const counted = pkg(
			"@b/counted",
			{ "src/module.ts": `import { meters } from "@b/meter";\nexport default meters;\n` },
			{ exports: { "./module": "./src/module.ts" }, dependencies: { "@b/meter": "*" } },
		);
		// Takes a helper from the bridge, never its point: it contributes nothing.
		const plain = pkg(
			"@b/plain",
			{ "src/module.ts": `import { helper } from "@b/reqs";\nexport default helper;\n` },
			{ exports: { "./module": "./src/module.ts" }, dependencies: { "@b/reqs": "*" } },
		);
		const app = pkg("@b/app", {
			"test/missing.test.ts": `import { sessionStandIn } from "@b/session/testing";\nimport entry from "@b/entry/module";\nexport const m = [entry, sessionStandIn];\n`,
			"test/adapter.test.ts": `import entry from "@b/entry/module";\nimport lifecycle from "@b/lifecycle/module";\nexport const m = [entry, lifecycle];\n`,
			"test/composed.test.ts": `import { sessionStandIn } from "@b/session/testing";\nimport entry from "@b/entry/module";\nimport reqs from "@b/reqs/module";\nexport const m = [entry, reqs, sessionStandIn];\n`,
			"test/no-session.test.ts": `import entry from "@b/entry/module";\nexport const m = [entry];\n`,
			"test/not-a-stand-in.test.ts": `import { sessionRecords } from "@b/session/testing";\nimport entry from "@b/entry/module";\nexport const m = [entry, sessionRecords];\n`,
			"test/plain.test.ts": `import { sessionStandIn } from "@b/session/testing";\nimport plain from "@b/plain/module";\nexport const m = [plain, sessionStandIn];\n`,
			"test/counted.test.ts": `import { sessionStandIn } from "@b/session/testing";\nimport counted from "@b/counted/module";\nexport const m = [counted, sessionStandIn];\n`,
		});
		expect(
			check([session, reqs, meter, counted, lifecycle, entry, plain, app], budget)
				.filter((v) => v.rule.startsWith("G29"))
				.map((v) => `${v.where} ${v.detail}`)
				.sort(),
		).toEqual([
			"@b/app/test/adapter.test.ts @b/reqs (@b/entry)",
			"@b/app/test/missing.test.ts @b/reqs (@b/entry)",
			"@b/entry/test/own.test.ts @b/reqs (@b/entry)",
		]);
	});

	it("G31 refuses an import of a contract its owner's manifest declares takenBy, from a package it does not name", () => {
		const owner = pkg(
			"@g31/keys",
			{
				"src/contract.ts": [
					`import { contract } from "@g31/kernel";`,
					`export const signing = contract<object>("keys.signing", { takenBy: ["taker"] });`,
					`export const open = contract<object>("keys.open");`,
				].join("\n"),
			},
			{ exports: { ".": "./src/contract.ts" }, takenBy: { signing: ["@g31/taker"] } },
		);
		const user = (name: string, files: Record<string, string>) =>
			pkg(name, files, {
				exports: { ".": "./src/contract.ts" },
				dependencies: { "@g31/keys": "*" },
			});
		const taker = user("@g31/taker", {
			"src/contract.ts": `import { signing } from "@g31/keys";\nexport const s = signing;\n`,
			"src/module.ts": `export default defineModule({ name: "taker" }, () => []);\n`,
		});
		const other = user("@g31/other", {
			"src/contract.ts": `import { open } from "@g31/keys";\nexport const o = open;\n`,
			"src/named.ts": `import { signing } from "@g31/keys";\nexport const s = signing;\n`,
			"src/alias.ts": `import { signing as s } from "@g31/keys";\nexport const t = s;\n`,
			"src/whole.ts": `import * as k from "@g31/keys";\nexport const t = k;\n`,
			"src/again.ts": `export { signing } from "@g31/keys";\n`,
			"src/every.ts": `export * from "@g31/keys";\n`,
			"src/typed.ts": `import type { signing } from "@g31/keys";\nexport type T = typeof signing;\n`,
			"test/other.test.ts": `import { signing } from "@g31/keys";\nexport const s = signing;\n`,
		});
		expect(
			check([owner, taker, other], budget)
				.filter((v) => v.rule.startsWith("G31"))
				.map((v) => `${v.where} ${v.detail}`)
				.sort(),
		).toEqual([
			"@g31/other/src/again.ts signing of @g31/keys",
			"@g31/other/src/alias.ts signing of @g31/keys",
			"@g31/other/src/every.ts signing of @g31/keys",
			"@g31/other/src/named.ts signing of @g31/keys",
			"@g31/other/src/whole.ts signing of @g31/keys",
		]);
	});

	it("G31 refuses a takenBy declaration its contract's own takenBy does not match, or that names nothing known", () => {
		const taker = pkg("@g31b/taker", {
			"src/contract.ts": "export const x = 1;\n",
			"src/module.ts": `export default defineModule({ name: "taker" }, () => []);\n`,
		});
		const bare = pkg("@g31b/bare", { "src/contract.ts": "export const x = 1;\n" });
		const owner = pkg(
			"@g31b/keys",
			{
				"src/contract.ts": [
					`export const same = contract<object>("k.same", { takenBy: ["taker"] });`,
					`export const apart = contract<object>("k.apart", { takenBy: ["someone"] });`,
					`export const unbound = contract<object>("k.unbound");`,
					`export const undeclared = contract<object>("k.undeclared", { takenBy: ["taker"] });`,
				].join("\n"),
			},
			{
				exports: { ".": "./src/contract.ts" },
				takenBy: {
					same: ["@g31b/taker"],
					apart: ["@g31b/taker"],
					unbound: ["@g31b/taker"],
					missing: ["@g31b/taker"],
					strange: ["@g31b/nobody"],
					moduleless: ["@g31b/bare"],
				},
			},
		);
		expect(
			check([owner, taker, bare], budget)
				.filter((v) => v.rule.startsWith("G31"))
				.map((v) => `${v.where} ${v.detail}`)
				.sort(),
		).toEqual([
			"@g31b/keys apart: takenBy in code names someone, the manifest taker",
			"@g31b/keys missing: no contract of that name declares takenBy",
			"@g31b/keys moduleless: @g31b/bare has no module to take it",
			"@g31b/keys strange: @g31b/nobody is no workspace package",
			"@g31b/keys unbound: no contract of that name declares takenBy",
			"@g31b/keys undeclared: takenBy in code, but not in the manifest",
		]);
	});

	it("G30 refuses an audit event recorded on the audit contract itself, outside the package and its tests", () => {
		const contract = [
			"export interface AuditRecord { readonly kind: string }",
			"export interface Audit { record(event: AuditRecord): void; lost(): number }",
			"export const auditEvents = <E>(events: E) => events;",
			'export function declaredAudit<E>(recorder: Pick<Audit, "record">, events: E) {',
			"\treturn { record(kind: keyof E & string): void { recorder.record({ kind }); } };",
			"}",
		].join("\n");
		const audit = pkg("@c/audit", {
			"src/contract.ts": `${contract}\n`,
			// The package itself hands events on: its own calls are not counted.
			"src/hub.ts": `import type { Audit } from "./contract.ts";\nexport const on = (a: Audit) => a.record({ kind: "x" });\n`,
		});
		const feature = pkg(
			"@c/feature",
			{
				"src/audit-events.ts": `import { auditEvents } from "@c/audit";\nexport default auditEvents({ "f.done": {} });\n`,
				"src/module.ts": [
					`import { type Audit, declaredAudit } from "@c/audit";`,
					`import events from "./audit-events.ts";`,
					`const records = { record: (n: number) => n };`,
					`export const raw = (audit: Audit) => audit.record({ kind: "f.done" });`,
					`export const picked = (p: { audit: Pick<Audit, "record"> }) => p.audit.record({ kind: "f.done" });`,
					`export const declared = (audit: Audit) => declaredAudit(audit, events).record("f.done");`,
					`export const other = () => records.record(1);`,
					`export const lost = (audit: Audit) => (audit as any).record({ kind: "f.done" });`,
				].join("\n"),
				"test/module.test.ts": `import type { Audit } from "@c/audit";\nexport const t = (a: Audit) => a.record({ kind: "f.done" });\n`,
			},
			{
				exports: { ".": "./src/module.ts", "./audit-events": "./src/audit-events.ts" },
				dependencies: { "@c/audit": "*" },
			},
		);
		expect(
			check([audit, feature], budget)
				.filter((v) => v.rule.startsWith("G30"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual([
			"@c/feature/src/module.ts:4 audit.record",
			"@c/feature/src/module.ts:5 p.audit.record",
		]);
	});

	describe("G32 internal by the packages declaring it", () => {
		const urls = pkg("@c/urls", {
			"src/contract.ts": [
				"declare const brand: unique symbol;",
				'export type ConfiguredUrl = string & { readonly [brand]: "ConfiguredUrl" };',
				"export const read = (text: string) => text as ConfiguredUrl;",
			].join("\n"),
		});
		const narrower = [
			'import type { ConfiguredUrl } from "@c/urls";',
			"export interface Narrower { readonly hosts?: readonly string[]; readonly internal?: ConfiguredUrl }",
		].join("\n");
		const sending = [
			'import type { Narrower } from "./narrower.ts";',
			"export type { Narrower };",
			"export const send = (url: string, n?: Narrower) => (n?.internal === undefined ? url : n.internal);",
		];
		/** The owner, stating what it holds to declaration, its contract writing `own` beside. */
		const owner = (
			owned: unknown = { type: "Narrower", property: "internal" },
			own: string[] = [],
		) =>
			pkg(
				"@c/policy",
				{
					// The interface re-exported from a file of its own, as a contract may.
					"src/narrower.ts": narrower,
					"src/contract.ts": [...sending, ...own].join("\n"),
				},
				{
					exports: { ".": "./src/contract.ts" },
					dependencies: { "@c/urls": "*" },
					narrowerOwner: owned,
				},
				"foundation",
			);
		/** A package writing `internal` in each way the rule counts, and in ways it does not. */
		const writer = (name: string, declared?: unknown, card = `# ${name}\n`) => ({
			...pkg(
				name,
				{
					"src/module.ts": [
						'import { type ConfiguredUrl, read } from "@c/urls";',
						'import { send } from "@c/policy";',
						"interface Source { readonly url: string; readonly internal?: ConfiguredUrl }",
						'const url = read("http://collector:8080/");',
						"export const direct = () => send(url, { internal: url });",
						"const own = { internal: url };",
						"export const kept = () => send(url, own);",
						"const internal: ConfiguredUrl | undefined = url;",
						"export const short = () => send(url, { hosts: [], ...(internal === undefined ? {} : { internal }) });",
						"export const source: Source = { url, internal: url };",
						'export const computed = () => send(url, { ["internal"]: url });',
						// Not counted: another field of that name, a binding, a value of no type.
						"export const flag = { internal: true };",
						"export const read2 = (s: Source) => { const { internal: i } = s; return i; };",
						"export const lost = () => send(url, { internal: (url as any) });",
						'const key = "internal";',
						"export const keyed = () => send(url, { [key]: url });",
						"export const got = { get internal() { return url; } };",
						// A generic factory's literal, whose type parameter the URL type could be bound to: counted.
						"const make = <T>(v: T) => ({ internal: v });",
						// Not counted: an object only spread on.
						"export const made = () => send(url, make(url));",
						"export const spread = () => send(url, { ...own });",
						// A key whose type "internal" fits: a type parameter's constraint, a mapped string.
						'export const generic = <K extends "internal">(key: K) => send(url, { [key]: url });',
						"export const lower = (key: Lowercase<string>) => send(url, { [key]: url });",
						// A key whose type holds a type parameter anywhere: counted, whatever it is bound to.
						'export const joined = <K extends "internal">(key: K | "other") => send(url, { [key]: url });',
						'export const narrowed = <K>(key: K) => (typeof key === "string" ? send(url, { [key]: url }) : url);',
						// Not counted: a key no "internal" fits.
						// biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture's source holds a template type
						"export const unrelated = (key: `unrelated-${string}`) => ({ [key]: url });",
						// Not counted: a generic factory's literal whose type parameter no URL fits.
						"export const counted = <T extends number>(v: T) => ({ internal: v });",
						// Not counted: a key whose type parameter's constraint admits no "internal".
						"interface Shape { readonly a?: string; readonly b?: boolean }",
						"export const picked = <K extends keyof Shape>(key: K, s: Shape) => ({ [key]: s[key] as Shape[K] });",
					].join("\n"),
					"test/module.test.ts":
						'import { read } from "@c/urls";\nexport const t = { internal: read("http://x/") };\n',
				},
				{
					exports: { ".": "./src/module.ts" },
					dependencies: { "@c/urls": "*", "@c/policy": "*" },
					...(declared === undefined ? {} : { narrower: declared }),
				},
			),
			card,
		});
		/** A card stating the declaration, as G26's do theirs. */
		const stating = (name: string) =>
			`# ${name}\n\n- Reaches private addresses (\`narrower\`: \`internal\`).\n`;
		/** A writer declaring `internal`, its card stating it. */
		const declaring = (name: string) => writer(name, "internal", stating(name));
		const found = (packages: Pkg[]) =>
			check(packages, budget)
				.filter((v) => v.rule.startsWith("G32"))
				.map((v) => `${v.where} ${v.detail}`);

		it("counts the owner too: it states internal, and writes none", () => {
			const leak = [
				'import { read } from "@c/urls";',
				'export const leak = () => send("x", { internal: read("http://x/") });',
			];
			expect(found([urls, owner(undefined, leak), declaring("@c/declared")])).toEqual([
				"@c/policy/src/contract.ts:5 internal",
			]);
		});

		it("refuses an owner whose contract exports no type of that name with the property", () => {
			const hidden = pkg(
				"@c/policy",
				{
					"src/contract.ts":
						'import type { ConfiguredUrl } from "@c/urls";\ninterface Narrower { readonly internal?: ConfiguredUrl }\nexport const send = (n?: Narrower) => n;\n',
				},
				{
					exports: { ".": "./src/contract.ts" },
					dependencies: { "@c/urls": "*" },
					narrowerOwner: { type: "Narrower", property: "internal" },
				},
				"foundation",
			);
			expect(found([urls, hidden])).toEqual([
				"@c/policy narrowerOwner, but it exports no Narrower with internal",
			]);
		});

		it("passes a package that declares internal in its manifest and states it on its card", () => {
			expect(found([urls, owner(), declaring("@c/declared")])).toEqual([]);
		});

		it("refuses each internal a package not declaring it writes, and counts no other field, binding or test", () => {
			expect(found([urls, owner(), declaring("@c/declared"), writer("@c/other")])).toEqual([
				"@c/other/src/module.ts:5 internal",
				"@c/other/src/module.ts:6 internal",
				"@c/other/src/module.ts:9 internal",
				"@c/other/src/module.ts:10 internal",
				"@c/other/src/module.ts:11 internal",
				"@c/other/src/module.ts:16 internal",
				"@c/other/src/module.ts:17 internal",
				"@c/other/src/module.ts:18 internal",
				"@c/other/src/module.ts:21 internal",
				"@c/other/src/module.ts:22 internal",
				"@c/other/src/module.ts:23 internal",
				"@c/other/src/module.ts:24 internal",
			]);
		});

		it("refuses a declaration that writes none, a value other than the property itself, and a card not stating it", () => {
			/** A package that writes none, declaring as given, its card stating `internal`. */
			const silent = (name: string, declared: unknown) => ({
				...pkg(
					name,
					{ "src/module.ts": "export const x = 1;\n" },
					{ exports: { ".": "./src/module.ts" }, narrower: declared },
				),
				card: stating(name),
			});
			expect(
				found([
					urls,
					owner(),
					silent("@c/silent", "internal"),
					silent("@c/listing", ["internal"]),
					silent("@c/other-word", "private"),
					silent("@c/flagged", true),
					silent("@c/cased", "Internal"),
					writer("@c/unstated", "internal"),
				]),
			).toEqual([
				'@c/listing narrower is ["internal"], not exactly "internal"',
				'@c/other-word narrower is "private", not exactly "internal"',
				'@c/flagged narrower is true, not exactly "internal"',
				'@c/cased narrower is "Internal", not exactly "internal"',
				"@c/unstated card states `narrower`: `internal`",
				"@c/silent narrower: internal, but it writes none",
			]);
		});

		it("refuses a declaration with no owner, two owners, and an owner's statement of no type or property", () => {
			expect(found([urls, declaring("@c/declared")])).toEqual([
				"@c/declared narrower: internal, but no package owns it",
			]);
			const second = { ...owner(), name: "@c/second" };
			expect(found([urls, owner(), second, declaring("@c/declared")])).toEqual([
				"@c/policy narrowerOwner: @c/second states it owns it too",
			]);
			expect(found([urls, owner({ type: "Narrower" })])).toEqual([
				"@c/policy narrowerOwner names no type and property it holds to declaration",
			]);
		});

		it("counts a generic helper's write at the helper, wherever it is called from", () => {
			const helper = pkg(
				"@c/helper",
				{
					"src/module.ts": [
						"export const make = <T>(v: T) => ({ internal: v });",
						"export const bounded = <T extends string>(v: T) => ({ internal: v });",
						"export const numbered = <T extends number>(v: T) => ({ internal: v });",
					].join("\n"),
				},
				{ exports: { ".": "./src/module.ts" } },
			);
			const calling = pkg(
				"@c/calling",
				{
					"src/module.ts": [
						'import { read } from "@c/urls";',
						'import { send } from "@c/policy";',
						'import { make } from "@c/helper";',
						'export const reach = () => send("x", make(read("http://x/")));',
					].join("\n"),
				},
				{
					exports: { ".": "./src/module.ts" },
					dependencies: { "@c/urls": "*", "@c/policy": "*", "@c/helper": "*" },
				},
			);
			expect(found([urls, owner(), helper, calling])).toEqual([
				"@c/helper/src/module.ts:1 internal",
				"@c/helper/src/module.ts:2 internal",
			]);
		});

		it("counts an assignment and a class field of the owned property under the same type rule", () => {
			const assigning = pkg(
				"@c/assigning",
				{
					"src/module.ts": [
						'import { type ConfiguredUrl, read } from "@c/urls";',
						'import type { Narrower } from "@c/policy";',
						'const url = read("http://x/");',
						"export const dotted = (n: { internal?: ConfiguredUrl }) => { n.internal = url; };",
						'export const indexed = (n: { internal?: ConfiguredUrl }) => { n["internal"] = url; };',
						"export const kept = (n: { internal?: ConfiguredUrl }) => { n.internal ??= url; };",
						"export class Field { internal = url; }",
						"export class Parameter { constructor(readonly internal: ConfiguredUrl) {} }",
						"export class Typed implements Narrower { readonly internal?: ConfiguredUrl; }",
						// Not counted: another type, a read, a comparison, another name.
						"export const flag = (n: { internal?: boolean }) => { n.internal = true; };",
						"export const read2 = (n: Narrower) => n.internal;",
						"export const same = (n: Narrower) => n.internal === url;",
						"export const other = (n: { hosts?: ConfiguredUrl }) => { n.hosts = url; };",
					].join("\n"),
				},
				{ exports: { ".": "./src/module.ts" }, dependencies: { "@c/urls": "*", "@c/policy": "*" } },
			);
			expect(found([urls, owner(), assigning])).toEqual([
				"@c/assigning/src/module.ts:4 internal",
				"@c/assigning/src/module.ts:5 internal",
				"@c/assigning/src/module.ts:6 internal",
				"@c/assigning/src/module.ts:7 internal",
				"@c/assigning/src/module.ts:8 internal",
			]);
		});

		it("counts a plain .mjs source by type, and a template of a source by the property's name", () => {
			const scripted = pkg(
				"@c/scripted",
				{
					"src/run.mjs": [
						'import { read } from "@c/urls";',
						'import { send } from "@c/policy";',
						'export const reach = () => send("x", { internal: read("http://x/") });',
						"export const flag = { internal: true };",
					].join("\n"),
					"templates/main.ts.template": [
						'import { send } from "{{policy}}";',
						"export const reach = (url) => send(url, { internal: url });",
						"export const flag = { internal: true };",
						"export const other = { hosts: [] };",
					].join("\n"),
					"templates/guard.ts.part": "const kept = { 'internal': {{url}} };\n",
					"templates/notes.md": "{ internal: url }\n",
				},
				{ exports: { ".": "./src/run.mjs" }, dependencies: { "@c/urls": "*", "@c/policy": "*" } },
			);
			expect(found([urls, owner(), scripted])).toEqual([
				"@c/scripted/src/run.mjs:3 internal",
				"@c/scripted/templates/main.ts.template:2 internal",
				"@c/scripted/templates/main.ts.template:3 internal",
				"@c/scripted/templates/guard.ts.part:1 internal",
			]);
		});

		it("refuses a workspace with fewer owners than its rules ask for, and asks none where they do not say", () => {
			const asking = { ...budget, declaredProperties: 1 };
			const under = (packages: Pkg[]) =>
				check(packages, asking)
					.filter((v) => v.rule.startsWith("G32"))
					.map((v) => `${v.where} ${v.detail}`);
			expect(under([urls])).toEqual([
				"workspace 1 package(s) must state what they hold to declaration, 0 do",
			]);
			expect(under([urls, owner(), declaring("@c/declared")])).toEqual([]);
			expect(found([urls])).toEqual([]);
		});

		it("refuses an owner naming a type its contract does not export, or a property its type lacks", () => {
			expect(found([urls, owner({ type: "Narowwer", property: "internal" })])).toEqual([
				"@c/policy narrowerOwner, but it exports no Narowwer with internal",
			]);
			expect(found([urls, owner({ type: "Narrower", property: "interal" })])).toEqual([
				"@c/policy narrowerOwner, but it exports no Narrower with interal",
			]);
		});

		it("reads an object in narrower as a writer's malformed declaration, never as an owner", () => {
			const mistaken = writer(
				"@c/mistaken",
				{ type: "Narrower", property: "internal" },
				stating("@c/mistaken"),
			);
			expect(found([urls, owner(), mistaken])).toEqual([
				'@c/mistaken narrower is {"type":"Narrower","property":"internal"}, not exactly "internal"',
				"@c/mistaken/src/module.ts:5 internal",
				"@c/mistaken/src/module.ts:6 internal",
				"@c/mistaken/src/module.ts:9 internal",
				"@c/mistaken/src/module.ts:10 internal",
				"@c/mistaken/src/module.ts:11 internal",
				"@c/mistaken/src/module.ts:16 internal",
				"@c/mistaken/src/module.ts:17 internal",
				"@c/mistaken/src/module.ts:18 internal",
				"@c/mistaken/src/module.ts:21 internal",
				"@c/mistaken/src/module.ts:22 internal",
				"@c/mistaken/src/module.ts:23 internal",
				"@c/mistaken/src/module.ts:24 internal",
			]);
		});

		it("reads the type and the property the owner states, never a name of guard's own", () => {
			const renamed = pkg(
				"@c/policy",
				{
					"src/contract.ts": [
						'import type { ConfiguredUrl } from "@c/urls";',
						"export interface Limits { readonly private?: ConfiguredUrl }",
						"export const send = (url: string, l?: Limits) => l?.private ?? url;",
					].join("\n"),
				},
				{
					exports: { ".": "./src/contract.ts" },
					dependencies: { "@c/urls": "*" },
					narrowerOwner: { type: "Limits", property: "private" },
				},
				"foundation",
			);
			const writing = (name: string, declared?: string) => ({
				...pkg(
					name,
					{
						"src/module.ts": [
							'import { read } from "@c/urls";',
							'import { send } from "@c/policy";',
							'export const reach = () => send("x", { private: read("http://x/") });',
							'export const named = () => send("x", { internal: read("http://x/") } as never);',
						].join("\n"),
					},
					{
						exports: { ".": "./src/module.ts" },
						dependencies: { "@c/urls": "*", "@c/policy": "*" },
						...(declared === undefined ? {} : { narrower: declared }),
					},
				),
				card: `# ${name}\n\n- (\`narrower\`: \`private\`).\n`,
			});
			expect(
				found([urls, renamed, writing("@c/declared", "private"), writing("@c/other")]),
			).toEqual(["@c/other/src/module.ts:3 private"]);
		});
	});
});
