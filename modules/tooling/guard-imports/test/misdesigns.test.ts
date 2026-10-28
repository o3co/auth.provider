import { describe, expect, it, vi } from "vitest";
import { importViolations } from "../src/contract.ts";
import type { Pkg } from "../src/workspace.ts";
import { budget, pkg } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

// Static-analysis specimens: packages written for the import rules to read, never composed. Each is a
// sound workspace but for one feature's misdesign, and the whole workspace's violations are checked.
const kernel = pkg(
	"@mis/kernel",
	{
		"src/contract.ts": [
			"export interface Contract<T> { readonly label: string; readonly _t?: T }",
			"export const contract = <T>(label: string): Contract<T> => ({ label });",
			"export const defineModule = (d: object, parts: (m: unknown) => unknown[]) => ({ d, parts });",
		].join("\n"),
	},
	{ exports: { ".": "./src/contract.ts" } },
	"foundation",
);
const store = pkg(
	"@mis/store",
	{
		"src/contract.ts":
			'import { contract } from "@mis/kernel";\nexport const store = contract<object>("store");\n',
	},
	{ exports: { ".": "./src/contract.ts" }, dependencies: { "@mis/kernel": "*" } },
	"capability",
);
/** A feature named `name`, providing its contract by `by`, importing `imports` and depending on `on`. */
const feature = (
	name: string,
	{ imports = "", by = "() => ({})", on = [] as readonly string[] } = {},
	kind = "feature",
) =>
	pkg(
		name,
		{
			"src/contract.ts": `import { contract } from "@mis/kernel";\nexport const offered = contract<object>("${name}");\n`,
			"src/module.ts": [
				'import { defineModule } from "@mis/kernel";',
				'import { offered } from "./contract.ts";',
				imports,
				`export default defineModule({ name: "${name}", takes: [] }, (m: any) => [m.provide(offered).by(${by})]);`,
			].join("\n"),
		},
		{
			exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
			dependencies: Object.fromEntries(["@mis/kernel", ...on].map((n) => [n, "*"])),
		},
		kind,
	);
const owner = feature("@mis/owner");
const adapter = pkg(
	"@mis/adapter",
	{
		"src/contract.ts":
			'import { contract } from "@mis/kernel";\nexport const adapted = contract<object>("adapted");\n',
	},
	{
		exports: { ".": "./src/contract.ts" },
		dependencies: { "@mis/kernel": "*", "@mis/owner": "*" },
		adapts: "@mis/owner",
	},
	"adapter",
);
const keys = pkg(
	"@mis/keys",
	{
		"src/contract.ts": [
			'import { contract } from "@mis/kernel";',
			'export const signing = contract<object>("keys.signing", { takenBy: ["@mis/signer"] });',
		].join("\n"),
	},
	{
		exports: { ".": "./src/contract.ts" },
		dependencies: { "@mis/kernel": "*" },
		takenBy: { signing: ["@mis/signer"] },
	},
	"foundation",
);
const signer = feature("@mis/signer", {
	imports: 'import { signing } from "@mis/keys";',
	by: "() => signing",
	on: ["@mis/keys"],
});
const sound: readonly Pkg[] = [kernel, store, owner, adapter, keys, signer];
/** The rules the whole workspace raises with `misdesigned` in it. */
const raised = (misdesigned: Pkg) =>
	[
		...new Set(importViolations([...sound, misdesigned], budget).map((v) => v.rule.split(" ")[0])),
	].sort();

describe("static-analysis specimens: misdesigns the import rules stop", () => {
	it("raises nothing for the sound workspace the specimens are put in", () => {
		expect(importViolations([...sound, feature("@mis/plain")], budget)).toEqual([]);
	});

	it("G16 stops a feature that takes a store directly", () => {
		const taking = feature("@mis/takes-store", {
			imports: 'import { store } from "@mis/store";',
			by: "() => store",
			on: ["@mis/store"],
		});
		expect(raised(taking)).toEqual(["G16"]);
	});

	it("G10 stops a feature that depends on an adapter", () => {
		const leaning = feature("@mis/on-adapter", {
			imports: 'import { adapted } from "@mis/adapter";',
			by: "() => adapted",
			on: ["@mis/adapter"],
		});
		expect(raised(leaning)).toEqual(["G10"]);
	});

	it("G3 stops a feature that composes another module itself", () => {
		const composing = feature("@mis/composes", {
			imports: 'import owner from "@mis/owner/module";',
			by: "() => owner",
			on: ["@mis/owner"],
		});
		expect(raised(composing)).toEqual(["G3"]);
	});

	it("G31 stops a feature that takes a contract its owner keeps for named takers", () => {
		const taking = feature("@mis/takes-signing", {
			imports: 'import { signing } from "@mis/keys";',
			by: "() => signing",
			on: ["@mis/keys"],
		});
		expect(raised(taking)).toEqual(["G31"]);
	});
});
