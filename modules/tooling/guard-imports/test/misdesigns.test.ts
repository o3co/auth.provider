import { describe, expect, it, vi } from "vitest";
import { importViolations } from "../src/contract.ts";
import type { Pkg } from "../src/workspace.ts";
import { budget, pkg } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

// Each case is one misdesign of a module whose shape is otherwise sound, and the one rule that stops
// it; docs/gates.md names these tests beside the gates no rule of the guard is.
const kernel = pkg(
	"@mis/kernel",
	{ "src/contract.ts": "export const contract = (name: string) => ({ name });\n" },
	{ exports: { ".": "./src/contract.ts" } },
	"foundation",
);
const store = pkg(
	"@mis/store",
	{ "src/contract.ts": "export const store = 1;\n" },
	{ exports: { ".": "./src/contract.ts" } },
	"capability",
);
const adapter = pkg(
	"@mis/adapter",
	{ "src/contract.ts": "export const adapted = 1;\n" },
	{ exports: { ".": "./src/contract.ts" } },
	"adapter",
);
const sibling = pkg(
	"@mis/sibling",
	{
		"src/contract.ts": "export const sibling = 1;\n",
		"src/module.ts": 'export default { name: "sibling" };\n',
	},
	{ exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" } },
);
const keys = pkg(
	"@mis/keys",
	{
		"src/contract.ts": [
			'import { contract } from "@mis/kernel";',
			'export const signing = contract("keys.signing");',
		].join("\n"),
	},
	{
		exports: { ".": "./src/contract.ts" },
		dependencies: { "@mis/kernel": "*" },
		takenBy: { signing: ["@mis/signer"] },
	},
	"foundation",
);
/** A feature whose module is `module`, depending on `on`. */
const feature = (name: string, module: string, on: readonly string[]) =>
	pkg(
		name,
		{ "src/contract.ts": "export const used = 1;\n", "src/module.ts": module },
		{
			exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
			dependencies: Object.fromEntries(on.map((n) => [n, "*"])),
		},
	);
/** The rules a feature's misdesign raises, among a workspace otherwise sound. */
const raised = (misdesigned: Pkg) =>
	[
		...new Set(
			importViolations([kernel, store, adapter, sibling, keys, misdesigned], budget)
				.filter((v) => v.where.startsWith(misdesigned.name))
				.map((v) => v.rule.split(" ")[0]),
		),
	].sort();

describe("misdesigns the import rules stop", () => {
	it("G16 stops a feature that keeps its data by taking the store itself, not through a store interface its wiring builds", () => {
		const keeping = feature(
			"@mis/own-store",
			'import { store } from "@mis/store";\nexport default store;\n',
			["@mis/store"],
		);
		expect(raised(keeping)).toEqual(["G16"]);
	});

	it("G10 stops a feature that leans on an adapter, below which it stands", () => {
		const leaning = feature(
			"@mis/on-adapter",
			'import { adapted } from "@mis/adapter";\nexport default adapted;\n',
			["@mis/adapter"],
		);
		expect(raised(leaning)).toEqual(["G10"]);
	});

	it("G3 stops a feature that composes another module itself, the assembly's to compose", () => {
		const composing = feature(
			"@mis/composes",
			'import sibling from "@mis/sibling/module";\nexport default sibling;\n',
			["@mis/sibling"],
		);
		expect(raised(composing)).toEqual(["G3"]);
	});

	it("G31 stops a feature taking a contract its owner keeps for named takers alone", () => {
		const taking = feature(
			"@mis/takes-signing",
			'import { signing } from "@mis/keys";\nexport default signing;\n',
			["@mis/keys"],
		);
		expect(raised(taking)).toEqual(["G31"]);
	});
});
