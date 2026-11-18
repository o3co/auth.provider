import { beforeAll, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { importViolations } from "../../contract.ts";
import { scopeOf } from "../../scope/scope.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const check = importViolations;

// The first syntax tree loads the parser, which under a full parallel run takes longer than a test may.
beforeAll(() => {
	check([pkg("@t/warm-taken", { "src/contract.ts": "export const n = 1;\n" })], budget);
}, 60_000);

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

it("G31 holds an entry its owner's manifest declares takenBy to the packages it names, by every edge, and refuses a taker handing it on", () => {
	const owner = pkg(
		"@g31e/store",
		{
			"src/contract.ts": "export type Writer = { readonly writer: true };\n",
			"src/writer.ts": "export const writer = Object.freeze({});\n",
		},
		{
			exports: { ".": "./src/contract.ts", "./writer": "./src/writer.ts" },
			takenBy: { "./writer": ["@g31e/taker", "@g31e/passer"], "./missing": ["@g31e/taker"] },
		},
	);
	const user = (name: string, files: Record<string, string>) =>
		pkg(name, files, {
			exports: { ".": "./src/contract.ts" },
			dependencies: { "@g31e/store": "*" },
		});
	const taker = user("@g31e/taker", {
		"src/contract.ts": `import { writer } from "@g31e/store/writer";\nexport const held = [writer];\n`,
	});
	const passer = user("@g31e/passer", {
		"src/contract.ts": `export { writer } from "@g31e/store/writer";\n`,
	});
	const other = user("@g31e/other", {
		"src/contract.ts": `import type { Writer } from "@g31e/store";\nexport type W = Writer;\n`,
		"src/named.ts": `import { writer } from "@g31e/store/writer";\nexport const w = writer;\n`,
		"src/again.ts": `export { writer } from "@g31e/store/writer";\n`,
		"src/later.ts": `export const w = () => import("@g31e/store/writer");\n`,
		"src/required.ts": `export const w = require("@g31e/store/writer");\n`,
		"src/typed.ts": `import type { writer } from "@g31e/store/writer";\nexport type T = typeof writer;\n`,
		"test/other.test.ts": `import { writer } from "@g31e/store/writer";\nexport const w = writer;\n`,
	});
	expect(
		check([owner, taker, passer, other], budget)
			.filter((v) => v.rule.startsWith("G31"))
			.map((v) => `${v.where} ${v.detail}`)
			.sort(),
	).toEqual([
		"@g31e/other/src/again.ts ./writer of @g31e/store",
		"@g31e/other/src/later.ts ./writer of @g31e/store",
		"@g31e/other/src/named.ts ./writer of @g31e/store",
		"@g31e/other/src/required.ts ./writer of @g31e/store",
		"@g31e/passer/src/contract.ts ./writer of @g31e/store: a taker does not hand it on",
		"@g31e/store ./missing: no entry of that name",
	]);
});

it("G31 keeps an entry only where its key is one plain segment, not standard, names its takers, is exported as one file, and exports values alone", () => {
	const files = {
		"src/contract.ts": "export type Token = { readonly token: true };\n",
		"src/ok.ts": "const token = Object.freeze({});\nexport { token };\nexport const other = 1;\n",
		"src/typed.ts": "export type T = 1;\nexport const token = Object.freeze({});\n",
		"src/shaped.ts": "export interface I {}\nexport const token = Object.freeze({});\n",
		"src/again.ts": 'export type { Token } from "./contract.ts";\n',
		"src/inline.ts": 'export { type Token } from "./contract.ts";\n',
		"src/star.ts": 'export * from "./ok.ts";\n',
		"src/spaced.ts": 'export * as shapes from "./ok.ts";\n',
	};
	const exports = Object.fromEntries([
		[".", "./src/contract.ts"],
		["./testing", "./src/ok.ts"],
		...["ok", "typed", "shaped", "again", "inline", "star", "spaced", "none", "Upper"].map((n) => [
			`./${n}`,
			`./src/${n === "none" || n === "Upper" ? "ok" : n}.ts`,
		]),
		["./odd", "./src/ok.ts"],
		["./split", { default: "./src/ok.ts" }],
	]);
	const taker = ["@g31k/taker"];
	const owner = pkg("@g31k/owner", files, {
		exports,
		takenBy: {
			"./ok": taker,
			".": taker,
			"./testing": taker,
			"./a/b": taker,
			"./Upper": taker,
			"./none": [],
			"./odd": [1],
			"./split": taker,
			"./missing": taker,
			"./typed": taker,
			"./shaped": taker,
			"./again": taker,
			"./inline": taker,
			"./star": taker,
			"./spaced": taker,
		},
	});
	const takerPkg = pkg(
		"@g31k/taker",
		{ "src/contract.ts": "export {};\n" },
		{
			exports: { ".": "./src/contract.ts" },
		},
	);
	// The scope's reading, from the manifest alone, nothing reported: what is kept, and why the rest is not.
	const said: string[] = [];
	const read = scopeOf([owner, takerPkg], budget, (rule) => said.push(rule)).takenEntries(owner);
	expect(read.kept).toEqual([
		"./ok",
		"./typed",
		"./shaped",
		"./again",
		"./inline",
		"./star",
		"./spaced",
	]);
	expect(read.notKept.map(({ key }) => key)).toEqual([
		".",
		"./testing",
		"./a/b",
		"./Upper",
		"./none",
		"./odd",
		"./split",
		"./missing",
	]);
	expect(said).toEqual([]);
	// The standard entries are the caller's to give.
	const given = { ...budget, standardEntries: [".", "./ok"] };
	const standard = scopeOf([owner, takerPkg], given, () => {}).takenEntries(owner);
	expect(standard.notKept.slice(0, 2)).toEqual([
		{ key: "./ok", why: "a reserved entry is kept for no taker" },
		{ key: ".", why: "a reserved entry is kept for no taker" },
	]);
	expect(standard.kept).toContain("./testing");
	// G31 reports each key not kept with the scope's reason, and refuses a kept entry exporting a type.
	const reported = check([owner, takerPkg], budget)
		.filter((v) => v.rule.startsWith("G31"))
		.map((v) => `${v.where} ${v.detail}`);
	expect(reported).toEqual(
		[
			".: a reserved entry is kept for no taker",
			"./testing: a reserved entry is kept for no taker",
			"./a/b: an entry kept is one plain segment, ./name",
			"./Upper: an entry kept is one plain segment, ./name",
			"./none: an entry kept names at least one taker",
			"./odd: takenBy names packages as a list of names",
			"./split: an entry kept is exported as one file",
			"./missing: no entry of that name",
			"./typed: an entry kept exports values alone, its types on `.`",
			"./shaped: an entry kept exports values alone, its types on `.`",
			"./again: an entry kept exports values alone, its types on `.`",
			"./inline: an entry kept exports values alone, its types on `.`",
			"./star: an entry kept exports values alone, its types on `.`",
			"./spaced: an entry kept exports values alone, its types on `.`",
		].map((why) => `@g31k/owner ${why}`),
	);
});

it("G31 counts no import by an adapter of the owner providing a kept contract, and every other one, a re-export of it too", () => {
	const owner = pkg(
		"@g31a/store",
		{
			"src/contract.ts": [
				`import { contract } from "@g31a/kernel";`,
				`export const upkeep = contract<object>("store.upkeep", { takenBy: [] });`,
			].join("\n"),
		},
		{ exports: { ".": "./src/contract.ts" }, takenBy: { upkeep: [] } },
	);
	const other = pkg("@g31a/other", { "src/contract.ts": "export {};\n" });
	const of = (name: string, manifest: Record<string, unknown>, text: string, kind: string) =>
		pkg(
			name,
			{ "src/module.ts": text },
			{ exports: { ".": "./src/module.ts" }, dependencies: { "@g31a/store": "*" }, ...manifest },
			kind,
		);
	const provides = `import { upkeep } from "@g31a/store";\nexport const provided = [upkeep];\n`;
	const adapter = of("@g31a/adapter", { adapts: "@g31a/store" }, provides, budget.adapterKind);
	const feature = of("@g31a/feature", {}, provides, budget.featureKind);
	const claiming = of("@g31a/claiming", { adapts: "@g31a/store" }, provides, budget.featureKind);
	const elsewhere = of("@g31a/elsewhere", { adapts: "@g31a/other" }, provides, budget.adapterKind);
	const passing = of(
		"@g31a/passing",
		{ replaces: "@g31a/store" },
		`export { upkeep } from "@g31a/store";\n`,
		budget.adapterKind,
	);
	expect(
		check([owner, other, adapter, feature, claiming, elsewhere, passing], budget)
			.filter((v) => v.rule.startsWith("G31"))
			.map((v) => `${v.where} ${v.detail}`)
			.sort(),
	).toEqual([
		"@g31a/claiming/src/module.ts upkeep of @g31a/store",
		"@g31a/elsewhere/src/module.ts upkeep of @g31a/store",
		"@g31a/feature/src/module.ts upkeep of @g31a/store",
		"@g31a/passing/src/module.ts upkeep of @g31a/store",
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

it("G31 refuses a taker of an entry, or an adapter of a contract's owner, exporting again what it imported, and lets one use it", () => {
	const owner = pkg(
		"@g31h/store",
		{
			"src/contract.ts": [
				`import { contract } from "@g31h/kernel";`,
				`export const upkeep = contract<object>("store.upkeep", { takenBy: [] });`,
			].join("\n"),
			"src/writer.ts": "export const writer = Object.freeze({});\n",
		},
		{
			exports: { ".": "./src/contract.ts", "./writer": "./src/writer.ts" },
			takenBy: { upkeep: [], "./writer": ["@g31h/taker"] },
		},
	);
	// The same shapes of handing on, over the entry and over the contract.
	const shapes = (name: string, from: string) => ({
		"src/direct.ts": `import { ${name} } from "${from}";\nexport { ${name} };\n`,
		"src/aliased.ts": `import { ${name} as held } from "${from}";\nexport { held as handed };\n`,
		"src/rebound.ts": `import { ${name} } from "${from}";\nconst kept = (${name});\nconst again = kept;\nexport { again };\n`,
		"src/declared.ts": `import { ${name} } from "${from}";\nexport const held = ${name} as object;\n`,
		"src/defaulted.ts": `import { ${name} } from "${from}";\nexport default ${name};\n`,
		"src/whole.ts": `import * as all from "${from}";\nexport { all };\n`,
		"src/used.ts": `import { ${name} } from "${from}";\nconst kept = ${name};\nexport const held = [kept];\nexport const named = (x: unknown) => x === kept;\n`,
		"src/contract.ts": "export {};\n",
	});
	const user = (
		name: string,
		files: Record<string, string>,
		more: Record<string, unknown>,
		kind: string,
	) =>
		pkg(
			name,
			files,
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@g31h/store": "*" }, ...more },
			kind,
		);
	const taker = user("@g31h/taker", shapes("writer", "@g31h/store/writer"), {}, budget.featureKind);
	const adapter = user(
		"@g31h/adapter",
		shapes("upkeep", "@g31h/store"),
		{ adapts: "@g31h/store" },
		budget.adapterKind,
	);
	const handed = ["aliased", "declared", "defaulted", "direct", "rebound", "whole"];
	expect(
		check([owner, taker, adapter], budget)
			.filter((v) => v.rule.startsWith("G31"))
			.map((v) => `${v.where} ${v.detail}`)
			.sort(),
	).toEqual([
		...handed.map((file) => `@g31h/adapter/src/${file}.ts upkeep of @g31h/store`),
		...handed.map(
			(file) => `@g31h/taker/src/${file}.ts ./writer of @g31h/store: a taker does not hand it on`,
		),
	]);
});
