import { relative } from "node:path";
import { describe, expect, it } from "vitest";
import { lexicalAnalysis } from "../facts.ts";
import { edgeLine, factsFor, usesOf } from "./harness.ts";

/** A row: a file (the first) and its neighbours, and the edges it is read to have, as lines. */
interface EdgeRow {
	readonly name: string;
	readonly files: Readonly<Record<string, string>>;
	readonly links?: Readonly<Record<string, string>>;
	readonly edges: readonly string[];
}

const edgesOf = (row: EdgeRow) => {
	const { facts, root } = factsFor(row.files, row.links);
	return facts.edges.map((edge) => edgeLine(edge, root));
};

/** The same module reached by every form, what each binds and whether it loads. */
const forms: EdgeRow[] = [
	{
		name: "an import by default, by name, by namespace, and for its effect alone",
		files: {
			"a.ts":
				'import d from "m";\nimport { x, y as z } from "m";\nimport * as ns from "m";\nimport "m";\nimport {} from "m";\n',
		},
		edges: [
			"import m loads → package m {default:default>d}",
			"import m loads → package m {named:x>x named:y>z}",
			"import m loads → package m {namespace:*>ns}",
			"import m loads → package m",
			"import m loads → package m",
		],
	},
	{
		name: "a type binding apart from a load: import type loads nothing, a type named in a value import still loads",
		files: {
			"a.ts":
				'import type { T } from "m";\nimport { type U, v } from "m";\nimport { type W } from "m";\nexport type { T } from "m";\n',
		},
		edges: [
			"import m - → package m {named:T>T(type)}",
			"import m loads → package m {named:U>U(type) named:v>v}",
			"import m loads → package m {named:W>W(type)}",
			"export-from m - → package m {named:T=>T(type)}",
		],
	},
	{
		name: "a re-export by name, all of it, as a namespace, and none of it",
		files: {
			"a.ts":
				'export { x, y as z } from "m";\nexport * from "m";\nexport * as ns from "m";\nexport type * as t from "m";\nexport {} from "m";\n',
		},
		edges: [
			"export-from m loads → package m {named:x=>x named:y=>z}",
			"export-from m loads → package m {star:*}",
			"export-from m loads → package m {namespace:*=>ns}",
			"export-from m - → package m {namespace:*=>t(type)}",
			"export-from m loads → package m",
		],
	},
	{
		name: "a default taken by name, by an import and by a re-export alike: a named binding of default",
		files: {
			"a.ts":
				'import { default as d } from "m";\nexport { default as e } from "m";\nexport { default } from "m";\n',
		},
		edges: [
			"import m loads → package m {named:default>d}",
			"export-from m loads → package m {named:default=>e}",
			"export-from m loads → package m {named:default=>default}",
		],
	},
	{
		name: "a dynamic import by a literal, a template, with options, and named at run time",
		files: {
			"a.ts": [
				'export const a = () => import("m");',
				"export const b = () => import(`m`);",
				'export const c = () => import("m", { with: { type: "json" } });',
				// biome-ignore lint/suspicious/noTemplateCurlyInString: the source a test reads.
				"export const d = (n: string) => import(`./${n}.ts`);",
				"export const e = (n: string) => import(n);",
				"",
			].join("\n"),
		},
		edges: [
			"dynamic-import m loads → package m",
			"dynamic-import m loads → package m",
			"dynamic-import m loads → package m",
			'dynamic-import ./… loads → unresolved computed "./"',
			"dynamic-import … loads → unresolved computed",
		],
	},
	{
		name: "require unbound, in parentheses, by a template, its result named whole or taken apart",
		files: {
			"a.ts": [
				'const m = require("m");',
				'const n = (require)("m");',
				"const o = require(`m`);",
				'const { a, b: c } = require("m");',
				"export const p = (s: string) => require(s);",
				"export const used = [m, n, o, a, c];",
				"",
			].join("\n"),
		},
		edges: [
			"require [require] m loads → package m {whole:*>m}",
			"require [require] m loads → package m {whole:*>n}",
			"require [require] m loads → package m {whole:*>o}",
			"require [require] m loads → package m {destructured:a>a destructured:b>c}",
			"require [require] … loads → unresolved computed",
		],
	},
	{
		name: "a loader createRequire made, by name or through the module's namespace; a local named require that is no loader",
		files: {
			"a.ts": [
				'import { createRequire } from "node:module";',
				'import * as mod from "module";',
				"const require = createRequire(import.meta.url);",
				"const load = mod.createRequire(import.meta.url);",
				'export const a = (require)("m");',
				'export const b = load("m");',
				"",
			].join("\n"),
		},
		edges: [
			"import node:module loads → builtin node:module {named:createRequire>createRequire}",
			"import module loads → builtin module {namespace:*>mod}",
			"require [createRequire] m loads → package m {whole:*>a}",
			"require [createRequire] m loads → package m {whole:*>b}",
		],
	},
	{
		name: "a local named require, which no createRequire made, is no loader",
		files: { "a.ts": 'const require = (s: string) => s;\nexport const c = require("m");\n' },
		edges: [],
	},
	{
		name: "import = require, of a value and of a type",
		files: {
			"a.ts":
				'import fs = require("node:fs");\nimport type T = require("m");\nexport const used = fs;\n',
		},
		edges: [
			"import-equals node:fs loads → builtin node:fs {equals:*>fs}",
			"import-equals m - → package m {equals:*>T(type)}",
		],
	},
	{
		name: "an import type and a typeof import, looked up, never loaded",
		files: { "a.ts": 'export type A = import("m").T;\nexport type B = typeof import("m");\n' },
		edges: ["import-type m - → package m", "import-type m - → package m"],
	},
	{
		name: "a resolve, by import.meta and by a loader, resolved and never loaded; a URL made and a worker started are no edge",
		files: {
			"a.ts": [
				'export const a = import.meta.resolve("m");',
				'export const b = require.resolve("m");',
				'export const c = new URL("./x.ts", import.meta.url);',
				'export const d = new Worker("./w.ts");',
				"",
			].join("\n"),
		},
		edges: ["resolve m - → package m", "resolve m - → package m"],
	},
	{
		name: "an import with attributes, and a declaration file's and an ambient module's imports, which load nothing",
		files: {
			"a.ts":
				'import s from "./s.json" with { type: "json" };\ndeclare module "x" {\n\timport { y } from "m";\n}\nexport const used = s;\n',
			"s.json": "{}\n",
			"b.d.ts": 'import { z } from "m";\nexport declare const w: typeof z;\n',
		},
		edges: [
			"import ./s.json loads → file s.json {default:default>s}",
			"import m - → package m {named:y>y}",
		],
	},
];

/** What binds a loader is read in its own file alone, as any other name is. */
forms.push(
	{
		name: "a require another file declares is still the unbound require here",
		files: {
			"a.ts": 'export const a = require("node:https");\n',
			"types.d.ts": "declare function require(id: string): unknown;\n",
		},
		edges: ["require [require] node:https loads → builtin node:https {whole:*>a}"],
	},
	{
		name: "a loader keeps the base createRequire was given: the file, an absolute path, a file URL, or none known",
		files: {
			"p/src/a.ts": [
				'import { createRequire } from "node:module";',
				"const here = createRequire(import.meta.url);",
				`const there = createRequire("${"<root>"}/q/package.json");`,
				`const url = createRequire("file://${"<root>"}/q/package.json");`,
				"const unknown = createRequire(process.argv[1] ?? '');",
				'export const a = here("./b.js");',
				'export const b = there("./c.js");',
				'export const c = url("./c.js");',
				'export const d = unknown("./c.js");',
				"",
			].join("\n"),
			"p/src/b.js": "",
			"q/c.js": "",
		},
		edges: [
			"import node:module loads → builtin node:module {named:createRequire>createRequire}",
			"require [createRequire] ./b.js loads → file p/src/b.js {whole:*>a}",
			"require [createRequire] ./c.js loads → file q/c.js {whole:*>b}",
			"require [createRequire] ./c.js loads → file q/c.js {whole:*>c}",
			"require [createRequire] ./c.js loads → unresolved unsupported {whole:*>d}",
		],
	},
);

forms.push({
	name: "a loader given a directory (a path or a URL ending in /) resolves from that directory itself",
	files: {
		"p/src/a.ts": [
			'import { createRequire } from "node:module";',
			'const inDir = createRequire("<root>/q/");',
			'const inUrl = createRequire("file://<root>/q/");',
			'export const a = inDir("./c.js");',
			'export const b = inUrl("./c.js");',
			"",
		].join("\n"),
		"q/c.js": "",
		"c.js": "",
	},
	edges: [
		"import node:module loads → builtin node:module {named:createRequire>createRequire}",
		"require [createRequire] ./c.js loads → file q/c.js {whole:*>a}",
		"require [createRequire] ./c.js loads → file q/c.js {whole:*>b}",
	],
});

forms.push(
	{
		name: "a loader's result taken apart by a quoted property name binds that name",
		files: {
			"a.ts":
				'const { "request": send, \'get\': fetchOne } = require("node:https");\nexport const used = [send, fetchOne];\n',
		},
		edges: [
			"require [require] node:https loads → builtin node:https {destructured:request>send destructured:get>fetchOne}",
		],
	},
	{
		name: "a loader createRequire was given a linked file resolves beside the name given, not beside what it links to",
		files: {
			"p/src/a.ts": [
				'import { createRequire } from "node:module";',
				'const beside = createRequire("<root>/p/link.js");',
				'export const a = beside("./c.js");',
				"",
			].join("\n"),
			"p/c.js": "",
			"q/real.js": "",
			"q/c.js": "",
		},
		links: { "p/link.js": "q/real.js" },
		edges: [
			"import node:module loads → builtin node:module {named:createRequire>createRequire}",
			"require [createRequire] ./c.js loads → file p/c.js {whole:*>a}",
		],
	},
);

forms.push({
	name: "a loader's result taken apart with a rest: the rest binds the module whole, never a name of it",
	files: { "a.ts": 'const { a, ...rest } = require("m");\nexport const used = [a, rest];\n' },
	edges: ["require [require] m loads → package m {destructured:a>a whole:*>rest}"],
});

describe("edges: every form a file reaches a module by", () => {
	it.each(forms)("$name", (row) => {
		expect(edgesOf(row)).toEqual(row.edges);
	});

	it("reads a declaration file's imports as loading nothing", () => {
		const { facts } = factsFor({
			"b.d.ts": 'import { z } from "m";\nexport declare const w: typeof z;\n',
		});
		expect(facts.edges.map((e) => e.loads)).toEqual([false]);
	});
});

/** Where a specifier leads, as Node's loaders read it. */
const resolution: EdgeRow[] = [
	{
		name: "within, beside and out of a package; a built-in by scheme and bare; a package and its subpath",
		files: {
			"p/src/a.ts": [
				'import "./b.ts";',
				'import "../lib/c.ts";',
				'import "../../q/src/d.ts";',
				'import "node:fs";',
				'import "fs/promises";',
				'import "@s/n/sub/path";',
				'import "pkg";',
				"",
			].join("\n"),
			"p/src/b.ts": "",
			"p/lib/c.ts": "",
			"q/src/d.ts": "",
		},
		edges: [
			"import ./b.ts loads → file p/src/b.ts",
			"import ../lib/c.ts loads → file p/lib/c.ts",
			"import ../../q/src/d.ts loads → file q/src/d.ts",
			"import node:fs loads → builtin node:fs",
			"import fs/promises loads → builtin fs/promises",
			"import @s/n/sub/path loads → package @s/n /sub/path",
			"import pkg loads → package pkg",
		],
	},
	{
		name: "encoded dots climb, a query and a fragment are no part of the path yet kept as identity",
		files: {
			"p/src/a.ts":
				'import "./%2e%2e/%2e%2e/q/src/d.mjs";\nimport "./b.mjs?v=1";\nimport "./b.mjs#x";\n',
			"p/src/b.mjs": "",
			"q/src/d.mjs": "",
		},
		edges: [
			"import ./%2e%2e/%2e%2e/q/src/d.mjs loads → file q/src/d.mjs",
			"import ./b.mjs?v=1 loads → file p/src/b.mjs?v=1",
			"import ./b.mjs#x loads → file p/src/b.mjs#x",
		],
	},
	{
		name: "links followed: a directory, a file with a query, and the importing file itself linked from another package",
		files: {
			"p/src/a.ts": 'import "../lib/d.mjs";\nimport "../one.mjs?v=1";\n',
			"q/src/d.mjs": "",
			"q/src/linked.ts": 'import "./d.mjs";\n',
		},
		links: { "p/lib": "q/src", "p/one.mjs": "q/src/d.mjs", "p/src/linked.ts": "q/src/linked.ts" },
		edges: [
			"import ../lib/d.mjs loads → file q/src/d.mjs",
			"import ../one.mjs?v=1 loads → file q/src/d.mjs?v=1",
		],
	},
	{
		name: "require reads a path, not a URL: nothing decoded, a ? part of the name, its extensions tried",
		files: {
			"p/src/a.ts":
				'require("./%2e%2e/b.js");\nrequire("./c?v=1");\nrequire("./d");\nrequire("./e");\n',
			"p/src/%2e%2e/b.js": "",
			"p/src/c?v=1": "",
			"p/src/d.json": "{}",
			"p/src/e/index.js": "",
		},
		edges: [
			"require [require] ./%2e%2e/b.js loads → file p/src/%2e%2e/b.js",
			"require [require] ./c?v=1 loads → file p/src/c?v=1",
			"require [require] ./d loads → file p/src/d.json",
			"require [require] ./e loads → file p/src/e/index.js",
		],
	},
	{
		name: "unresolved, named so: a missing file, a private import, another scheme",
		files: {
			"p/src/a.ts":
				'import "./none.ts";\nimport "#internal";\nimport "data:text/javascript,1";\nimport "https://x.example/m.js";\n',
		},
		edges: [
			"import ./none.ts loads → unresolved missing p/src/none.ts",
			"import #internal loads → unresolved private-import",
			"import data:text/javascript,1 loads → unresolved scheme",
			"import https://x.example/m.js loads → unresolved scheme",
		],
	},
];

resolution.push(
	{
		name: "a required directory by its package.json main, then its index, an addon too; none found unresolved",
		files: {
			"p/src/a.ts": 'require("./main");\nrequire("./addon");\nrequire("./empty");\n',
			"p/src/main/package.json": '{ "main": "lib/start" }',
			"p/src/main/lib/start.js": "",
			"p/src/addon/index.node": "",
			"p/src/empty/readme.md": "",
		},
		edges: [
			"require [require] ./main loads → file p/src/main/lib/start.js",
			"require [require] ./addon loads → file p/src/addon/index.node",
			"require [require] ./empty loads → unresolved missing p/src/empty",
		],
	},
	{
		name: "an ESM import of a directory, and a file URL Node cannot take, are unresolved, never a file",
		files: {
			"p/src/a.ts": 'import "./dir";\nimport "file://elsewhere/x.mjs";\nimport "./a%2Fb.mjs";\n',
			"p/src/dir/index.js": "",
		},
		edges: [
			"import ./dir loads → unresolved unsupported",
			"import file://elsewhere/x.mjs loads → unresolved unsupported",
			"import ./a%2Fb.mjs loads → unresolved unsupported",
		],
	},
);

resolution.push({
	name: "a require ending in / names a directory alone: its index, never a file of that name",
	files: {
		"p/src/a.ts": 'require("./d/");\n',
		"p/src/d.js": "",
		"p/src/d/index.js": "",
	},
	edges: ["require [require] ./d/ loads → file p/src/d/index.js"],
});

resolution.push({
	name: "a require ending in a . or .. segment names a directory alone, as one ending in / does",
	files: {
		"p/src/a.ts": 'require("./d/.");\nrequire("./d/e/..");\n',
		"p/src/d.js": "",
		"p/src/d/index.js": "",
		"p/src/d/e/index.js": "",
	},
	edges: [
		"require [require] ./d/. loads → file p/src/d/index.js",
		"require [require] ./d/e/.. loads → file p/src/d/index.js",
	],
});

describe("resolution: where a specifier leads", () => {
	it.each(resolution)("$name", (row) => {
		expect(edgesOf(row)).toEqual(row.edges);
	});

	it("reads the importing file from its real place, a link from another package resolving there", () => {
		const { facts, root } = factsFor(
			{ "p/src/linked.ts": "", "q/src/linked.ts": 'import "./d.mjs";\n', "q/src/d.mjs": "" },
			{},
		);
		expect(facts.edges).toEqual([]);
		const linked = factsFor(
			{ "q/src/linked.ts": 'import "./d.mjs";\n', "q/src/d.mjs": "" },
			{ "p/src/linked.ts": "q/src/linked.ts" },
		);
		expect(linked.facts.edges.map((e) => e.target.kind)).toEqual(["file"]);
		expect(root).not.toBe(linked.root);
	});
});

/** A name's uses: its role and what it is bound to. */
const roles: { name: string; source: string; uses: Readonly<Record<string, readonly string[]>> }[] =
	[
		{
			name: "types erased, a type query a lookup, an instantiation and a class's extends values, implements a type",
			source: [
				"interface I { fetch: Date }",
				"type A = Date;",
				"export const x = 1 as unknown as Date;",
				"export const y = { a: 1 } satisfies Record<string, Date>;",
				"export type Q = typeof Date;",
				"export const C = class extends Date implements Iterable<Date> {};",
				"export const later = setTimeout<[]>;",
				"export type U = I | A;",
				"",
			].join("\n"),
			uses: {
				Date: [
					"type unbound",
					"type unbound",
					"type unbound",
					"type unbound",
					"type-query unbound",
					"value unbound",
					"type unbound",
				],
				Iterable: ["type unbound"],
				setTimeout: ["value unbound"],
				fetch: ["property"],
			},
		},
		{
			name: "names that are no value read: properties, keys, methods, labels, attribute keys, meta",
			source: [
				'import s from "./s.json" with { type: "json" };',
				"export const o = { fetch: 1, process() { return 2; } };",
				"export const p = o.fetch;",
				"loop: for (;;) { break loop; }",
				"export const u = import.meta.url;",
				"export const used = s;",
				"",
			].join("\n"),
			uses: {
				type: ["attribute-key"],
				fetch: ["property", "property"],
				process: ["property"],
				loop: ["label", "label"],
				meta: ["property"],
				url: ["property"],
			},
		},
		{
			name: "a local shadows the unbound name; a type of the name is no value; a shorthand and a local export read what they name",
			source: [
				"type fetch = string;",
				"export const call = (u: string) => fetch(u);",
				"export const local = (process: string) => process;",
				"const held = { setTimeout };",
				"export { Date as Clock, held };",
				"type Kept = string;",
				"export { type Kept };",
				"export type { Kept as Again };",
				"",
			].join("\n"),
			uses: {
				fetch: ["declared local", "value unbound"],
				process: ["declared local", "value local"],
				setTimeout: ["value unbound"],
				Date: ["value unbound"],
				Clock: ["declared unbound"],
				held: ["declared local", "value local"],
				Kept: ["declared local", "type local", "type local"],
			},
		},
		{
			name: "an imported name read, a namespace's member, a destructured loader's result",
			source: [
				'import { a } from "m";',
				'import * as ns from "n";',
				'const { b } = require("o");',
				"export const used = [a, ns.c, b];",
				"",
			].join("\n"),
			uses: {
				a: ["declared imported a", "value imported a"],
				ns: ["declared imported *", "value imported *"],
				c: ["property"],
				b: ["declared imported b", "value imported b"],
			},
		},
	];

roles.push(
	{
		name: "a shorthand's default reads its own name, never the property's",
		source:
			"let selected: unknown;\nexport const pick = (options: object) => ({ selected = fetch } = options as never);\nexport const used = selected;\n",
		uses: { fetch: ["value unbound"], selected: ["declared local", "value local", "value local"] },
	},
	{
		name: "an ambient declaration runs nothing: a declared class's extends and a declared namespace's names are types",
		source:
			"export declare class Socket extends WebSocket {}\ndeclare namespace N {\n\tconst at: typeof fetch;\n\tclass C extends EventSource {}\n}\nexport const S = class extends WebSocket {};\n",
		uses: {
			WebSocket: ["type unbound", "value unbound"],
			EventSource: ["type unbound"],
			fetch: ["type-query unbound"],
		},
	},
);

roles.push({
	name: "a loader's rest reads the module whole: its members are properties, no name imported",
	source: 'const { ...http } = require("node:http");\nexport const used = http.request;\n',
	uses: { http: ["declared imported *", "value imported *"], request: ["property"] },
});

describe("references: what each name stands for and is bound to", () => {
	it.each(roles)("$name", (row) => {
		const { facts } = factsFor({ "a.ts": row.source, "s.json": "{}" });
		for (const [name, uses] of Object.entries(row.uses))
			expect(usesOf(facts, name), name).toEqual(uses);
	});

	it("reads a property of an unbound name by a dot or a literal key, and leaves a computed one unnamed", () => {
		const { facts } = factsFor({
			"a.ts":
				'export const a = globalThis.fetch;\nexport const b = globalThis["fetch"];\nexport const c = (k: string) => globalThis[k];\n',
		});
		expect(
			facts.members.map((m) => `${m.object.node.text}.${m.name ?? "?"} ${m.object.binding?.kind}`),
		).toEqual(["globalThis.fetch unbound", "globalThis.fetch unbound", "globalThis.? unbound"]);
	});

	it("keeps each file a module: a script's top-level name binds nothing in another file", () => {
		const { facts } = factsFor({
			"a.ts": "export const x = shared;\n",
			"b.ts": "var shared = 1;\n",
		});
		expect(usesOf(facts, "shared")).toEqual(["value unbound"]);
	});
});

it("refuses a file it does not read (JSX, .cts, .cjs, .mts), and one it was not made over", () => {
	const { facts } = factsFor({ "a.ts": "export const a = 1;\n" });
	const analysis = lexicalAnalysis([facts.path]);
	for (const path of ["a.tsx", "a.cts", "a.cjs", "a.mts"]) {
		expect(() => analysis.factsOf(facts.path.replace("a.ts", path)), path).toThrow(
			"not a file a lexical program reads",
		);
	}
	expect(() => analysis.factsOf(facts.path.replace("a.ts", "b.ts"))).toThrow(
		"not among the files analysed",
	);
});

it("reads a file named by any ordinary spelling of its path, and answers it by any other", () => {
	const { facts } = factsFor({ "a.ts": 'import "node:fs";\n' });
	const spelled = relative(process.cwd(), facts.path);
	const analysis = lexicalAnalysis([`./${spelled}`]);
	expect(analysis.factsOf(facts.path).edges.length).toBe(1);
	expect(analysis.factsOf(spelled).edges.length).toBe(1);
});

/** Each ambient context, with what it may hold: no edge in one loads, and no name in one is read as a value. */
const ambientContexts: {
	context: string;
	file: string;
	source: string;
	names: readonly string[];
}[] = [
	{
		context: "a declaration file",
		file: "a.d.ts",
		source: [
			'import { x } from "m";',
			'export { y } from "m";',
			'import z = require("m");',
			'export declare class Pool extends (require("undici").Pool) {}',
			"export declare class Socket extends globalThis.WebSocket {}",
			"export declare const f: typeof fetch;",
			"export declare const at: typeof x | typeof z;",
		].join("\n"),
		names: ["WebSocket", "globalThis", "fetch"],
	},
	{
		context: "declare module",
		file: "a.ts",
		source: [
			'declare module "other" {',
			'\timport { x } from "m";',
			'\texport { y } from "m";',
			'\timport z = require("m");',
			'\texport class Pool extends (require("undici").Pool) {}',
			"\texport class Socket extends globalThis.WebSocket {}",
			"\texport const f: typeof fetch;",
			"\texport const at: typeof x | typeof z;",
			"}",
			"export {};",
		].join("\n"),
		names: ["WebSocket", "globalThis", "fetch"],
	},
	{
		context: "declare namespace",
		file: "a.ts",
		source: [
			"declare namespace N {",
			'\tclass Pool extends (require("undici").Pool) {}',
			"\tclass Socket extends globalThis.WebSocket {}",
			"\tconst f: typeof fetch;",
			"}",
			"export {};",
		].join("\n"),
		names: ["WebSocket", "globalThis", "fetch"],
	},
	{
		context: "declare class",
		file: "a.ts",
		source: [
			'export declare class Pool extends (require("undici").Pool) {}',
			"export declare class Socket extends globalThis.WebSocket {}",
			"export declare class Plain extends WebSocket {}",
		].join("\n"),
		names: ["WebSocket", "globalThis"],
	},
];

describe("ambient contexts: an edge in one loads nothing, and no name in one is a value read", () => {
	it.each(ambientContexts)("in $context", ({ file, source, names }) => {
		const { facts } = factsFor({ [file]: `${source}\n` });
		expect(facts.edges.length).toBeGreaterThan(0);
		expect(facts.edges.map((e) => `${e.form} ${e.specifier.text} ${e.loads}`)).toEqual(
			facts.edges.map((e) => `${e.form} ${e.specifier.text} false`),
		);
		for (const name of names) {
			const roles = facts.references.filter((r) => r.node.text === name).map((r) => r.role);
			expect(roles.length, name).toBeGreaterThan(0);
			expect(
				roles.filter((role) => role === "value"),
				name,
			).toEqual([]);
		}
	});

	it("leaves the same forms run where nothing is declared", () => {
		const { facts } = factsFor({
			"a.ts":
				'export class Pool extends (require("undici").Pool) {}\nexport class Socket extends globalThis.WebSocket {}\n',
		});
		expect(facts.edges.map((e) => `${e.form} ${e.loads}`)).toEqual(["require true"]);
		expect(usesOf(facts, "globalThis")).toEqual(["value unbound"]);
	});
});
