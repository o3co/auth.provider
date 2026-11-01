import { symlinkSync } from "node:fs";
import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../contract.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

/** What a rule says of a package, as `where detail`: G33 unless named. */
const said = (p: Pkg, rule = "G33") =>
	check([p], budget)
		.filter((v) => v.rule.startsWith(`${rule} `))
		.map((v) => `${v.where} ${v.detail}`);
/** A protocol package with these shipped files, its contract first. */
const protocol = (name: string, files: Record<string, string>, manifest: Pkg["manifest"] = {}) =>
	pkg(name, files, { exports: { ".": "./src/contract.ts" }, ...manifest }, "protocol");
/** A protocol whose contract is these lines. */
const contract = (name: string, ...lines: string[]) =>
	protocol(name, { "src/contract.ts": `${lines.join("\n")}\n` });

describe("G33: a protocol holds a wire's contract alone", () => {
	it("lets types, frozen constants, zod's schemas and the functions that build by them through", () => {
		const wire = protocol("@w/clean", {
			"src/contract.ts": [
				'import { z } from "zod";',
				'import type { Readable } from "node:stream";',
				'import type { Other } from "@w/other";',
				"export interface Call { readonly process: string; readonly console: number }",
				"export type Status = 200 | 404;",
				"export type Stream = Readable | Other;",
				'export const paths = Object.freeze({ read: "/read", list: Object.freeze(["a"]) });',
				"const process = z.string();",
				"export const answer = z.object({ process, enrolled: z.boolean() });",
				"export const body = (subject: string, at: number) => ({ subject, at: Number(at) });",
				"export function isAnswer(x: unknown): boolean { return answer.safeParse(x).success; }",
				"export const text = (x: unknown) => JSON.stringify(x) ?? String(undefined);",
				'export { more } from "./more.ts";',
			].join("\n"),
			"src/more.ts":
				'import { z } from "zod";\nimport type Stream = require("node:stream");\nimport schema from "./schema.json" with { type: "json" };\nexport const more = z.literal(1);\nexport type Readable = Stream.Readable;\nexport const shape = schema;\n',
			"src/schema.json": "{}\n",
			"test/wire.test.ts":
				'import { readFileSync } from "node:fs";\nlet seen = Date.now();\nexport { readFileSync, seen };\n',
		});
		expect(said(wire)).toEqual([]);
	});

	it("refuses an export but its contract, and network words or forks in its manifest", () => {
		const wire = protocol(
			"@w/shape",
			{ "src/contract.ts": "export const a = 1;\n", "src/module.ts": "export const m = 1;\n" },
			{
				exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
				network: ["outbound"],
				forks: { "src/a.ts": "src/b.mjs" },
			},
		);
		expect(said(wire)).toEqual([
			"@w/shape exports ./module: a protocol exports its contract alone",
			"@w/shape declares network: a protocol reaches nothing",
			"@w/shape declares forks: a protocol reaches nothing",
		]);
	});

	it("imports at run time zod and its own files alone", () => {
		const wire = contract(
			"@w/imports",
			'import { readFileSync } from "node:fs";',
			'import path from "path";',
			'import { kernel } from "@w/kernel";',
			'export { other } from "lib";',
			// It still loads the module: import type binds types alone.
			'import { type Readable } from "node:stream";',
			"export const used = [readFileSync, path, kernel];",
		);
		expect(said(wire)).toEqual([
			"@w/imports/src/contract.ts imports node:fs: a protocol imports zod and its own files alone",
			"@w/imports/src/contract.ts imports path: a protocol imports zod and its own files alone",
			"@w/imports/src/contract.ts imports @w/kernel: a protocol imports zod and its own files alone",
			"@w/imports/src/contract.ts imports lib: a protocol imports zod and its own files alone",
			"@w/imports/src/contract.ts imports node:stream: a protocol imports zod and its own files alone",
		]);
	});

	it("takes a file for its own, leaving where it is to G34, as for any package", () => {
		const wire = protocol("@w/relative", {
			"src/contract.ts": [
				'import { inner } from "../lib/inner.ts";',
				'import { feature } from "../../@w_feature/src/contract.ts";',
				"export const used = [inner, feature];",
			].join("\n"),
			"lib/inner.ts": "export const inner = 1;\n",
		});
		expect(said(wire)).toEqual([]);
		expect(said(wire, "G34")).toEqual([
			"@w/relative/src/contract.ts ../../@w_feature/src/contract.ts",
		]);
	});

	it("leaves a link out of the package to G34 too", () => {
		const feature = pkg("@w/linkfeature", { "src/contract.ts": "export const feature = 1;\n" });
		const wire = protocol("@w/linked", {
			"src/contract.ts": 'export { feature } from "./out/contract.ts";\n',
		});
		symlinkSync(join(feature.dir, "src"), join(wire.dir, "src", "out"));
		expect(said(wire)).toEqual([]);
		expect(said(wire, "G34")).toEqual(["@w/linked/src/contract.ts ./out/contract.ts"]);
	});

	it("refuses loading a module at run time, however it is named", () => {
		const wire = contract(
			"@w/loads",
			'export const a = () => require("node:fs");',
			"export const b = () => import(`node:fs`);",
			'export const c = () => import("node:fs");',
			"export const d = () => import.meta.url;",
		);
		expect(said(wire)).toEqual([
			"@w/loads/src/contract.ts reaches the global require",
			"@w/loads/src/contract.ts loads a module at run time: import()",
			"@w/loads/src/contract.ts loads a module at run time: import()",
			"@w/loads/src/contract.ts reads import.meta",
		]);
	});

	it("reaches no global but the few that hold no behaviour of the host", () => {
		const wire = contract(
			"@w/globals",
			"export const run = (s: string) => eval(s) ?? new Function(s);",
			"export const env = () => globalThis.process.env;",
			"export const later = (f: () => void) => globalThis.setTimeout(f, 1);",
			"export const at = () => Date.now() + Math.random() + performance.now();",
			"export const ids = () => crypto.randomUUID();",
			"export const get = (u: string) => fetch(u);",
			"export const kept = new Map();",
			"export const held = { console };",
			"export { Date as Clock };",
		);
		expect(said(wire)).toEqual([
			"@w/globals/src/contract.ts reaches the global eval",
			"@w/globals/src/contract.ts reaches the global Function",
			"@w/globals/src/contract.ts reaches the global globalThis",
			"@w/globals/src/contract.ts reaches the global globalThis",
			"@w/globals/src/contract.ts reaches the global Date",
			"@w/globals/src/contract.ts reaches the global Math",
			"@w/globals/src/contract.ts reaches the global performance",
			"@w/globals/src/contract.ts reaches the global crypto",
			"@w/globals/src/contract.ts reaches the global fetch",
			"@w/globals/src/contract.ts reaches the global Map",
			"@w/globals/src/contract.ts reaches the global console",
			"@w/globals/src/contract.ts reaches the global Date",
		]);
	});

	it("reads a class's extends and an instantiation as values, and type arguments and implements not", () => {
		const wire = contract(
			"@w/heritage",
			"export const Clock = class extends Date {};",
			"export const now = () => new Clock().getTime();",
			"export const List = class extends Array<Date> {};",
			"export const later = setTimeout<[]>;",
			"export const Shaped = class implements Iterable<Date> {};",
		);
		expect(said(wire)).toEqual([
			"@w/heritage/src/contract.ts reaches the global Date",
			"@w/heritage/src/contract.ts reaches the global setTimeout",
		]);
	});

	it("refuses behaviour a constant's initializer runs, as it would anywhere", () => {
		const wire = contract(
			"@w/initializer",
			'import { z } from "zod";',
			'export function loud() { console.log("loaded"); return 1; }',
			"export const value = loud();",
			"export const checked = z.string().refine((s) => { console.warn(s); return true; });",
		);
		expect(said(wire)).toEqual([
			"@w/initializer/src/contract.ts reaches the global console",
			"@w/initializer/src/contract.ts reaches the global console",
		]);
	});

	it("refuses state that changes and code run as the file loads", () => {
		const wire = contract(
			"@w/state",
			'import fs = require("node:fs");',
			"export let count = 0;",
			"var seen = [];",
			"export class Ledger {}",
			"seen.push(1);",
			"export const used = seen;",
		);
		expect(said(wire)).toEqual([
			"@w/state/src/contract.ts imports node:fs: a protocol imports zod and its own files alone",
			"@w/state/src/contract.ts holds state or runs as it loads: a statement",
			"@w/state/src/contract.ts holds state or runs as it loads: let",
			"@w/state/src/contract.ts holds state or runs as it loads: var",
			"@w/state/src/contract.ts holds state or runs as it loads: class",
			"@w/state/src/contract.ts holds state or runs as it loads: a statement",
		]);
	});

	it("refuses its shipped code loading a test file, which G33 does not read", () => {
		const wire = protocol("@w/testload", {
			"src/contract.ts":
				'export { now } from "../test/clock.ts";\nexport type { Kept } from "../test/kept.ts";\n',
			"test/clock.ts": "export const now = () => Date.now();\n",
			"test/kept.ts": "export type Kept = string;\n",
		});
		expect(said(wire)).toEqual(["@w/testload/src/contract.ts loads a test file: ../test/clock.ts"]);
	});

	it("takes a default export, reading the value it exports", () => {
		const wire = protocol("@w/default", {
			"src/contract.ts": "const schema = Object.freeze({});\nexport default schema;\n",
			"src/clock.ts": "export default Date.now();\n",
		});
		expect(said(wire)).toEqual(["@w/default/src/clock.ts reaches the global Date"]);
	});

	it("reads no package of another kind", () => {
		const feature = pkg("@w/feature", {
			"src/contract.ts":
				'export let n = 0;\nexport const at = () => Date.now();\nimport("node:fs");\n',
		});
		expect(said(feature)).toEqual([]);
	});
});
