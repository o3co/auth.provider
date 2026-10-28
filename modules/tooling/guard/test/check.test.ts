import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { type Pkg, surfacesOf } from "@mod/guard-imports";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	branchingImports,
	check,
	dependencyCards,
	heavyDependencyCards,
	measures,
} from "../src/contract.ts";
import { budget, pkg, root } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const rules = (packages: Pkg[]) => check(packages, budget).map((v) => v.rule.split(" ")[0]);

describe("guard", () => {
	// The first syntax tree loads the parser, which under a full parallel run takes longer than a test may.
	beforeAll(() => {
		check([pkg("@t/warm", { "src/contract.ts": "export const n = 1;\n" })], budget);
	}, 60_000);

	it("passes a clean pair", () => {
		const a = pkg("@t/a", { "src/contract.ts": "export const a = 1;\n" });
		const b = pkg(
			"@t/b",
			{ "src/contract.ts": 'import { a } from "@t/a";\nexport const b = a;\n' },
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/a": "workspace:*" } },
		);
		expect(check([a, b], budget)).toEqual([]);
	});

	it("finds cycles, undeclared runtime imports and odd export keys", () => {
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
		expect(rules([a, b]).sort()).toEqual(["G1", "G5", "G8"]);
	});

	it("takes a package's audit event declarations as part of its public interface", () => {
		const p = pkg(
			"@t/e",
			{ "src/contract.ts": "export const x = 1;\n", "src/audit-events.ts": "export default {};\n" },
			{ exports: { ".": "./src/contract.ts", "./audit-events": "./src/audit-events.ts" } },
		);
		expect(rules([p])).toEqual([]);
	});

	it("finds feature vocabulary in what the common mechanism exports or imports, not in its locals", () => {
		const feature = pkg("@t/f", {
			"src/contract.ts": "export const grantType = 1;\nexport const keys = 2;\n",
		});
		const common = pkg(
			"@t/k",
			{
				"src/contract.ts":
					'import { keys } from "./x.ts";\nexport const grantType = 0;\nconst run = (o: object) => Object.keys(o);\nexport { run, keys as k };\n',
			},
			{ exports: { ".": "./src/contract.ts" } },
			"common",
		);
		expect(
			check([feature, common], budget)
				.filter((v) => v.rule.startsWith("G6"))
				.map((v) => v.detail)
				.sort(),
		).toEqual(["grantType (@t/f)", "keys (@t/f)"]);
	});

	it("holds a protocol, as common, to names no other contract owns, its own names its own", () => {
		const feature = pkg("@t/pf", { "src/contract.ts": "export const grantType = 1;\n" });
		const kernel = pkg(
			"@t/pk",
			{ "src/contract.ts": "export const run = 1;\n" },
			undefined,
			"common",
		);
		const wire = pkg(
			"@t/pw",
			{ "src/contract.ts": "export const answer = 1;\nexport const grantType = 2;\n" },
			undefined,
			"protocol",
		);
		expect(
			check([feature, kernel, wire], budget)
				.filter((v) => v.rule.startsWith("G6"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@t/pw contract grantType (@t/pf)"]);
		const twin = pkg(
			"@t/pt",
			{ "src/contract.ts": "export const answer = 3;\n" },
			undefined,
			"protocol",
		);
		expect(
			check([wire, twin], budget)
				.filter((v) => v.rule.startsWith("G6"))
				.map((v) => `${v.where} ${v.detail}`)
				.sort(),
		).toEqual(["@t/pt contract answer (@t/pw)", "@t/pw contract answer (@t/pt)"]);
	});

	it("counts a protocol a unit imports against its dependencies, as it does any package but common", () => {
		const wire = pkg(
			"@t/dw",
			{ "src/contract.ts": "export const w = 1;\n" },
			undefined,
			"protocol",
		);
		const kernel = pkg(
			"@t/dk",
			{ "src/contract.ts": "export const k = 1;\n" },
			undefined,
			"common",
		);
		const user = pkg(
			"@t/du",
			{
				"src/contract.ts":
					'import { w } from "@t/dw";\nimport { k } from "@t/dk";\nexport const u = w + k;\n',
			},
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/dw": "*", "@t/dk": "*" } },
		);
		expect(
			check([wire, kernel, user], { ...budget, dependencies: 0 })
				.filter((v) => v.rule.startsWith("G7") && v.where.startsWith("@t/du"))
				.map((v) => v.detail),
		).toEqual(["dependencies 1 > 0"]);
	});

	it("counts only values against the contract budget and finds unexported types in public signatures", () => {
		const p = pkg("@t/s", {
			"src/contract.ts":
				"interface Hidden { a: number }\nexport interface Shown { h: Hidden }\nexport const make = (x: Shown): Shown => x;\nexport type T1 = 1;\n",
		});
		expect(
			check([p], { ...budget, contractValues: 1, contractMembers: 100 }).map(
				(v) => `${v.rule.split(" ")[0]} ${v.detail}`,
			),
		).toEqual(["G9 Hidden (Shown)"]);
	});

	it("holds a package to the limit an exception gives it for one measure, and refuses one without a reason or a package", () => {
		const p = pkg("@t/x", { "src/contract.ts": "export const a = 1;\nexport const b = 2;\n" });
		const tight = { ...budget, contractValues: 1 };
		const g7 = (b: typeof budget) =>
			check([p], b)
				.filter((v) => v.rule === "G7 budget")
				.map((v) => `${v.where} ${v.detail}`);
		expect(g7(tight)).toEqual(["@t/x contract values 2 > 1"]);
		const excepted = (e: object) => ({
			...tight,
			exceptions: [{ package: "@t/x", measure: "contract values", limit: 2, reason: "why", ...e }],
		});
		expect(g7(excepted({}))).toEqual([]);
		expect(g7(excepted({ reason: " " }))).toEqual([
			"budget exception @t/x contract values gives no reason",
		]);
		expect(g7(excepted({ package: "@t/none" }))).toEqual([
			"@t/x contract values 2 > 1",
			"budget exception @t/none contract values names no package in the workspace",
		]);
	});

	it("limits the members of a contract's exported types, more widely for the kinds others build on", () => {
		const source = {
			"src/contract.ts":
				"export interface Wide { a: 1; b: 2; c: 3; d: 4 }\nexport type Narrow = { e: 5 };\n" +
				// Names and words have no members of their own, whatever the platform's strings carry.
				'export type Word = "x" | "y";\nexport type Name = string;\nexport type Count = number | 1;\n',
		};
		const members = (kind: string) =>
			check(
				[
					{
						...pkg(`@t/${kind}`, source),
						manifest: { ...pkg(`@t/${kind}`, source).manifest, kind },
					},
				],
				budget,
			)
				.filter((v) => v.detail.startsWith("contract members"))
				.map((v) => v.detail);
		expect(members("feature")).toEqual(["contract members 5 > 3"]);
		expect(members("foundation")).toEqual([]);
	});

	it("counts a published contract test suite as test lines, yet checks its imports as shipped code", () => {
		const p = pkg(
			"@t/suite",
			{
				"src/contract.ts": "export const a = 1;\n",
				"src/testing.ts": 'import { x } from "undeclared";\nexport const t = x;\n',
			},
			{ exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" } },
		);
		const violations = check([p], { ...budget, sourceLines: 1, testLines: 1 });
		expect(violations.map((v) => `${v.rule.split(" ")[0]} ${v.detail}`)).toEqual([
			"G8 undeclared",
			"G7 test lines 2 > 1",
		]);
	});

	it("reads a unit's .mjs files as its own bytes, and a generated file not as its bytes", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/mjs", {
			"src/contract.ts": line,
			"src/helper.mjs": line.repeat(3),
			// Written by a tool from another file: no one reads it as written.
			"src/check.bundled.mjs": line.repeat(500),
		});
		// The .ts line and the three .mjs lines; the bundle's 500 are not read.
		const own = 4 * line.length;
		const reading = (limit: number) =>
			check([p], { ...budget, readRangeBytes: limit }).map((v) => `${v.where} ${v.detail}`);
		expect(reading(own)).toEqual([]);
		expect(reading(own - 1)).toEqual([`@t/mjs reading scope bytes ${own} > ${own - 1}`]);
	});

	it("gives every unit's measures, each with its limit, the ones under it too", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/measured", {
			"src/contract.ts": line.repeat(3),
			"src/inner/README.md": "# inner\n- one item\n- a second, longer item\n",
			"src/inner/a.ts": line.repeat(4),
			"src/inner/test/a.test.ts": line.repeat(2),
		});
		const of = (where: string) =>
			Object.fromEntries(
				measures([p], budget)
					.filter((m) => m.where === where)
					.map((m) => [m.what, [m.value, m.limit]]),
			);
		expect(of("@t/measured")).toMatchObject({
			"source lines": [3, budget.sourceLines],
			"test lines": [0, budget.testLines],
			"contract values": [1, budget.contractValues],
			"contract members": [0, budget.contractMembers],
			"card lines": [2, budget.cardLines],
			"card items": [0, undefined],
		});
		expect(of("@t/measured/src/inner")).toMatchObject({
			"source lines": [4, budget.sourceLines],
			"test lines": [2, budget.testLines],
			"comment lines": [0, budget.commentFloor],
			"card items": [2, undefined],
			"card item bytes": [Buffer.byteLength("- a second, longer item"), budget.cardItemBytes],
			dependencies: [0, budget.dependencies],
		});
		expect(of("@t/measured/src/inner")).not.toHaveProperty("contract values");
	});

	it("measures on the surfaces it is given, read once by its caller, without reading them again", () => {
		const p = pkg("@t/given", { "src/contract.ts": "export const n = 1;\n" });
		const [read] = [...surfacesOf([p]).values()];
		if (!read) throw new Error("no surface");
		const given = new Map([[p.name, { ...read, members: 7 }]]);
		const members = measures([p], budget, given).find(
			(m) => m.where === "@t/given" && m.what === "contract members",
		);
		expect(members?.value).toBe(7);
	});

	it("measures each internal module, a directory with a card, apart from the rest of its package", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/deep", {
			"src/contract.ts": line.repeat(3),
			"src/inner/README.md": "# inner\nNot yet built\n",
			"src/inner/a.ts": line.repeat(4),
			"src/inner/test/a.test.ts": line.repeat(2),
			"src/inner/deeper/README.md": "# deeper\n",
			"src/inner/deeper/b.ts": line.repeat(5),
		});
		const found = check([p], { ...budget, sourceLines: 4, testLines: 1 }).map(
			(v) => `${v.rule.split(" ")[0]} ${v.where} ${v.detail}`,
		);
		expect(found).toEqual([
			"G7 @t/deep/src/inner test lines 2 > 1",
			"G17 @t/deep/src/inner Not yet built",
			"G7 @t/deep/src/inner/deeper source lines 5 > 4",
		]);
		const reading = (limit: number) =>
			check([p], { ...budget, readRangeBytes: limit }).map((v) => `${v.where} ${v.detail}`);
		// The deepest reads its own files and the cards of the modules it lies in: 5 lines and 3 cards.
		const deeper =
			5 * line.length +
			"# deeper\n".length +
			"# inner\nNot yet built\n".length +
			"# @t/deep\n".length;
		expect(reading(deeper)).not.toContainEqual(expect.stringContaining("src/inner/deeper reading"));
		expect(reading(deeper - 1)).toContainEqual(
			`@t/deep/src/inner/deeper reading scope bytes ${deeper} > ${deeper - 1}`,
		);
		// And the cards of the packages its files import.
		const dep = pkg("@t/used", { "src/contract.ts": line });
		const using = pkg(
			"@t/using",
			{
				"src/contract.ts": line,
				"src/inner/README.md": "# inner\n",
				"src/inner/a.ts": 'import { n } from "@t/used";\nexport const m = n;\n',
			},
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/used": "workspace:*" } },
		);
		const inner =
			'import { n } from "@t/used";\nexport const m = n;\n'.length +
			"# inner\n".length +
			"# @t/using\n".length +
			"# @t/used\n".length;
		const scope = check([dep, using], { ...budget, readRangeBytes: inner - 1 }).map((v) => v.where);
		expect(scope).toContain("@t/using/src/inner");
	});

	it("measures the cards of the packages each unit's shipped code imports, without failing", () => {
		const used = pkg("@t/card-a", { "src/contract.ts": "export const a = 1;\n" });
		const other = pkg("@t/card-b", { "src/contract.ts": "export const b = 1;\n" });
		const p = pkg(
			"@t/measured",
			{
				"src/contract.ts": 'import { a } from "@t/card-a";\nexport const n = a;\n',
				"src/inner/README.md": "# inner\n",
				"src/inner/x.ts":
					'import type { a } from "@t/card-a";\nimport { b } from "@t/card-b";\nexport const m = b;\n',
				"src/inner/y.ts": 'import { b } from "@t/card-b";\nexport const k = b;\n',
				"src/inner/test/x.test.ts": 'import { b } from "@t/card-b";\nexport const t = b;\n',
				"test/root.test.ts": 'import { b } from "@t/card-b";\nexport const t = b;\n',
			},
			{ exports: { ".": "./src/contract.ts" } },
		);
		const card = (name: string) => `# ${name}\n`.length;
		expect(dependencyCards([used, other, p], budget)).toContainEqual({
			where: "@t/measured",
			bytes: card("@t/card-a"),
		});
		expect(dependencyCards([used, other, p], budget)).toContainEqual({
			where: "@t/measured/src/inner",
			bytes: card("@t/card-a") + card("@t/card-b"),
		});
		expect(check([used, other, p], { ...budget, readRangeBytes: 1_000_000 })).not.toContainEqual(
			expect.objectContaining({ detail: expect.stringContaining("dependency") }),
		);
	});

	it("reports an internal module whose imports no other unit shares, as a sign its dependencies branch", () => {
		const shared = pkg("@t/shared", { "src/contract.ts": "export const s = 1;\n" });
		const own = pkg("@t/own", { "src/contract.ts": "export const o = 1;\n" });
		const solo = pkg("@t/solo", { "src/contract.ts": "export const v = 1;\n" });
		const p = pkg("@t/host", {
			"src/contract.ts":
				'import { s } from "@t/shared";\nimport { r } from "rooted";\nexport const n = s + r;\n',
			"src/inner/README.md": "# inner\n",
			"src/inner/a.ts":
				'import { s } from "@t/shared";\nimport { o } from "@t/own";\nimport * as heavy from "heavy-lib";\nexport const m = s + o + heavy.n;\n',
			"src/inner/test/a.test.ts": 'import { x } from "@t/elsewhere";\nexport const t = x;\n',
			"src/other/README.md": "# other\n",
			"src/other/b.ts": 'import { s } from "@t/shared";\nexport const k = s;\n',
			"src/lone/README.md": "# lone\n",
			"src/lone/c.ts":
				'import { v } from "@t/solo";\nimport * as lib from "lone-lib";\nexport const l = v + lib.n;\n',
		});
		expect(branchingImports([shared, own, solo, p], budget)).toEqual([
			{ where: "@t/host/src/lone", packages: ["@t/solo", "lone-lib"] },
		]);
	});

	it("reports, not refuses, a unit whose imported cards pass their measure, and limits the card of a package many depend on", () => {
		const big = pkg("@t/big", { "src/contract.ts": "export const b = 1;\n" });
		const user = pkg(
			"@t/user",
			{ "src/contract.ts": 'import { b } from "@t/big";\nexport const u = b;\n' },
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/big": "workspace:*" } },
		);
		const card = "# @t/big\n".length;
		const measured = { ...budget, dependencyCardBytes: card - 1 };
		expect(check([big, user], measured)).toEqual([]);
		expect(heavyDependencyCards([big, user], measured)).toEqual([
			{ where: "@t/user", bytes: card },
		]);
		expect(heavyDependencyCards([big, user], { ...budget, dependencyCardBytes: card })).toEqual([]);
		const lines = (n: number) => `# p\n${"- x\n".repeat(n)}`;
		const dependedOn = {
			...pkg("@t/core", { "src/contract.ts": "export const c = 1;\n" }),
			card: lines(5),
		};
		const users = ["a", "b"].map((n) =>
			pkg(
				`@t/on-${n}`,
				{ "src/contract.ts": "export const x = 1;\n" },
				{
					exports: { ".": "./src/contract.ts" },
					dependencies: { "@t/core": "workspace:*" },
				},
			),
		);
		const narrow = { ...budget, narrowCardFanIn: 2, narrowCardLines: 6 };
		expect(check([dependedOn, ...users], narrow).map((v) => v.detail)).toEqual([
			"card lines 7 > 6",
		]);
		expect(check([dependedOn, ...users.slice(1)], narrow)).toEqual([]);
	});

	it("counts the workspace packages each unit's shipped code imports, against the dependency limit", () => {
		const deps = ["a", "b", "c"].map((n) =>
			pkg(`@t/dep-${n}`, { "src/contract.ts": "export const d = 1;\n" }),
		);
		const common = pkg(
			"@t/shared",
			{ "src/contract.ts": "export const s = 1;\n" },
			undefined,
			"common",
		);
		const declared = Object.fromEntries([...deps, common].map((d) => [d.name, "workspace:*"]));
		const uses = (names: string[]) =>
			names.map((n, i) => `import { d as d${i} } from "@t/dep-${n}";\n`).join("") +
			'import { s } from "@t/shared";\nexport const u = s;\n';
		const split = pkg(
			"@t/split",
			{
				"src/contract.ts": uses(["a"]),
				"src/inner/README.md": "# inner\n",
				"src/inner/inner.ts": uses(["b", "c"]),
			},
			{ exports: { ".": "./src/contract.ts" }, dependencies: declared },
		);
		const limit = { ...budget, dependencies: 1 };
		// The package declares three, but each unit is measured by what it imports; common ones are not counted.
		expect(
			check([...deps, common, split], limit)
				.filter((v) => v.detail.startsWith("dependencies"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@t/split/src/inner dependencies 2 > 1"]);
	});

	it("counts fixtures as test lines, but no other test table such as vectors", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/tables", {
			"src/contract.ts": line,
			"test/a.test.ts": line.repeat(2),
			"test/fixtures/big.ts": line.repeat(10),
			"test/cases.vectors.ts": line.repeat(10),
		});
		expect(check([p], { ...budget, testLines: 12 })).toEqual([]);
		expect(check([p], { ...budget, testLines: 11 }).map((v) => v.detail)).toEqual([
			"test lines 12 > 11",
		]);
	});

	it("holds every card item, nested ones too, to its bytes, naming its opening", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/items", {
			"src/contract.ts": line,
			"src/inner/README.md": `# inner\n  - ${"y".repeat(40)}\n`,
			"src/inner/x.ts": line,
		});
		expect(check([p], { ...budget, cardItemBytes: 44 })).toEqual([]);
		expect(
			check([p], { ...budget, cardItemBytes: 40 }).map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@t/items/src/inner card item bytes 44 > 40 (yyyyyyyyyyyy…)"]);
	});

	it("holds each card item to a package's exception for its bytes, looser or stricter than the budget", () => {
		const p = {
			...pkg("@t/item", { "src/contract.ts": "export const n = 1;\n" }),
			card: `# item\n- ${"z".repeat(13)}\n`,
		};
		const items = (cardItemBytes: number, limit: number) =>
			check([p], {
				...budget,
				cardItemBytes,
				exceptions: [{ package: "@t/item", measure: "card item bytes", limit, reason: "why" }],
			})
				.filter((v) => v.detail.startsWith("card item bytes"))
				.map((v) => v.detail);
		// The item is 15 bytes: past the budget's 10, within the exception's 20.
		expect(items(10, 20)).toEqual([]);
		// Within the budget's 20, past the exception's 12.
		expect(items(20, 12)).toEqual(["card item bytes 15 > 12 (zzzzzzzzzzzz…)"]);
	});

	it("counts comment lines from the syntax tree, ignoring // inside strings, against a share or a floor", () => {
		const p = pkg("@t/d", {
			"src/contract.ts":
				// biome-ignore lint/suspicious/noTemplateCurlyInString: the source under test holds a template
				"export const url = `http://x/${1}//y`;\n// why\n/* a\n b */\n// c\n// d\nexport const n = 1;\n",
		});
		expect(check([p], budget).map((v) => v.detail)).toEqual(["comment lines 5 > 4"]);
		const code = "export const n = 1;\n".repeat(60);
		const large = pkg("@t/large", { "src/contract.ts": `${"// why\n".repeat(6)}${code}` });
		expect(check([large], budget)).toEqual([]);
		const over = pkg("@t/over", { "src/contract.ts": `${"// why\n".repeat(7)}${code}` });
		expect(check([over], budget).map((v) => v.detail)).toEqual(["comment lines 7 > 6.7"]);
	});

	it("leaves the doc comments of a package's public surface out of the comment share, and counts every other comment", () => {
		const why = (n: number) => "// why\n".repeat(n);
		const filler = (n: number) =>
			Array.from({ length: n }, (_, i) => `const f${i} = ${i};\n`).join("");
		const surface =
			"/** A value. */\nexport const a = 1;\n/**\n * A shape.\n */\nexport interface Shape {\n" +
			"\t/** Its size. */\n\treadonly size: number;\n}\n/** A name. */\n" +
			'export type Name = { readonly first: string };\nexport { b } from "./b.ts";\n';
		const reexported = "/** Another value. */\nexport const b = 2;\n";
		// Seven doc comment lines on the public surface, five comments of the implementation, sixty lines.
		const docs = pkg("@t/docs", {
			"src/contract.ts": `${surface}${why(5)}${filler(41)}`,
			"src/b.ts": reexported,
		});
		expect(check([docs], budget)).toEqual([]);
		const implementation = pkg("@t/implementation", {
			"src/contract.ts": `${surface}${why(7)}${filler(39)}`,
			"src/b.ts": reexported,
		});
		expect(check([implementation], budget).map((v) => v.detail)).toEqual(["comment lines 7 > 6"]);
		// A declaration exported only to another file of the package is no public surface.
		const between = pkg("@t/between", {
			"src/contract.ts": `import { b } from "./b.ts";\nexport const a = b;\n${why(5)}${filler(49)}`,
			"src/b.ts": "/**\n * Shared within the package.\n */\nexport const b = 2;\n",
		});
		expect(check([between], budget).map((v) => v.detail)).toEqual(["comment lines 8 > 6"]);
	});

	it("G15 refuses branches, loops, choosing operators and walking calls in a wiring module's source", () => {
		const branchy =
			"export const a = (x: number) => (x > 0 ? 1 : 2);\nexport function b(xs: number[]) {\n\tfor (const x of xs) if (x) return x;\n\twhile (xs.length) xs.pop();\n\tswitch (xs.length) {\n\t\tdefault:\n\t}\n\tdo {} while (false);\n\txs.map((x) => x).filter(Boolean);\n\treturn (xs[0] ?? xs[1]) || (xs[2] && xs[3]);\n}\n";
		const wiring = pkg(
			"@t/wiring",
			{ "src/contract.ts": branchy, "test/x.test.ts": branchy },
			undefined,
			"wiring",
		);
		expect(
			check([wiring], budget)
				.filter((v) => v.rule.startsWith("G15"))
				.map((v) => v.detail)
				.sort(),
		).toEqual([
			"&&",
			".filter()",
			".map()",
			"?:",
			"??",
			"do",
			"for",
			"if",
			"switch",
			"while",
			"||",
		]);
		const plain = pkg("@t/plain", { "src/contract.ts": branchy });
		expect(rules([plain])).not.toContain("G15");
	});

	it("G17 refuses a card that writes a plan or a move in progress", () => {
		const planned = pkg("@t/planned", { "src/contract.ts": "export const n = 1;\n" });
		const moving = pkg("@t/moving", { "src/contract.ts": "export const n = 1;\n" });
		const cards = [
			{ ...planned, card: `${planned.card}- Not yet built (some day): something\n` },
			{ ...moving, card: `${moving.card}- Moving to another module: something\n` },
		];
		expect(
			check(cards, budget)
				.filter((v) => v.rule.startsWith("G17"))
				.map((v) => v.where),
		).toEqual(["@t/planned", "@t/moving"]);
		expect(rules([planned])).not.toContain("G17");
	});

	it("G17 refuses a card that says a part moved or is being removed, never a value that moved or one removed", () => {
		const moved = pkg("@t/moved", { "src/contract.ts": "export const n = 1;\n" });
		const going = pkg("@t/going", { "src/contract.ts": "export const n = 1;\n" });
		const kept = pkg("@t/kept", { "src/contract.ts": "export const n = 1;\n" });
		const cards = [
			{ ...moved, card: `${moved.card}- Moved to another module: something\n` },
			{ ...going, card: `${going.card}- The old entry, being removed: something\n` },
			{
				...kept,
				card: `${kept.card}- A value moved to another owner is refused, and one removed is gone.\n`,
			},
		];
		expect(
			check(cards, budget)
				.filter((v) => v.rule.startsWith("G17"))
				.map((v) => v.where),
		).toEqual(["@t/moved", "@t/going"]);
	});

	it("G13 refuses reading the clock directly where the time must come from the kernel", () => {
		const reads =
			"export const a = Date.now();\nexport const b = new Date();\nexport const c = performance.now();\n";
		const passes = "export const d = new Date(0);\nexport const e = { now: () => 1 }.now();\n";
		const feature = pkg("@t/clock", { "src/contract.ts": reads + passes, "test/x.test.ts": reads });
		expect(check([feature], budget).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`)).toEqual([
			"G13 Date.now()",
			"G13 new Date()",
			"G13 performance.now()",
		]);
		const tooling = pkg("@t/tool", { "src/contract.ts": reads }, undefined, "verification");
		expect(rules([tooling])).not.toContain("G13");
		const suite = pkg(
			"@t/suite",
			{ "src/contract.ts": "export const n = 1;\n", "src/testing.ts": reads },
			{ exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" } },
		);
		expect(rules([suite])).not.toContain("G13");
	});

	it("G23 refuses drawing randomness directly where it must come from the kernel", () => {
		const names = [
			"randomBytes",
			"randomFill",
			"randomFillSync",
			"randomInt",
			"randomUUID",
			"getRandomValues",
			"generateKey",
			"generateKeySync",
			"generateKeyPair",
			"generateKeyPairSync",
			"generatePrime",
			"generatePrimeSync",
		];
		const draws = [
			`import { ${names.join(", ")} as last } from "node:crypto";`,
			'import * as nc from "crypto";',
			"export const a = Math.random();",
			"export const b = nc.randomInt(9);",
			"export const c = crypto.getRandomValues(new Uint8Array(4));",
			"export const d = globalThis.crypto.randomUUID();",
			"export const e = crypto.subtle.generateKey(x, true, []);",
			"",
		].join("\n");
		const passes = [
			'import { createHash } from "node:crypto";',
			"export const f = (c) => c.random.bytes(16);",
			"export const g = ({ random: () => 1 }).random();",
			"export const h = nc.createHash('sha256');",
			"",
		].join("\n");
		const feature = pkg("@t/random", {
			"src/contract.ts": draws + passes,
			"test/x.test.ts": draws,
		});
		const found = check([feature], budget).filter((v) => v.rule.startsWith("G23"));
		expect(found.map((v) => `${v.rule.split(" ")[0]} ${v.detail}`)).toEqual([
			...names.map((name) => `G23 ${name} from node:crypto`),
			"G23 Math.random()",
			"G23 randomInt from crypto",
			"G23 crypto.getRandomValues()",
			"G23 globalThis.crypto.randomUUID()",
			"G23 crypto.subtle.generateKey()",
		]);
		const tooling = pkg("@t/tool-random", { "src/contract.ts": draws }, undefined, "verification");
		expect(rules([tooling])).not.toContain("G23");
		const suite = pkg(
			"@t/suite-random",
			{ "src/contract.ts": "export const n = 1;\n", "src/testing.ts": draws },
			{ exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" } },
		);
		expect(rules([suite])).not.toContain("G23");
	});

	it("G21 refuses a document line that lays out a list of the configuration in its order", () => {
		const lines = [
			"1. common 2. protocol 3. foundation 4. capability, in that order",
			"- `foundation`, `capability` and `feature`",
			"a foundation module and a capability, then a feature",
			"feature, capability, foundation",
			"foundation, capability",
			"foundation, feature, adapter",
			"Foundation, Capability, or Feature",
			"capability, feature, adapter",
			"the common, foundation",
		];
		const g21 = check([], budget, [{ path: join(root, "notes.md"), text: lines.join("\n") }])
			.filter((v) => v.rule.startsWith("G21"))
			.map((v) => v.detail);
		expect(g21).toEqual([
			"common, protocol, foundation, capability",
			"foundation, capability, feature",
			"foundation, capability, feature",
			"capability, feature, adapter",
		]);
	});

	it("G11 refuses line numbers in comments and documents, and G12 files outside a document's directory", () => {
		const p = pkg("@t/refs", {
			"src/contract.ts": `// see a.ts:${12}\nexport const s = "b.ts:${3}";\n`,
			"README.md": "x\n",
		});
		expect(check([p], budget).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`)).toEqual([
			`G11 a.ts:${12}`,
		]);
		const dir = p.dir;
		mkdirSync(join(dir, "modules"));
		const doc = (text: string) => check([], budget, [{ path: join(dir, "README.md"), text }]);
		const found = (text: string) => doc(text).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`);
		expect(
			found(
				`see \`src/contract.ts\` and \`./testing\`, [card](README.md), [rfc](https://x.example/a.md)`,
			),
		).toEqual([]);
		expect(found(`at line ${12}`)).toEqual([`G11 line ${12}`]);
		expect(found("[x](f.ts#L3)")).toEqual(["G11 #L3", "G12 f.ts"]);
		expect(found("[up](../other/README.md) and `modules/x/y.ts`")).toEqual([
			"G12 ../other/README.md",
			"G12 modules/x/y.ts",
		]);
	});

	it("G12 reads an inline path rooted at / as a location, and still reads a link target in full", () => {
		const p = pkg("@t/routes", { "README.md": "x\n" });
		mkdirSync(join(p.dir, "some"));
		const doc = (text: string) => check([], budget, [{ path: join(p.dir, "README.md"), text }]);
		const found = (text: string) => doc(text).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`);
		expect(
			found("| `GET /.well-known/jwks.json` | `POST /oauth/token` | `/etc/app/config.json` |"),
		).toEqual([]);
		// Read from any later position, each tail would name a missing file and be refused.
		expect(
			found("`/modules/x/README.md`, (/a/b.ts), '/c/d.json', \"/e/../f.md\" and /g/h.yaml"),
		).toEqual([]);
		expect(found("[card](/modules/x/README.md)")).toEqual(["G12 /modules/x/README.md"]);
		expect(found("`../other/file.md` and `some/dir/missing.md`")).toEqual([
			"G12 ../other/file.md",
			"G12 some/dir/missing.md",
		]);
	});

	it("G12 reads no fenced code block, whose samples show another project's files; G11 and G21 still do", () => {
		const p = pkg("@t/samples", { "README.md": "x\n" });
		mkdirSync(join(p.dir, "some"));
		const doc = (text: string) => check([], budget, [{ path: join(p.dir, "README.md"), text }]);
		const found = (text: string) => doc(text).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`);
		const fence = "\x60\x60\x60";
		const sample = `${fence}json\n{ "exports": { "./module": { "types": "./module.d.ts", "default": "./module.js" } } }\n[up](../other/README.md)\n${fence}`;
		expect(found(`${sample}\n`)).toEqual([]);
		expect(found(`${sample}\nsee \x60some/dir/missing.md\x60\n`)).toEqual([
			"G12 some/dir/missing.md",
		]);
		expect(found(`${fence}\nat line ${12}\n${fence}\n`)).toEqual([`G11 line ${12}`]);
	});

	it("G12 tells a refused path whole, its extension too, and reads no file whose extension it does not know", () => {
		const p = pkg("@t/whole", { "README.md": "x\n" });
		mkdirSync(join(p.dir, "some"));
		mkdirSync(join(p.dir, "other"));
		const doc = (text: string) => check([], budget, [{ path: join(p.dir, "README.md"), text }]);
		const found = (text: string) => doc(text).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`);
		expect(found("`some/dir/package.json` and `other/dir/notes.yaml`")).toEqual([
			"G12 some/dir/package.json",
			"G12 other/dir/notes.yaml",
		]);
		expect(found("`some/dir/view.tsx` and `some/dir/data.jsonl`")).toEqual([]);
	});

	it("G12 reads an inline path as the repository's only where its first part is beside the document", () => {
		const p = pkg("@t/generated", { "README.md": "x\n", "docs/guide.md": "x\n" });
		const doc = (text: string) => check([], budget, [{ path: join(p.dir, "README.md"), text }]);
		const found = (text: string) => doc(text).map((v) => `${v.rule.split(" ")[0]} ${v.detail}`);
		// No config/ or src/ beside the document: these name files of a generated app, fenced or not.
		expect(
			found(
				"Edit `config/local.conf` and `config/application.conf`, then `src/main.ts`.\n\n```sh\ncp config/local.conf.example config/local.conf\n```\n",
			),
		).toEqual([]);
		// docs/ is beside the document, so a missing file in it is still refused; a code block is not read.
		expect(found("`docs/guide.md`, `docs/missing.md`\n\n```\nsee docs/migraton.md\n```\n")).toEqual(
			["G12 docs/missing.md"],
		);
		// An explicitly relative path is read whatever its first part; a link target is read in full.
		expect(found("`./config/local.conf`, `../other/file.md` and [cfg](config/local.conf)")).toEqual(
			["G12 config/local.conf", "G12 ./config/local.conf", "G12 ../other/file.md"],
		);
	});
});
