import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { branchingImports, check, dependencyCards } from "../src/contract.ts";
import type { Pkg } from "../src/workspace.ts";
import { budget, pkg, root } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const rules = (packages: Pkg[]) => check(packages, budget).map((v) => v.rule.split(" ")[0]);

describe("guard", () => {
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

	it("limits the cards each unit imports, and the card of a package many depend on", () => {
		const big = pkg("@t/big", { "src/contract.ts": "export const b = 1;\n" });
		const user = pkg(
			"@t/user",
			{ "src/contract.ts": 'import { b } from "@t/big";\nexport const u = b;\n' },
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/big": "workspace:*" } },
		);
		const card = "# @t/big\n".length;
		expect(
			check([big, user], { ...budget, dependencyCardBytes: card - 1 }).map(
				(v) => `${v.where} ${v.detail}`,
			),
		).toEqual([`@t/user dependency cards ${card} > ${card - 1}`]);
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

	it("counts no test table as test lines: fixtures and vectors", () => {
		const line = "export const n = 1;\n";
		const p = pkg("@t/tables", {
			"src/contract.ts": line,
			"test/a.test.ts": line.repeat(2),
			"test/fixtures/big.ts": line.repeat(10),
			"test/cases.vectors.ts": line.repeat(10),
		});
		expect(check([p], { ...budget, testLines: 2 })).toEqual([]);
		expect(check([p], { ...budget, testLines: 1 }).map((v) => v.detail)).toEqual([
			"test lines 2 > 1",
		]);
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
			"1. common 2. foundation 3. capability 4. feature, in that order",
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
			"common, foundation, capability, feature",
			"foundation, capability, feature",
			"foundation, capability, feature",
			"capability, feature, adapter",
		]);
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
		expect(
			check([feature, keyed, bare, unkeyed], budget)
				.filter((v) => v.rule.startsWith("G24"))
				.map((v) => `${v.where} ${v.detail}`),
		).toEqual(["@t/g @t/g-store keys no guarantee by them"]);
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
		// docs/ is beside the document, so a missing file in it is still refused, fenced or not.
		expect(found("`docs/guide.md`, `docs/missing.md`\n\n```\nsee docs/migraton.md\n```\n")).toEqual(
			["G12 docs/missing.md", "G12 docs/migraton.md"],
		);
		// An explicitly relative path is read whatever its first part; a link target is read in full.
		expect(found("`./config/local.conf`, `../other/file.md` and [cfg](config/local.conf)")).toEqual(
			["G12 config/local.conf", "G12 ./config/local.conf", "G12 ../other/file.md"],
		);
	});
});
