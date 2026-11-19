import { expect, it } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import type { Pkg } from "../../workspace.ts";
import { budgetsAsTest, scopeOf } from "../scope.ts";

/** Each of a package's files read as test code, by the scope of the packages given. */
const testCode = (p: Pkg, files: readonly string[]) => {
	const s = scopeOf([p], budget, () => {});
	return files.filter((file) => budgetsAsTest(s, p, file));
};

const suite = {
	"src/contract.ts": 'import type { Shape } from "./shape.ts";\nexport const a: Shape = 1;\n',
	"src/shape.ts": "export type Shape = number;\n",
	"src/testing.ts":
		'export { helper } from "./helper.ts";\nexport { shared } from "./shared.ts";\nimport type { Shape } from "./shape.ts";\nexport const t: Shape = 2;\n',
	"src/helper.ts": 'import { deeper } from "./deeper.ts";\nexport const helper = deeper;\n',
	"src/deeper.ts": "export const deeper = 1;\n",
	"src/shared.ts": "export const shared = 1;\n",
	"src/module.ts": 'import { shared } from "./shared.ts";\nexport default shared;\n',
	"src/loose.ts": "export const loose = 1;\n",
	"test/a.test.ts": 'import { loose } from "../src/loose.ts";\nexport const t = loose;\n',
};
const files = Object.keys(suite);

it("reads as test code a file `./testing` reaches and nothing else in the package does", () => {
	const p = pkg("@bt/suite", suite, {
		exports: {
			".": "./src/contract.ts",
			"./testing": "./src/testing.ts",
			"./module": "./src/module.ts",
		},
	});
	// shape.ts is reached from `.` by a type edge, shared.ts from `./module`, loose.ts from nothing but a test.
	expect(testCode(p, files)).toEqual([
		"src/testing.ts",
		"src/helper.ts",
		"src/deeper.ts",
		"test/a.test.ts",
	]);
});

it("reads a file `./testing` shares with a file no export names, as a script's entry, as shipped", () => {
	const script = {
		...suite,
		"src/script.ts": 'import { helper } from "./helper.ts";\nexport const run = helper;\n',
	};
	const p = pkg("@bt/script", script, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	const read = testCode(p, Object.keys(script));
	expect(read).not.toContain("src/helper.ts");
	expect(read).not.toContain("src/deeper.ts");
	expect(read).toContain("src/testing.ts");
});

it("reads every file as shipped where the shipped files hold an import the graph cannot resolve", () => {
	const unresolved = {
		...suite,
		"src/contract.ts":
			"export const a = 1;\nexport const load = (name: string) => import(`./${name}.ts`);\n",
	};
	const p = pkg("@bt/unresolved", unresolved, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	expect(testCode(p, Object.keys(unresolved))).toEqual(["test/a.test.ts"]);
});

it("takes each string target of a conditional export as shipped, and a conditional `./testing` as no test root", () => {
	const conditional = pkg("@bt/conditional", suite, {
		exports: {
			".": { types: "./src/contract.ts", default: "./src/helper.ts" },
			"./testing": "./src/testing.ts",
		} as never,
	});
	const read = testCode(conditional, files);
	expect(read).not.toContain("src/helper.ts");
	expect(read).toContain("src/testing.ts");
	const conditionalTesting = pkg("@bt/conditional-testing", suite, {
		exports: { ".": "./src/contract.ts", "./testing": { default: "./src/testing.ts" } } as never,
	});
	expect(testCode(conditionalTesting, files)).toEqual(["test/a.test.ts"]);
});

it("reads a file outside the graph by its name alone, never throwing", () => {
	const p = pkg("@bt/outside", suite, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	expect(
		testCode(p, ["templates/entry.ts.template", "dist/bundle.bundled.mjs", "missing.ts"]),
	).toEqual([]);
});

it("follows from `./testing` the imports that load or take types, never a resolve, which leaves a file it only names shipped", () => {
	const named = {
		...suite,
		"src/testing.ts": `${suite["src/testing.ts"]}export const where = import.meta.resolve("./script.ts");\nimport type { Kind } from "./kinds.ts";\nexport const k: Kind = 1;\n`,
		"src/script.ts": "export const run = 1;\n",
		"src/kinds.ts": "export type Kind = number;\n",
	};
	const p = pkg("@bt/named", named, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	const read = testCode(p, Object.keys(named));
	expect(read).not.toContain("src/script.ts");
	expect(read).toContain("src/kinds.ts");
	expect(read).toContain("src/helper.ts");
});

it("reads every file as shipped where the shipped walk reaches a script of the package that is no source, a root too", () => {
	const intermediate = {
		...suite,
		"src/contract.ts": 'import { bridge } from "./bridge.config.ts";\nexport const a = bridge;\n',
		"src/bridge.config.ts":
			'import { helper } from "./helper.ts";\nexport const bridge = helper;\n',
	};
	const viaConfig = pkg("@bt/intermediate", intermediate, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	expect(testCode(viaConfig, Object.keys(intermediate))).toEqual(["test/a.test.ts"]);
	const built = { ...suite, "dist/built.js": "export const built = 1;\n" };
	const rootBuilt = pkg("@bt/built", built, {
		exports: {
			".": "./src/contract.ts",
			"./built": "./dist/built.js",
			"./testing": "./src/testing.ts",
		},
	});
	expect(testCode(rootBuilt, Object.keys(built))).toEqual(["test/a.test.ts"]);
	const data = {
		...suite,
		"src/contract.ts":
			'import data from "./data.json" with { type: "json" };\nexport const a = data;\n',
		"src/data.json": "1\n",
	};
	const withData = pkg("@bt/data", data, {
		exports: { ".": "./src/contract.ts", "./testing": "./src/testing.ts" },
	});
	expect(testCode(withData, Object.keys(data))).toContain("src/helper.ts");
});
