import { expect, it } from "vitest";
import { loadsSubpath } from "../contract.ts";

// Each case is one node v26.12.0's resolver was asked to load, with what it did.
const loads = (target: unknown) => loadsSubpath({ "./module": target }, "./module");

it("loads a path inside the package, and conditions whose first met one reaches one", () => {
	expect(loads("./dist/module.js")).toBe(true);
	expect(loads({ import: "./dist/module.js" })).toBe(true);
	expect(loads({ types: "./m.d.ts", default: "./dist/module.js" })).toBe(true);
	expect(loads({ node: { require: "./m.cjs" }, default: "./dist/module.js" })).toBe(true);
});

it("loads no blocked target, refused path, or conditions node refuses", () => {
	for (const target of [
		null,
		{ require: "./dist/module.cjs" },
		{ node: null, default: "./dist/module.js" },
		{ "node-addons": null, default: "./dist/module.js" },
		{ "0": "./unused.js", import: "./dist/module.js" },
		"dist/module.js",
		"./../escape.js",
		"./node_modules/dep/index.js",
		"./dist/%2e%2e/escape.js",
		"./dist%2Fmodule.js",
		"./dist%5cmodule.js",
	]) {
		expect(loads(target), JSON.stringify(target)).toBe(false);
	}
});

it("loads no array and no empty segment, stricter than node, and nothing of a subpath not exported", () => {
	expect(loads(["./dist/module.js"])).toBe(false);
	expect(loads({ import: "./dist//module.js" })).toBe(false);
	expect(loadsSubpath({ ".": "./index.js" }, "./module")).toBe(false);
	expect(loadsSubpath("./index.js", "./module")).toBe(false);
});
