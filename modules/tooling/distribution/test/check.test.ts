import { describe, expect, it } from "vitest";
import { type Bundle, check } from "../src/contract.ts";

const bundle = (
	dir: string,
	shipped: boolean | undefined,
	members: [string, string[]][],
): Bundle => ({
	dir,
	shipped,
	members: members.map(([name, dependencies]) => ({ name, dir: `${dir}/${name}`, dependencies })),
});

describe("distribution", () => {
	it("derives bundle dependencies from members and accepts an acyclic shipped set", () => {
		const base = bundle("base", true, [["a", []]]);
		const feature = bundle("feature", true, [["b", ["a", "external-lib"]]]);
		expect(check([base, feature])).toEqual([]);
	});

	it("takes members of one bundle depending on each other as no cycle", () => {
		const one = bundle("one", true, [
			["a", ["b"]],
			["b", ["a"]],
		]);
		expect(check([one])).toEqual([]);
	});

	it("reports a cycle between bundles once, along its path", () => {
		const one = bundle("one", true, [["a", ["b"]]]);
		const two = bundle("two", true, [["b", ["a"]]]);
		expect(check([one, two])).toEqual(["bundle cycle: one → two → one"]);
	});

	it("reports a shipped bundle that depends on an unshipped one, and a missing manifest", () => {
		const tools = bundle("tools", false, [["t", []]]);
		const app = bundle("app", true, [["a", ["t"]]]);
		const loose = bundle("loose", undefined, [["l", []]]);
		expect(check([tools, app, loose])).toEqual([
			"app: depends on unshipped bundle tools",
			"loose: bundle manifest is missing",
		]);
	});

	it("lets an unshipped bundle depend on another, and reports a missing manifest only as missing", () => {
		const tools = bundle("tools", false, [["t", []]]);
		const scripts = bundle("scripts", false, [["s", ["t"]]]);
		const loose = bundle("loose", undefined, [["l", []]]);
		const app = bundle("app", true, [["a", ["l"]]]);
		expect(check([tools, scripts, loose, app])).toEqual(["loose: bundle manifest is missing"]);
	});
});
