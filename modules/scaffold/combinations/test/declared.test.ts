import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { completedWith, declaredIn, declaredInIndex } from "../src/declared.ts";

// Generating and reading a workspace spawn pnpm, slow on a loaded machine.
vi.setConfig({ testTimeout: 30_000 });

/** The fixture workspace, read once: reading a workspace takes a while. */
const declared = declaredIn(join(import.meta.dirname, "fixture"));

it("finds the wirings and bridges the modules declare, in code point order of name", () => {
	expect([...declared.wirings]).toEqual([
		["@t/bridge", ["@t/bridge-store"]],
		["@t/feature", ["@t/feature-store", "@t/other-store"]],
	]);
	expect(declared.bridges).toEqual([
		{ joins: ["@t/bridge", "@t/feature"], bridge: "@t/across" },
		{ joins: ["@t/feature", "@t/plain"], bridge: "@t/bridge" },
	]);
});

it("refuses a joins that is not a non-empty list of names, and a wires that is not a name, naming each package", () => {
	expect(() => declaredIn(join(import.meta.dirname, "malformed"))).toThrow(
		"@t/empty, @t/odd, @t/string: joins is not a non-empty list of module names; " +
			"@t/wired-empty, @t/wired-list, @t/wired-number: wires is not a module name",
	);
}, 30_000);

it("completes modules with what is declared for them: wirings by feature, a bridge once all it joins are there", () => {
	expect(completedWith(declared, ["@t/feature", "@t/feature"])).toEqual([
		"@t/feature",
		"@t/feature",
		"@t/feature-store",
		"@t/other-store",
	]);
	expect(completedWith(declared, ["@t/plain"])).toEqual(["@t/plain"]);
});

it("completes what completing brought in: a bridge's wiring, and a bridge that joins a bridge", () => {
	expect(completedWith(declared, ["@t/plain", "@t/feature", "@t/feature-store"])).toEqual([
		"@t/plain",
		"@t/feature",
		"@t/feature-store",
		"@t/other-store",
		"@t/bridge",
		"@t/bridge-store",
		"@t/across",
	]);
});

it("reads the same declarations from a bundle's index as from the workspace it was written from", () => {
	const workspace = join(import.meta.dirname, "composition");
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], {
			cwd: workspace,
			encoding: "utf8",
		}),
	) as { path: string }[];
	const packages = listed.map(({ path }) => ({
		manifest: JSON.parse(readFileSync(join(path, "package.json"), "utf8")),
	}));
	const index = join(mkdtempSync(join(tmpdir(), "combinations-")), "index.json");
	writeFileSync(index, JSON.stringify({ version: "0.18.0", packages }));
	expect(declaredInIndex(index)).toEqual(declaredIn(workspace));
}, 30_000);
