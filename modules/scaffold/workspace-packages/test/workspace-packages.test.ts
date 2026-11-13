import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { workspacePackages } from "../src/contract.ts";

const made: string[] = [];
afterEach(() => {
	for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A workspace in a new directory: its definition (none where undefined) and a package at each path. */
function workspace(definition: string | undefined, packages: Record<string, string | undefined>) {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "workspace-packages-")));
	made.push(root);
	writeFileSync(join(root, "package.json"), JSON.stringify({ name: "root" }));
	if (definition !== undefined) writeFileSync(join(root, "pnpm-workspace.yaml"), definition);
	for (const [path, name] of Object.entries(packages)) {
		mkdirSync(join(root, path), { recursive: true });
		if (name !== undefined)
			writeFileSync(join(root, path, "package.json"), JSON.stringify({ name }));
	}
	return root;
}

const names = (root: string) => workspacePackages(root).map((p) => p.name);

describe("workspacePackages", () => {
	it("lists this repository's packages as pnpm does, in the same order", () => {
		const root = realpathSync(join(import.meta.dirname, "..", "..", "..", ".."));
		const listed = JSON.parse(
			execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], {
				cwd: root,
				encoding: "utf8",
			}),
		) as { name: string; path: string }[];
		expect(workspacePackages(root)).toEqual(
			listed.filter((e) => e.path !== root).map((e) => ({ name: e.name, dir: e.path })),
		);
	}, 60_000);

	it("counts a directory only where it holds a package.json", () => {
		const root = workspace('packages:\n  - "a/*"\n', { "a/x": "x", "a/empty": undefined });
		expect(workspacePackages(root)).toEqual([{ name: "x", dir: join(root, "a", "x") }]);
	});

	it("takes neither a hidden directory nor node_modules for a *", () => {
		const root = workspace('packages:\n  - "a/*"\n', {
			"a/x": "x",
			"a/.hidden": "hidden",
			"a/node_modules": "modules",
		});
		expect(names(root)).toEqual(["x"]);
	});

	it("leaves out what a negation reaches, before or after the pattern it narrows", () => {
		const packages = { "a/x": "x", "a/y": "y", "b/z": "z" };
		expect(names(workspace('packages:\n  - "!a/y"\n  - "a/*"\n  - "b/*"\n', packages))).toEqual([
			"x",
			"z",
		]);
		expect(names(workspace('packages:\n  - "a/*"\n  - "!a/y"\n  - "a/y"\n', packages))).toEqual([
			"x",
		]);
	});

	it("answers real paths, the root reached through a link", () => {
		const root = workspace('packages:\n  - "a/*"\n', { "a/x": "x" });
		const link = join(realpathSync(mkdtempSync(join(tmpdir(), "workspace-link-"))), "here");
		made.push(join(link, ".."));
		symlinkSync(root, link);
		expect(workspacePackages(link)).toEqual([{ name: "x", dir: join(root, "a", "x") }]);
	});

	it("lists a definition it does not read as pnpm does, the root left out", () => {
		const root = workspace('packages:\n  - "a/**"\n', { "a/x": "x", "a/deep/y": "y" });
		expect(names(root)).toEqual(["y", "x"]);
	}, 60_000);

	it("leaves a package.json it cannot read to pnpm, never dropping the package", () => {
		const root = workspace('packages:\n  - "a/*"\n', { "a/x": "x", "a/broken": "broken" });
		writeFileSync(join(root, "a", "broken", "package.json"), "{ not json");
		expect(() => workspacePackages(root)).toThrow();
	}, 60_000);

	it("reads pnpm's lists whole, a bracket in a path among them", () => {
		const root = workspace('packages:\n  - "a/**"\n', { "a/x][y": "x", "a/z": "z" });
		expect(names(root)).toEqual(["x", "z"]);
	}, 60_000);

	it("lists a workspace with no definition as pnpm does", () => {
		const root = workspace(undefined, { "a/x": "x" });
		expect(names(root)).toEqual(["x"]);
	}, 60_000);
});
