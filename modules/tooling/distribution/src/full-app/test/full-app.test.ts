import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, it } from "vitest";
import { entrance, fullApp, releaseOptIns } from "../full-app.ts";

const scratch = mkdtempSync(join(tmpdir(), "full-app-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const bundle = "@o3co/auth-provider-scaffold";
/** A release's own opt-ins, which the workspace's `combinations` does not name. */
const theRelease = ["@mod/only-in-the-release"];
/** The `combinations` source of a release that opts `theRelease` in. */
const releaseCombinations = 'export const optIns = () => ["@mod/only-in-the-release"];\n';

/** Writes `files` under `dir`, each path relative to it. */
const written = (dir: string, files: Readonly<Record<string, string>>) => {
	for (const [path, text] of Object.entries(files)) {
		mkdirSync(join(dir, path, ".."), { recursive: true });
		writeFileSync(join(dir, path), text);
	}
};

const entranceManifest = (dependencies: Readonly<Record<string, string>>) =>
	JSON.stringify({
		name: entrance,
		version: "9.9.9",
		type: "module",
		bin: { "create-auth-provider": "main.js" },
		dependencies,
	});
const bundleFiles = (combinations: string) => ({
	"package.json": JSON.stringify({
		name: bundle,
		version: "9.9.9",
		type: "module",
		exports: { "./combinations": "./combinations/contract.js" },
	}),
	"combinations/contract.js": combinations,
});

/** A project with an entrance and its bundle installed as a flat `node_modules` holds them. */
const installed = (name: string, dependencies: Record<string, string>, combinations: string) => {
	const project = join(scratch, name);
	written(join(project, "node_modules", entrance), {
		"package.json": entranceManifest(dependencies),
	});
	written(join(project, "node_modules", bundle), bundleFiles(combinations));
	return project;
};

it("reads the features that opt in from the release installed, not from the workspace", () => {
	const project = installed("told", { [bundle]: "9.9.9" }, releaseCombinations);
	expect(releaseOptIns(project)).toEqual(theRelease);
});

it("refuses an entrance that depends on other than its bundle alone", () => {
	const project = installed("two", { [bundle]: "9.9.9", other: "1.0.0" }, "");
	expect(() => releaseOptIns(project)).toThrow(
		`${entrance} depends on 2 packages, not its bundle alone`,
	);
});

it("refuses opt-ins the release does not tell as a list of names", () => {
	const project = installed(
		"malformed",
		{ [bundle]: "9.9.9" },
		"export const optIns = () => [1];\n",
	);
	expect(() => releaseOptIns(project)).toThrow("the release's opt-ins are not a list of names");
});

it("is refused, before anything is installed, where the tarballs hold no entrance", () => {
	expect(() => fullApp({ "@o3co/auth-provider-oauth": "/t/oauth.tgz" }, scratch)).toThrow(
		`no ${entrance} tarball among the tarballs`,
	);
});

it("makes the full template with every feature the release in the tarballs opts in", () => {
	const tarballs = join(scratch, "tarballs");
	mkdirSync(tarballs);
	/** Packs `files` as a package's tarball; `main.js`, where given, made executable. */
	const packed = (name: string, files: Readonly<Record<string, string>>) => {
		const src = join(scratch, `${name}-src`);
		written(join(src, "package"), files);
		if (files["main.js"]) chmodSync(join(src, "package", "main.js"), 0o755);
		const file = join(tarballs, `${name}-9.9.9.tgz`);
		execFileSync("tar", ["-czf", file, "package"], { cwd: src });
		return file;
	};
	// The entrance writes the arguments it was given into the app.
	const main = `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const [app, ...given] = process.argv.slice(2);
mkdirSync(app, { recursive: true });
writeFileSync(join(app, "given.json"), JSON.stringify(given));
`;
	const byName = {
		[entrance]: packed("entrance", {
			"package.json": entranceManifest({ [bundle]: "9.9.9" }),
			"main.js": main,
		}),
		[bundle]: packed("scaffold", bundleFiles(releaseCombinations)),
	};
	const { app } = fullApp(byName, mkdtempSync(join(scratch, "made-")));
	expect(JSON.parse(readFileSync(join(app, "given.json"), "utf8"))).toEqual([
		"--pattern",
		"full",
		"--add",
		theRelease[0],
	]);
}, 120_000);
