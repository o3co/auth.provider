import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { parse } from "yaml";
import { run } from "../src/contract.ts";
import { generateFull } from "../src/full.ts";
import { generateListed } from "../src/listed.ts";
import { generatePattern } from "../src/pattern.ts";
import { patternNamed } from "../src/patterns/patterns.ts";
import { workspacePackages } from "../src/project.ts";
import { root } from "./full-app.ts";

// Composing reads the whole workspace, and reading a package asks pnpm, slow on a loaded machine.
vi.setConfig({ testTimeout: 120_000 });

/** An index as distribution writes it, every module of the workspace in one bundle at 0.19.0. */
function indexOfWorkspace(): string {
	const file = join(mkdtempSync(join(tmpdir(), "index-")), "index.json");
	const packages = [...workspacePackages(root).keys()]
		.filter((name) => name.startsWith("@mod/"))
		.map((name) => ({
			name,
			package: "@o3co/auth-provider-oauth",
			entry: `@o3co/auth-provider-oauth/${name.slice("@mod/".length)}`,
			manifest: { name },
		}));
	writeFileSync(file, JSON.stringify({ version: "0.19.0", packages }));
	return file;
}

/** The project an operator had pnpm install `@x/grant@1.2.0` into, a feature needing tokens (see src/outside's tests). */
function project(extra: Record<string, unknown> = {}): string {
	const at = mkdtempSync(join(tmpdir(), "project-"));
	const lock = readFileSync(
		join(import.meta.dirname, "..", "src", "outside", "test", "fixtures", "staging-lock.yaml"),
		"utf8",
	);
	writeFileSync(join(at, "pnpm-lock.yaml"), lock);
	writeFileSync(join(at, ".npmrc"), "registry=http://127.0.0.1:4873/\n");
	const stored = join(at, "node_modules", ".pnpm", "@x+grant@1.2.0", "node_modules", "@x", "grant");
	mkdirSync(stored, { recursive: true });
	writeFileSync(
		join(stored, "package.json"),
		JSON.stringify({
			name: "@x/grant",
			version: "1.2.0",
			exports: { "./module": "./dist/module.js" },
			dependencies: { "jose-lite": "^1.0.0", "real-alias": "npm:real-lib@^1.0.0" },
			optionalDependencies: { "fast-path": "^2.0.0" },
			peerDependencies: { "@o3co/auth-provider-oauth": "^0.19.0", zod: "^4.6.0" },
			authProvider: { format: 1, kind: "feature", needs: ["@mod/tokens"] },
			...extra,
		}),
	);
	writeFileSync(join(stored, "config.example"), 'grant {\n\tissuer = "REPLACE-ISSUER"\n}\n');
	writeFileSync(
		join(stored, "README.md"),
		"# grant\n\n## Deployment\n\nIt asks for a DID resolver.\n",
	);
	mkdirSync(join(at, "node_modules", "@x"), { recursive: true });
	symlinkSync(stored, join(at, "node_modules", "@x", "grant"));
	return at;
}

const read = (target: string, path: string) => readFile(join(target, path), "utf8");

describe("an app listing a package outside the release", () => {
	it("composes it with what it needs, depends on it at its recorded version, imports it by its name, and holds the lockfile to its record", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-app-")), "app");
		const plan = { target, outside: { from: project(), names: ["@x/grant"] } };
		await generateListed(plan, ["@x/grant"], "@mod/log-stdout", indexOfWorkspace());

		const manifest = JSON.parse(await read(target, "package.json"));
		expect(manifest.dependencies).toMatchObject({
			"@x/grant": "1.2.0",
			"@o3co/auth-provider-oauth": "0.19.0",
			zod: "4.6.7",
		});
		expect(manifest.scripts["check:outside"]).toBe("node scripts/check-outside.mjs");
		const main = await read(target, "src/main.ts");
		expect(main).toContain('from "@x/grant/module"');
		expect(main).toContain('from "@o3co/auth-provider-oauth/tokens/module"');
		expect(JSON.parse(await read(target, "outside-modules.json"))).toMatchObject({
			modules: [{ name: "@x/grant", version: "1.2.0" }],
			registries: { default: "http://127.0.0.1:4873" },
		});
		expect(parse(await read(target, "pnpm-workspace.yaml")).overrides).toEqual({
			"@o3co/auth-provider-oauth": "0.19.0",
			zod: "4.6.7",
		});
		expect(await read(target, "config/application.conf")).toContain("issuer = ${?GRANT_ISSUER}");
		const guide = await read(target, "README.md");
		expect(guide).toContain("`node_modules/@x/grant/README.md#deployment`");
		expect(guide).toContain("| `@x/grant` | `1.2.0` |");
	});

	it("lets a version published within the last day be installed where named, at its recorded version alone", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-app-")), "app");
		const plan = { target, outside: { from: project(), names: ["@x/grant"], fresh: ["@x/grant"] } };
		await generateListed(plan, ["@x/grant"], "@mod/log-stdout", indexOfWorkspace());
		const settings = parse(await read(target, "pnpm-workspace.yaml"));
		expect(settings.minimumReleaseAge).toBe(1440);
		expect(settings.minimumReleaseAgeExclude).toEqual([
			"@o3co/auth-provider-oauth",
			"@x/grant@1.2.0",
		]);
	});

	it("refuses through generation a package that breaks a rule, writing nothing", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-app-")), "app");
		const plan = {
			target,
			outside: { from: project({ scripts: { postinstall: "node x" } }), names: ["@x/grant"] },
		};
		await expect(
			generateListed(plan, ["@x/grant"], "@mod/log-stdout", indexOfWorkspace()),
		).rejects.toThrow("@x/grant: it runs postinstall when installed");
		await expect(readFile(join(target, "package.json"))).rejects.toThrow();
	});

	it("refuses to compose it beside a linked workspace, or beside no published release", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-app-")), "app");
		const outside = { from: project(), names: ["@x/grant"] };
		await expect(
			generateListed(
				{ target, workspace: root, outside },
				["@x/grant"],
				"@mod/log-stdout",
				indexOfWorkspace(),
			),
		).rejects.toThrow("a linked workspace composes no package outside the release");
		await expect(
			generateListed(
				{ target, outside },
				["@x/grant"],
				"@mod/log-stdout",
				join(tmpdir(), "no-index.json"),
			),
		).rejects.toThrow(
			"packages outside the release are composed beside the published release alone",
		);
	});
});

describe("naming a package outside the release on the command line", () => {
	const io = () => {
		const said = { out: "", err: "" };
		return {
			said,
			io: { out: (t: string) => (said.out += t), err: (t: string) => (said.err += t) },
		};
	};
	const target = () => join(mkdtempSync(join(tmpdir(), "outside-cli-")), "app");

	it("refuses npm:<name> without the project it is read from, and a project no npm: name uses", async () => {
		const missing = io();
		expect(await run([target(), "npm:@x/grant"], missing.io)).toBe(64);
		expect(missing.said.err).toContain("npm:<name> is read from --outside-from <project>");
		const unused = io();
		expect(await run([target(), "@mod/tokens", "--outside-from", "/somewhere"], unused.io)).toBe(
			64,
		);
		expect(unused.said.err).toContain("--outside-from names no package: none is named npm:<name>");
	});

	it("refuses npm:<name> beside a linked workspace, and a fresh name not named npm:", async () => {
		const linked = io();
		expect(
			await run(
				[target(), "npm:@x/grant", "--outside-from", "/somewhere", "--workspace", root],
				linked.io,
			),
		).toBe(64);
		expect(linked.said.err).toContain("a linked workspace composes no package outside the release");
		const fresh = io();
		expect(
			await run(
				[target(), "npm:@x/grant", "--outside-from", "/somewhere", "--allow-fresh", "@x/other"],
				fresh.io,
			),
		).toBe(64);
		expect(fresh.said.err).toContain("--allow-fresh @x/other: not named npm:@x/other");
	});

	it("refuses npm: naming no package, in a list or in --add", async () => {
		for (const args of [["npm:"], ["--add", "npm:"]]) {
			const said = io();
			expect(await run([target(), ...args, "--outside-from", "/somewhere"], said.io)).toBe(64);
			expect(said.said.err).toContain("npm: names no package: write npm:<name>");
		}
	});

	it("reads only the last choice of an axis given twice: a package outside it chose before is not read", async () => {
		const said = io();
		const args = [
			"--pattern",
			"simple-web",
			"--axis",
			"@mod/users=npm:@x/old",
			"--axis",
			"@mod/users=@mod/users",
		];
		expect(await run([target(), ...args, "--outside-from", "/somewhere"], said.io)).toBe(64);
		expect(said.said.err).toContain("--outside-from names no package: none is named npm:<name>");
	});

	it("takes npm:<name> in --add and an axis's module as well, and tells a plan it cannot make", async () => {
		// In the workspace nothing is published, so the plan is refused, after the names are taken.
		for (const args of [
			["--add", "npm:@x/grant"],
			["--pattern", "simple-web", "--axis", "@mod/users=npm:@x/users-db"],
		]) {
			const said = io();
			expect(await run([target(), ...args, "--outside-from", project()], said.io)).toBe(1);
			expect(said.said.err).toContain(
				"packages outside the release are composed beside the published release alone",
			);
		}
	});
});

describe("the full template and a pattern adding a package outside the release", () => {
	it("composes it in the full template, with the rest of the release", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-full-")), "app");
		const plan = {
			target,
			template: "full" as const,
			add: ["@x/grant"],
			outside: { from: project(), names: ["@x/grant"] },
		};
		await generateFull(plan, indexOfWorkspace());
		expect(await read(target, "src/main.ts")).toContain('from "@x/grant/module"');
		expect(JSON.parse(await read(target, "outside-modules.json")).modules[0].name).toBe("@x/grant");
	});

	it("composes it in a pattern, added to the pattern's selection", async () => {
		const target = join(mkdtempSync(join(tmpdir(), "outside-pattern-")), "app");
		const plan = {
			target,
			template: "simple-web",
			add: ["@x/grant"],
			outside: { from: project(), names: ["@x/grant"] },
		};
		await generatePattern(plan, patternNamed("simple-web"), indexOfWorkspace());
		expect(await read(target, "src/main.ts")).toContain('from "@x/grant/module"');
		expect(JSON.parse(await read(target, "package.json")).dependencies["@x/grant"]).toBe("1.2.0");
	});
});
