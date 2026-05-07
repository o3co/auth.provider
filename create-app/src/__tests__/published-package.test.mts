/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CREATE_APP_DIR = resolve(__dirname, "../..");

interface NpmPackResult {
	readonly filename: string;
}

describe("published-package install context (e2e)", () => {
	let workspace: string;
	let tarballPath: string;

	beforeAll(() => {
		workspace = mkdtempSync(join(tmpdir(), "create-auth-provider-e2e-"));
		// Isolate npm's cache to a per-run directory so a polluted developer
		// `~/.npm/_cacache/` (e.g. root-owned files left by a sudo install) cannot
		// fail the test with EPERM. The prepack hook only needs to read the
		// workspace, but `npm pack` itself touches the cache regardless.
		const npmCache = join(workspace, "npm-cache");
		// `npm pack` runs the `prepack` script (rimraf dist + copy-templates + tsc),
		// so this exercises the same artifact npm publishes to the registry.
		const stdout = execFileSync("npm", ["pack", "--pack-destination", workspace, "--json"], {
			cwd: CREATE_APP_DIR,
			encoding: "utf-8",
			env: { ...process.env, npm_config_cache: npmCache },
		});
		const [packed] = JSON.parse(stdout) as readonly NpmPackResult[];
		tarballPath = join(workspace, packed.filename);
	}, 120_000);

	afterAll(() => {
		if (workspace) rmSync(workspace, { recursive: true, force: true });
	});

	it("scaffolds successfully when installed under a path containing 'node_modules'", () => {
		// Regression for v0.5.0 npx bug: simulate the actual install layout
		// (~/.npm/_npx/<hash>/node_modules/@o3co/create-auth-provider/) so the
		// cpSync filter sees an absolute source path whose ancestors include
		// 'node_modules'. Before the fix, the filter excluded every file and
		// `cpSync` left the target directory empty.
		const installRoot = join(workspace, "node_modules", "@o3co", "create-auth-provider");
		mkdirSync(installRoot, { recursive: true });
		execFileSync("tar", ["-xzf", tarballPath, "--strip-components=1", "-C", installRoot]);

		const projectCwd = join(workspace, "scaffold-cwd");
		mkdirSync(projectCwd);
		execFileSync("node", [join(installRoot, "dist", "cli.mjs"), "my-test-project"], {
			cwd: projectCwd,
			encoding: "utf-8",
		});

		const targetDir = join(projectCwd, "my-test-project");
		expect(existsSync(targetDir)).toBe(true);
		expect(existsSync(join(targetDir, "package.json"))).toBe(true);
		expect(existsSync(join(targetDir, "src", "app.mts"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "application.conf"))).toBe(true);

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-test-project");
		for (const section of ["dependencies", "devDependencies", "peerDependencies"] as const) {
			const deps = pkg[section] as Record<string, string> | undefined;
			if (!deps) continue;
			for (const [, version] of Object.entries(deps)) {
				expect(version).not.toBe("workspace:*");
			}
		}
	}, 30_000);
});
