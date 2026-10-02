/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_TEMPLATE, scaffold } from "../index.mjs";

// A scaffold, with and without MFA, typechecked and run: its own suite, which
// boots the composition from the scaffold's configuration. The packages are
// the workspace's, linked from the template's own `node_modules` — every one
// but the MFA package for the scaffold without MFA, so an import of it left
// anywhere fails the typecheck and the run.

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATE_MODULES = resolve(__dirname, "../../../templates", DEFAULT_TEMPLATE, "node_modules");
const MFA_PACKAGE = "auth-provider-mfa";

/**
 * Link `targetDir/node_modules` to the template's installed packages, leaving
 * out `@o3co/<omit>`. The links resolve to the workspace's packages, built.
 */
const linkModules = (targetDir: string, omit: readonly string[]): void => {
	const modules = join(targetDir, "node_modules");
	mkdirSync(join(modules, "@o3co"), { recursive: true });
	for (const entry of readdirSync(TEMPLATE_MODULES)) {
		if (entry === "@o3co" || entry === ".bin") continue;
		symlinkSync(join(TEMPLATE_MODULES, entry), join(modules, entry));
	}
	for (const entry of readdirSync(join(TEMPLATE_MODULES, "@o3co"))) {
		if (omit.includes(entry)) continue;
		symlinkSync(join(TEMPLATE_MODULES, "@o3co", entry), join(modules, "@o3co", entry));
	}
};

/** Run `node <script> ...args` in `cwd`, outside this run's own vitest environment. */
const run = (cwd: string, script: string, args: readonly string[]) => {
	const env = Object.fromEntries(
		Object.entries(process.env).filter(([name]) => !name.startsWith("VITEST")),
	);
	return spawnSync(process.execPath, [script, ...args], { cwd, env, encoding: "utf-8" });
};

describe.each([
	{ variant: "with MFA", mfa: true, omit: [] },
	{ variant: "without MFA", mfa: false, omit: [MFA_PACKAGE] },
])("a scaffold $variant", ({ mfa, omit }) => {
	let workspace: string;
	let targetDir: string;

	beforeAll(() => {
		workspace = mkdtempSync(join(tmpdir(), "create-auth-provider-runs-"));
		targetDir = join(workspace, "project");
		scaffold(targetDir, "project", DEFAULT_TEMPLATE, { mfa });
		linkModules(targetDir, omit);
	});

	afterAll(() => {
		if (workspace) rmSync(workspace, { recursive: true, force: true });
	});

	it("is linked to the packages it names, and no other (the runs below are not vacuous)", () => {
		expect(existsSync(join(targetDir, "node_modules", "@o3co", "auth-provider-core"))).toBe(true);
		expect(existsSync(join(targetDir, "node_modules", "@o3co", MFA_PACKAGE))).toBe(mfa);
	});

	it("typechecks", () => {
		const result = run(targetDir, join("node_modules", "typescript", "bin", "tsc"), [
			"--noEmit",
			"-p",
			"tsconfig.json",
		]);
		expect(result.stdout + result.stderr, "tsc --noEmit").toBe("");
		expect(result.status).toBe(0);
	}, 180_000);

	it("passes its own suite, which boots its composition", () => {
		const result = run(targetDir, join("node_modules", "vitest", "vitest.mjs"), [
			"run",
			"--maxWorkers=2",
		]);
		expect(result.status, result.stdout + result.stderr).toBe(0);
	}, 300_000);
});
