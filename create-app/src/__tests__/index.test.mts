import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isValidDirName, isValidProjectName, scaffold } from "../index.mjs";

describe("scaffold", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "create-auth-provider-test-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("copies template files to target directory", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		expect(existsSync(join(targetDir, "package.json"))).toBe(true);
		expect(existsSync(join(targetDir, "tsconfig.json"))).toBe(true);
		expect(existsSync(join(targetDir, "src", "app.mts"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "application.conf"))).toBe(true);
	});

	it("rewrites package.json name to project name", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-auth");
	});

	it("replaces all workspace:* dependencies with caret versions", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));

		// No workspace:* should remain anywhere
		for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
			const deps = pkg[section];
			if (!deps) continue;
			for (const [name, version] of Object.entries(deps)) {
				expect(version, `${section}.${name} should not be workspace:*`).not.toBe("workspace:*");
			}
		}

		// Specific checks
		expect(pkg.dependencies["@o3co/auth-provider-core"]).toMatch(/^\^/);
		expect(pkg.dependencies["@o3co/auth-provider-foundation"]).toMatch(/^\^/);
	});

	it("removes private field from package.json", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.private).toBeUndefined();
	});

	it("writes scoped project name verbatim into package.json", () => {
		const targetDir = join(tempDir, "auth.provider");
		scaffold(targetDir, "@piratis-blossoms/auth.provider");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.provider");
	});
});

describe("isValidProjectName", () => {
	it.each([
		["my-auth"],
		["auth.provider"],
		["a"],
		["foo_bar~baz.1"],
		["@piratis-blossoms/auth.provider"],
		["@foo-bar/baz_qux~1"],
	])("accepts %s", (name) => {
		expect(isValidProjectName(name)).toBe(true);
	});

	it.each([
		[""],
		["."],
		[".."],
		["UPPER"],
		["with space"],
		["with/slash"],
		["with\\back"],
		["@"],
		["@/"],
		["@scope"],
		["@/pkg"],
		["@scope/"],
		["@scope//pkg"],
		["@SCOPE/pkg"],
		["a".repeat(215)],
	])("rejects %s", (name) => {
		expect(isValidProjectName(name)).toBe(false);
	});
});

describe("isValidDirName", () => {
	it.each([["my-auth"], ["auth.provider"], ["a"], ["foo_bar~baz.1"]])("accepts %s", (name) => {
		expect(isValidDirName(name)).toBe(true);
	});

	it.each([
		[""],
		["."],
		[".."],
		["@scope/pkg"],
		["with/slash"],
		["with\\back"],
		["@piratis-blossoms"],
		["UPPER"],
		["a".repeat(215)],
	])("rejects %s", (name) => {
		expect(isValidDirName(name)).toBe(false);
	});
});
