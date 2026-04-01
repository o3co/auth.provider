import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scaffold } from "../index.mjs";

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

	it("replaces workspace:* core dependency with caret version", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.dependencies["@o3co/auth-provider-core"]).not.toBe("workspace:*");
		expect(pkg.dependencies["@o3co/auth-provider-core"]).toMatch(/^\^/);
	});

	it("removes private field from package.json", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.private).toBeUndefined();
	});
});
