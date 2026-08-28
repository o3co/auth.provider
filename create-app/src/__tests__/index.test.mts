import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix, win32 } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shouldCopyTemplateEntry } from "../internal/template-filter.mjs";

// generateLockfile shells out to a package manager. Every test in this file
// drives that boundary through the mock: the suite must never touch the
// network, and the monorepo's own template pins `workspace:*` placeholders
// that no registry can resolve anyway.
const { spawnSyncMock } = vi.hoisted(() => ({ spawnSyncMock: vi.fn() }));
vi.mock("node:child_process", () => ({ spawnSync: spawnSyncMock }));

// Imported AFTER vi.mock (repo pattern — see federation-google's test suite)
// so the mocked child_process is definitely registered before the module
// under test loads, independent of transform hoisting behavior.
const { generateLockfile, isValidDirName, isValidProjectName, main, scaffold } = await import(
	"../index.mjs"
);

const enoent = (bin: string) => Object.assign(new Error(`spawn ${bin} ENOENT`), { code: "ENOENT" });

beforeEach(() => {
	spawnSyncMock.mockReset();
	spawnSyncMock.mockReturnValue({ status: 0, signal: null });
});

// Both POSIX and Windows separators are exercised explicitly so the suite
// validates the separator-relative segment logic regardless of the host
// platform. (`path.sep` is the production default; tests pass it explicitly.)
const platforms = [
	{
		name: "POSIX-style paths",
		sep: posix.sep,
		installRoot:
			"/Users/x/.npm/_npx/abc/node_modules/@o3co/create-auth-provider/templates/standalone",
		localRoot: "/repo/templates/standalone",
	},
	{
		name: "Windows-style paths",
		sep: win32.sep,
		installRoot:
			"C:\\Users\\x\\AppData\\Roaming\\npm-cache\\_npx\\abc\\node_modules\\@o3co\\create-auth-provider\\templates\\standalone",
		localRoot: "C:\\repo\\templates\\standalone",
	},
] as const;

describe.each(platforms)("shouldCopyTemplateEntry on $name", ({ sep, installRoot, localRoot }) => {
	const joinSegments = (base: string, ...rest: readonly string[]): string =>
		[base, ...rest].join(sep);

	it("includes the template root itself", () => {
		expect(shouldCopyTemplateEntry(installRoot, installRoot, sep)).toBe(true);
	});

	it("includes a file directly under the template root even when ancestor path contains 'node_modules'", () => {
		// Regression for v0.5.0 npx install bug: when the package is installed
		// at .../node_modules/@o3co/create-auth-provider/..., the previous filter
		// checked every segment of the absolute source path and excluded
		// everything, so cpSync copied no files.
		expect(
			shouldCopyTemplateEntry(joinSegments(installRoot, "package.json"), installRoot, sep),
		).toBe(true);
	});

	it("includes nested template files even when ancestor path contains 'node_modules' or 'dist'", () => {
		expect(
			shouldCopyTemplateEntry(joinSegments(installRoot, "src", "app.mts"), installRoot, sep),
		).toBe(true);
		expect(
			shouldCopyTemplateEntry(
				joinSegments(installRoot, "config", "application.conf"),
				installRoot,
				sep,
			),
		).toBe(true);
	});

	it("excludes node_modules subdirectories that live INSIDE the template root", () => {
		expect(
			shouldCopyTemplateEntry(
				joinSegments(localRoot, "node_modules", "foo", "index.js"),
				localRoot,
				sep,
			),
		).toBe(false);
	});

	it("excludes dist subdirectories that live INSIDE the template root", () => {
		expect(
			shouldCopyTemplateEntry(joinSegments(localRoot, "dist", "index.mjs"), localRoot, sep),
		).toBe(false);
	});
});

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
		expect(existsSync(join(targetDir, "config", "development.conf"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "production.conf"))).toBe(true);
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
		expect(pkg.dependencies["@o3co/auth-provider-federation-google"]).toMatch(/^\^/);
		expect(pkg.dependencies["@o3co/auth-provider-federation-github"]).toBeUndefined();
		expect(pkg.dependencies["@o3co/auth-provider-foundation"]).toMatch(/^\^/);
	});

	it('keeps "private": true so a scaffolded service is not publishable by accident', () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.private).toBe(true);
	});

	it("writes scoped project name verbatim into package.json", () => {
		const targetDir = join(tempDir, "auth.provider");
		scaffold(targetDir, "@piratis-blossoms/auth.provider");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.provider");
	});

	it("ships versions for every workspace auth-provider package, in sync with each package.json", () => {
		const versions: Record<string, string> = JSON.parse(
			readFileSync(join("templates", "versions.json"), "utf-8"),
		);

		const expectedPackages: Record<string, string> = {
			"@o3co/auth-provider-core": "../packages/core/package.json",
			"@o3co/auth-provider-dpop": "../packages/dpop/package.json",
			"@o3co/auth-provider-mtls": "../packages/mtls/package.json",
			"@o3co/auth-provider-federation-github": "../packages/federation-github/package.json",
			"@o3co/auth-provider-federation-google": "../packages/federation-google/package.json",
			"@o3co/auth-provider-foundation": "../packages/foundation/package.json",
			"@o3co/auth-provider-oauth": "../packages/oauth/package.json",
			"@o3co/auth-provider-oauth-token-exchange": "../packages/oauth-token-exchange/package.json",
			"@o3co/auth-provider-redis": "../packages/redis/package.json",
			"@o3co/auth-provider-session": "../packages/session/package.json",
			"@o3co/auth-provider-webauthn": "../packages/webauthn/package.json",
		};

		for (const [name, pkgPath] of Object.entries(expectedPackages)) {
			const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
			expect(versions[name], `versions.json missing entry for ${name}`).toBeDefined();
			expect(versions[name], `versions.json[${name}] out of sync with ${pkgPath}`).toBe(
				pkg.version,
			);
		}

		expect(Object.keys(versions).sort()).toEqual(Object.keys(expectedPackages).sort());
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

describe("scaffold — pnpm-workspace.yaml generation", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "create-auth-provider-wsyaml-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("writes the bcrypt build allowlist where pnpm >= 10.29 reads it", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		const yaml = readFileSync(join(targetDir, "pnpm-workspace.yaml"), "utf-8");
		expect(yaml).toMatch(/onlyBuiltDependencies:\n\s*- bcrypt/);
	});
});

describe("generateLockfile", () => {
	const LOCKFILE_ARGS = ["install", "--lockfile-only", "--ignore-workspace"];

	it("resolves the dependency graph with pnpm in the target directory", () => {
		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(true);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		const [bin, args, options] = spawnSyncMock.mock.calls[0];
		expect(bin).toBe("pnpm");
		expect(args).toEqual(LOCKFILE_ARGS);
		expect(options.cwd).toBe("/tmp/target");
		// A scaffolded project must get its OWN lockfile even when the target
		// directory happens to sit inside somebody else's pnpm workspace.
		expect(args).toContain("--ignore-workspace");
	});

	it("falls back to corepack when pnpm is not on PATH", () => {
		spawnSyncMock
			.mockReturnValueOnce({ error: enoent("pnpm") })
			.mockReturnValueOnce({ status: 0, signal: null });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(true);
		expect(spawnSyncMock).toHaveBeenCalledTimes(2);
		const [bin, args] = spawnSyncMock.mock.calls[1];
		expect(bin).toBe("corepack");
		expect(args).toEqual(["pnpm", ...LOCKFILE_ARGS]);
	});

	it("does not retry with corepack when pnpm ran and failed", () => {
		// A non-zero exit means resolution failed (offline, private registry,
		// unpublished version). Running the same resolution through a second
		// launcher would fail identically and only doubles the wait.
		spawnSyncMock.mockReturnValue({ status: 1, signal: null });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
	});

	it("does not retry with corepack when launching pnpm failed for any other reason", () => {
		// ENOENT is "this binary is not on PATH", which the next launcher can
		// answer. EACCES is not: pnpm IS there and could not be executed, and
		// retrying would both hide that and hand the operator the wrong
		// instruction ("install pnpm") for a permissions problem.
		spawnSyncMock.mockReturnValue({
			error: Object.assign(new Error("spawn pnpm EACCES"), { code: "EACCES" }),
		});

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		if (result.ok) throw new Error("unreachable");
		expect(result.reason).toMatch(/EACCES/);
	});

	it("reports failure when no package manager can be launched", () => {
		spawnSyncMock
			.mockReturnValueOnce({ error: enoent("pnpm") })
			.mockReturnValueOnce({ error: enoent("corepack") });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.reason).toMatch(/pnpm/);
	});
});

describe("main (argv parsing and directory derivation)", () => {
	let cwdBackup: string;
	let workdir: string;
	let argvBackup: string[];

	beforeEach(() => {
		cwdBackup = process.cwd();
		workdir = mkdtempSync(join(tmpdir(), "create-auth-provider-main-"));
		process.chdir(workdir);
		argvBackup = process.argv;
	});

	afterEach(() => {
		process.chdir(cwdBackup);
		process.argv = argvBackup;
		rmSync(workdir, { recursive: true, force: true });
	});

	const runMain = (args: string[]): { exitCode: number | null; stderr: string } => {
		process.argv = ["node", "cli", ...args];
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`__exit__:${code ?? 0}`);
		}) as never);
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		let exitCode: number | null = 0;
		try {
			main();
		} catch (e) {
			const m = /__exit__:(\d+)/.exec((e as Error).message);
			exitCode = m ? Number(m[1]) : null;
		}
		const stderr = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
		exitSpy.mockRestore();
		errSpy.mockRestore();
		logSpy.mockRestore();
		return { exitCode, stderr };
	};

	// Positive: unscoped, no --dir
	it("unscoped name: dir = name, pkg.name = name", () => {
		const r = runMain(["my-auth"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "my-auth", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-auth");
	});

	// Positive: scoped, no --dir
	it("scoped name: dir = pkg part, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.provider"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "auth.provider", "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.provider");
	});

	// Positive: scoped + --dir space
	it("scoped name with --dir <val>: dir = val, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.provider", "--dir", "provider"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "provider", "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.provider");
	});

	// Positive: scoped + --dir= equals form
	it("scoped name with --dir=<val>: dir = val, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.provider", "--dir=provider2"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "provider2", "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.provider");
	});

	// Positive: unscoped + --dir
	it("unscoped name with --dir <val>: dir = val, pkg.name = unscoped", () => {
		const r = runMain(["my-auth", "--dir", "custom"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "custom", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-auth");
	});

	// #289: the scaffold resolves the new project's lockfile by default…
	it("generates a lockfile in the scaffolded project by default", () => {
		const r = runMain(["my-auth"]);
		expect(r.exitCode).toBe(0);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		const [, , options] = spawnSyncMock.mock.calls[0];
		// process.cwd() is still `workdir` here (afterEach restores it later),
		// and comparing through it sidesteps mkdtemp's /var → /private/var
		// symlink on macOS.
		expect(options.cwd).toBe(join(process.cwd(), "my-auth"));
	});

	// …and --no-lockfile is the opt-out.
	it("--no-lockfile skips lockfile generation", () => {
		const r = runMain(["my-auth", "--no-lockfile"]);
		expect(r.exitCode).toBe(0);
		expect(spawnSyncMock).not.toHaveBeenCalled();
	});

	// Positive: flags may come before the positional
	it("flags before positional: --dir custom my-auth", () => {
		const r = runMain(["--dir", "custom", "my-auth"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "custom", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-auth");
	});

	// Negative cases
	it.each([
		{ case: "no args", args: [] },
		{ case: "two positionals", args: ["foo", "bar"] },
		{ case: "dot", args: ["."] },
		{ case: "dotdot", args: [".."] },
		{ case: "backslash in name", args: ["back\\slash"] },
		{ case: "empty scope", args: ["@/pkg"] },
		{ case: "empty pkg", args: ["@scope/"] },
		{ case: "double slash", args: ["@scope//pkg"] },
		{ case: "name too long", args: ["a".repeat(215)] },
		{ case: "--dir invalid (dot)", args: ["foo", "--dir", "."] },
		{ case: "--dir invalid (slash)", args: ["foo", "--dir", "a/b"] },
		{ case: "--dir invalid (at)", args: ["foo", "--dir", "@foo"] },
		{ case: "--dir invalid (back)", args: ["foo", "--dir", "a\\b"] },
		{ case: "--dir empty space form", args: ["foo", "--dir", ""] },
		{ case: "--dir empty equals form", args: ["foo", "--dir="] },
		{ case: "--dir missing value", args: ["foo", "--dir"] },
		{ case: "--dir duplicated", args: ["foo", "--dir", "a", "--dir", "b"] },
		{ case: "unknown flag", args: ["foo", "--unknown"] },
		{ case: "literal double-dash", args: ["foo", "--"] },
	])("rejects: $case", ({ args }) => {
		const r = runMain(args);
		expect(r.exitCode).toBe(1);
		expect(r.stderr.length).toBeGreaterThan(0);
	});

	it("target directory already exists", () => {
		mkdirSync(join(workdir, "foo"));
		const r = runMain(["foo"]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr.length).toBeGreaterThan(0);
	});
});
