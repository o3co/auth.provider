import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix, resolve, win32 } from "node:path";
import { type Config, parseFile, parseString } from "@o3co/ts.hocon";
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
const {
	availableTemplates,
	DEFAULT_TEMPLATE,
	templateRefusal,
	generateLockfile,
	isValidDirName,
	isValidProjectName,
	main,
	scaffold,
} = await import("../index.mjs");

/** The templates this package bundles, which `scaffold()` copies from. */
const BUNDLED_TEMPLATES = resolve(import.meta.dirname, "../../templates");

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
		// Installed at .../node_modules/@o3co/create-auth-provider/..., the
		// package's own path contains `node_modules`: a filter that checked every
		// segment of the absolute source path would exclude everything, and
		// cpSync would copy no files.
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
		expect(existsSync(join(targetDir, "config", "reference.conf"))).toBe(true);
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
		expect(pkg.dependencies["@o3co/auth-provider-federation-oidc"]).toMatch(/^\^/);
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
			"@o3co/auth-provider-device-grant": "../packages/device-grant/package.json",
			"@o3co/auth-provider-dpop": "../packages/dpop/package.json",
			"@o3co/auth-provider-mtls": "../packages/mtls/package.json",
			"@o3co/auth-provider-federation-apple": "../packages/federation-apple/package.json",
			"@o3co/auth-provider-federation-github": "../packages/federation-github/package.json",
			"@o3co/auth-provider-federation-grants": "../packages/federation-grants/package.json",
			"@o3co/auth-provider-federation-google": "../packages/federation-google/package.json",
			"@o3co/auth-provider-federation-oidc": "../packages/federation-oidc/package.json",
			"@o3co/auth-provider-foundation": "../packages/foundation/package.json",
			"@o3co/auth-provider-mfa": "../packages/mfa/package.json",
			"@o3co/auth-provider-oauth": "../packages/oauth/package.json",
			"@o3co/auth-provider-oauth-token-exchange": "../packages/oauth-token-exchange/package.json",
			"@o3co/auth-provider-redis": "../packages/redis/package.json",
			"@o3co/auth-provider-session": "../packages/session/package.json",
			"@o3co/auth-provider-standard": "../packages/standard/package.json",
			"@o3co/auth-provider-test-kit": "../packages/test-kit/package.json",
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

describe("availableTemplates", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "create-auth-provider-templates-"));
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	it("lists every directory that holds a package.json, sorted, and nothing else", () => {
		for (const name of ["zeta", "alpha"]) {
			mkdirSync(join(root, name));
			writeFileSync(join(root, name, "package.json"), "{}\n");
		}
		// A directory without a manifest is not a template, and neither is a file
		// beside the templates — `copy-templates.mjs` writes `versions.json` there.
		mkdirSync(join(root, "not-a-template"));
		writeFileSync(join(root, "versions.json"), "{}\n");

		expect(availableTemplates(root)).toEqual(["alpha", "zeta"]);
	});

	it("lists none when the templates directory does not exist", () => {
		expect(availableTemplates(join(root, "missing"))).toEqual([]);
	});

	it("includes the default template in what this package ships", () => {
		expect(availableTemplates()).toContain(DEFAULT_TEMPLATE);
		expect(DEFAULT_TEMPLATE).toBe("standalone");
	});
});

describe("templateRefusal", () => {
	it("refuses nothing for a template that is there", () => {
		expect(templateRefusal("standalone", ["m2m", "standalone"])).toBeUndefined();
	});

	it("names the templates there are when the one asked for is not", () => {
		expect(templateRefusal("nope", ["m2m", "standalone"])).toBe(
			"Unknown template 'nope'. Available templates: m2m, standalone.",
		);
	});

	it("says how to bundle the templates when there are none", () => {
		// A checkout that never ran the prebuild script has no templates at all;
		// "Unknown template 'standalone'. Available templates: ." would send the
		// developer looking for the wrong thing.
		expect(templateRefusal("standalone", [])).toMatch(/No templates found.*prebuild/);
	});
});

describe("scaffold — choosing a template", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "create-auth-provider-choice-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("copies the template it is named", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth", DEFAULT_TEMPLATE);

		expect(existsSync(join(targetDir, "src", "app.mts"))).toBe(true);
		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-auth");
	});

	it.each([
		{ case: "an unknown name", template: "nope" },
		{ case: "a path out of the templates directory", template: "../templates/standalone" },
		{ case: "a nested path", template: "standalone/src" },
		{ case: "the versions file beside the templates", template: "versions.json" },
	])("refuses $case, naming the templates it has, and writes nothing", ({ template }) => {
		const targetDir = join(tempDir, "my-auth");

		expect(() => scaffold(targetDir, "my-auth", template)).toThrow(
			`Unknown template '${template}'. Available templates: `,
		);
		expect(() => scaffold(targetDir, "my-auth", template)).toThrow(
			/Available templates: .*standalone/,
		);
		expect(existsSync(targetDir)).toBe(false);
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

describe("scaffold — the MFA switch (--no-mfa)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "create-auth-provider-mfa-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	const applicationConf = (projectDir: string): string =>
		join(projectDir, "config", "application.conf");

	/**
	 * `mfaMode` as the template reads it: the project's application.conf over
	 * `reference` (the project's own config/reference.conf unless given), each
	 * substituted with `env`.
	 */
	const resolvedMfaMode = (
		projectDir: string,
		env: Record<string, string>,
		reference: Config = parseFile(join(projectDir, "config", "reference.conf"), { env }),
	): unknown =>
		(
			parseFile(applicationConf(projectDir), { env }).withFallback(reference).toObject() as Record<
				string,
				unknown
			>
		).mfaMode;

	it("writes the switch off, then binds MFA_MODE, at the end of application.conf", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth", DEFAULT_TEMPLATE, { noMfa: true });

		const written = readFileSync(applicationConf(targetDir), "utf-8");
		expect(written).toMatch(
			/# written by create-app --no-mfa: MFA is off unless MFA_MODE turns it on\nmfaMode = "off"\nmfaMode = \$\{\?MFA_MODE\}\n$/,
		);
	});

	it("resolves the switch off with no MFA_MODE, whatever the template's default", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth", DEFAULT_TEMPLATE, { noMfa: true });

		expect(resolvedMfaMode(targetDir, {})).toBe("off");
		expect(resolvedMfaMode(targetDir, {}, parseString('mfaMode = "required"', { env: {} }))).toBe(
			"off",
		);
	});

	it("lets MFA_MODE turn MFA on", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth", DEFAULT_TEMPLATE, { noMfa: true });

		expect(resolvedMfaMode(targetDir, { MFA_MODE: "required" })).toBe("required");
		expect(resolvedMfaMode(targetDir, { MFA_MODE: "optional" })).toBe("optional");
	});

	it("leaves application.conf as the template has it without the option", () => {
		const targetDir = join(tempDir, "my-auth");
		scaffold(targetDir, "my-auth");

		expect(readFileSync(applicationConf(targetDir))).toEqual(
			readFileSync(join(BUNDLED_TEMPLATES, DEFAULT_TEMPLATE, "config", "application.conf")),
		);
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
		// Both backups are taken before anything is changed, so the afterEach
		// below can always put the process back the way it found it.
		cwdBackup = process.cwd();
		argvBackup = process.argv;
		workdir = mkdtempSync(join(tmpdir(), "create-auth-provider-main-"));
		process.chdir(workdir);
	});

	afterEach(() => {
		process.argv = argvBackup;
		process.chdir(cwdBackup);
		rmSync(workdir, { recursive: true, force: true });
	});

	const runMain = (args: string[]): { exitCode: number; stderr: string } => {
		process.argv = ["node", "cli", ...args];
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`__exit__:${code ?? 0}`);
		}) as never);
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			let exitCode = 0;
			try {
				main();
			} catch (e) {
				// Only the `process.exit` stand-in above is an outcome. Anything else
				// `main()` throws is a failure of the scaffold itself and must reach
				// the test report under its own name: folded into `exitCode: null`,
				// it would surface as "expected null to be +0" and hide the error
				// that explains it.
				const m = e instanceof Error ? /^__exit__:(\d+)$/.exec(e.message) : null;
				if (!m) throw e;
				exitCode = Number(m[1]);
			}
			return { exitCode, stderr: errSpy.mock.calls.map((c) => c.join(" ")).join("\n") };
		} finally {
			// Restored on every path, the rethrow included, so one failing case
			// cannot leave `process.exit` or the console stubbed for the next.
			exitSpy.mockRestore();
			errSpy.mockRestore();
			logSpy.mockRestore();
		}
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

	// The scaffold resolves the new project's lockfile by default…
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

	it("--no-mfa writes the scaffold's MFA switch off", () => {
		const r = runMain(["my-auth", "--no-mfa"]);
		expect(r.exitCode).toBe(0);
		const written = readFileSync(join(workdir, "my-auth", "config", "application.conf"), "utf-8");
		expect(written).toMatch(/\nmfaMode = "off"\nmfaMode = \$\{\?MFA_MODE\}\n$/);
	});

	it("without --no-mfa the scaffold's application.conf writes no MFA switch", () => {
		const r = runMain(["my-auth"]);
		expect(r.exitCode).toBe(0);
		const written = readFileSync(join(workdir, "my-auth", "config", "application.conf"), "utf-8");
		expect(written).not.toMatch(/^mfaMode\b/m);
	});

	// Positive: --template names the template, in both forms
	it("--template <name> scaffolds from that template", () => {
		const r = runMain(["my-auth", "--template", "standalone"]);
		expect(r.exitCode).toBe(0);
		expect(existsSync(join(workdir, "my-auth", "src", "app.mts"))).toBe(true);
	});

	it("--template=<name> scaffolds from that template", () => {
		const r = runMain(["--template=standalone", "my-auth"]);
		expect(r.exitCode).toBe(0);
		expect(existsSync(join(workdir, "my-auth", "src", "app.mts"))).toBe(true);
	});

	it("an empty --template is refused as a missing value", () => {
		const r = runMain(["my-auth", "--template="]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr).toMatch(/--template requires a value/);
	});

	it("a --template given twice is refused, even when both name the same template", () => {
		const r = runMain(["my-auth", "--template", "standalone", "--template", "standalone"]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr).toMatch(/--template specified more than once/);
	});

	it("checks the project name before the template, in the order the README gives", () => {
		const r = runMain(["UPPER", "--template", "nope"]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr).toMatch(/<project-name> must be a valid npm package name/);
		expect(r.stderr).not.toMatch(/Unknown template/);
	});

	it("an unknown --template is refused before anything is written, naming the templates", () => {
		const r = runMain(["my-auth", "--template", "nope"]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr).toMatch(/Unknown template 'nope'/);
		expect(r.stderr).toMatch(/standalone/);
		expect(existsSync(join(workdir, "my-auth"))).toBe(false);
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
		{ case: "--template missing value", args: ["foo", "--template"] },
		{ case: "--template empty space form", args: ["foo", "--template", ""] },
		{ case: "--template empty equals form", args: ["foo", "--template="] },
		{ case: "--template duplicated", args: ["foo", "--template", "a", "--template", "b"] },
		{ case: "--template out of the templates directory", args: ["foo", "--template", ".."] },
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
