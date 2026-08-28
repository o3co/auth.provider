/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { shouldCopyTemplateEntry } from "./internal/template-filter.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = resolve(__dirname, "../templates/standalone");

const getPackageVersions = (): Record<string, string> => {
	const versionFile = resolve(__dirname, "../templates/versions.json");
	if (existsSync(versionFile)) {
		return JSON.parse(readFileSync(versionFile, "utf-8"));
	}
	return {};
};

const UNSCOPED_NAME_RE = /^[a-z0-9][a-z0-9-._~]*$/;
const SCOPED_NAME_RE = /^@[a-z0-9][a-z0-9-._~]*\/[a-z0-9][a-z0-9-._~]*$/;
const MAX_NAME_LEN = 214;

export const isValidProjectName = (name: string): boolean => {
	if (name.length === 0 || name.length > MAX_NAME_LEN) return false;
	if (name === "." || name === "..") return false;
	return UNSCOPED_NAME_RE.test(name) || SCOPED_NAME_RE.test(name);
};

export const isValidDirName = (name: string): boolean => {
	if (name.length === 0 || name.length > MAX_NAME_LEN) return false;
	if (name === "." || name === "..") return false;
	return UNSCOPED_NAME_RE.test(name);
};

export const scaffold = (targetDir: string, projectName: string): void => {
	if (!existsSync(TEMPLATES_DIR)) {
		throw new Error(
			`Template directory not found at ${TEMPLATES_DIR}. If developing locally, run the prebuild script first.`,
		);
	}

	// Copy template to target
	cpSync(TEMPLATES_DIR, targetDir, {
		recursive: true,
		filter: (source) => shouldCopyTemplateEntry(source, TEMPLATES_DIR),
	});

	// Rewrite package.json
	const pkgPath = resolve(targetDir, "package.json");
	const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
	pkg.name = projectName;
	delete pkg.private;

	// Replace all workspace:* references with per-package published versions
	const versions = getPackageVersions();
	for (const section of ["dependencies", "devDependencies", "peerDependencies"] as const) {
		const deps = pkg[section];
		if (!deps) continue;
		for (const [name, version] of Object.entries(deps)) {
			if (version === "workspace:*") {
				const resolved = versions[name];
				if (!resolved) {
					throw new Error(
						`Cannot resolve version for workspace dependency "${name}". Ensure versions.json includes this package.`,
					);
				}
				deps[name] = `^${resolved}`;
			}
		}
	}

	writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
};

/** Outcome of the scaffold-time lockfile generation. */
export type LockfileResult =
	| { readonly ok: true; readonly command: string }
	| { readonly ok: false; readonly reason: string };

/**
 * `--lockfile-only` resolves the dependency graph without installing or
 * running any script. `--ignore-workspace` keeps the new project's lockfile
 * its own even when the target directory happens to sit inside somebody
 * else's pnpm workspace.
 */
const LOCKFILE_ARGS = ["install", "--lockfile-only", "--ignore-workspace"] as const;

/**
 * Launchers tried in order. `pnpm` on PATH is the common case; `corepack pnpm`
 * answers the machine that has Node's bundled corepack but no global pnpm.
 * The fallback fires only on ENOENT — the one launch error a different
 * launcher can answer. A non-zero exit (offline, private registry,
 * unpublished version) would fail identically through any launcher, and
 * EACCES-shaped errors surface as themselves rather than as "package manager
 * missing".
 */
const LOCKFILE_LAUNCHERS: readonly (readonly string[])[] = [["pnpm"], ["corepack", "pnpm"]];

/**
 * Resolve the scaffolded project's dependency graph into `pnpm-lock.yaml`.
 *
 * This is what makes the template's `pnpm install --frozen-lockfile` build
 * possible: the lockfile cannot be shipped with the template, because the
 * dependency set it would pin does not exist until `scaffold` has replaced
 * every `workspace:*` with a published version (#289). It is therefore
 * resolved once, here, against the rewritten `package.json`. Best-effort by
 * design — it needs a package manager and a reachable registry — so failure
 * is a result, not a throw.
 */
export const generateLockfile = (targetDir: string): LockfileResult => {
	const attempts: string[] = [];

	for (const launcher of LOCKFILE_LAUNCHERS) {
		const [bin, ...prefix] = launcher;
		const args = [...prefix, ...LOCKFILE_ARGS];
		const printable = [bin, ...args].join(" ");
		const result = spawnSync(bin, args, {
			cwd: targetDir,
			stdio: "inherit",
			shell: false,
			env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: "0" },
		});

		if (result.error) {
			attempts.push(`${printable}: ${result.error.message}`);
			// Only "not on PATH" is worth asking a different launcher about.
			if ((result.error as NodeJS.ErrnoException).code === "ENOENT") continue;
			break;
		}
		if (result.status === 0) return { ok: true, command: printable };

		const how =
			result.status === null ? `killed by signal ${result.signal}` : `exit code ${result.status}`;
		attempts.push(`${printable}: ${how}`);
		break;
	}

	return { ok: false, reason: attempts.join("; ") };
};

interface ParsedArgs {
	projectName: string;
	dir: string | undefined;
	lockfile: boolean;
}

const parseArgs = (args: string[]): ParsedArgs => {
	const positionals: string[] = [];
	let dir: string | undefined;
	let dirSeen = false;
	let lockfile = true;

	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a === "--dir") {
			if (dirSeen) throw new Error("--dir specified more than once");
			if (i + 1 >= args.length) throw new Error("--dir requires a value");
			dir = args[i + 1];
			dirSeen = true;
			i++;
		} else if (a.startsWith("--dir=")) {
			if (dirSeen) throw new Error("--dir specified more than once");
			dir = a.slice("--dir=".length);
			dirSeen = true;
		} else if (a === "--no-lockfile") {
			lockfile = false;
		} else if (a.startsWith("-")) {
			// Treats `--` and any --unknown as an unknown flag.
			throw new Error(`unknown flag: ${a}`);
		} else {
			positionals.push(a);
		}
	}

	if (positionals.length === 0) throw new Error("missing <project-name>");
	if (positionals.length > 1) throw new Error("too many positional arguments");

	return { projectName: positionals[0], dir, lockfile };
};

const deriveDirName = (projectName: string, dir: string | undefined): string => {
	if (dir !== undefined) return dir;
	if (projectName.startsWith("@")) {
		const pkgPart = projectName.split("/")[1];
		if (!pkgPart) {
			// Unreachable when projectName has passed isValidProjectName (SCOPED_NAME_RE
			// guarantees a non-empty package segment after the single "/"). Guarded here
			// so refactors that reorder validation cannot silently produce undefined.
			throw new Error(`invariant: unvalidated scoped name ${projectName}`);
		}
		return pkgPart;
	}
	return projectName;
};

// CLI entry point
export const main = (): void => {
	const args = process.argv.slice(2);

	let parsed: ParsedArgs;
	try {
		parsed = parseArgs(args);
	} catch (e) {
		console.error(`Error: ${(e as Error).message}`);
		console.error(
			"Usage: @o3co/create-auth-provider <project-name> [--dir <dir-name>] [--no-lockfile]",
		);
		console.error(
			"<project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped).",
		);
		process.exit(1);
	}

	const { projectName, dir, lockfile } = parsed;

	if (!isValidProjectName(projectName)) {
		console.error(
			"Error: <project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped; max 214 chars; no backslashes; no extra '/' beyond the single scope separator).",
		);
		process.exit(1);
	}

	if (dir !== undefined && !isValidDirName(dir)) {
		console.error(
			"Error: --dir must be a valid unscoped package name (no '/', '\\', '@'; not '.' or '..'; max 214 chars).",
		);
		process.exit(1);
	}

	const dirName = deriveDirName(projectName, dir);
	const targetDir = resolve(process.cwd(), dirName);

	if (existsSync(targetDir)) {
		console.error(`Error: Directory '${dirName}' already exists.`);
		process.exit(1);
	}

	console.log(`Creating ${projectName}...`);
	scaffold(targetDir, projectName);

	let lockfileGenerated = false;
	if (lockfile) {
		console.log("\nResolving dependencies into pnpm-lock.yaml...");
		const result = generateLockfile(targetDir);
		lockfileGenerated = result.ok;
		if (!result.ok) {
			console.error(`\nWarning: could not generate pnpm-lock.yaml (${result.reason}).`);
			console.error(
				`Run 'pnpm install' in ${dirName} and commit pnpm-lock.yaml: the Dockerfile installs with --frozen-lockfile and will not build without it.`,
			);
		}
	}

	console.log(`\nDone! Created ${projectName} at ${targetDir}`);
	if (lockfileGenerated) {
		console.log(
			"\nCommit pnpm-lock.yaml along with the rest: it is what makes 'docker build' reproducible.",
		);
	}
	console.log(`\nNext steps:`);
	console.log(`  cd ${dirName}`);
	console.log("  pnpm install");
	console.log("  pnpm run debug");
};
