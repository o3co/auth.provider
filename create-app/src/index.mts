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
import {
	appendFileSync,
	cpSync,
	existsSync,
	readdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { shouldCopyTemplateEntry } from "./internal/template-filter.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_ROOT = resolve(__dirname, "../templates");

/** The template a scaffold is made from when none is named. */
export const DEFAULT_TEMPLATE = "standalone";

/**
 * The templates under `templatesRoot`: every directory — not a symbolic link,
 * not dot-named — holding a `package.json`, sorted; none when the directory is
 * missing. This is the rule `scripts/templates.mjs` copies templates by, read
 * here from the copy, where `versions.json` sits beside them. A name is only
 * ever looked up in this list, so nothing outside the templates directory can
 * be named as a template.
 */
export const availableTemplates = (templatesRoot: string = TEMPLATES_ROOT): string[] => {
	if (!existsSync(templatesRoot)) return [];
	return readdirSync(templatesRoot, { withFileTypes: true })
		.filter(
			(entry) =>
				entry.isDirectory() &&
				!entry.name.startsWith(".") &&
				existsSync(resolve(templatesRoot, entry.name, "package.json")),
		)
		.map((entry) => entry.name)
		.sort();
};

/**
 * Why `template` cannot be scaffolded from `templates`, or `undefined` when it
 * can: none is bundled (a checkout that never ran the prebuild script), or it
 * is not one of them.
 */
export const templateRefusal = (
	template: string,
	templates: readonly string[],
): string | undefined => {
	if (templates.length === 0) {
		return `No templates found at ${TEMPLATES_ROOT}. If developing locally, run the prebuild script first.`;
	}
	if (!templates.includes(template)) {
		return `Unknown template '${template}'. Available templates: ${templates.join(", ")}.`;
	}
	return undefined;
};

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

/** What `scaffold()` changes in the copy beyond the name and the versions. */
export interface ScaffoldOptions {
	/**
	 * Write the template's MFA switch off (`MFA_OFF_LINES`), so the scaffold
	 * stays off whatever default a later template ships; `MFA_MODE` still
	 * turns MFA on.
	 */
	readonly noMfa?: boolean;
}

/**
 * Appended to the scaffold's `config/application.conf` by `noMfa`: the
 * template's switch `mfaMode` written off, then bound to `MFA_MODE` so the
 * variable wins over the written value. The MFA package stays a dependency.
 */
const MFA_OFF_LINES: readonly string[] = [
	"",
	"# written by create-app --no-mfa: MFA is off unless MFA_MODE turns it on",
	'mfaMode = "off"',
	// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
	"mfaMode = ${?MFA_MODE}",
];

export const scaffold = (
	targetDir: string,
	projectName: string,
	template: string = DEFAULT_TEMPLATE,
	options: ScaffoldOptions = {},
): void => {
	const refusal = templateRefusal(template, availableTemplates());
	if (refusal !== undefined) throw new Error(refusal);
	const templateDir = resolve(TEMPLATES_ROOT, template);

	// Copy template to target
	cpSync(templateDir, targetDir, {
		recursive: true,
		filter: (source) => shouldCopyTemplateEntry(source, templateDir),
	});

	// npm drops a file literally named `.gitignore` from a published package,
	// so `copy-templates.mjs` stages it dot-less and it is restored here.
	// Without it the first `git add .` in a scaffolded project commits the
	// `.env` and the signing key the README's setup steps create.
	const stagedGitignore = resolve(targetDir, "gitignore");
	if (existsSync(stagedGitignore)) {
		renameSync(stagedGitignore, resolve(targetDir, ".gitignore"));
	}

	if (options.noMfa === true) {
		appendFileSync(
			resolve(targetDir, "config", "application.conf"),
			`${MFA_OFF_LINES.join("\n")}\n`,
		);
	}

	// Rewrite package.json
	const pkgPath = resolve(targetDir, "package.json");
	const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
	pkg.name = projectName;
	// `"private": true` is deliberately kept: the scaffold is an identity
	// provider (keys, config, policy), so an accidental `npm publish` must fail
	// by default. An operator who means to publish removes the field.
	// o3co/auth.policy-verifier's scaffolder does the same; change the two together.

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

	// pnpm ≥10.29 reads `onlyBuiltDependencies` only from pnpm-workspace.yaml,
	// even in single-package projects. The template cannot ship the file:
	// inside the monorepo it would shadow the workspace root. So the scaffold
	// writes it, mirroring the workspace root's allowlist.
	writeFileSync(
		resolve(targetDir, "pnpm-workspace.yaml"),
		[
			"# pnpm (>= 10.29) reads onlyBuiltDependencies from this file, even in a",
			"# single-package project. bcrypt's install hook compiles the native addon",
			"# on platforms with no shipped prebuild; without this allowlist pnpm",
			"# silently skips the hook and bcrypt fails at require time there.",
			"onlyBuiltDependencies:",
			"  - bcrypt",
			"",
		].join("\n"),
	);
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
 * Launchers tried in order: `pnpm` on PATH, then `corepack pnpm` for a machine
 * with Node's bundled corepack but no global pnpm. Only ENOENT falls through to
 * the next launcher; a non-zero exit would fail identically through any of
 * them, and other launch errors surface as themselves.
 */
const LOCKFILE_LAUNCHERS: readonly (readonly string[])[] = [["pnpm"], ["corepack", "pnpm"]];

/**
 * Resolve the scaffolded project's dependency graph into `pnpm-lock.yaml`,
 * which the template's `pnpm install --frozen-lockfile` build needs. The
 * lockfile cannot ship with the template: the dependency set it pins exists
 * only after `scaffold` has replaced every `workspace:*`. Best-effort (it needs
 * a package manager and a reachable registry), so failure is a result, not a
 * throw.
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
	template: string | undefined;
	lockfile: boolean;
	noMfa: boolean;
}

/** The flags that take a value, as `--flag <value>` or `--flag=<value>`. */
const VALUE_FLAGS = ["--dir", "--template"] as const;
type ValueFlag = (typeof VALUE_FLAGS)[number];

const parseArgs = (args: string[]): ParsedArgs => {
	const positionals: string[] = [];
	const values = new Map<ValueFlag, string>();
	let lockfile = true;
	let noMfa = false;

	const setValue = (flag: ValueFlag, value: string): void => {
		if (values.has(flag)) throw new Error(`${flag} specified more than once`);
		if (value === "") throw new Error(`${flag} requires a value`);
		values.set(flag, value);
	};

	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		const spaced = VALUE_FLAGS.find((flag) => a === flag);
		const joined = VALUE_FLAGS.find((flag) => a.startsWith(`${flag}=`));
		if (spaced !== undefined) {
			if (i + 1 >= args.length) throw new Error(`${spaced} requires a value`);
			setValue(spaced, args[i + 1]);
			i++;
		} else if (joined !== undefined) {
			setValue(joined, a.slice(`${joined}=`.length));
		} else if (a === "--no-lockfile") {
			lockfile = false;
		} else if (a === "--no-mfa") {
			noMfa = true;
		} else if (a.startsWith("-")) {
			// Treats `--` and any --unknown as an unknown flag.
			throw new Error(`unknown flag: ${a}`);
		} else {
			positionals.push(a);
		}
	}

	if (positionals.length === 0) throw new Error("missing <project-name>");
	if (positionals.length > 1) throw new Error("too many positional arguments");

	return {
		projectName: positionals[0],
		dir: values.get("--dir"),
		template: values.get("--template"),
		lockfile,
		noMfa,
	};
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
			"Usage: @o3co/create-auth-provider <project-name> [--template <name>] [--dir <dir-name>] [--no-lockfile] [--no-mfa]",
		);
		console.error(
			"<project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped).",
		);
		console.error(
			`--template names the template to copy (default: ${DEFAULT_TEMPLATE}); available: ${availableTemplates().join(", ")}.`,
		);
		process.exit(1);
	}

	const { projectName, dir, lockfile, noMfa } = parsed;
	const template = parsed.template ?? DEFAULT_TEMPLATE;

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

	const refusal = templateRefusal(template, availableTemplates());
	if (refusal !== undefined) {
		console.error(`Error: ${refusal}`);
		process.exit(1);
	}

	const dirName = deriveDirName(projectName, dir);
	const targetDir = resolve(process.cwd(), dirName);

	if (existsSync(targetDir)) {
		console.error(`Error: Directory '${dirName}' already exists.`);
		process.exit(1);
	}

	console.log(`Creating ${projectName} from the ${template} template...`);
	scaffold(targetDir, projectName, template, { noMfa });

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
