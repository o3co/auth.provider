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
import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

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
	const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);
	cpSync(TEMPLATES_DIR, targetDir, {
		recursive: true,
		filter: (source) => {
			const segments = source.split(sep);
			return !segments.some((s) => EXCLUDED_DIRS.has(s));
		},
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

interface ParsedArgs {
	projectName: string;
	dir: string | undefined;
}

const parseArgs = (args: string[]): ParsedArgs => {
	const positionals: string[] = [];
	let dir: string | undefined;
	let dirSeen = false;

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
		} else if (a.startsWith("-")) {
			// Treats `--` and any --unknown as an unknown flag.
			throw new Error(`unknown flag: ${a}`);
		} else {
			positionals.push(a);
		}
	}

	if (positionals.length === 0) throw new Error("missing <project-name>");
	if (positionals.length > 1) throw new Error("too many positional arguments");

	return { projectName: positionals[0], dir };
};

const deriveDirName = (projectName: string, dir: string | undefined): string => {
	if (dir !== undefined) return dir;
	if (projectName.startsWith("@")) return projectName.split("/")[1];
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
			"Usage: create-o3co-auth-provider <project-name> [--dir <dir-name>]",
		);
		console.error(
			"<project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped).",
		);
		process.exit(1);
	}

	const { projectName, dir } = parsed;

	if (!isValidProjectName(projectName)) {
		console.error(
			"Error: <project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped; max 214 chars; no path separators).",
		);
		process.exit(1);
	}

	if (dir !== undefined && !isValidDirName(dir)) {
		console.error(
			"Error: --dir must be a valid unscoped package name (no '/', '\\\\', '@'; not '.' or '..'; max 214 chars).",
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

	console.log(`\nDone! Created ${projectName} at ${targetDir}`);
	console.log(`\nNext steps:`);
	console.log(`  cd ${dirName}`);
	console.log("  npm install");
	console.log("  npm run debug");
};
