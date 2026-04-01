#!/usr/bin/env node
import { execSync } from "node:child_process";
/*
 * Copyright 2026 1o1 Inc.
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
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = resolve(__dirname, "../templates/standalone");

export const scaffold = (targetDir: string, projectName: string): void => {
	if (!existsSync(TEMPLATES_DIR)) {
		throw new Error(
			`Template directory not found at ${TEMPLATES_DIR}. Run 'pnpm run prebuild' first.`,
		);
	}

	// Copy template to target
	cpSync(TEMPLATES_DIR, targetDir, {
		recursive: true,
		filter: (source) => {
			return !source.includes("node_modules") && !source.includes("/dist/");
		},
	});

	// Rewrite package.json
	const pkgPath = resolve(targetDir, "package.json");
	const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
	pkg.name = projectName;
	delete pkg.private;

	// Replace workspace reference with published version
	if (pkg.dependencies?.["@o3co/auth-provider-core"] === "workspace:*") {
		const corePkgPath = resolve(TEMPLATES_DIR, "..", "..", "packages", "core", "package.json");
		let coreVersion = "0.0.0";
		if (existsSync(corePkgPath)) {
			const corePkg = JSON.parse(readFileSync(corePkgPath, "utf-8"));
			coreVersion = corePkg.version ?? "0.0.0";
		}
		pkg.dependencies["@o3co/auth-provider-core"] = `^${coreVersion}`;
	}

	writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
};

// CLI entry point
const main = (): void => {
	const args = process.argv.slice(2);
	const projectName = args[0];

	if (!projectName) {
		console.error("Usage: create-o3co-auth-provider <project-name>");
		process.exit(1);
	}

	const targetDir = resolve(process.cwd(), projectName);

	if (existsSync(targetDir)) {
		console.error(`Error: Directory '${projectName}' already exists.`);
		process.exit(1);
	}

	console.log(`Creating ${projectName}...`);
	scaffold(targetDir, projectName);

	console.log(`Installing dependencies...`);
	execSync("pnpm install", { cwd: targetDir, stdio: "inherit" });

	console.log(`\nDone! Created ${projectName} at ${targetDir}`);
	console.log(`\nNext steps:`);
	console.log(`  cd ${projectName}`);
	console.log(`  pnpm run debug`);
};

// Only run CLI when executed directly (not imported in tests)
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
	main();
}
