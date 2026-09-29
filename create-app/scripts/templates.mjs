/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// What a template is, for everything that runs before a scaffold: the copy
// into this package (`copy-templates.mjs`), CI's build of every template, and
// `published-package.test.mts`. The scaffolder's `availableTemplates()` reads
// the copy by the same rule, which `templates.test.mts` holds it to. Plain
// JavaScript because it runs before `tsc`, and outside `src/` because the
// published package does not carry it.

import { cpSync, existsSync, mkdirSync, readdirSync, renameSync, rmSync } from "node:fs";
import { resolve, sep } from "node:path";

/**
 * A template's name is a CLI argument and, in CI, a Docker image tag, which
 * is lowercase only.
 */
const TEMPLATE_NAME = /^[a-z0-9][a-z0-9-]*$/;

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

/**
 * The templates under `root`: every directory — not a symbolic link, not
 * dot-named — holding a `package.json`, sorted. A template whose name is not
 * lowercase kebab-case, and a root holding no template, are refused.
 */
export function listTemplates(root) {
	const names = readdirSync(root, { withFileTypes: true })
		.filter(
			(entry) =>
				entry.isDirectory() &&
				!entry.name.startsWith(".") &&
				existsSync(resolve(root, entry.name, "package.json")),
		)
		.map((entry) => entry.name)
		.sort();
	const misnamed = names.filter((name) => !TEMPLATE_NAME.test(name));
	if (misnamed.length > 0) {
		throw new Error(
			`templates: ${misnamed.join(", ")} under ${root} must be named in lowercase kebab-case`,
		);
	}
	if (names.length === 0) {
		throw new Error(`templates: no template found under ${root}`);
	}
	return names;
}

// Mirrors `shouldCopyTemplateEntry` in src/internal/template-filter.mts: only
// segments INSIDE the template's root are checked against EXCLUDED_DIRS, not
// the absolute path above it. Without this, running the prebuild script with
// the workspace itself living under a `node_modules` directory would copy zero
// files. (This runs before tsc, so it cannot import the compiled module — the
// logic is duplicated by necessity.)
const shouldCopyFrom = (root) => (source) => {
	if (source === root) return true;
	const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
	if (!source.startsWith(prefix)) return true;
	const rel = source.slice(prefix.length);
	return !rel.split(sep).some((segment) => EXCLUDED_DIRS.has(segment));
};

/**
 * Copy every template under `srcRoot` to `destRoot/<name>`, without its
 * `node_modules` and `dist`, and return their names. `destRoot` is rebuilt
 * whole, so a template removed from the repository does not linger in the next
 * package.
 */
export function copyTemplates(srcRoot, destRoot) {
	const names = listTemplates(srcRoot);
	rmSync(destRoot, { recursive: true, force: true });
	mkdirSync(destRoot, { recursive: true });

	for (const name of names) {
		const src = resolve(srcRoot, name);
		const dest = resolve(destRoot, name);
		cpSync(src, dest, { recursive: true, filter: shouldCopyFrom(src) });

		// #407: npm drops a file literally named `.gitignore` from a published
		// package, so each template's copy is staged under a dot-less name and
		// `scaffold()` renames it back when it writes the project. The source of
		// truth stays `templates/<name>/.gitignore`, where it also does its own
		// job for anyone working on the template in-tree.
		const stagedGitignore = resolve(dest, ".gitignore");
		if (existsSync(stagedGitignore)) {
			renameSync(stagedGitignore, resolve(dest, "gitignore"));
		}
	}
	return names;
}
