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

/**
 * moduleConfigRequires.drift.test.mts — no manifest outside core requires
 * `config` (#728). A module reads its own section (`deps.section`) and what
 * another module owns through a slot whose contract is core's; the whole
 * configuration is core's to parse. The manifests that require `config` today
 * are listed below, and the list may only shrink: a manifest that requires it
 * and is not listed fails, and so does a listed one that no longer does.
 *
 * What it reads, with TypeScript's parser, in the product code of every
 * workspace but core — a source under `src/` outside `__tests__/` that is not
 * a `*.test.*` or `*.spec.*` file: every object literal carrying both a `name`
 * and a `requires` property, the shape of a manifest handed to `defineModule`.
 * `requires` is read as an array literal, through `as const` and through a
 * `const` of the same file; `name` as a string literal or a `const` of the
 * same file. A manifest whose `requires` cannot be read that way fails, and so
 * does one requiring `config` whose `name` cannot: the list is keyed by it.
 *
 * What it does not follow is left to review: a manifest assembled at run time
 * (spread from another object, or built by a function whose argument is the
 * array), and a `requires` imported from another file.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/**
 * The manifests outside core that require `config` today, keyed
 * `<workspace> -> <module name>` (#728). The list may only shrink: each entry
 * leaves as its module reads its own section and the slots it needs instead.
 */
const CONFIG_REQUIRERS: readonly string[] = [
	// Each reads a section of its own that is not yet under its name, and some
	// a key of another module's section beside it.
	"packages/device-grant -> device-grant",
	"packages/dpop -> dpop",
	"packages/federation-grants -> federation-grants",
	"packages/mfa -> mfa",
	"packages/mfa -> mfa-totp-factor",
	"packages/mtls -> mtls",
	"packages/oauth -> oauth",
	"packages/oauth -> oauth-authorization",
	"packages/oauth -> oauth-session",
	"packages/oauth -> subject-revocation-service",
	"packages/oauth-token-exchange -> oauth-token-exchange",
	"packages/session -> session",
	"packages/session -> session-store",
	"packages/webauthn -> webauthn",
	// The Redis stores read their own sections, and the deployment mode.
	"packages/redis -> redis-access-token-denylist",
	"packages/redis -> redis-challenge-store",
	"packages/redis -> redis-code-repository",
	"packages/redis -> redis-consent-store",
	"packages/redis -> redis-device-code-store",
	"packages/redis -> redis-federation-grant-intent-store",
	"packages/redis -> redis-federation-grant-store",
	"packages/redis -> redis-federation-token-store",
	"packages/redis -> redis-mfa-factor-store",
	"packages/redis -> redis-mfa-transaction-store",
	"packages/redis -> redis-rate-limiter",
	"packages/redis -> redis-refresh-token-family-store",
	"packages/redis -> redis-replay-seen-set",
	"packages/redis -> redis-session-stores",
	// The standalone template's own modules, which read the template's
	// settings and the adapter selection.
	"templates/standalone -> audit-sink",
	"templates/standalone -> google-federation-config",
	"templates/standalone -> key-store",
	"templates/standalone -> oidc-federation-config",
	"templates/standalone -> redis-clients",
	"templates/standalone -> repositories",
	"templates/standalone -> standalone-in-memory-code-repository",
	"templates/standalone -> stores",
];

/** The directories `pnpm-workspace.yaml` names, `dir/*` expanded to its children that hold a package.json. */
function workspaceDirs(): string[] {
	const text = readFileSync(join(repoRoot, "pnpm-workspace.yaml"), "utf8");
	const block = text.split(/^packages:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
	const globs = [...block.matchAll(/^\s+-\s+["']?([^"'\s]+)["']?\s*$/gm)].map((match) =>
		String(match[1]),
	);
	const dirs: string[] = [];
	for (const glob of globs) {
		if (!glob.endsWith("/*")) {
			dirs.push(glob);
			continue;
		}
		const parent = glob.slice(0, -2);
		for (const entry of readdirSync(join(repoRoot, parent), { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const dir = `${parent}/${entry.name}`;
			try {
				readFileSync(join(repoRoot, dir, "package.json"));
				dirs.push(dir);
			} catch {
				// a directory without a package.json is no workspace
			}
		}
	}
	return dirs.sort();
}

/** Whether `file` is a test: under a `__tests__/` directory, or a `*.test.*` / `*.spec.*` file. */
const isTest = (file: string): boolean =>
	file.split("/").includes("__tests__") || /\.(test|spec)\.[cm]?[jt]s$/.test(file);

/** Every product source under `dir`, relative to the repository. */
function productSourcesUnder(dir: string): string[] {
	const files: string[] = [];
	let entries: Dirent[];
	try {
		entries = readdirSync(join(repoRoot, dir), { withFileTypes: true });
	} catch {
		return files;
	}
	for (const entry of entries) {
		if (["node_modules", "dist", "coverage"].includes(entry.name)) continue;
		const path = `${dir}/${entry.name}`;
		if (entry.isDirectory()) files.push(...productSourcesUnder(path));
		else if (/\.[cm]?[jt]s$/.test(entry.name) && !entry.name.endsWith(".d.mts") && !isTest(path)) {
			files.push(path);
		}
	}
	return files;
}

/** One manifest found: where, its name (`undefined` when it cannot be read), and what it requires. */
interface Manifest {
	readonly line: number;
	readonly name: string | undefined;
	/** `undefined` when the `requires` cannot be read as an array of string literals. */
	readonly requires: readonly string[] | undefined;
}

/** The manifests in `text`, a source named `fileName`. */
function manifestsIn(fileName: string, text: string): Manifest[] {
	const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true);
	const constants = new Map<string, ts.Expression>();
	const collect = (node: ts.Node): void => {
		if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
			constants.set(node.name.text, node.initializer);
		}
		ts.forEachChild(node, collect);
	};
	collect(source);
	/** The expression under `as`, `satisfies` and parentheses, and behind a `const` of the file. */
	const unwrap = (expression: ts.Expression, seen = new Set<string>()): ts.Expression => {
		let current = expression;
		while (
			ts.isAsExpression(current) ||
			ts.isSatisfiesExpression(current) ||
			ts.isParenthesizedExpression(current)
		) {
			current = current.expression;
		}
		if (ts.isIdentifier(current) && !seen.has(current.text)) {
			const bound = constants.get(current.text);
			if (bound !== undefined) return unwrap(bound, new Set([...seen, current.text]));
		}
		return current;
	};
	const found: Manifest[] = [];
	const visit = (node: ts.Node): void => {
		if (ts.isObjectLiteralExpression(node)) {
			const property = (key: string) =>
				node.properties.find(
					(p): p is ts.PropertyAssignment =>
						ts.isPropertyAssignment(p) && p.name.getText(source) === key,
				);
			const nameProperty = property("name");
			const requiresProperty = property("requires");
			if (nameProperty !== undefined && requiresProperty !== undefined) {
				const name = unwrap(nameProperty.initializer);
				const requires = unwrap(requiresProperty.initializer);
				const elements =
					ts.isArrayLiteralExpression(requires) &&
					requires.elements.every((element) => ts.isStringLiteralLike(element))
						? requires.elements.map((element) => (element as ts.StringLiteralLike).text)
						: undefined;
				found.push({
					line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
					name: ts.isStringLiteralLike(name) ? name.text : undefined,
					requires: elements,
				});
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return found;
}

/** Every manifest in the product code of every workspace but core, with its workspace and file. */
const FOUND = workspaceDirs()
	.filter((dir) => dir !== "packages/core")
	.flatMap((dir) =>
		productSourcesUnder(`${dir}/src`).flatMap((file) =>
			manifestsIn(file, readFileSync(join(repoRoot, file), "utf8")).map((manifest) => ({
				...manifest,
				workspace: dir,
				file,
			})),
		),
	);

describe("the manifest scan", () => {
	it("reads requires as an array literal, through as const and a const of the file, and a name through a const", () => {
		const found = manifestsIn(
			"example.mts",
			[
				'const NAME = "b";',
				'const REQUIRES = ["config", "keyStore"] as const;',
				'defineModule({ name: "a", requires: ["config"] });',
				"defineModule({ name: NAME, requires: REQUIRES });",
				'defineModule({ name: "c", requires: ["keyStore"] as const });',
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([
			["a", ["config"]],
			["b", ["config", "keyStore"]],
			["c", ["keyStore"]],
		]);
	});

	it("reports a requires or a name it cannot read", () => {
		const found = manifestsIn(
			"example.mts",
			[
				"defineModule({ name: prefix + n, requires: [...base, 'config'] });",
				'defineModule({ name: "y", requires: build() });',
			].join("\n"),
		);
		expect(found.map(({ name, requires }) => [name, requires])).toEqual([
			[undefined, undefined],
			["y", undefined],
		]);
	});

	it("walks a plausible workspace (the guard is not vacuous)", () => {
		expect(FOUND.length).toBeGreaterThan(20);
		expect(FOUND.some((manifest) => manifest.name === "oauth")).toBe(true);
	});
});

describe("no manifest outside core requires config (#728)", () => {
	it("reads every manifest's requires", () => {
		expect(
			FOUND.filter((manifest) => manifest.requires === undefined).map(
				(manifest) => `${manifest.file}:${manifest.line}`,
			),
		).toEqual([]);
	});

	it("names every manifest that requires config", () => {
		expect(
			FOUND.filter(
				(manifest) => manifest.name === undefined && manifest.requires?.includes("config"),
			).map((manifest) => `${manifest.file}:${manifest.line}`),
		).toEqual([]);
	});

	it("finds no manifest requiring config beyond the list", () => {
		const requirers = FOUND.filter((manifest) => manifest.requires?.includes("config")).map(
			(manifest) => `${manifest.workspace} -> ${manifest.name}`,
		);
		expect(
			requirers.filter((key) => !CONFIG_REQUIRERS.includes(key)),
			"a module reads its own section (deps.section) and another module's values through a slot",
		).toEqual([]);
	});

	it("keeps no entry whose manifest no longer requires config: the list only shrinks", () => {
		const requirers = new Set(
			FOUND.filter((manifest) => manifest.requires?.includes("config")).map(
				(manifest) => `${manifest.workspace} -> ${manifest.name}`,
			),
		);
		expect(
			CONFIG_REQUIRERS.filter((key) => !requirers.has(key)),
			"remove it from CONFIG_REQUIRERS",
		).toEqual([]);
	});
});
