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

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

/**
 * #495 / #496 — the invariant #472 was reaching for.
 *
 * `AppConfigSchema` is a strip-mode `z.object`, and the documented way to
 * build a configuration (`packages/core/README.md`, and the shape
 * `templates/standalone/src/app.mts` uses) parses through it *before*
 * `createApp` composes the modules' own `configSchema`s. A key the schema
 * does not declare is therefore gone by the time the module that reads it
 * runs — and because most module schemas carry a `.default(...)`, what
 * arrives is not an error but a silently different deployment.
 *
 * That has now been found seven times, each time as one missing section:
 * `redisSessionStores` (MIN-3), `redisRefreshTokenFamilyStore` (D-2 v2),
 * `redisCodeRepository` (OR-9), `redisFederationTokenStore` (#456),
 * `redisDeviceCodeStore` + `oauth.deviceAuthorization` (#472),
 * `redisRateLimiter` (#495) and `oauth.mtls` / `oauth.dpop` (#496).
 * `reference-conf-drift.test.mts` closes the half of the class that a
 * shipped `.conf` can see; a section that appears in no `.conf` — which is
 * exactly what #495 was — is invisible to it.
 *
 * So this test asks the modules instead. It reads every `defineModule(...)`
 * manifest in the repository straight off the source (no build, no import,
 * no hand-maintained list), collects the config paths each one's
 * `configSchema` declares, and requires `AppConfigSchema` to declare them
 * too. A new module cannot be added without either declaring its section
 * here or saying, at the key, that it is deliberately not meant to survive
 * the pre-parse — see `EXEMPT_DIRECTIVE`.
 */

const REPO_ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));

/**
 * Where module manifests live. `packages/*​/src` is every published package;
 * `templates/standalone/src` is the composition root we ship, whose own
 * modules run through the same pre-parse.
 */
const SCAN_ROOTS = [join(REPO_ROOT, "packages"), join(REPO_ROOT, "templates")];

/**
 * A module whose section is deliberately NOT meant to survive
 * `AppConfigSchema.parse(...)` says so at the key, in a comment:
 *
 * ```typescript
 * configSchema: z.object({
 *   // app-config-strip-exempt: consumed before the pre-parse by X
 *   somethingLocal: z.object({ ... }),
 * }),
 * ```
 *
 * A reason is required. The point of the directive is that the decision is
 * written down where the key is, rather than reached by leaving the key out
 * of `AppConfigSchema` — which is indistinguishable from forgetting.
 */
const EXEMPT_DIRECTIVE = /app-config-strip-exempt:\s*(\S.*)/;

// ---------------------------------------------------------------------------
// Source enumeration
// ---------------------------------------------------------------------------

function collectSourceFiles(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "__tests__") {
			continue;
		}
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			collectSourceFiles(full, out);
		} else if (entry.name.endsWith(".mts") && !entry.name.endsWith(".d.mts")) {
			out.push(full);
		}
	}
	return out;
}

/** Every `.mts` under a `src/` directory of a workspace in `SCAN_ROOTS`. */
function moduleSourceFiles(): string[] {
	const files: string[] = [];
	for (const root of SCAN_ROOTS) {
		for (const workspace of readdirSync(root, { withFileTypes: true })) {
			if (!workspace.isDirectory()) continue;
			const src = join(root, workspace.name, "src");
			try {
				collectSourceFiles(src, files);
			} catch {
				// A workspace without a `src/` directory contributes no manifests.
			}
		}
	}
	return files.sort();
}

// ---------------------------------------------------------------------------
// Schema-expression resolution
//
// The manifests are read, not executed: a `configSchema` may be an inline
// `z.object({...})`, a `const` declared elsewhere in the same file (exported
// or not), or a projection of core's own `fullSectionsSchema`, and several
// manifests are produced by a factory function that cannot be called without
// its dependencies. Parsing sidesteps all of that — and stays correct for a
// package whose `dist/` is stale or absent.
// ---------------------------------------------------------------------------

type Resolved =
	/** A `z.object({...})` — its properties are config keys. */
	| { readonly kind: "object"; readonly literal: ts.ObjectLiteralExpression }
	/** `<schema>.pick({ a: true, b: true })` — the picked names are the keys. */
	| { readonly kind: "pick"; readonly keys: readonly string[] }
	/** Anything else: a record, an array, an enum, a scalar. A leaf. */
	| { readonly kind: "leaf" };

function propertyKey(name: ts.PropertyName): string | undefined {
	if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
	if (ts.isNoSubstitutionTemplateLiteral(name)) return name.text;
	return undefined;
}

function declarationOf(source: ts.SourceFile, identifier: string): ts.Expression | undefined {
	let found: ts.Expression | undefined;
	const visit = (node: ts.Node): void => {
		if (
			found === undefined &&
			ts.isVariableDeclaration(node) &&
			ts.isIdentifier(node.name) &&
			node.name.text === identifier &&
			node.initializer !== undefined
		) {
			found = node.initializer;
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return found;
}

function resolveSchema(expr: ts.Expression, source: ts.SourceFile, depth = 0): Resolved {
	if (depth > 32) return { kind: "leaf" };

	let node: ts.Expression = expr;
	while (
		ts.isParenthesizedExpression(node) ||
		ts.isAsExpression(node) ||
		ts.isSatisfiesExpression(node)
	) {
		node = node.expression;
	}

	if (ts.isIdentifier(node)) {
		const declared = declarationOf(source, node.text);
		return declared ? resolveSchema(declared, source, depth + 1) : { kind: "leaf" };
	}

	if (!ts.isCallExpression(node)) return { kind: "leaf" };
	const callee = node.expression;
	if (!ts.isPropertyAccessExpression(callee)) return { kind: "leaf" };

	const method = callee.name.text;
	const target = callee.expression;

	if (method === "object" && ts.isIdentifier(target) && target.text === "z") {
		const [shape] = node.arguments;
		return shape && ts.isObjectLiteralExpression(shape)
			? { kind: "object", literal: shape }
			: { kind: "leaf" };
	}

	if (method === "pick") {
		const [selection] = node.arguments;
		if (!selection || !ts.isObjectLiteralExpression(selection)) return { kind: "leaf" };
		const keys = selection.properties
			.map((property) =>
				ts.isPropertyAssignment(property) ? propertyKey(property.name) : undefined,
			)
			.filter((key): key is string => key !== undefined);
		return { kind: "pick", keys };
	}

	// Any other chained builder — `.optional()`, `.default(...)`, `.readonly()`,
	// `.describe(...)` — wraps the schema without changing which keys it
	// declares, so look through it. `z.record(...)`, `z.array(...)`,
	// `z.enum(...)` and friends land on the bare `z` identifier and resolve to
	// a leaf, which is what they are: nothing below them is a declared key.
	return resolveSchema(target, source, depth + 1);
}

// ---------------------------------------------------------------------------
// Manifest walk
// ---------------------------------------------------------------------------

interface DeclaredPath {
	/** Repo-relative file the manifest is written in. */
	readonly file: string;
	/** `name:` off the manifest, when it is a string literal. */
	readonly module: string;
	/** The config path, one element per key. */
	readonly segments: readonly string[];
	/** The reason given by an `app-config-strip-exempt` directive, if any. */
	readonly exemptReason?: string;
}

/** A `configSchema` shape this reader does not understand — never silent. */
interface Unreadable {
	readonly file: string;
	readonly module: string;
	readonly detail: string;
}

const display = (segments: readonly string[]): string => segments.join(".");

function exemptReasonOf(node: ts.Node, source: ts.SourceFile): string | undefined {
	const ranges = ts.getLeadingCommentRanges(source.text, node.getFullStart()) ?? [];
	for (const range of ranges) {
		const match = EXEMPT_DIRECTIVE.exec(source.text.slice(range.pos, range.end));
		if (match) return match[1].trim();
	}
	return undefined;
}

function walkShape(
	resolved: Resolved,
	source: ts.SourceFile,
	context: { readonly file: string; readonly module: string },
	prefix: readonly string[],
	paths: DeclaredPath[],
	unreadable: Unreadable[],
): void {
	if (resolved.kind === "pick") {
		for (const key of resolved.keys) {
			paths.push({ ...context, segments: [...prefix, key] });
		}
		return;
	}
	if (resolved.kind !== "object") return;

	for (const property of resolved.literal.properties) {
		if (!ts.isPropertyAssignment(property)) {
			unreadable.push({
				...context,
				detail: `unsupported property form at ${display(prefix)} — declare config keys as plain \`key: schema\` assignments`,
			});
			continue;
		}
		const key = propertyKey(property.name);
		if (key === undefined) {
			unreadable.push({ ...context, detail: `computed key under ${display(prefix)}` });
			continue;
		}
		const segments = [...prefix, key];
		const exemptReason = exemptReasonOf(property, source);
		paths.push({ ...context, segments, ...(exemptReason ? { exemptReason } : {}) });
		if (exemptReason !== undefined) continue;
		walkShape(
			resolveSchema(property.initializer, source),
			source,
			context,
			segments,
			paths,
			unreadable,
		);
	}
}

interface Scan {
	readonly paths: readonly DeclaredPath[];
	readonly unreadable: readonly Unreadable[];
	/** `name:` of every manifest found, whether or not it declares config. */
	readonly modules: readonly string[];
}

/** Reads every `defineModule(...)` manifest in `text` and what it declares. */
function scanManifests(fileName: string, text: string): Scan {
	const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true);
	const paths: DeclaredPath[] = [];
	const unreadable: Unreadable[] = [];
	const modules: string[] = [];

	const visit = (node: ts.Node): void => {
		if (
			ts.isCallExpression(node) &&
			ts.isIdentifier(node.expression) &&
			node.expression.text === "defineModule"
		) {
			const [manifest] = node.arguments;
			if (manifest && ts.isObjectLiteralExpression(manifest)) {
				const nameProperty = manifest.properties.find(
					(property): property is ts.PropertyAssignment =>
						ts.isPropertyAssignment(property) && propertyKey(property.name) === "name",
				);
				const moduleName =
					nameProperty && ts.isStringLiteral(nameProperty.initializer)
						? nameProperty.initializer.text
						: "<unnamed>";
				modules.push(moduleName);

				const context = { file: fileName, module: moduleName };
				for (const property of manifest.properties) {
					const isConfigSchema =
						(ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) &&
						propertyKey(property.name) === "configSchema";
					if (!isConfigSchema) continue;
					const expression = ts.isPropertyAssignment(property)
						? property.initializer
						: property.name;
					const resolved = resolveSchema(expression, source);
					if (resolved.kind === "leaf") {
						unreadable.push({ ...context, detail: "configSchema is not a readable z.object(...)" });
						continue;
					}
					walkShape(resolved, source, context, [], paths, unreadable);
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(source);

	return { paths, unreadable, modules };
}

// ---------------------------------------------------------------------------
// AppConfigSchema introspection
// ---------------------------------------------------------------------------

interface ZodInternals {
	readonly _zod?: { readonly def?: Record<string, unknown> };
	readonly shape?: Record<string, unknown>;
}

const defOf = (schema: unknown): Record<string, unknown> | undefined =>
	(schema as ZodInternals | undefined)?._zod?.def;

/** Strips the wrappers that do not change which keys a schema declares. */
function unwrap(schema: unknown): unknown {
	let current = schema;
	for (let hop = 0; hop < 32; hop += 1) {
		const def = defOf(current);
		switch (def?.type) {
			case "optional":
			case "nullable":
			case "default":
			case "prefault":
			case "catch":
			case "nonoptional":
			case "readonly":
			case "promise":
				current = def.innerType;
				break;
			case "pipe":
				// `z.preprocess(...)` and `z.coerce`-style pipes: the output side
				// is the schema whose shape a config key is checked against.
				current = def.out;
				break;
			case "lazy":
				current = (def.getter as () => unknown)();
				break;
			default:
				return current;
		}
	}
	return current;
}

/**
 * Whether `AppConfigSchema` carries `segments` through a parse — that is,
 * whether the path is declared rather than stripped.
 */
function declaresPath(schema: unknown, segments: readonly string[]): boolean {
	const current = unwrap(schema);
	if (segments.length === 0) return true;
	const def = defOf(current);
	const [head, ...rest] = segments;

	switch (def?.type) {
		case "object": {
			const shape = (current as ZodInternals).shape ?? {};
			if (Object.hasOwn(shape, head)) return declaresPath(shape[head], rest);
			// `.passthrough()` / a catchall keeps unknown keys, so everything
			// below this point survives.
			const catchall = def.catchall;
			return catchall !== undefined && defOf(catchall)?.type !== "never";
		}
		case "record":
			return declaresPath(def.valueType, rest);
		case "union":
			return (def.options as unknown[]).some((option) => declaresPath(option, segments));
		case "intersection":
			return declaresPath(def.left, segments) || declaresPath(def.right, segments);
		case "unknown":
		case "any":
			return true;
		default:
			return false;
	}
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

const scans = moduleSourceFiles().map((file) =>
	scanManifests(relative(REPO_ROOT, file), readFileSync(file, "utf-8")),
);
const declaredPaths = scans.flatMap((scan) => scan.paths);
const unreadable = scans.flatMap((scan) => scan.unreadable);
const moduleNames = scans.flatMap((scan) => scan.modules);

describe("every module's configSchema survives AppConfigSchema (#495, #496)", () => {
	it("finds the manifests, so the assertions below are over something", () => {
		expect(moduleNames).toContain("mtls");
		expect(moduleNames).toContain("redis-rate-limiter");
		expect(moduleNames).toContain("core-rate-limiter-memory");
		expect(moduleNames.length).toBeGreaterThan(20);
		expect(declaredPaths.length).toBeGreaterThan(20);
	});

	it("reads every configSchema it finds", () => {
		// A manifest listed here declares its config in a shape this reader
		// cannot follow, so the parity assertion below silently skips it.
		// Rewrite the schema as a plain `z.object({ ... })` — inline or a
		// `const` in the same file — rather than widening the reader.
		expect(unreadable.map((entry) => `${entry.file} [${entry.module}] ${entry.detail}`)).toEqual(
			[],
		);
	});

	it("declares every config path a module reads", () => {
		const missing = declaredPaths
			.filter((path) => path.exemptReason === undefined)
			.filter((path) => !declaresPath(AppConfigSchema, path.segments))
			.map((path) => `${display(path.segments)} — declared by [${path.module}] in ${path.file}`);
		// A path listed here is one an operator can write, a module reads, and
		// `AppConfigSchema.parse(...)` throws away in between. Declare it —
		// presence-only, the way the `redis*` sections in `fullSectionsSchema`
		// are — or, if it genuinely must not survive the pre-parse, say so at
		// the key with an `app-config-strip-exempt:` comment.
		expect([...new Set(missing)].sort()).toEqual([]);
	});

	it("keeps the strip exemptions honest", () => {
		const stale = declaredPaths
			.filter((path) => path.exemptReason !== undefined)
			.filter((path) => declaresPath(AppConfigSchema, path.segments))
			.map((path) => `${display(path.segments)} — declared by [${path.module}] in ${path.file}`);
		// `AppConfigSchema` now declares this path, so the exemption on it is
		// no longer true. Drop the directive.
		expect(stale).toEqual([]);
	});
});

describe("the manifest reader", () => {
	const read = (text: string) => scanManifests("synthetic.mts", text);

	it("follows a configSchema declared as a const in the same file", () => {
		const scan = read(`
			const schema = z.object({ alpha: z.object({ beta: z.string() }) });
			export const m = defineModule({ name: "synthetic", configSchema: schema });
		`);
		expect(scan.unreadable).toEqual([]);
		expect(scan.paths.map((path) => display(path.segments))).toEqual(["alpha", "alpha.beta"]);
	});

	it("looks through the builder chain and stops at a record", () => {
		const scan = read(`
			export const m = defineModule({
				name: "synthetic",
				configSchema: z.object({
					alpha: z.object({ beta: z.string() }).default({ beta: "x" }).optional(),
					gamma: z.record(z.string(), z.object({ delta: z.string() })),
				}),
			});
		`);
		expect(scan.paths.map((path) => display(path.segments))).toEqual([
			"alpha",
			"alpha.beta",
			"gamma",
		]);
	});

	it("reads a section exempted at the key, with its reason", () => {
		const scan = read(`
			export const m = defineModule({
				name: "synthetic",
				configSchema: z.object({
					// app-config-strip-exempt: resolved by the composition root first
					local: z.object({ beta: z.string() }),
				}),
			});
		`);
		expect(scan.paths).toEqual([
			{
				file: "synthetic.mts",
				module: "synthetic",
				segments: ["local"],
				exemptReason: "resolved by the composition root first",
			},
		]);
	});

	it("reports a configSchema it cannot read rather than skipping it", () => {
		const scan = read(`
			export const m = defineModule({ name: "synthetic", configSchema: buildSchema() });
		`);
		expect(scan.unreadable).toEqual([
			{
				file: "synthetic.mts",
				module: "synthetic",
				detail: "configSchema is not a readable z.object(...)",
			},
		]);
	});
});
