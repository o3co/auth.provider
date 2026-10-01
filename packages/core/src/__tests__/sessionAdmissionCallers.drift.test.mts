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
 * No shipped source outside `packages/core/src/session-admission/` reads a
 * session by other means than admission (the session-admission ADR's D10).
 *
 * What it finds, by shape and by following the receiver, since a literal grep
 * would miss an aliased store (`const store = opts.userSessionStore`) or
 * boundary (`const revocation = options.subjectRevocation;
 * revocation.revokedBefore(…)`):
 *
 * - `get(` on a receiver typed `UserSessionStore`: a property named
 *   `userSessionStore` on anything; a local, destructured name or parameter
 *   followed to its declaration (a type annotation naming `UserSessionStore`,
 *   a binding element keyed `userSessionStore`, or an initializer that
 *   resolves the same way, through `await`, `!`, `as`, `??` and `?:`);
 * - `revokedBefore(` on a receiver typed `SubjectRevocation`, followed the
 *   same way (`subjectRevocation`, a type naming `SubjectRevocation`);
 * - a call of `selectAcr(`;
 * - a `SessionClaim` literal: an object literal with a `carrier` property
 *   whose value is one of the four carriers;
 * - a call of `recordSecondFactor(`, `establishWithoutAsking(`,
 *   `resumePrimary(` or `continuationOf(`, each kept to the files listed
 *   below (that ADR's D3, D5, D10);
 * - a call of one of admission's own brand minters, `brandClaim(`,
 *   `establish(` or `askEvery(`, kept to `admit.mts` and the file that
 *   defines it: `session-admission/testing/` ships through `./testing`, and
 *   an `Establishment` minted elsewhere would skip every requirement's
 *   `admitPrimary`.
 *
 * A guarded function is found under an import alias (`import { selectAcr as
 * pick }`), as a string element access (`store["get"]`), and as a reference
 * that is not a call (`.bind`, `.call`, a method taken off its object, a
 * value passed on).
 *
 * Every site outside the home is pinned to its file and count with a reason
 * ({@link ALLOWED}): the token-side reads of that ADR's D9, outside
 * admission in this release, and `jwt/verify.mts`'s permanent boundary read.
 * A site not listed, a second one in a listed file, or an entry whose site
 * went away fails.
 *
 * Left to review: a receiver reached under a name declared in another file; a
 * namespace import (`core.selectAcr`) or a computed key (`store[key]`); a
 * local alias of a guarded function (`const f = selectAcr` is a site,
 * `f(…)` is not a second one); a store reached through reflection
 * (`Reflect.get`, `Object.values`); a receiver whose type only a
 * `ts.Program` knows, which this guard does not build.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/** The one directory that may read a session, select an acr or build a claim. */
const HOME = "packages/core/src/session-admission/";

type What =
	| "get"
	| "revokedBefore"
	| "selectAcr"
	| "claim"
	| "recordSecondFactor"
	| "establishWithoutAsking"
	| "resumePrimary"
	| "continuationOf"
	| "brandClaim"
	| "establish"
	| "askEvery";

/** The guarded functions: a call, a reference (`.bind`, `.call`, a value passed on) or an aliased import of any is a site. */
const GUARDED_FUNCTIONS: ReadonlySet<string> = new Set([
	"selectAcr",
	"recordSecondFactor",
	"establishWithoutAsking",
	"resumePrimary",
	"continuationOf",
	"brandClaim",
	"establish",
	"askEvery",
]);

interface Site {
	readonly line: number;
	readonly what: What;
}

type Receiver = "store" | "revocation";

/** The guarded methods, by their receiver's kind. */
const GUARDED_METHODS: ReadonlyMap<string, Receiver> = new Map([
	["get", "store"],
	["revokedBefore", "revocation"],
]);

const CARRIERS: ReadonlySet<string> = new Set(["cookie", "code", "link", "token"]);

/**
 * The sites in `source`: each `get(` on a store-typed receiver, each
 * `revokedBefore(` on a revocation-typed one, each `selectAcr(` call, each
 * claim literal, each `recordSecondFactor(` and `establishWithoutAsking(`
 * call, with its 1-based line.
 */
function sessionAdmissionSites(source: string, fileName = "scan.mts"): Site[] {
	const kind = /\.(?:js|mjs|cjs)$/.test(fileName) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
	const sites: Site[] = [];
	const found = (node: ts.Node, what: What): void => {
		sites.push({ line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, what });
	};
	const bare = (node: ts.Expression): ts.Expression =>
		ts.isParenthesizedExpression(node) ||
		ts.isAsExpression(node) ||
		ts.isSatisfiesExpression(node) ||
		ts.isTypeAssertionExpression(node) ||
		ts.isNonNullExpression(node) ||
		ts.isAwaitExpression(node)
			? bare(node.expression)
			: node;
	const byName = (name: string): Receiver | undefined =>
		name === "userSessionStore" ? "store" : name === "subjectRevocation" ? "revocation" : undefined;
	const byType = (type: ts.TypeNode | undefined): Receiver | undefined => {
		if (type === undefined) return undefined;
		const text = type.getText(file);
		if (/\bUserSessionStore\b/.test(text)) return "store";
		if (/\bSubjectRevocation\b/.test(text)) return "revocation";
		return undefined;
	};
	const keyOf = (element: ts.BindingElement): string | undefined => {
		const key = element.propertyName ?? element.name;
		return ts.isIdentifier(key) || ts.isStringLiteralLike(key) ? key.text : undefined;
	};
	/** The binding element naming `name` in `pattern`, at any depth. */
	const elementNamed = (pattern: ts.BindingName, name: string): ts.BindingElement | undefined => {
		if (ts.isIdentifier(pattern)) return undefined;
		for (const element of pattern.elements) {
			if (ts.isOmittedExpression(element)) continue;
			if (ts.isIdentifier(element.name) && element.name.text === name) return element;
			const inner = elementNamed(element.name, name);
			if (inner !== undefined) return inner;
		}
		return undefined;
	};
	/** What the declaration of `name` in scope at `from` says its value is. */
	const resolveName = (name: string, from: ts.Node, depth: number): Receiver | undefined => {
		if (depth > 8) return undefined;
		for (let scope = from.parent; scope !== undefined; scope = scope.parent) {
			let statements: ts.NodeArray<ts.Statement> | undefined;
			if (ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isModuleBlock(scope)) {
				statements = scope.statements;
			} else if (ts.isCaseClause(scope) || ts.isDefaultClause(scope)) {
				statements = scope.statements;
			}
			if (statements !== undefined) {
				for (const statement of statements) {
					if (!ts.isVariableStatement(statement)) continue;
					for (const declaration of statement.declarationList.declarations) {
						if (ts.isIdentifier(declaration.name)) {
							if (declaration.name.text !== name) continue;
							return (
								byType(declaration.type) ??
								(declaration.initializer === undefined
									? undefined
									: classify(declaration.initializer, depth + 1))
							);
						}
						const element = elementNamed(declaration.name, name);
						if (element !== undefined) {
							const key = keyOf(element);
							return key === undefined ? undefined : byName(key);
						}
					}
				}
			}
			if (ts.isFunctionLike(scope)) {
				for (const parameter of scope.parameters) {
					if (ts.isIdentifier(parameter.name)) {
						if (parameter.name.text === name) return byType(parameter.type);
						continue;
					}
					const element = elementNamed(parameter.name, name);
					if (element !== undefined) {
						const key = keyOf(element);
						return key === undefined ? undefined : byName(key);
					}
				}
			}
		}
		return undefined;
	};
	/** What `expression`'s value is, by its shape or by its declaration. */
	const classify = (expression: ts.Expression, depth = 0): Receiver | undefined => {
		const node = bare(expression);
		if (ts.isPropertyAccessExpression(node)) return byName(node.name.text);
		if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
			return byName(node.argumentExpression.text);
		}
		if (ts.isIdentifier(node)) return resolveName(node.text, node, depth);
		if (ts.isConditionalExpression(node)) {
			return classify(node.whenTrue, depth + 1) ?? classify(node.whenFalse, depth + 1);
		}
		if (ts.isBinaryExpression(node)) {
			const op = node.operatorToken.kind;
			if (op === ts.SyntaxKind.QuestionQuestionToken || op === ts.SyntaxKind.BarBarToken) {
				return classify(node.left, depth + 1) ?? classify(node.right, depth + 1);
			}
			if (op === ts.SyntaxKind.AmpersandAmpersandToken) return classify(node.right, depth + 1);
		}
		return undefined;
	};
	// An import alias: `import { selectAcr as pick }` makes `pick` the guarded name.
	const aliases = new Map<string, string>();
	for (const statement of file.statements) {
		if (!ts.isImportDeclaration(statement)) continue;
		const bindings = statement.importClause?.namedBindings;
		if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
		for (const element of bindings.elements) {
			const original = element.propertyName?.text ?? element.name.text;
			if (GUARDED_FUNCTIONS.has(original)) aliases.set(element.name.text, original);
		}
	}
	const guardedFunction = (name: string): string | undefined =>
		GUARDED_FUNCTIONS.has(name) ? name : aliases.get(name);
	/** A member access — `x.get` or `x["get"]` — as its receiver and member name. */
	const member = (
		node: ts.Node,
	): { readonly receiver: ts.Expression; readonly name: string } | undefined =>
		ts.isPropertyAccessExpression(node)
			? { receiver: node.expression, name: node.name.text }
			: ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)
				? { receiver: node.expression, name: node.argumentExpression.text }
				: undefined;
	/** Whether `node` is the callee of the call that is its parent. */
	const isCallee = (node: ts.Node): boolean =>
		ts.isCallExpression(node.parent) && node.parent.expression === node;
	/** Whether an identifier names a declaration, an import, a property or a type — not a reference to a value. */
	const isDeclarationName = (node: ts.Identifier): boolean => {
		const parent = node.parent;
		return (
			(ts.isPropertyAccessExpression(parent) && parent.name === node) ||
			ts.isImportSpecifier(parent) ||
			ts.isImportClause(parent) ||
			ts.isExportSpecifier(parent) ||
			(ts.isPropertyAssignment(parent) && parent.name === node) ||
			(ts.isVariableDeclaration(parent) && parent.name === node) ||
			(ts.isFunctionDeclaration(parent) && parent.name === node) ||
			(ts.isParameter(parent) && parent.name === node) ||
			(ts.isBindingElement(parent) && (parent.name === node || parent.propertyName === node)) ||
			(ts.isPropertySignature(parent) && parent.name === node) ||
			(ts.isMethodSignature(parent) && parent.name === node) ||
			(ts.isMethodDeclaration(parent) && parent.name === node) ||
			(ts.isPropertyDeclaration(parent) && parent.name === node) ||
			ts.isTypeReferenceNode(parent) ||
			ts.isTypeQueryNode(parent) ||
			ts.isQualifiedName(parent)
		);
	};
	/** A guarded method on a receiver of its kind: the site's kind, else `undefined`. */
	const guardedMember = (node: ts.Node): What | undefined => {
		const access = member(node);
		if (access === undefined) return undefined;
		const receiver = GUARDED_METHODS.get(access.name);
		return receiver !== undefined && classify(access.receiver) === receiver
			? (access.name as What)
			: undefined;
	};
	const visit = (node: ts.Node): void => {
		if (ts.isCallExpression(node)) {
			const callee = node.expression;
			const method = guardedMember(callee);
			if (method !== undefined) {
				found(node, method);
			} else if (ts.isIdentifier(callee)) {
				const name = guardedFunction(callee.text);
				if (name !== undefined) found(node, name as What);
			} else {
				// A string element access to a guarded function: `x["recordSecondFactor"](…)`.
				const access = member(callee);
				if (access !== undefined && GUARDED_FUNCTIONS.has(access.name)) {
					found(node, access.name as What);
				} else if (
					ts.isPropertyAccessExpression(callee) &&
					GUARDED_FUNCTIONS.has(callee.name.text)
				) {
					found(node, callee.name.text as What);
				}
			}
		} else if (ts.isIdentifier(node) && !isCallee(node) && !isDeclarationName(node)) {
			// A reference that is not a call: `.bind`, `.call`, a value passed on.
			const name = guardedFunction(node.text);
			if (name !== undefined) found(node, name as What);
		} else if (
			(ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) &&
			!isCallee(node)
		) {
			// A method taken off its object without being called there — not a
			// `typeof` check of it, which reads nothing.
			const method = ts.isTypeOfExpression(node.parent) ? undefined : guardedMember(node);
			if (method !== undefined) found(node, method);
		} else if (ts.isObjectLiteralExpression(node)) {
			for (const property of node.properties) {
				if (
					ts.isPropertyAssignment(property) &&
					(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) &&
					property.name.text === "carrier" &&
					ts.isStringLiteralLike(property.initializer) &&
					CARRIERS.has(property.initializer.text)
				) {
					found(node, "claim");
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return sites;
}

/** A shipped source: any TypeScript or JavaScript source, no declaration file, no test. */
const isShippedSource = (name: string): boolean =>
	/\.(?:ts|mts|cts|js|mjs|cjs)$/.test(name) &&
	!/\.d\.(?:ts|mts|cts)$/.test(name) &&
	!/\.test\.(?:ts|mts|cts|js|mjs|cjs)$/.test(name);

/** Every shipped source of every package and of the standalone template, `/`-separated from the root. */
function shippedSources(): string[] {
	const files: string[] = [];
	const collect = (dir: string): void => {
		let entries: Dirent[];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (entry.name === "__tests__" || entry.name === "node_modules" || entry.name === "dist") {
				continue;
			}
			const path = join(dir, entry.name);
			if (entry.isDirectory()) collect(path);
			else if (isShippedSource(entry.name))
				files.push(relative(repoRoot, path).split(sep).join("/"));
		}
	};
	for (const pkg of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
		if (pkg.isDirectory()) collect(join(repoRoot, "packages", pkg.name, "src"));
	}
	collect(join(repoRoot, "templates", "standalone", "src"));
	return files.sort();
}

/** A file outside the home that reads a session, selects an acr or builds a claim: its sites by kind and count, and why they stay. */
interface AllowedSites {
	readonly file: string;
	readonly sites: Partial<Record<What, number>>;
	readonly why: string;
}

const TOKEN_SIDE =
	"a session read from a token, not a cookie: outside this release, routed through admission by a later record (D9)";

/**
 * Every site outside the home, pinned to its file, its kind and its exact
 * count, with why. `recordSecondFactor(` and `establishWithoutAsking(` are
 * not counted here: their callers are held to files by prefix below.
 */
const ALLOWED: ReadonlyArray<AllowedSites> = [
	// The token side of the session-admission ADR's D9: not through admission
	// in this release.
	{
		file: "packages/oauth/src/routes.mts",
		sites: { get: 1 },
		why: `${TOKEN_SIDE}: introspection's liveness read`,
	},
	{
		file: "packages/oauth/src/routes/federationToken.mts",
		sites: { get: 1 },
		why: `${TOKEN_SIDE}: the federation-token route's read`,
	},
	{
		file: "packages/oauth/src/routes/logout.mts",
		sites: { get: 2 },
		why: `${TOKEN_SIDE}: the two logout routes' reads`,
	},
	{
		file: "packages/oauth/src/routes/userinfo.mts",
		sites: { get: 1 },
		why: `${TOKEN_SIDE}: userinfo's liveness read`,
	},
	{
		file: "packages/oauth-token-exchange/src/grant.mts",
		sites: { get: 1 },
		why: `${TOKEN_SIDE}: the token-exchange grant's liveness read`,
	},
	{
		file: "packages/device-grant/src/grant.mts",
		sites: { revokedBefore: 1 },
		why: `${TOKEN_SIDE}: the device_code grant's boundary read at the poll`,
	},
	// The token side's boundary, permanent.
	{
		file: "packages/core/src/jwt/verify.mts",
		sites: { revokedBefore: 1 },
		why: "permanent: the subject-revocation boundary applied to a token by verifyJwt (D9); a token carrier's admission skips the boundary because this reads it",
	},
];

/** The files whose prefixes may call `recordSecondFactor(`: the two bundled stores, and the MFA package (the session-admission ADR's D3, D10). */
const RECORD_SECOND_FACTOR_CALLERS: readonly string[] = [
	"packages/core/src/user-sessions/memory/userSessionStore.mts",
	"packages/redis/src/userSessionStore.mts",
	"packages/mfa/src/",
];

/** The one file that may call `establishWithoutAsking(`: the federation callback (the session-admission ADR's D5). */
const ESTABLISH_WITHOUT_ASKING_CALLERS: readonly string[] = [
	"packages/session/src/routes/Federation.mts",
];

/** The files whose prefixes may call `resumePrimary(` or build a continuation: the MFA package (the session-admission ADR's D5); the full-set fixture under `tools/` is not scanned. */
const RESUME_PRIMARY_CALLERS: readonly string[] = ["packages/mfa/src/"];

const ADMIT = "packages/core/src/session-admission/admit.mts";
const ESTABLISHMENT = "packages/core/src/session-admission/establishment.mts";

/** The one file, beside the one that defines it, that may call each of admission's brand minters: `admit.mts`. */
const MINTER_CALLERS: Readonly<Record<"brandClaim" | "establish" | "askEvery", readonly string[]>> =
	{
		brandClaim: [ADMIT, "packages/core/src/session-admission/request-check.mts"],
		establish: [ADMIT, ESTABLISHMENT],
		askEvery: [ADMIT, ESTABLISHMENT],
	};

/** `sites`, counted by kind. */
const counted = (sites: readonly Site[]): Partial<Record<What, number>> => {
	const counts: Partial<Record<What, number>> = {};
	for (const { what } of sites) counts[what] = (counts[what] ?? 0) + 1;
	return counts;
};

describe("session-admission callers", () => {
	it("finds a store read whatever the receiver is called: a property, an alias, a destructured name, a typed parameter", () => {
		for (const source of [
			"await deps.userSessionStore.get(sid);",
			"const store = opts.userSessionStore; await store.get(sid);",
			"const { userSessionStore } = options; await userSessionStore.get(sid);",
			"const { userSessionStore: sessions } = options; await sessions.get(sid);",
			"function f(store: UserSessionStore) { return store.get(sid); }",
			"function f({ userSessionStore }: Options) { return userSessionStore.get(sid); }",
			"async function f() { const store = opts.userSessionStore; if (store) { const s = await (store as UserSessionStore).get(sid); } }",
			"const store = a ? opts.userSessionStore : undefined; store?.get(sid);",
			"let store: UserSessionStore | undefined; store = undefined; store?.get(sid);",
		]) {
			expect(
				sessionAdmissionSites(source).map((s) => s.what),
				source,
			).toEqual(["get"]);
		}
	});

	it("does not take a map, another store, or the express-session store for one", () => {
		for (const source of [
			"const store = new Map<string, Bucket>(); store.get(sid);",
			"await opts.federationTokenStore.get(sid, name);",
			"function f(store: SessionStore) { store.get(key(id), cb); }",
			"const { federationTokenStore: store } = deps; store.get(sid);",
			"const store = deps.userSessionStore; const other = new Map(); other.get(sid);",
		]) {
			expect(sessionAdmissionSites(source), source).toEqual([]);
		}
	});

	it("finds a boundary read on a subject revocation: a property, an alias, a typed parameter, a conditional", () => {
		for (const source of [
			"await deps.subjectRevocation.revokedBefore(sub);",
			"const revocation = options.subjectRevocation; await revocation.revokedBefore(subject);",
			'const sessionsBoundaryFor = (revocation: Pick<SubjectRevocation, "revokedBefore">) => async (s) => revocation.revokedBefore(s);',
			'const subjectRevocation = revocation === "none" ? undefined : revocation.subjectRevocation; await subjectRevocation.revokedBefore(sub);',
		]) {
			expect(
				sessionAdmissionSites(source).map((s) => s.what),
				source,
			).toEqual(["revokedBefore"]);
		}
		expect(sessionAdmissionSites("await grants.revokedBefore(sub);")).toEqual([]);
	});

	it("finds a selectAcr call, a claim literal, and the two guarded calls", () => {
		expect(sessionAdmissionSites("const s = selectAcr(requested, amr, table, reach);")).toEqual([
			{ line: 1, what: "selectAcr" },
		]);
		expect(
			sessionAdmissionSites('const c = { authenticated: true, sid, subject, carrier: "cookie" };'),
		).toEqual([{ line: 1, what: "claim" }]);
		expect(
			sessionAdmissionSites('const c = { carrier: kind }; const d = { carrier: "bus" };'),
		).toEqual([]);
		expect(sessionAdmissionSites("await store.recordSecondFactor(sid, event);")).toEqual([
			{ line: 1, what: "recordSecondFactor" },
		]);
		expect(sessionAdmissionSites("const e = establishWithoutAsking(login);")).toEqual([
			{ line: 1, what: "establishWithoutAsking" },
		]);
		expect(sessionAdmissionSites("const a = await resumePrimary(deps, c, done);")).toEqual([
			{ line: 1, what: "resumePrimary" },
		]);
		expect(sessionAdmissionSites("const c = continuationOf(primary, [], name);")).toEqual([
			{ line: 1, what: "continuationOf" },
		]);
	});

	it("follows an import alias, a string element access, and a reference that is not a call — bind, call, a value passed on", () => {
		for (const [source, what] of [
			[
				'import { selectAcr as pick } from "@o3co/auth-provider-core"; pick(a, b, t, r);',
				"selectAcr",
			],
			[
				'import { resumePrimary as go } from "@o3co/auth-provider-core"; await go(d, c, x);',
				"resumePrimary",
			],
			['function f(store: UserSessionStore) { return store["get"](sid); }', "get"],
			['await store["recordSecondFactor"](sid, event);', "recordSecondFactor"],
			["function f(store: UserSessionStore) { const read = store.get; return read(sid); }", "get"],
			["function f(store: UserSessionStore) { return store.get.bind(store); }", "get"],
			["function f(store: UserSessionStore) { return store.get.call(store, sid); }", "get"],
			["function f(store: UserSessionStore) { return use(store.get); }", "get"],
			["const f = selectAcr; f(a, b, t, r);", "selectAcr"],
			["run(establishWithoutAsking);", "establishWithoutAsking"],
		] as const) {
			expect(
				sessionAdmissionSites(source).map((s) => s.what),
				source,
			).toEqual([what]);
		}
	});

	const sites = new Map<string, Site[]>();
	for (const file of shippedSources()) {
		const found = sessionAdmissionSites(readFileSync(join(repoRoot, file), "utf8"), file);
		if (found.length > 0) sites.set(file, found);
	}

	it("scans the home, which builds the claims and selects the acr (sanity: the guard is not vacuous)", () => {
		const home = [...sites].filter(([file]) => file.startsWith(HOME));
		expect(home.length).toBeGreaterThan(0);
		const inHome = counted(home.flatMap(([, s]) => s));
		// The five builders — cookie, the code's two reads, link, token — and the contract suite's own live input.
		expect(inHome.claim).toBe(6);
		expect(inHome.selectAcr).toBe(1);
		expect(inHome.get).toBe(1);
		expect(inHome.revokedBefore).toBe(1);
	});

	it("reads a session, the boundary and the acr, and builds a claim, nowhere outside the home but the sites listed, each at its count", () => {
		const outside = [...sites]
			.filter(([file]) => !file.startsWith(HOME))
			.map(([file, found]) => {
				const {
					recordSecondFactor: _r,
					establishWithoutAsking: _e,
					resumePrimary: _p,
					continuationOf: _c,
					...rest
				} = counted(found);
				return [file, rest] as const;
			})
			.filter(([, counts]) => Object.keys(counts).length > 0);
		const actual = Object.fromEntries(outside);
		const expected = Object.fromEntries(ALLOWED.map(({ file, sites: s }) => [file, s]));
		expect(
			actual,
			"read a session through admitSession with a claim core built (core/src/session-admission/)",
		).toEqual(expected);
	});

	it("keeps recordSecondFactor( to the two bundled stores and the MFA package, and establishWithoutAsking( to the federation callback", () => {
		const offenders = (what: What, allowed: readonly string[]): string[] =>
			[...sites]
				.filter(
					([file, found]) =>
						!file.startsWith(HOME) &&
						found.some((s) => s.what === what) &&
						!allowed.some((prefix) => file === prefix || file.startsWith(prefix)),
				)
				.map(([file]) => file);
		expect(offenders("recordSecondFactor", RECORD_SECOND_FACTOR_CALLERS)).toEqual([]);
		expect(offenders("establishWithoutAsking", ESTABLISH_WITHOUT_ASKING_CALLERS)).toEqual([]);
		expect(offenders("resumePrimary", RESUME_PRIMARY_CALLERS)).toEqual([]);
		expect(offenders("continuationOf", RESUME_PRIMARY_CALLERS)).toEqual([]);
	});

	it("finds a call of each brand minter, under an alias and as a value passed on", () => {
		for (const [source, what] of [
			["const c = brandClaim({ authenticated: true });", "brandClaim"],
			["return establish(primary);", "establish"],
			["return askEvery(deps, requirements, primary, primary, []);", "askEvery"],
			[
				'import { establish as mint } from "../session-admission/establishment.mjs"; mint(p);',
				"establish",
			],
			["run(askEvery);", "askEvery"],
		] as const) {
			expect(
				sessionAdmissionSites(source).map((s) => s.what),
				source,
			).toEqual([what]);
		}
	});

	it("keeps admission's brand minters to admit.mts and the file that defines each, its testing entry excluded", () => {
		const offenders = [...sites].flatMap(([file, found]) =>
			(Object.keys(MINTER_CALLERS) as (keyof typeof MINTER_CALLERS)[])
				.filter((what) => found.some((s) => s.what === what))
				.filter((what) => !MINTER_CALLERS[what].includes(file))
				.map((what) => `${file}: ${what}`),
		);
		expect(offenders, "mint a claim or an Establishment through admit.mts").toEqual([]);
		// Not vacuous: admit.mts mints through each.
		const inAdmit = counted(sites.get(ADMIT) ?? []);
		expect(inAdmit.brandClaim).toBe(5);
		expect(inAdmit.establish).toBe(1);
		expect(inAdmit.askEvery).toBe(2);
	});

	it("has the federation callback call establishWithoutAsking exactly once", () => {
		const [callback] = ESTABLISH_WITHOUT_ASKING_CALLERS;
		const found = (sites.get(callback) ?? []).filter((s) => s.what === "establishWithoutAsking");
		expect(found, `${callback} — the callback's login path`).toHaveLength(1);
	});

	it("has no stale entry: every listed file is scanned and has the sites it lists", () => {
		for (const { file, sites: s, why } of ALLOWED) {
			const found = sites.get(file);
			expect(found, `${file} — ${why}`).toBeDefined();
			const {
				recordSecondFactor: _r,
				establishWithoutAsking: _e,
				resumePrimary: _p,
				continuationOf: _c,
				...rest
			} = counted(found ?? []);
			expect(rest, `${file} — ${why}`).toEqual(s);
		}
	});
});
