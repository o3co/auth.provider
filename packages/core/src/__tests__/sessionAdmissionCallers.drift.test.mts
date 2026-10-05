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
 * What it finds, in one TypeScript program over every shipped source, typed
 * as the workspace builds it:
 *
 * - `get` on a receiver whose type is core's `UserSessionStore`, and
 *   `revokedBefore` on one whose type is core's `SubjectRevocation`: the
 *   checker resolves the member on the receiver's type (a member of its union,
 *   an intersection, a type parameter's constraint, a `Pick`) to the
 *   interface's own declaration. How the receiver is reached or written does
 *   not matter: a property, an alias, a call's result, a name declared in
 *   another file, optional chaining, an element access by a literal key, or
 *   the method destructured off it. A property or interface merely named like
 *   one is not it;
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
 * pick }`), as a member access (`store["recordSecondFactor"]`), and as a
 * reference that is not a call (`.bind`, `.call`, a value passed on); a
 * guarded method, also when taken off its object without being called there.
 *
 * Every site outside the home is pinned to its file and count with a reason
 * ({@link ALLOWED}): the token-side reads of that ADR's D9, outside
 * admission in this release, and `jwt/verify.mts`'s permanent boundary read.
 * A site not listed, a second one in a listed file, or an entry whose site
 * went away fails.
 *
 * Left to review: a receiver typed `any`, or a class's own `get` (a store
 * implementation's, not the interface's); a namespace import
 * (`core.selectAcr`) or a computed key that is not one literal; a local alias
 * of a guarded function (`const f = selectAcr` is a site, `f(…)` is not a
 * second one); a store reached through reflection (`Reflect.get`,
 * `Object.values`). The program resolves another package's import of core to
 * core's build, so the guard runs after the workspace build, as CI runs it.
 */

import { type Dirent, readdirSync } from "node:fs";
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

/** The interfaces whose guarded methods are tracked, by name, as core declares them. */
const TRACKED_INTERFACES: ReadonlyMap<string, Receiver> = new Map([
	["UserSessionStore", "store"],
	["SubjectRevocation", "revocation"],
]);

/** Where core declares them: its source, and the build every other package's import resolves to. */
const TRACKED_DECLARATION_FILES: ReadonlySet<string> = new Set([
	"packages/core/src/user-sessions/types.mts",
	"packages/core/dist/user-sessions/types.d.mts",
]);

const CARRIERS: ReadonlySet<string> = new Set(["cookie", "code", "link", "token"]);

/** `fileName`, `/`-separated from the root. */
const fromRoot = (fileName: string): string => relative(repoRoot, fileName).split(sep).join("/");

/**
 * The sites in `file`: each `get` on a `UserSessionStore` and each
 * `revokedBefore` on a `SubjectRevocation`, as `checker` types the receiver;
 * each guarded function; each claim literal; with its 1-based line.
 */
function sessionAdmissionSites(checker: ts.TypeChecker, file: ts.SourceFile): Site[] {
	const sites: Site[] = [];
	const found = (node: ts.Node, what: What): void => {
		sites.push({ line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, what });
	};
	/** The tracked interface `declaration` is a member of, if any. */
	const trackedOwner = (declaration: ts.Declaration): Receiver | undefined => {
		const owner = declaration.parent;
		return ts.isInterfaceDeclaration(owner) &&
			TRACKED_DECLARATION_FILES.has(fromRoot(owner.getSourceFile().fileName))
			? TRACKED_INTERFACES.get(owner.name.text)
			: undefined;
	};
	/**
	 * Whether `name` on a value of `type` is the guarded method of its kind: the
	 * member some part of the type resolves it to — the type itself, a member of
	 * its union, an intersection, a constraint, a `Pick` — is the tracked
	 * interface's own.
	 */
	const isGuarded = (type: ts.Type, name: string): boolean => {
		const kind = GUARDED_METHODS.get(name);
		if (kind === undefined) return false;
		const defined = checker.getNonNullableType(type);
		return (defined.isUnion() ? defined.types : [defined]).some((part) =>
			(checker.getPropertyOfType(checker.getApparentType(part), name)?.declarations ?? []).some(
				(declaration) => trackedOwner(declaration) === kind,
			),
		);
	};
	/** A computed key's name: a string literal, or an expression whose type is one string literal. */
	const keyOf = (key: ts.Expression): string | undefined => {
		if (ts.isStringLiteralLike(key)) return key.text;
		const type = checker.getTypeAtLocation(key);
		return type.isStringLiteral() ? type.value : undefined;
	};
	/** A binding element's property name: `get` in `{ get }`, `{ get: read }`, `{ "get": read }` or `{ [key]: read }`. */
	const boundName = (element: ts.BindingElement): string | undefined => {
		const key = element.propertyName ?? element.name;
		if (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) return key.text;
		return ts.isComputedPropertyName(key) ? keyOf(key.expression) : undefined;
	};
	/** A member access — `x.get`, `x?.get`, `x["get"]`, `x[key]` — as its receiver and member name. */
	const member = (
		node: ts.Node,
	): { readonly receiver: ts.Expression; readonly name: string | undefined } | undefined =>
		ts.isPropertyAccessExpression(node)
			? { receiver: node.expression, name: node.name.text }
			: ts.isElementAccessExpression(node)
				? { receiver: node.expression, name: keyOf(node.argumentExpression) }
				: undefined;
	/** A guarded method on a receiver typed as its interface: the site's kind, else `undefined`. */
	const guardedMember = (node: ts.Node): What | undefined => {
		const access = member(node);
		if (access?.name === undefined || !GUARDED_METHODS.has(access.name)) return undefined;
		return isGuarded(checker.getTypeAtLocation(access.receiver), access.name)
			? (access.name as What)
			: undefined;
	};
	/** A guarded method taken off its object by destructuring: `const { get } = store`. */
	const guardedBinding = (element: ts.BindingElement): What | undefined => {
		if (!ts.isObjectBindingPattern(element.parent)) return undefined;
		const name = boundName(element);
		if (name === undefined || !GUARDED_METHODS.has(name)) return undefined;
		return isGuarded(checker.getTypeAtLocation(element.parent), name) ? (name as What) : undefined;
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
				// A member access to a guarded function: `x.recordSecondFactor(…)`, `x["recordSecondFactor"](…)`.
				const name = member(callee)?.name;
				if (name !== undefined && GUARDED_FUNCTIONS.has(name)) found(node, name as What);
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
		} else if (ts.isBindingElement(node)) {
			const method = guardedBinding(node);
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
			else if (isShippedSource(entry.name)) files.push(fromRoot(path));
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
	{
		file: "packages/webauthn/src/grant.mts",
		sites: { revokedBefore: 1 },
		why: `${TOKEN_SIDE}: the passkey grant's boundary read before it mints`,
	},
	// A login's MFA transaction, before any session exists: the MFA ADR's D8
	// (build-order step 11-B).
	{
		file: "packages/mfa/src/coordinator.mts",
		sites: { revokedBefore: 1 },
		why: "a login's MFA transaction held to its subject's sessions boundary at every use: no session exists yet for admission to read, and a ceremony begun before a revocation must bind nothing (the MFA ADR's D8)",
	},
	// The subject's own release of its MFA lock: the MFA ADR's D21.
	{
		file: "packages/mfa/src/lockRecovery.mts",
		sites: { revokedBefore: 1 },
		why: "the release of a subject's MFA lock hands the store the subject's sessions boundary, which the store holds against the attack's first counted failure: a value, not a session's admission (the MFA ADR's D21)",
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

/**
 * The probes the tests below hold the recognizer to. Each is a module beside
 * core's tests that sees the two tracked interfaces as core declares them, on
 * its first line, so a site on that line is on line 1.
 */
const PRELUDE =
	'import type { SubjectRevocation, UserSessionStore } from "../user-sessions/types.mjs"; ';

const STORE_READS: readonly string[] = [
	"declare const deps: { userSessionStore: UserSessionStore }; await deps.userSessionStore.get(sid);",
	"declare const opts: { sessions: UserSessionStore }; const store = opts.sessions; await store.get(sid);",
	"declare const options: { userSessionStore: UserSessionStore }; const { userSessionStore: s } = options; await s.get(sid);",
	"function f(store: UserSessionStore) { return store.get(sid); }",
	"type Sessions = UserSessionStore; function f(store: Sessions) { return store.get(sid); }",
	"declare function sessions(): UserSessionStore; await sessions().get(sid);",
	"declare const c: { readUserSessionStore(): UserSessionStore }; const s = c.readUserSessionStore(); await s.get(sid);",
	"declare const store: UserSessionStore | undefined; await store?.get(sid);",
	"declare const a: boolean; declare const opts: { userSessionStore: UserSessionStore }; const store = a ? opts.userSessionStore : undefined; store?.get(sid);",
	"function f<S extends UserSessionStore>(store: S) { return store.get(sid); }",
	"function f(store: UserSessionStore & { readonly extra: true }) { return store.get(sid); }",
	"function f(store: Readonly<UserSessionStore>) { return store.get(sid); }",
	"async function f(store: Promise<UserSessionStore>) { return (await store).get(sid); }",
];

const NOT_STORE_READS: readonly string[] = [
	"const store = new Map<string, number>(); store.get(sid);",
	"declare const deps: { userSessionStore: Map<string, number> }; deps.userSessionStore.get(sid);",
	"declare const opts: { federationTokenStore: { get(sid: string, name: string): unknown } }; await opts.federationTokenStore.get(sid, name);",
	"declare const store: { get(key: string, cb: () => void): void }; store.get(key, cb);",
	"class Own { get(sid: string) { return sid; } } new Own().get(sid);",
	"namespace local { export interface UserSessionStore { get(sid: string): unknown } } declare const store: local.UserSessionStore; store.get(sid);",
	"declare const store: UserSessionStore; const other = new Map<string, number>(); other.get(sid); store.kind;",
	"declare const store: UserSessionStore; typeof store.get;",
];

const BOUNDARY_READS: readonly string[] = [
	"declare const deps: { subjectRevocation: SubjectRevocation }; await deps.subjectRevocation.revokedBefore(sub);",
	"declare const options: { subjectRevocation: SubjectRevocation }; const revocation = options.subjectRevocation; await revocation.revokedBefore(subject);",
	'const sessionsBoundaryFor = (revocation: Pick<SubjectRevocation, "revokedBefore">) => async (s: string) => revocation.revokedBefore(s);',
	'declare const revocation: "none" | { subjectRevocation: SubjectRevocation }; const r = revocation === "none" ? undefined : revocation.subjectRevocation; await r?.revokedBefore(sub);',
	"declare const c: { readSubjectRevocation(): SubjectRevocation }; const r = c.readSubjectRevocation(); await r.revokedBefore(sub);",
	"declare const r: SubjectRevocation; const { revokedBefore: boundary } = r; await boundary(sub);",
];

const NOT_BOUNDARY_READS: readonly string[] = [
	"declare const grants: { revokedBefore(sub: string): unknown }; await grants.revokedBefore(sub);",
	"declare const store: UserSessionStore & { revokedBefore(sub: string): unknown }; await store.revokedBefore(sub);",
];

/** A probe and the one kind of site it holds. */
const ONE_SITE: ReadonlyArray<readonly [string, What]> = [
	['import { selectAcr as pick } from "@o3co/auth-provider-core"; pick(a, b, t, r);', "selectAcr"],
	[
		'import { resumePrimary as go } from "@o3co/auth-provider-core"; await go(d, c, x);',
		"resumePrimary",
	],
	['function f(store: UserSessionStore) { return store["get"](sid); }', "get"],
	['function f(store: UserSessionStore) { const key = "get"; return store[key](sid); }', "get"],
	['await store["recordSecondFactor"](sid, event);', "recordSecondFactor"],
	["function f(store: UserSessionStore) { const read = store.get; return read(sid); }", "get"],
	["function f(store: UserSessionStore) { return store.get.bind(store); }", "get"],
	["function f(store: UserSessionStore) { return store.get.call(store, sid); }", "get"],
	["function f(store: UserSessionStore) { return use(store.get); }", "get"],
	["function f({ get }: UserSessionStore) { return get(sid); }", "get"],
	["declare const store: UserSessionStore; const { get: read } = store; read(sid);", "get"],
	["const f = selectAcr; f(a, b, t, r);", "selectAcr"],
	["run(establishWithoutAsking);", "establishWithoutAsking"],
	["const c = brandClaim({ authenticated: true });", "brandClaim"],
	["return establish(primary);", "establish"],
	["return askEvery(deps, requirements, primary, primary, []);", "askEvery"],
	[
		'import { establish as mint } from "../session-admission/establishment.mjs"; mint(p);',
		"establish",
	],
	["run(askEvery);", "askEvery"],
];

/** A probe and the one site it holds, on its first line. */
const LINE_ONE_SITE: ReadonlyArray<readonly [string, What]> = [
	["const s = selectAcr(requested, amr, table, reach);", "selectAcr"],
	['const c = { authenticated: true, sid, subject, carrier: "cookie" };', "claim"],
	["await store.recordSecondFactor(sid, event);", "recordSecondFactor"],
	["const e = establishWithoutAsking(login);", "establishWithoutAsking"],
	["const a = await resumePrimary(deps, c, done);", "resumePrimary"],
	["const c = continuationOf(primary, [], name);", "continuationOf"],
];

const NO_SITE: readonly string[] = ['const c = { carrier: kind }; const d = { carrier: "bus" };'];

const PROBES: ReadonlyMap<string, string> = new Map(
	[
		...STORE_READS,
		...NOT_STORE_READS,
		...BOUNDARY_READS,
		...NOT_BOUNDARY_READS,
		...ONE_SITE.map(([source]) => source),
		...LINE_ONE_SITE.map(([source]) => source),
		...NO_SITE,
	].map((source, i) => [
		source,
		join(repoRoot, "packages/core/src/__tests__", `__session_admission_probe_${i}__.mts`),
	]),
);

/**
 * One program over every shipped source and every probe, typed as the
 * workspace builds them: each package's `#/` import resolves to its source,
 * a package import to that package's build.
 */
function workspaceProgram(sources: readonly string[]): ts.Program {
	const base = ts.readConfigFile(join(repoRoot, "tsconfig.base.json"), ts.sys.readFile);
	const options: ts.CompilerOptions = {
		...ts.parseJsonConfigFileContent(base.config, ts.sys, repoRoot).options,
		noEmit: true,
		allowJs: true,
		customConditions: ["development"],
		types: [],
	};
	const probes = new Map([...PROBES].map(([source, fileName]) => [fileName, PRELUDE + source]));
	const host = ts.createCompilerHost(options, true);
	// JSDoc only where it carries types (a JavaScript file): about half the parse.
	host.jsDocParsingMode = ts.JSDocParsingMode.ParseForTypeInfo;
	const readFile = host.readFile.bind(host);
	const fileExists = host.fileExists.bind(host);
	const getSourceFile = host.getSourceFile.bind(host);
	host.readFile = (f) => probes.get(f) ?? readFile(f);
	host.fileExists = (f) => probes.has(f) || fileExists(f);
	host.getSourceFile = (f, language, onError, create) => {
		const probe = probes.get(f);
		return probe === undefined
			? getSourceFile(f, language, onError, create)
			: ts.createSourceFile(f, probe, language, true, ts.ScriptKind.TS);
	};
	return ts.createProgram({
		rootNames: [...sources.map((file) => join(repoRoot, file)), ...probes.keys()],
		options,
		host,
	});
}

const shipped = shippedSources();
const program = workspaceProgram(shipped);
const checker = program.getTypeChecker();

/** The sites in a probe. */
const sitesIn = (source: string): Site[] => {
	const fileName = PROBES.get(source);
	const file = fileName === undefined ? undefined : program.getSourceFile(fileName);
	if (file === undefined) throw new Error(`not a probe: ${source}`);
	return sessionAdmissionSites(checker, file);
};

describe("session-admission callers", () => {
	it("finds a store read by the receiver's type, however the receiver is reached or written", () => {
		for (const source of STORE_READS) {
			expect(
				sitesIn(source).map((s) => s.what),
				source,
			).toEqual(["get"]);
		}
	});

	it("does not take a map, another store, the express-session store, or a property or interface merely named like one", () => {
		for (const source of NOT_STORE_READS) expect(sitesIn(source), source).toEqual([]);
	});

	it("finds a boundary read on a subject revocation by its type: a property, an alias, a Pick, a conditional, a call's result, a destructured method", () => {
		for (const source of BOUNDARY_READS) {
			expect(
				sitesIn(source).map((s) => s.what),
				source,
			).toEqual(["revokedBefore"]);
		}
		for (const source of NOT_BOUNDARY_READS) expect(sitesIn(source), source).toEqual([]);
	});

	it("finds a selectAcr call, a claim literal, and the guarded calls, each on its line", () => {
		for (const [source, what] of LINE_ONE_SITE) {
			expect(sitesIn(source), source).toEqual([{ line: 1, what }]);
		}
		for (const source of NO_SITE) expect(sitesIn(source), source).toEqual([]);
	});

	it("follows an import alias, an element access, a destructured method, and a reference that is not a call — bind, call, a value passed on", () => {
		for (const [source, what] of ONE_SITE) {
			expect(
				sitesIn(source).map((s) => s.what),
				source,
			).toEqual([what]);
		}
	});

	const sites = new Map<string, Site[]>();
	for (const file of shipped) {
		const sourceFile = program.getSourceFile(join(repoRoot, file));
		if (sourceFile === undefined) throw new Error(`not in the program: ${file}`);
		const found = sessionAdmissionSites(checker, sourceFile);
		if (found.length > 0) sites.set(file, found);
	}

	it("types the other packages' receivers through core's build (sanity: run after the workspace build)", () => {
		const declarations = [...TRACKED_DECLARATION_FILES].map((file) =>
			program.getSourceFile(join(repoRoot, file)),
		);
		expect(
			declarations.map((file) => file !== undefined),
			[...TRACKED_DECLARATION_FILES].join(", "),
		).toEqual([true, true]);
	});

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
