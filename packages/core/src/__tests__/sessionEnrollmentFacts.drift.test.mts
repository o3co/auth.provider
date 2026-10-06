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
 * A session's stored enrollment facts have one reading, `readEnrollmentFacts`
 * (`user-sessions/enrollmentFacts.mts`), which answers a value a store of a
 * deployment's own kept in another shape — `"Enrolled"`, say — as none, so
 * the reader fails closed. A raw read of the record's field would take that
 * value as "not enrolled", which fails open.
 *
 * So no product file in any package, nor in the standalone template, reads
 * `enrollmentFacts` off a stored record but where the record is copied or
 * read through that reading: admission's `viewOf`, the two bundled
 * user-session stores, and `establishSession`, which writes the facts. A read
 * off the view admission hands a requirement (`SessionView`), or off a
 * primary core built (`PrimaryAuthentication`, whose facts core derived from
 * the login's `User`), reads core's own copy and is allowed anywhere: the
 * receiver is an identifier declared with one of those two types. Any other
 * read — off a record, an admission's `session`, a property chain whose type
 * the guard cannot tell — is a raw read.
 *
 * Read with TypeScript's parser and binder, one file at a time, so a comment,
 * a string, a declaration or an object literal's key is not a read, and a
 * name is resolved in its own scope. Tests are left out: they build records
 * by hand on purpose.
 *
 * The limits of that reading: a type is matched by its name as written, so
 * an alias or a local type of the same name passes as core's; and TypeScript
 * is structural, so a `UserSession` handed to a parameter typed
 * `SessionView` type-checks and is then read as a copy there. Admission
 * builds the one view (`viewOf`); a caller that hands a record where a view
 * is typed goes around this guard, and review catches it.
 */

import { type Dirent, existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

/** The repository root, from `packages/core/src/__tests__`. */
const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));

const FIELD = "enrollmentFacts";

/** The declared types whose `enrollmentFacts` is core's own copy, never a stored record's. */
const COPIES: ReadonlySet<string> = new Set(["SessionView", "PrimaryAuthentication"]);

/** Where a raw read may be: a file, and — when given — the function or constant it must sit in. */
interface AllowedRawRead {
	readonly file: string;
	readonly within?: string;
	readonly why: string;
}

const ALLOWED_RAW_READS: readonly AllowedRawRead[] = [
	{
		file: "packages/core/src/session-admission/admit.mts",
		within: "viewOf",
		why: "admission copies the record's facts into the view through readEnrollmentFacts",
	},
	{
		file: "packages/core/src/session-admission/live-session.mts",
		within: "copyRecord",
		why: "admission copies the store's answer once by its declared fields, inside the guarded live read; viewOf reads the facts off that copy",
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		why: "the memory store records what recordableEnrollmentFacts answers, and copies it out",
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		why: "the Redis store records what recordableEnrollmentFacts answers, and reads its envelope through readEnrollmentFacts",
	},
	{
		file: "packages/session/src/establish-session.mts",
		within: "establishSession",
		why: "the one writer: it hands the primary's derived facts to the store's create",
	},
];

/**
 * The expression under any parentheses, type assertions (`as`, `<T>`,
 * `satisfies`), non-null assertions and instantiation expressions: every
 * wrapper TypeScript's own `skipOuterExpressions` removes from parsed source.
 */
function skipOuterExpressions(node: ts.Expression): ts.Expression {
	let current = node;
	while (
		ts.isParenthesizedExpression(current) ||
		ts.isAsExpression(current) ||
		ts.isTypeAssertionExpression(current) ||
		ts.isSatisfiesExpression(current) ||
		ts.isNonNullExpression(current) ||
		ts.isExpressionWithTypeArguments(current)
	) {
		current = current.expression;
	}
	return current;
}

/** One read of the field: its line, what it is read off, whether that is core's copy, and the names of the functions and constants around it. */
interface FactsRead {
	readonly line: number;
	readonly receiver: string;
	readonly copy: boolean;
	readonly within: readonly string[];
}

/** The name a declared type is written with, when it is a plain reference: `SessionView`, `PrimaryAuthentication`. */
function typeNameOf(type: ts.TypeNode | undefined): string | undefined {
	return type !== undefined && ts.isTypeReferenceNode(type) ? type.typeName.getText() : undefined;
}

/** The type an identifier was declared with — a parameter's or a variable's own annotation — when the binder finds its declaration. */
function declaredTypeOf(checker: ts.TypeChecker, name: ts.Identifier): string | undefined {
	const declaration = checker.getSymbolAtLocation(name)?.valueDeclaration;
	if (declaration === undefined) return undefined;
	if (ts.isParameter(declaration) || ts.isVariableDeclaration(declaration)) {
		return typeNameOf(declaration.type);
	}
	return undefined;
}

/** Whether `receiver`, what the field is read off, is an identifier declared as one of {@link COPIES}. */
function readsCopy(checker: ts.TypeChecker, receiver: ts.Expression): boolean {
	const bare = skipOuterExpressions(receiver);
	if (!ts.isIdentifier(bare)) return false;
	const type = declaredTypeOf(checker, bare);
	return type !== undefined && COPIES.has(type);
}

/** Whether a destructuring binding reads core's copy: its pattern annotated as one, or taken from an identifier declared as one. */
function bindsCopy(checker: ts.TypeChecker, element: ts.BindingElement): boolean {
	const holder = element.parent.parent;
	if (ts.isParameter(holder)) return COPIES.has(typeNameOf(holder.type) ?? "");
	if (ts.isVariableDeclaration(holder)) {
		const annotated = typeNameOf(holder.type);
		if (annotated !== undefined) return COPIES.has(annotated);
		return holder.initializer !== undefined && readsCopy(checker, holder.initializer);
	}
	return false;
}

/** The names of the functions and constants `node` sits in, innermost first. */
function enclosingNames(node: ts.Node): string[] {
	const names: string[] = [];
	for (let at: ts.Node | undefined = node.parent; at !== undefined; at = at.parent) {
		if (
			(ts.isFunctionDeclaration(at) ||
				ts.isVariableDeclaration(at) ||
				ts.isMethodDeclaration(at)) &&
			at.name !== undefined &&
			ts.isIdentifier(at.name)
		) {
			names.push(at.name.text);
		}
	}
	return names;
}

/**
 * Every read of `enrollmentFacts` in `source`: a property access, an element
 * access by the literal name, or a destructuring binding — each with whether
 * it reads core's copy. Bound in a program of its own, so each name resolves
 * in its scope; no import is followed.
 */
function factsReads(source: string, fileName = "scan.mts"): FactsRead[] {
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
	const options: ts.CompilerOptions = { noResolve: true, noLib: true, types: [] };
	const host = ts.createCompilerHost(options);
	host.getSourceFile = (name) => (name === fileName ? file : undefined);
	const checker = ts.createProgram([fileName], options, host).getTypeChecker();
	const named = (node: ts.Node | undefined): boolean =>
		node !== undefined &&
		(ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
		node.text === FIELD;
	const reads: FactsRead[] = [];
	const found = (node: ts.Node, receiver: ts.Node | undefined, copy: boolean): void => {
		reads.push({
			line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1,
			receiver: receiver?.getText(file) ?? "",
			copy,
			within: enclosingNames(node),
		});
	};
	const visit = (node: ts.Node): void => {
		if (ts.isPropertyAccessExpression(node) && node.name.text === FIELD) {
			found(node, node.expression, readsCopy(checker, node.expression));
		} else if (ts.isElementAccessExpression(node) && named(node.argumentExpression)) {
			found(node, node.expression, readsCopy(checker, node.expression));
		} else if (
			ts.isBindingElement(node) &&
			(node.propertyName !== undefined ? named(node.propertyName) : named(node.name))
		) {
			const holder = node.parent.parent;
			found(
				node,
				ts.isVariableDeclaration(holder) ? holder.initializer : holder.name,
				bindsCopy(checker, node),
			);
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return reads;
}

/**
 * Every product source file under `packages/<name>/src` and
 * `templates/standalone/src`, relative to the root, `/`-separated.
 */
function productSources(): string[] {
	const found: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir, { withFileTypes: true }) as Dirent[]) {
			if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "__tests__") {
				continue;
			}
			const path = join(dir, entry.name);
			if (entry.isDirectory()) {
				walk(path);
			} else if (
				/\.m?ts$/.test(entry.name) &&
				!/\.d\.m?ts$/.test(entry.name) &&
				!/\.test\.m?ts$/.test(entry.name)
			) {
				found.push(relative(repoRoot, path).split(sep).join("/"));
			}
		}
	};
	for (const pkg of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
		const src = join(repoRoot, "packages", pkg.name, "src");
		if (pkg.isDirectory() && existsSync(src)) walk(src);
	}
	walk(join(repoRoot, "templates", "standalone", "src"));
	return found.sort();
}

/** Every product file's reads of the field, by file; files that name it nowhere are skipped unread by the parser. */
function productReads(): Map<string, FactsRead[]> {
	const byFile = new Map<string, FactsRead[]>();
	for (const file of productSources()) {
		const source = readFileSync(join(repoRoot, file), "utf8");
		if (!source.includes(FIELD)) continue;
		const reads = factsReads(source, file);
		if (reads.length > 0) byFile.set(file, reads);
	}
	return byFile;
}

const allowed = (file: string, read: FactsRead): boolean =>
	ALLOWED_RAW_READS.some(
		(entry) =>
			entry.file === file && (entry.within === undefined || read.within.includes(entry.within)),
	);

describe("a session's stored enrollment facts have one reading", () => {
	it("are read raw by no product file, the template's included, but admission's record copy and viewOf, the two session stores and establishSession", () => {
		const offenders = [...productReads()].flatMap(([file, reads]) =>
			reads
				.filter((read) => !read.copy && !allowed(file, read))
				.map((read) => `${file}:${read.line}`),
		);
		expect(offenders).toEqual([]);
	});

	it("scans every package's product sources and the standalone template's, not their tests", () => {
		const sources = productSources();
		expect(sources).toContain("templates/standalone/src/buildModules.mts");
		expect(sources).toContain("packages/mfa/src/requirement.mts");
		expect(sources.filter((file) => /(^|\/)__tests__\/|\.test\.m?ts$/.test(file))).toEqual([]);
	});

	it("is not vacuous: each allowed place reads the record raw, and the mfa requirement reads core's copies alone", () => {
		const reads = productReads();
		for (const entry of ALLOWED_RAW_READS) {
			const raw = (reads.get(entry.file) ?? []).filter(
				(read) => !read.copy && allowed(entry.file, read),
			);
			expect(raw.length, `${entry.file} — ${entry.why}`).toBeGreaterThan(0);
		}
		const requirement = reads.get("packages/mfa/src/requirement.mts") ?? [];
		expect(requirement.length, "the mfa requirement reads the facts").toBeGreaterThan(0);
		expect(requirement.filter((read) => !read.copy)).toEqual([]);
	});

	it("tells core's copy from a record, by the type its receiver is declared with, in the receiver's own scope", () => {
		const copy = (source: string) => factsReads(source).map((read) => read.copy);
		// Core's copies.
		expect(copy("const f = (view: SessionView) => view.enrollmentFacts?.witness;")).toEqual([true]);
		expect(
			copy("function g(primary: PrimaryAuthentication) { return primary.enrollmentFacts; }"),
		).toEqual([true]);
		expect(
			copy(
				"function h(primary: PrimaryAuthentication) { const { enrollmentFacts: f } = primary; }",
			),
		).toEqual([true]);
		expect(
			copy("function k({ enrollmentFacts }: SessionView) { return enrollmentFacts; }"),
		).toEqual([true]);
		expect(copy('const v = (view: SessionView) => view["enrollmentFacts"];')).toEqual([true]);
		// Records, and receivers the guard cannot tell.
		for (const raw of [
			"const f = (session: UserSession) => session.enrollmentFacts;",
			"const f = (admission: Admission) => admission.session?.enrollmentFacts;",
			"function g(record) { return record.enrollmentFacts; }",
			'const f = (session: UserSession) => session["enrollmentFacts"];',
			"function h({ enrollmentFacts }: UserSession) { return enrollmentFacts; }",
			"const { enrollmentFacts } = await store.get(sid);",
			"const f = (view: Readonly<SessionView>) => view.enrollmentFacts;",
			// Shadowed: the inner parameter is the record, whatever the outer name was declared as.
			"const view: SessionView = make(); function k(view: UserSession) { return view.enrollmentFacts; }",
		]) {
			expect(copy(raw), raw).toEqual([false]);
		}
	});

	it("reads nothing that only names the field", () => {
		for (const notARead of [
			"// reads session.enrollmentFacts through readEnrollmentFacts",
			"/* view.enrollmentFacts */",
			'const message = "record.enrollmentFacts is malformed";',
			"interface V { readonly enrollmentFacts?: SessionEnrollmentFacts }",
			"const record = { enrollmentFacts: facts };",
			"const record = { enrollmentFacts };",
			"readEnrollmentFacts(value);",
			"type K = UserSession['enrollmentFacts'];",
		]) {
			expect(factsReads(notARead), notARead).toEqual([]);
		}
	});

	it("allows a raw read in admit.mts inside viewOf alone", () => {
		const [inView] = factsReads(
			"const viewOf = (session: UserSession) => readEnrollmentFacts(session.enrollmentFacts);",
		);
		const [elsewhere] = factsReads(
			"function answer(session: UserSession) { return session.enrollmentFacts; }",
		);
		expect(allowed("packages/core/src/session-admission/admit.mts", inView as FactsRead)).toBe(
			true,
		);
		expect(allowed("packages/core/src/session-admission/admit.mts", elsewhere as FactsRead)).toBe(
			false,
		);
	});
});
