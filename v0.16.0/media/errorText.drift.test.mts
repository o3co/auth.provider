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
 * errorText.drift.test.mts — the error text this repository writes in its
 * own words keeps to RFC 6749's `1*NQSCHAR` (Appendix A.7, A.8): printable
 * ASCII without `"` and `\`.
 *
 * `errorEnvelope` sanitises whatever it is handed, so a `"`, an em dash or a
 * section sign written into a description still leaves conforming — as `?`,
 * which no test notices and no reader can read. And a writer that builds its
 * body itself (a literal `{ error, error_description }`, a redirect's query)
 * is not sanitised at all unless it asks. The same few characters have
 * crept in over and over, because they are what prose reaches for; this
 * guard refuses them where they are written.
 *
 * What it reads, in every package's source and the standalone template's
 * (tests excluded; `create-app`'s copy is generated from the template): the
 * static text of the string and template literals written as error text —
 * - the value of an `error_description` or `errorDescription` property, and
 *   of a `description` property beside an `error` whose value is a string
 *   literal (an OAuth code: `{ ok: false, error: "invalid_scope",
 *   description }`);
 * - the value of an `error` property beside any of those (the code);
 * - `errorEnvelope(code, description)`'s arguments;
 * - `searchParams.set` / `.append("error" | "error_description", text)`;
 * - an argument passed, in the same file, to a function that writes that
 *   parameter as one of the above (`jsonError(res, 400, "invalid_request",
 *   "…")`);
 * following a name to a `const` declared in the same file, both arms of
 * `?:`, `??` and `||`, both sides of `+`, and the argument of
 * `sanitizeErrorText(…)` / `auditErrorText(…)`.
 *
 * A code is checked whole when it is written whole — non-empty, `1*NQSCHAR` —
 * and by its characters alone when it is a piece of a template or a
 * concatenation (`${prefix}_denied`), because a piece may be empty. An object
 * literal handed to a logger (`log.`, `logger.`, `….logger.`, `console.` with
 * a level) is a log payload, not a response, and is not read; neither is a
 * `description` beside an `error` that is not a literal
 * (`{ error: err, description }`).
 *
 * These are heuristics about shape, not a proof: a non-OAuth object that
 * happens to pair `error: "…"` with `description`, or names a key
 * `error_description` outside a log call, is read as error text. Rename the
 * key, or keep its text in the same characters.
 *
 * What it does not see (left to review, and to `errorEnvelope` at run time):
 * - text returned by another function (`describeRedirectRejection`), or a
 *   `const` declared in another file;
 * - text handed to a helper declared in another file;
 * - what a template literal's `${…}` substitutes: an echo of the client, the
 *   configuration or an adapter is the writer's to sanitise
 *   (`sanitizeErrorText`), and a test of that writer's to pin.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { isWellFormedErrorCode, sanitizeErrorText } from "#/errors/envelope.mjs";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));

type Kind = "code" | "description";

/** A piece of literal text written as error text, where it was written. */
interface Written {
	readonly kind: Kind;
	readonly text: string;
	/** The whole literal, rather than a piece of a template or a concatenation. */
	readonly whole: boolean;
	readonly line: number;
}

/** A piece of static text, and whether it is a literal written whole. */
interface Piece {
	readonly text: string;
	readonly whole: boolean;
}

const DESCRIPTION_KEYS = new Set(["error_description", "errorDescription"]);
const SANITISERS = new Set(["sanitizeErrorText", "auditErrorText"]);

function sourceFiles(dir: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir)) {
		if (entry === "__tests__" || entry === "node_modules" || entry === "dist") continue;
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
		else if (entry.endsWith(".mts") && !entry.endsWith(".test.mts")) out.push(full);
	}
	return out;
}

function propertyName(name: ts.PropertyName): string | undefined {
	if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
	return undefined;
}

/** The keys an object literal names, shorthand included. */
function keysOf(literal: ts.ObjectLiteralExpression): ReadonlySet<string> {
	const keys = new Set<string>();
	for (const property of literal.properties) {
		if (ts.isPropertyAssignment(property)) {
			const key = propertyName(property.name);
			if (key !== undefined) keys.add(key);
		} else if (ts.isShorthandPropertyAssignment(property)) {
			keys.add(property.name.text);
		}
	}
	return keys;
}

/** Whether the object literal's `error` is written as a string literal: an OAuth code. */
function literalErrorIn(literal: ts.ObjectLiteralExpression): boolean {
	return literal.properties.some(
		(property) =>
			ts.isPropertyAssignment(property) &&
			propertyName(property.name) === "error" &&
			(ts.isStringLiteral(property.initializer) ||
				ts.isNoSubstitutionTemplateLiteral(property.initializer)),
	);
}

/** What a property of an object literal is written as, if it is error text. */
function kindOfProperty(
	key: string,
	siblings: ReadonlySet<string>,
	literalError: boolean,
): Kind | undefined {
	if (DESCRIPTION_KEYS.has(key)) return "description";
	if (key === "description" && literalError) return "description";
	if (
		key === "error" &&
		((siblings.has("description") && literalError) ||
			[...DESCRIPTION_KEYS].some((k) => siblings.has(k)))
	)
		return "code";
	return undefined;
}

/** A logger call: a level on `log`, `logger`, `….logger` or `console`. */
function isLoggerCall(call: ts.CallExpression, file: ts.SourceFile): boolean {
	const callee = call.expression;
	if (!ts.isPropertyAccessExpression(callee)) return false;
	if (!["trace", "debug", "info", "warn", "error", "fatal", "log"].includes(callee.name.text)) {
		return false;
	}
	return /(^|\.)(log|logger|console)$/.test(callee.expression.getText(file).replace(/\?/g, ""));
}

/** Every piece of literal error text in `source`. */
function writtenErrorText(fileName: string, source: string): Written[] {
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
	const lineOf = (node: ts.Node): number =>
		file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;

	// `const NAME = …` anywhere in the file, and the functions a file declares
	// by name (a declaration, or a `const` holding an arrow or function).
	const constants = new Map<string, ts.Expression>();
	const functions = new Map<string, ts.SignatureDeclaration & { body?: ts.Node }>();
	const collect = (node: ts.Node): void => {
		if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
			functions.set(node.name.text, node);
		}
		if (
			ts.isVariableDeclaration(node) &&
			ts.isIdentifier(node.name) &&
			node.initializer !== undefined &&
			ts.isVariableDeclarationList(node.parent) &&
			(node.parent.flags & ts.NodeFlags.Const) !== 0
		) {
			const init = node.initializer;
			if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
				functions.set(node.name.text, init);
			} else {
				constants.set(node.name.text, init);
			}
		}
		ts.forEachChild(node, collect);
	};
	collect(file);

	/** The static text an expression writes, as pieces. */
	const piecesOf = (expression: ts.Expression, seen: ReadonlySet<string> = new Set()): Piece[] => {
		if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
			return [{ text: expression.text, whole: true }];
		}
		if (ts.isTemplateExpression(expression)) {
			return [
				expression.head.text,
				...expression.templateSpans.map((span) => span.literal.text),
			].map((text) => ({ text, whole: false }));
		}
		if (
			ts.isParenthesizedExpression(expression) ||
			ts.isAsExpression(expression) ||
			ts.isSatisfiesExpression(expression)
		) {
			return piecesOf(expression.expression, seen);
		}
		if (ts.isConditionalExpression(expression)) {
			return [...piecesOf(expression.whenTrue, seen), ...piecesOf(expression.whenFalse, seen)];
		}
		if (
			ts.isBinaryExpression(expression) &&
			[ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken].includes(
				expression.operatorToken.kind,
			)
		) {
			return [...piecesOf(expression.left, seen), ...piecesOf(expression.right, seen)];
		}
		if (
			ts.isBinaryExpression(expression) &&
			expression.operatorToken.kind === ts.SyntaxKind.PlusToken
		) {
			return [...piecesOf(expression.left, seen), ...piecesOf(expression.right, seen)].map(
				({ text }) => ({ text, whole: false }),
			);
		}
		if (
			ts.isCallExpression(expression) &&
			ts.isIdentifier(expression.expression) &&
			SANITISERS.has(expression.expression.text)
		) {
			return expression.arguments.flatMap((argument) => piecesOf(argument, seen));
		}
		if (ts.isIdentifier(expression) && !seen.has(expression.text)) {
			const value = constants.get(expression.text);
			if (value !== undefined) return piecesOf(value, new Set([...seen, expression.text]));
		}
		return [];
	};

	const written: Written[] = [];
	const record = (kind: Kind, expression: ts.Expression, at: ts.Node): void => {
		for (const { text, whole } of piecesOf(expression)) {
			written.push({ kind, text, whole, line: lineOf(at) });
		}
	};

	/**
	 * Where error text is written, as `(kind, expression)`: an object literal's
	 * property, `errorEnvelope(…)`'s arguments, a redirect's query.
	 */
	const writerSites = (node: ts.Node, visit: (kind: Kind, expression: ts.Expression) => void) => {
		const walk = (n: ts.Node): void => {
			// A log payload is not a response.
			if (ts.isCallExpression(n) && isLoggerCall(n, file)) return;
			if (ts.isObjectLiteralExpression(n)) {
				const siblings = keysOf(n);
				const literalError = literalErrorIn(n);
				for (const property of n.properties) {
					if (ts.isPropertyAssignment(property)) {
						const key = propertyName(property.name);
						const kind =
							key === undefined ? undefined : kindOfProperty(key, siblings, literalError);
						if (kind !== undefined) visit(kind, property.initializer);
					} else if (ts.isShorthandPropertyAssignment(property)) {
						const kind = kindOfProperty(property.name.text, siblings, literalError);
						if (kind !== undefined) visit(kind, property.name);
					}
				}
			}
			if (ts.isCallExpression(n)) {
				const callee = n.expression;
				const name = ts.isIdentifier(callee)
					? callee.text
					: ts.isPropertyAccessExpression(callee)
						? callee.name.text
						: undefined;
				const [first, second] = n.arguments;
				if (name === "errorEnvelope") {
					if (first !== undefined) visit("code", first);
					if (second !== undefined) visit("description", second);
				}
				if (
					(name === "set" || name === "append") &&
					ts.isPropertyAccessExpression(callee) &&
					/searchParams$/.test(callee.expression.getText(file)) &&
					first !== undefined &&
					ts.isStringLiteral(first) &&
					second !== undefined
				) {
					if (first.text === "error") visit("code", second);
					if (first.text === "error_description") visit("description", second);
				}
			}
			ts.forEachChild(n, walk);
		};
		walk(node);
	};

	// A same-file helper: which of its parameters it writes as error text.
	const helperParameters = new Map<string, Map<number, Kind>>();
	for (const [name, fn] of functions) {
		if (fn.body === undefined) continue;
		const indexOf = new Map(
			fn.parameters.flatMap((parameter, index) =>
				ts.isIdentifier(parameter.name) ? [[parameter.name.text, index] as const] : [],
			),
		);
		const written = new Map<number, Kind>();
		writerSites(fn.body, (kind, expression) => {
			if (ts.isIdentifier(expression)) {
				const index = indexOf.get(expression.text);
				if (index !== undefined) written.set(index, kind);
			}
		});
		if (written.size > 0) helperParameters.set(name, written);
	}

	writerSites(file, (kind, expression) => record(kind, expression, expression));
	const calls = (node: ts.Node): void => {
		if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
			const parameters = helperParameters.get(node.expression.text);
			for (const [index, kind] of parameters ?? []) {
				const argument = node.arguments[index];
				if (argument !== undefined) record(kind, argument, argument);
			}
		}
		ts.forEachChild(node, calls);
	};
	calls(file);
	return written;
}

/**
 * Whether a piece of text may be sent: NQSCHARs, and for a code written whole
 * `1*NQSCHAR` — non-empty. A piece of a template or a concatenation may be
 * empty (`${prefix}_denied`'s head); the whole code is what must not be.
 */
const conforms = ({ kind, text, whole }: Written): boolean =>
	kind === "code" && whole ? isWellFormedErrorCode(text) : sanitizeErrorText(text) === text;

/** Every package's source and the standalone template's; `create-app`'s copy is generated from it. */
function everyShippedSource(): { file: string; source: string }[] {
	const roots = [
		...readdirSync(join(repoRoot, "packages")).map((pkg) => join(repoRoot, "packages", pkg, "src")),
		join(repoRoot, "templates", "standalone", "src"),
	];
	return roots.flatMap((src) => {
		try {
			statSync(src);
		} catch {
			return [];
		}
		return sourceFiles(src).map((file) => ({ file, source: readFileSync(file, "utf8") }));
	});
}

describe("error text written in this repository's own words (RFC 6749 Appendix A.7, A.8)", () => {
	const sources = everyShippedSource();
	const written = sources.flatMap(({ file, source }) =>
		writtenErrorText(file, source).map((piece) => ({
			...piece,
			at: `${relative(repoRoot, file)}:${piece.line}`,
		})),
	);

	it("reads the writers it exists for", () => {
		// A walk that silently matched nothing would pass the check below.
		expect(written.filter((piece) => piece.kind === "description").length).toBeGreaterThan(300);
		expect(written.filter((piece) => piece.kind === "code").length).toBeGreaterThan(300);
	});

	it("reads the standalone template's source, which create-app's copy is generated from", () => {
		// The template answers every error through core's `terminalErrorHandler`
		// and writes no error text of its own; the walk still covers its tree, so
		// text it adds is held to the rule where it is written.
		expect(
			sources.some(({ file }) => relative(repoRoot, file).startsWith("templates/standalone/src/")),
		).toBe(true);
	});

	it("keeps to printable ASCII without '\"' and '\\': quote with ', write 'section', no em dash", () => {
		expect(
			written.filter((piece) => !conforms(piece)).map((piece) => `${piece.at} ${piece.text}`),
		).toEqual([]);
	});

	describe("the guard sees the shapes it exists for", () => {
		const flagged = (source: string): string[] =>
			writtenErrorText("sample.mts", source)
				.filter((piece) => !conforms(piece))
				.map((piece) => piece.text);

		it.each([
			["an error_description property", `res.json({ error: "x", error_description: "a — b" });`],
			["an errorDescription property", `return { error: "x", errorDescription: 'say "hi"' };`],
			["a description beside an error", `return { ok: false, error: "x", description: "§5" };`],
			["a code beside a description", `res.json({ error: 'bad"code', description: "ok" });`],
			["errorEnvelope's description", `res.json(errorEnvelope("x", "caf\\u00e9"));`],
			["errorEnvelope's code", `res.json(errorEnvelope('x"y'));`],
			// biome-ignore lint/suspicious/noTemplateCurlyInString: the source text under test holds a template
			["a template's static text", "res.json({ error: 'x', error_description: `a \"${b}\"` });"],
			["a conditional arm", `res.json({ error: "x", error_description: c ? "ok" : "a — b" });`],
			["a fallback", `res.json({ error: "x", error_description: d ?? "a — b" });`],
			["a concatenation", `res.json({ error: "x", error_description: "ok " + "§1" });`],
			[
				"a sanitised literal",
				`res.json({ error: "x", error_description: sanitizeErrorText("a — b") });`,
			],
			[
				"a same-file const",
				`const TEXT = "a — b"; res.json({ error: "x", error_description: TEXT });`,
			],
			["a redirect's query", `url.searchParams.set("error_description", "a — b");`],
			[
				"a same-file helper's argument",
				`const jsonError = (res, status, error, description) => res.status(status).json({ error, error_description: description });
				jsonError(res, 400, "invalid_request", 'decision must be "accept"');`,
			],
		])("flags %s", (_label, source) => {
			expect(flagged(source)).not.toEqual([]);
		});

		it.each([
			[
				"conforming text",
				`res.json({ error: "invalid_request", error_description: "decision must be 'accept' or 'deny'" });`,
			],
			["a log line's error", `logger.warn({ error: "redis \\"down\\"" }, "failed");`],
			[
				"a WWW-Authenticate challenge",
				`res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');`,
			],
			["a thrown message", `throw new Error('mode = "pki" requires trustedCas — set it');`],
			[
				"a code written as a template that starts with a substitution",
				// biome-ignore lint/suspicious/noTemplateCurlyInString: the source text under test holds a template
				"res.json({ error: `${prefix}_denied`, error_description: 'refused' });",
			],
			[
				"an error object beside a description that is not an OAuth body",
				`return { error: err, description: "retrying — the store is down" };`,
			],
			[
				"a log payload that names its field error_description",
				`logger.warn({ error_description: 'upstream said "no"' }, "idp_refused");`,
			],
		])("leaves %s alone", (_label, source) => {
			expect(flagged(source)).toEqual([]);
		});
	});
});
