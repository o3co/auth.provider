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
 * logErrorProjection.drift.test.mts — no log line in the workspace's source
 * hands a logger a caught error as it is.
 *
 * A store's or a library's error carries whatever the system it talked to
 * said: ioredis puts the refused command on `err.command.args` (under
 * `encryption.mode = "allow-plaintext"`, a token record), openid-client puts
 * the token answer it refused on `cause.cause.body`, a JSON parser quotes its
 * input in `message`. A logger that serialises the whole error writes all of
 * it out, and a deployment chooses its logger. So every logger call passes a
 * caught error through `loggableError(...)` — the projection core owns — and
 * never the error, nor anything read off it.
 *
 * What it flags, per file: a name bound as a caught error — `catch (x)`,
 * `.catch((x) => …)` / `.catch(x => …)` / `.catch(function (x) …)`,
 * `.on("error", (x) => …)` / `.once(…)`, the error-named first parameter of
 * a callback passed as an argument (node-style: `save((err) => …)`,
 * `get(key, function (err, value) …)`), the first parameter of an Express
 * error handler (`(err, req, res, next)`, whatever the names but the last's
 * `next`, typed or not — `Request<P, B>`, `(err?: unknown) => void` — and
 * followed by an arrow or a body, so a call's arguments are not one), and an
 * error-named value awaited from a helper
 * (`const consumeErr = await …`) — used anywhere in the arguments of a
 * logger call (`log.`, `logger.`, `….logger.` with a level or `child`;
 * `console.`) other than as an object key, as the argument of
 * `loggableError(...)` (or of a projection `OTHER_PROJECTIONS` accepts in
 * that file), or as another object's field (`result.err`); inside a template
 * literal's `${…}` too. A name that merely looks like an error — a policy's
 * `error` code — is not flagged.
 *
 * What it does not see (known holes, left to review):
 * - an error that reaches a log call under a name none of those bound in
 *   that file: a callback parameter or an awaited value not named like an
 *   error (`(failure) => …`, `(e) => …` outside a `.catch` or an `error`
 *   listener, `const outcome = await …`), a re-bound value
 *   (`const failure = err`), an `allSettled` result's `reason`;
 * - an error flattened into a value before the call (`const reason =
 *   err.message`, then `{ reason }`). The second rule below closes the
 *   common shapes of this by flagging the flattening itself, wherever it is,
 *   since the string it makes can travel into another file: `x.message`
 *   read behind an `instanceof Error` test, or a subclass's
 *   (`instanceof TypeError`) — `x instanceof Error ? x.message`,
 *   `x instanceof Error && x.message`, `if (x instanceof Error) return
 *   x.message`, braced or not — and `(x as Error).message` or
 *   `(x as TypeError).message`. Not flagged, and left to review: a bare
 *   `err.message` or `err?.message` with no such test or cast, a cast to a
 *   structural type (`(x as { message: string }).message`), and
 *   `String(err)`, `` `${err}` `` and `err.toString()` — each reads the
 *   message, but a regex cannot tell it from the same read of a non-error;
 * - an error handed to a helper that logs it: `refuse(…, { err })`, a
 *   failure reporter. The call site is not a logger call, and the helper's
 *   own log line sees only its parameter (`{ reason, ...context }`), not a
 *   caught error — so such a helper projects what it is handed itself, as
 *   oauth's client-assertion `refuse()` does, with a context typed to the
 *   fields it may log;
 * - a logger reached some other way (a destructured `warn`, `logger[level]`,
 *   a bound `const log = logger.warn.bind(logger)`), and an audit sink or a
 *   deployment's callback (`report`), which are not loggers;
 * - an Express error handler whose parameter list runs past 400
 *   characters, or whose default values hold what the bracket scan reads
 *   as a bracket: a string, template or regex literal with a bracket or a
 *   comma in it, a `<` comparison (it opens a bracket no `>` closes) or a
 *   `>` comparison (it closes one early). Its first parameter is not
 *   bound; a return type longer than 200 characters hides it too;
 * - bindings are per file, not per scope: a variable elsewhere in the file
 *   that shares a caught error's name is flagged too (rename it).
 *
 * A third rule reads each logger call's first argument. A call that opens
 * with a string or template literal and passes anything after it is flagged
 * in every source tree: pino, the standalone's logger, treats what follows a
 * string as printf arguments and drops them when the message has no
 * placeholder, so the error such a line carries never reaches the log. In
 * the trees this change reworks (`STRING_FIRST_EVERYWHERE`) any string-first
 * call is flagged, alone or not: a line there is object-first with an event
 * name. `STRING_FIRST_ALLOWED` lists the calls that stay, with the reason. It
 * sees only a literal: a message held in a variable or built by a call
 * (`logger.warn(message)`, `logger.warn(describe(x))`) is not flagged.
 *
 * Where it looks is `SOURCE_ROOTS` below: every workspace package's `src`
 * and the standalone template's, tests (`__tests__`) left out. A package
 * added under `packages/` or `templates/` fails "names every workspace
 * source tree" until it is listed. `create-app` and `tools/` are not held to
 * it: they depend on none of these packages, and what they print is for the
 * person running them.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
/** The source trees held to the rule, from the repository root: all of them. */
const SOURCE_ROOTS: readonly string[] = [
	"packages/core/src",
	"packages/device-grant/src",
	"packages/dpop/src",
	"packages/federation-apple/src",
	"packages/federation-github/src",
	"packages/federation-google/src",
	"packages/federation-grants/src",
	"packages/federation-oidc/src",
	"packages/foundation/src",
	"packages/mtls/src",
	"packages/oauth/src",
	"packages/oauth-token-exchange/src",
	"packages/redis/src",
	"packages/session/src",
	"packages/webauthn/src",
	"templates/standalone/src",
];

/**
 * A projection other than `loggableError` that one file hands a caught error
 * to inside a logger call, accepted there as `loggableError(...)` is — each
 * at least as strict, and why. An entry whose file no longer calls it in a
 * logger call fails "has no stale entry".
 */
const OTHER_PROJECTIONS: ReadonlyArray<{
	readonly file: string;
	readonly projection: string;
	readonly why: string;
}> = [
	...[
		"packages/core/src/middleware/tokenBinding.mts",
		"packages/core/src/middleware/protectedResourceBinding.mts",
	].map((file) => ({
		file,
		projection: "unavailableLogFields",
		why:
			"core's own (middleware/_responseHeaders.mts): a token-binding refusal's string `reason` " +
			"and `loggableError` of its `cause` — nothing else of the refusal, so exactly as strict " +
			"as loggableError",
	})),
];

/**
 * A logger call: a level (or `child`, or console's `log`) on a receiver that
 * is `log`, `console`, or a name ending in `logger` / `Logger` —
 * `consoleLogger`, `opts.logger`, `this.auditLogger` — or a parenthesised
 * fallback between two (`(opts.logger ?? console)`, `(logger ??
 * consoleLogger)`); with a non-null assertion (`logger!.warn`), optional
 * chaining (`logger?.warn`) or an optional call (`warn?.(`).
 */
const LOGGER_CALL =
	/(?:\b(?:[\w$]+[!?]?\.)*(?:log|console|\w*[Ll]ogger)|\(\s*[\w$.!?]+\s*\?\?\s*[\w$.!?]+\s*\))!?\??\.(?:trace|debug|info|warn|error|fatal|child|log)(?:\?\.)?\(/g;

const IDENTIFIER = "[A-Za-z_$][\\w$]*";

/**
 * A name that reads as an error: what a node-style callback's first parameter
 * is called. Not a bare `e`, which `.map((e) => …)` and `.filter((e) => …)`
 * use for an element; `catch (e)` and `.catch((e) => …)` bind any name.
 */
const ERROR_NAME = "(?:err|error|[a-z][A-Za-z]*Err|[a-z][A-Za-z]*Error)";

/**
 * Where a caught error is bound: `catch (x)`, `.catch(…x…)`,
 * `.on("error", …x…)`; the error-named first parameter of a callback passed
 * as an argument — node-style, `save((err) => …)`, `get(key, function (err,
 * value) …)`, `save(err => …)`; and an error-named value awaited from a
 * helper — `const consumeErr = await …`, which is also what a promise
 * wrapping a node-style callback resolves. An Express error handler's first
 * parameter is bound by {@link errorHandlerNames}.
 */
const CATCH_BINDINGS = [
	new RegExp(String.raw`\bcatch\s*\(\s*(?:async\s*)?\(?\s*(${IDENTIFIER})\s*[):,=]`, "g"),
	new RegExp(
		String.raw`\.catch\(\s*(?:async\s+)?function\s*(?:${IDENTIFIER})?\s*\(\s*(${IDENTIFIER})`,
		"g",
	),
	new RegExp(
		String.raw`\.(?:on|once)\(\s*["'\x60]error["'\x60]\s*,\s*(?:async\s*)?(?:function\s*(?:${IDENTIFIER})?\s*)?\(?\s*(${IDENTIFIER})`,
		"g",
	),
	new RegExp(
		String.raw`[(,]\s*(?:async\s+)?(?:function\s*(?:${IDENTIFIER})?\s*)?\(\s*(${ERROR_NAME})\s*(?::[^,)]*)?[,)]`,
		"g",
	),
	new RegExp(String.raw`[(,]\s*(?:async\s+)?(${ERROR_NAME})\s*=>`, "g"),
	/\b(?:const|let)\s+([a-z][\w$]*(?:Err|Error))\s*(?::[^=]*)?=\s*await\b/g,
];

/** How far a parameter list is read before it is taken for something else. */
const MAX_PARAMETER_LIST = 400;

/**
 * The top-level entries of the list that opens at `open`, split on the
 * commas outside every bracket — `()`, `[]`, `{}` and a type's `<>`, an
 * arrow's `=>` not closing one — so a parameter typed `Request<P, B>` or
 * `(err?: unknown) => void` stays whole, and where the list closes. `null`
 * when it does not close within {@link MAX_PARAMETER_LIST} characters: a
 * comparison's `<` leaves it open, and it is not a parameter list.
 */
function parametersFrom(
	source: string,
	open: number,
): { readonly parameters: string[]; readonly close: number } | null {
	const parameters: string[] = [];
	let depth = 0;
	let start = open + 1;
	const end = Math.min(source.length, open + MAX_PARAMETER_LIST);
	for (let i = open; i < end; i++) {
		const c = source[i];
		if (c === "(" || c === "[" || c === "{" || c === "<") depth++;
		else if (c === ")" || c === "]" || c === "}" || (c === ">" && source[i - 1] !== "=")) {
			if (--depth === 0) {
				parameters.push(source.slice(start, i));
				return { parameters, close: i };
			}
		} else if (c === "," && depth === 1) {
			parameters.push(source.slice(start, i));
			start = i + 1;
		}
	}
	return null;
}

/** The name a parameter binds — `err` of `err: unknown` or `err = x` — when it is a plain one. */
const parameterName = (parameter: string): string | undefined =>
	new RegExp(String.raw`^\s*(${IDENTIFIER})\s*(?:[?:=]|$)`).exec(parameter)?.[1];

/**
 * What follows a parameter list: an arrow, or a function or method body,
 * maybe after a return type (`: void`, `: Promise<void>`). A call's
 * arguments are followed by anything else.
 */
const FUNCTION_AFTER_PARAMETERS = /^\s*(?::[^;{}=]*)?(?:=>|\{)/;

/**
 * An Express error handler's first parameter, whatever it is called: a list
 * of four parameters whose last is `next` or `_next`, each maybe typed, that
 * is a function's (an arrow or a body follows it, not a call's `;` or `)`) —
 * read by {@link parametersFrom}, because the types hold commas and
 * parentheses a regex over the list cannot tell from its own.
 */
function errorHandlerNames(source: string): string[] {
	const names: string[] = [];
	for (let open = source.indexOf("("); open >= 0; open = source.indexOf("(", open + 1)) {
		const list = parametersFrom(source, open);
		if (list === null) continue;
		if (!FUNCTION_AFTER_PARAMETERS.test(source.slice(list.close + 1, list.close + 201))) continue;
		const { parameters } = list;
		if (parameters.length !== 4) continue;
		if (!/^_?next$/.test(parameterName(parameters[3] ?? "") ?? "")) continue;
		const first = parameterName(parameters[0] ?? "");
		if (first !== undefined) names.push(first);
	}
	return names;
}

/** Every name the file binds as a caught error. */
function caughtNames(source: string): ReadonlySet<string> {
	const names = new Set<string>(errorHandlerNames(source));
	for (const binding of CATCH_BINDINGS) {
		for (const match of source.matchAll(binding)) {
			const name = match[1];
			if (name !== undefined && name !== "function" && name !== "async") names.add(name);
		}
	}
	return names;
}

function sourceFiles(dir: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir)) {
		if (entry === "__tests__" || entry === "node_modules" || entry === "dist") continue;
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
		else if (entry.endsWith(".mts")) out.push(full);
	}
	return out;
}

/** The source with comments blanked out (line breaks kept, so line numbers hold). */
function withoutComments(source: string): string {
	return source
		.replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, " "))
		.replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

/** The text between a call's parentheses, from the index of its `(`; strings and templates skipped whole. */
function argumentsFrom(source: string, open: number): string {
	let depth = 0;
	let quote: string | undefined;
	for (let i = open; i < source.length; i++) {
		const c = source[i];
		if (quote !== undefined) {
			if (c === "\\") i++;
			else if (c === quote) quote = undefined;
			continue;
		}
		if (c === '"' || c === "'" || c === "`") quote = c;
		else if (c === "(") depth++;
		else if (c === ")" && --depth === 0) return source.slice(open + 1, i);
	}
	return "";
}

/** String and template literals replaced by `""`, so their text cannot match. */
const literalsBlanked = (text: string): string =>
	text.replace(/`(?:\\[\s\S]|[^`\\])*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');

/** The expressions inside every template literal's `${…}`, in text blanked of other literals. */
function templateExpressions(text: string): string[] {
	const out: string[] = [];
	for (const template of text.matchAll(/`(?:\\[\s\S]|[^`\\])*`/g)) {
		for (const expression of template[0].matchAll(/\$\{([^}]*)\}/g)) {
			out.push(expression[1] ?? "");
		}
	}
	return out;
}

/**
 * Whether `text` uses `name` other than as an object key, as the argument of
 * one of `projections` — `loggableError` and what `OTHER_PROJECTIONS`
 * accepts in the file — or as another object's field.
 */
function usesRaw(text: string, name: string, projections: readonly string[]): boolean {
	const occurrence = new RegExp(String.raw`(?<![\w$.])${name.replace(/\$/g, "\\$")}(?![\w$])`, "g");
	const projected = new RegExp(String.raw`\b(?:${projections.join("|")})\(\s*$`);
	for (const match of text.matchAll(occurrence)) {
		const at = match.index ?? 0;
		const before = text.slice(0, at);
		const after = text.slice(at + name.length);
		if (projected.test(before) && /^\s*\)/.test(after)) continue;
		if (/[{,]\s*$/.test(before) && /^\s*:/.test(after)) continue;
		return true;
	}
	return false;
}

/** Every logger call in `source` (comments blanked): its line and the text between its parentheses. */
function loggerCalls(source: string): Array<{ readonly line: number; readonly args: string }> {
	return [...source.matchAll(LOGGER_CALL)].map((call) => ({
		line: source.slice(0, call.index).split("\n").length,
		args: argumentsFrom(source, (call.index ?? 0) + call[0].length - 1),
	}));
}

/**
 * The line of every logger call in `original` that passes a caught error as
 * it is; `projections` beside `loggableError` are what the file may hand one
 * to instead.
 */
function sitesIn(original: string, projections: readonly string[] = []): number[] {
	const source = withoutComments(original);
	const names = caughtNames(source);
	const accepted = ["loggableError", ...projections];
	const lines: number[] = [];
	if (names.size === 0) return lines;
	for (const { line, args } of loggerCalls(source)) {
		const code = literalsBlanked(args);
		const templates = templateExpressions(args);
		for (const name of names) {
			if (
				usesRaw(code, name, accepted) ||
				templates.some((expression) => usesRaw(expression, name, accepted))
			) {
				lines.push(line);
				break;
			}
		}
	}
	return lines;
}

/** What `OTHER_PROJECTIONS` accepts in `file` (a path from the repository root). */
const projectionsFor = (file: string): string[] =>
	OTHER_PROJECTIONS.filter((entry) => entry.file === file).map((entry) => entry.projection);

function rawErrorLogSites(): string[] {
	const sites: string[] = [];
	for (const root of SOURCE_ROOTS) {
		for (const file of sourceFiles(join(repoRoot, root))) {
			const path = relative(repoRoot, file);
			for (const line of sitesIn(readFileSync(file, "utf8"), projectionsFor(path))) {
				sites.push(`${path}:${line}`);
			}
		}
	}
	return sites;
}

/** Every `packages/*` and `templates/*` directory with a `package.json` and a `src`. */
function workspaceSourceTrees(): string[] {
	const trees: string[] = [];
	for (const parent of ["packages", "templates"]) {
		for (const entry of readdirSync(join(repoRoot, parent))) {
			const dir = join(repoRoot, parent, entry);
			if (existsSync(join(dir, "package.json")) && existsSync(join(dir, "src"))) {
				trees.push(`${parent}/${entry}/src`);
			}
		}
	}
	return trees;
}

/**
 * The shape the rule above cannot follow: a caught error flattened to its
 * text, which then travels as an ordinary string, often into another file,
 * and reaches a log line nobody would read as holding an error. Flagged:
 * `.message` (optionally chained, on a name or a member path) read right
 * after an `instanceof` test of `Error` or any `…Error` class — as a
 * ternary's `?`, after `&&`, or as the `return` an `if` makes, braced or
 * not — and `(x as Error).message` or `(x as TypeError).message`, through
 * any chain of `as` casts ending in such a class. Not flagged, and not
 * distinguishable by a regex from the same read of a non-error: a bare
 * `err.message` or `err?.message`, `(x as { message: string }).message`,
 * `String(err)`, `` `${err}` ``, `err.toString()`.
 * Core's readiness runner did this: each failed probe's `err.message` went into
 * the report the readiness route logs. The flattening is the part a file can
 * be read for, so it is what is flagged, wherever it is; a site that
 * legitimately needs the text (a message it throws, with the original kept as
 * `cause`) is listed here with the reason. Each entry allows exactly that many
 * sites in its file, so a new one fails and a removed one fails as stale.
 */
const FLATTENED_ERROR_TEXT =
	/\binstanceof\s+\w*Error\s*\)?\s*(?:\?|&&|\{?\s*return)\s*(?:[A-Za-z_$][\w$]*\??\.)+message\b|\(\s*[A-Za-z_$][\w$.]*(?:\s+as\s+[\w$]+)*\s+as\s+\w*Error\s*\)\s*\??\.message\b/g;

const FLATTENING_ALLOWED: ReadonlyArray<{
	readonly file: string;
	readonly sites: number;
	readonly why: string;
}> = [
	{
		file: "packages/core/src/federation-tokens/refresh-error.mts",
		sites: 1,
		why: "a legacy classifier reads the text for `invalid_grant` / `5xx`; it is never logged",
	},
	{
		file: "packages/core/src/jwt/verify.mts",
		sites: 1,
		why: "jose's own fixed text about the token, as the verdict's message; jose's claims ride on the error, not in its message",
	},
	{
		file: "packages/redis/src/ioredis.mts",
		sites: 1,
		why:
			"the NOSCRIPT classifier: ioredis's ReplyError carries no code, only Redis's reply text, and " +
			"ioredis's own Script reads the same text the same way; the text decides a boolean and is " +
			"never logged or thrown",
	},
];

/**
 * The trees this change reworks: every logger call in them is object-first.
 * Elsewhere only the string-first call that passes more (the one pino loses
 * the rest of) is flagged.
 */
const STRING_FIRST_EVERYWHERE: readonly string[] = [
	"packages/core/src",
	"packages/dpop/src",
	"packages/federation-apple/src",
	"packages/federation-github/src",
	"packages/federation-google/src",
	"packages/federation-grants/src",
	"packages/federation-oidc/src",
	"packages/mtls/src",
	"packages/oauth/src",
	"packages/oauth-token-exchange/src",
	"packages/redis/src",
	"packages/session/src",
	"packages/webauthn/src",
	"templates/standalone/src",
];

/** The string-first calls that stay, each file's count exact, with why. */
const STRING_FIRST_ALLOWED: ReadonlyArray<{
	readonly file: string;
	readonly sites: number;
	readonly why: string;
}> = [
	{
		file: "packages/core/src/middleware/cors.mts",
		sites: 1,
		why: "a boot-time notice about a configured origin, with no error; the message is written whole",
	},
	...[
		"packages/core/src/federation-grants/factory.mts",
		"packages/core/src/federation-grants/intentFactory.mts",
		"packages/core/src/federation-tokens/factory.mts",
	].map((file) => ({
		file,
		sites: 1,
		why: "a fixed dev/test-only notice when the in-memory adapter is built, with no error; the message is written whole",
	})),
];

/** How many arguments a call's text holds, from its top-level commas; literals blanked first. */
function argumentCount(args: string): number {
	const code = literalsBlanked(args).trim().replace(/,$/, "");
	if (code.length === 0) return 0;
	let depth = 0;
	let count = 1;
	for (const c of code) {
		if (c === "(" || c === "[" || c === "{") depth++;
		else if (c === ")" || c === "]" || c === "}") depth--;
		else if (c === "," && depth === 0) count++;
	}
	return count;
}

/**
 * The line of every logger call in `original` that opens with a string or
 * template literal — any such call when `everyStringFirst`, else only one
 * that passes more after it.
 */
function stringFirstSitesIn(
	original: string,
	{ everyStringFirst }: { readonly everyStringFirst: boolean },
): number[] {
	return loggerCalls(withoutComments(original))
		.filter(({ args }) => /^\s*["'`]/.test(args))
		.filter(({ args }) => everyStringFirst || argumentCount(args) > 1)
		.map(({ line }) => line);
}

function stringFirstSites(): Map<string, number[]> {
	const sites = new Map<string, number[]>();
	for (const root of SOURCE_ROOTS) {
		const everyStringFirst = STRING_FIRST_EVERYWHERE.includes(root);
		for (const file of sourceFiles(join(repoRoot, root))) {
			const lines = stringFirstSitesIn(readFileSync(file, "utf8"), { everyStringFirst });
			if (lines.length > 0) sites.set(relative(repoRoot, file), lines);
		}
	}
	return sites;
}

function flatteningSites(): Map<string, number[]> {
	const sites = new Map<string, number[]>();
	for (const root of SOURCE_ROOTS) {
		for (const file of sourceFiles(join(repoRoot, root))) {
			const source = withoutComments(readFileSync(file, "utf8"));
			const lines: number[] = [];
			for (const match of source.matchAll(FLATTENED_ERROR_TEXT)) {
				lines.push(source.slice(0, match.index).split("\n").length);
			}
			if (lines.length > 0) sites.set(relative(repoRoot, file), lines);
		}
	}
	return sites;
}

describe("a caught error is not flattened to text on its way to a log line", () => {
	it(`in ${SOURCE_ROOTS.join(", ")}: every flattening is one this file lists, with its reason`, () => {
		const unexpected: string[] = [];
		for (const [file, lines] of flatteningSites()) {
			const allowed = FLATTENING_ALLOWED.find((entry) => entry.file === file)?.sites ?? 0;
			if (lines.length > allowed) unexpected.push(`${file}:${lines.join(",")}`);
		}
		expect(unexpected).toEqual([]);
	});

	it("has no stale entry in FLATTENING_ALLOWED", () => {
		const sites = flatteningSites();
		for (const { file, sites: allowed, why } of FLATTENING_ALLOWED) {
			expect(sites.get(file)?.length ?? 0, `${file} — ${why}`).toBe(allowed);
		}
	});

	it.each([
		["a ternary", "const text = err instanceof Error ? err.message : String(err);"],
		["a helper's early return", "if (err instanceof Error) return err.message;"],
		["a helper's braced early return", "if (err instanceof Error) {\n\treturn err.message;\n}"],
		["a short-circuit", "const text = err instanceof Error && err.message;"],
		["a cast", "const text = (err as Error).message;"],
		["a cast, optionally chained", "const text = (err as Error)?.message;"],
		["a subclass test", "const text = err instanceof TypeError ? err.message : String(err);"],
		["a cast to a subclass", "const text = (err as TypeError).message;"],
	])("flags %s", (_label, source) => {
		expect(source.match(FLATTENED_ERROR_TEXT)).not.toBeNull();
	});
});

describe("a caught error reaches a logger only through loggableError", () => {
	it(`in ${SOURCE_ROOTS.join(", ")}`, () => {
		expect(rawErrorLogSites()).toEqual([]);
	});

	it("names every workspace source tree", () => {
		expect([...SOURCE_ROOTS].sort()).toEqual(workspaceSourceTrees().sort());
	});

	it("has no stale entry in OTHER_PROJECTIONS", () => {
		for (const { file, projection, why } of OTHER_PROJECTIONS) {
			const source = withoutComments(readFileSync(join(repoRoot, file), "utf8"));
			const used = loggerCalls(source).some(({ args }) =>
				new RegExp(String.raw`\b${projection}\(`).test(literalsBlanked(args)),
			);
			expect(used, `${file} hands a logger ${projection}(...) — ${why}`).toBe(true);
		}
	});

	describe("the guard sees the shapes it exists for, and no others", () => {
		// A self-check against a guard that silently matches nothing, or that
		// refuses another PR's code for a name it happens to use.
		const flags = (source: string): boolean => sitesIn(source).length > 0;

		it.each([
			["shorthand", `try { x() } catch (err) { log.warn({ err }, "failed"); }`],
			[
				"another key",
				`try { x() } catch (storeErr) { log.warn({ err: storeErr, sid }, "failed"); }`,
			],
			[
				"a binding of any name",
				`try { x() } catch (failure) { logger.warn({ err: failure }, "failed"); }`,
			],
			["{ cause: err }", `try { x() } catch (err) { logger.warn({ cause: err }, "failed"); }`],
			["{ reason: err }", `try { x() } catch (err) { logger.warn({ reason: err }, "failed"); }`],
			["a positional argument", "try { x() } catch (error) { logger.warn(`failed:`, error); }"],
			[
				"its message",
				`try { x() } catch (err) { logger.warn("x", { reason: err instanceof Error ? err.message : String(err) }); }`,
			],
			// biome-ignore lint/suspicious/noTemplateCurlyInString: the source text under test holds a template
			["a template literal", "try { x() } catch (err) { logger.warn(`failed: ${err.message}`); }"],
			["logger.child", `try { x() } catch (err) { const scoped = logger.child({ err }); }`],
			["console", `try { x() } catch (err) { console.error("failed", err); }`],
			[
				"a receiver named `…Logger`",
				`try { x() } catch (err) { consoleLogger.warn({ err }, "failed"); }`,
			],
			[
				"a member path ending in `…Logger`",
				`try { x() } catch (err) { this.auditLogger.error({ err }, "failed"); }`,
			],
			["a non-null assertion", `try { x() } catch (err) { logger!.warn({ err }, "failed"); }`],
			[
				"a fallback to another logger",
				`try { x() } catch (err) { (logger ?? consoleLogger).warn({ err }, "failed"); }`,
			],
			["an optional call", `try { x() } catch (err) { logger.warn?.({ err }, "failed"); }`],
			[
				"an optional call on an optional receiver",
				`try { x() } catch (err) { opts.logger?.warn?.({ err }, "failed"); }`,
			],
			[".catch", `p.catch((err) => logger.warn({ err }, "failed"));`],
			['.on("error")', `client.on("error", (err) => logger.error({ err }, "client_error"));`],
			['.once("error")', `client.once("error", async (e) => log.error({ e }, "client_error"));`],
			[
				"a node-style callback's error",
				`req.session.save((err) => { if (err) log.warn({ err }, "session save failed"); });`,
			],
			[
				"a node-style callback written as a function",
				`store.get(sid, function (err, value) { logger.error({ err }, "store read failed"); });`,
			],
			[
				"an error a helper's promise resolved with",
				`const consumeErr = await consumeTransaction(); if (consumeErr) log.warn({ err: consumeErr }, "delete failed");`,
			],
			[
				"a node-style callback's error beside a `.map((e) => …)`",
				`const kinds = entries.map((e) => e.kind); req.session.save((err) => { if (err) log.warn({ err, kinds }, "session save failed"); });`,
			],
			[".catch((e) => …)", `p.catch((e) => logger.warn({ err: e }, "failed"));`],
			["catch (e)", `try { x() } catch (e) { log.warn({ err: e }, "failed"); }`],
			[
				"an error a callback resolved a promise with",
				`const saveErr = await new Promise((resolve) => { req.session.save((err) => resolve(err ?? null)); }); if (saveErr) log.warn({ err: saveErr }, "save failed");`,
			],
			[
				"an Express error handler's error, returned from a factory",
				`const handler = (logger) => { return (err, req, res, next) => { logger.error({ err, endpoint: req.path }, "unhandled"); }; };`,
			],
			[
				"an Express error handler's error under any name, typed",
				`app.use((failure: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => { console.error(failure); });`,
			],
			[
				"an Express error handler written as a function",
				`function onError(error, req, res, next) { log.error({ error }, "unhandled"); }`,
			],
			[
				"an Express error handler whose request type has generic arguments",
				`const handler = (logger) => { return (failure: unknown, req: Request<P, B>, res: Response, next: NextFunction) => { logger.error({ err: failure }, "unhandled"); }; };`,
			],
			[
				"an Express error handler whose parameter types hold parentheses and nested generics",
				`app.use((failure: unknown, _req: Request<{ id: string }, unknown>, res: Response<unknown, Record<string, unknown>>, next: (err?: unknown) => void) => { console.error(failure); });`,
			],
			[
				"an Express error handler with a return type",
				`app.use((failure, req, res, next): void => { logger.error({ err: failure }, "unhandled"); });`,
			],
			[
				"an Express error handler written as a method",
				`class Handler { handle(failure: unknown, req: Request, res: Response, next: NextFunction) { logger.error({ err: failure }, "unhandled"); } }`,
			],
			[
				"a projection accepted in another file",
				`try { x() } catch (err) { log.error(unexpectedErrorFields(err), "unexpected"); }`,
			],
		])("flags %s", (_label, source) => {
			expect(flags(source)).toBe(true);
		});

		it.each([
			[
				"the projection",
				`try { x() } catch (err) { log.warn({ err: loggableError(err) }, "failed"); }`,
			],
			[
				"a projection's field",
				"try { x() } catch (err) { logger.warn(`failed:`, loggableError(err).name); }",
			],
			[
				"a code string named error",
				`const error = sanitize(code); logger.warn({ error: auditErrorText(String(error)) }, "token_error_code_malformed");`,
			],
			[
				"a code string in shorthand",
				`const error = sanitize(code); logger.warn({ error, clientId }, "refused");`,
			],
			["a literal", `log.warn({ error: "invalid_grant", reason: "typ" }, "refused");`],
			[
				"another object's field",
				`try { x() } catch (err) { log.warn({ code: result.err }, "x"); }`,
			],
			[
				"an arrow's parameter that is not an error",
				`log.info({ names: items.map((item) => item.name) }, "loaded");`,
			],
			[
				"an awaited value that is not an error",
				`const result = await load(); log.info({ result }, "loaded");`,
			],
			[
				"a `.map((e) => …)` element read in a later log call",
				`const summary = entries.map((e) => e.module).join(", "); for (const e of entries) log.warn({ module: e.module, summary }, "cleanup failed");`,
			],
			[
				"a `.filter((e) => …)` element read in a later log call",
				`const named = entries.filter((e) => e.kind === "name-keyed"); for (const e of named) logger.info({ kind: e.kind }, "collected");`,
			],
			[
				"a node-style callback's error, projected",
				`req.session.save((err) => { if (err) log.warn({ err: loggableError(err) }, "save failed"); });`,
			],
			[
				"an Express error handler's error, projected",
				`return (err, req, res, next) => { logger.error({ err: loggableError(err), endpoint: req.path }, "unhandled"); };`,
			],
			[
				"an Express error handler with generic parameter types, projected",
				`app.use((err: unknown, req: Request<P, B>, res: Response, next: NextFunction) => { logger.error({ err: loggableError(err) }, "unhandled"); });`,
			],
			[
				"a four-argument call whose last argument is `next`, which binds nothing",
				`const chain = compose(first, second, third, next); logger.info({ first }, "composed");`,
			],
			[
				"a four-argument call with a type argument, which binds nothing",
				`const chain = compose<Request, Response>(first, second, third, next); logger.info({ first }, "composed");`,
			],
			[
				"a middleware's request, which is not an error",
				`app.use((req, res, next) => { logger.info({ path: req.path, req }, "request"); next(); });`,
			],
		])("does not flag %s", (_label, source) => {
			expect(flags(source)).toBe(false);
		});

		it("accepts a projection OTHER_PROJECTIONS names only where it names it", () => {
			const source = `try { x() } catch (err) { log.error(unexpectedErrorFields(err), "unexpected"); }`;
			expect(sitesIn(source, ["unexpectedErrorFields"])).toEqual([]);
			expect(sitesIn(source)).toEqual([1]);
		});
	});
});

describe("a logger call opens with an object, not a string (string-first rule)", () => {
	it.each([
		[
			"a template message with the error after it",
			// biome-ignore lint/suspicious/noTemplateCurlyInString: the source text under test holds a template
			"try { x() } catch (err) { logger.warn(`POST /x/${name}: failed:`, loggableError(err)); }",
			false,
		],
		["a string message with a value after it", `log.error("drain", obj);`, false],
		["a string message alone, where the rule holds for every call", `logger.warn("notice");`, true],
	])("flags %s", (_label, source, anywhere) => {
		expect(stringFirstSitesIn(source, { everyStringFirst: true })).toEqual([1]);
		expect(stringFirstSitesIn(source, { everyStringFirst: false })).toEqual(anywhere ? [] : [1]);
	});

	it.each([
		["an object-first line", `logger.warn({ err: loggableError(err) }, "event");`],
		["a call on something that is not a logger", `res.status(400).json("text");`],
		["a message built elsewhere (a known gap)", `logger.warn(message, extra);`],
	])("does not flag %s", (_label, source) => {
		expect(stringFirstSitesIn(source, { everyStringFirst: true })).toEqual([]);
	});

	it(`in ${SOURCE_ROOTS.join(", ")}: every string-first call is one this file lists, with its reason`, () => {
		const unexpected: string[] = [];
		for (const [file, lines] of stringFirstSites()) {
			const allowed = STRING_FIRST_ALLOWED.find((entry) => entry.file === file)?.sites ?? 0;
			if (lines.length > allowed) unexpected.push(`${file}:${lines.join(",")}`);
		}
		expect(unexpected).toEqual([]);
	});

	it("has no stale entry in STRING_FIRST_ALLOWED", () => {
		const sites = stringFirstSites();
		for (const { file, sites: allowed, why } of STRING_FIRST_ALLOWED) {
			expect(sites.get(file)?.length ?? 0, `${file} — ${why}`).toBe(allowed);
		}
	});
});
