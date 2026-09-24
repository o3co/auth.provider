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
 * logErrorProjection.drift.test.mts — no log line in the listed packages
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
 * `get(key, function (err, value) …)`), and an error-named value awaited
 * from a helper (`const consumeErr = await …`) — used anywhere in the arguments of
 * a logger call (`log.`, `logger.`, `….logger.` with a level or `child`;
 * `console.`) other than as an object key, as the argument of
 * `loggableError(...)`, or as another object's field (`result.err`); inside
 * a template literal's `${…}` too. A name that merely looks like an error —
 * a policy's `error` code — is not flagged.
 *
 * What it does not see (known holes, left to review):
 * - an error that reaches a log call under a name none of those bound in
 *   that file: a callback parameter or an awaited value not named like an
 *   error (`(failure) => …`, `const outcome = await …`), a re-bound value
 *   (`const failure = err`), an `allSettled` result's `reason`, a helper's
 *   parameter that it logs;
 * - an error flattened into a value before the call (`const reason =
 *   err.message`, then `{ reason }`);
 * - a logger reached some other way (a destructured `warn`, `logger[level]`),
 *   and an audit sink, which is not a logger;
 * - bindings are per file, not per scope: a variable elsewhere in the file
 *   that shares a caught error's name is flagged too (rename it).
 *
 * The packages are `PACKAGES` below. redis, device-grant, dpop,
 * oauth-token-exchange and the standalone template still log six raw errors
 * between them; the follow-up that converts those sites adds them here.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
/**
 * The packages held to the rule — a path under `packages/`. Widen it with the
 * follow-up: `redis`, `device-grant`, `dpop`, `oauth-token-exchange`, and the
 * standalone template (under `templates/`, not `packages/`).
 */
const PACKAGES: readonly string[] = ["core", "session", "oauth"];

/** A logger call: a level (or `child`) on `log`, `logger` or `….logger`, and `console`'s. */
const LOGGER_CALL =
	/\b(?:(?:log|logger|(?:\w+\.)+logger)\??\.(?:trace|debug|info|warn|error|fatal|child)|console\.(?:log|trace|debug|info|warn|error))\(/g;

const IDENTIFIER = "[A-Za-z_$][\\w$]*";

/** A name that reads as an error: what a node-style callback or an awaited helper's result is called. */
const ERROR_NAME = "(?:err|error|e|[a-z][A-Za-z]*Err|[a-z][A-Za-z]*Error)";

/**
 * Where a caught error is bound: `catch (x)`, `.catch(…x…)`,
 * `.on("error", …x…)`; the error-named first parameter of a callback passed
 * as an argument — node-style, `save((err) => …)`, `get(key, function (err,
 * value) …)`, `save(err => …)`; and an error-named value awaited from a
 * helper — `const consumeErr = await …`, which is also what a promise
 * wrapping a node-style callback resolves.
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

/** Every name the file binds as a caught error. */
function caughtNames(source: string): ReadonlySet<string> {
	const names = new Set<string>();
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
 * `loggableError(...)`, or as another object's field.
 */
function usesRaw(text: string, name: string): boolean {
	const occurrence = new RegExp(String.raw`(?<![\w$.])${name.replace(/\$/g, "\\$")}(?![\w$])`, "g");
	for (const match of text.matchAll(occurrence)) {
		const at = match.index ?? 0;
		const before = text.slice(0, at);
		const after = text.slice(at + name.length);
		if (/loggableError\(\s*$/.test(before) && /^\s*\)/.test(after)) continue;
		if (/[{,]\s*$/.test(before) && /^\s*:/.test(after)) continue;
		return true;
	}
	return false;
}

/** The line of every logger call in `original` that passes a caught error as it is. */
function sitesIn(original: string): number[] {
	const source = withoutComments(original);
	const names = caughtNames(source);
	const lines: number[] = [];
	if (names.size === 0) return lines;
	for (const call of source.matchAll(LOGGER_CALL)) {
		const open = (call.index ?? 0) + call[0].length - 1;
		const raw = argumentsFrom(source, open);
		const code = literalsBlanked(raw);
		const templates = templateExpressions(raw);
		for (const name of names) {
			if (usesRaw(code, name) || templates.some((expression) => usesRaw(expression, name))) {
				lines.push(source.slice(0, call.index).split("\n").length);
				break;
			}
		}
	}
	return lines;
}

function rawErrorLogSites(): string[] {
	const sites: string[] = [];
	for (const pkg of PACKAGES) {
		for (const file of sourceFiles(join(repoRoot, "packages", pkg, "src"))) {
			for (const line of sitesIn(readFileSync(file, "utf8"))) {
				sites.push(`${relative(repoRoot, file)}:${line}`);
			}
		}
	}
	return sites;
}

describe("a caught error reaches a logger only through loggableError", () => {
	it(`in ${PACKAGES.join(", ")}`, () => {
		expect(rawErrorLogSites()).toEqual([]);
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
		])("does not flag %s", (_label, source) => {
			expect(flags(source)).toBe(false);
		});
	});
});
