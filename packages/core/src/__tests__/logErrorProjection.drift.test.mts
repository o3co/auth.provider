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
 * logErrorProjection.drift.test.mts — no log line in core, session or oauth
 * hands a logger a caught error as it is.
 *
 * A store's or a library's error carries whatever the system it talked to
 * said: ioredis puts the refused command on `err.command.args` (under
 * `encryption.mode = "allow-plaintext"`, a token record), openid-client puts
 * the token answer it refused on `cause.cause.body`, a JSON parser quotes its
 * input in `message`. A logger that serialises the whole error writes all of
 * it out, and a deployment chooses its logger. So every logger call in these
 * packages passes a caught error through `loggableError(...)` — the
 * projection core owns — and never the error, nor its `message` or
 * `String(...)` of it.
 *
 * What counts as passing the error: an object property `err` / `error`
 * that is shorthand or holds an error-named identifier as it is; a bare
 * identifier that names an error (`err`, `error`, `e`, `cause`, `*Err`,
 * `*Error`) as a positional argument after the message; and `<err>.message`
 * or `String(<err>)` anywhere in the arguments. Comments are ignored.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const PACKAGES = ["core", "session", "oauth"] as const;

const ERROR_NAME = "(?:err|error|e|cause|[a-z][A-Za-z]*Err|[a-z][A-Za-z]*Error)";
const LOGGER_CALL =
	/\b(?:log|logger|(?:\w+\.)+logger)\??\.(?:trace|debug|info|warn|error|fatal)\(/g;

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

/** The top-level comma-separated arguments. */
function topLevelArguments(text: string): string[] {
	const parts: string[] = [];
	let depth = 0;
	let start = 0;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (c === "(" || c === "{" || c === "[") depth++;
		else if (c === ")" || c === "}" || c === "]") depth--;
		else if (c === "," && depth === 0) {
			parts.push(text.slice(start, i));
			start = i + 1;
		}
	}
	parts.push(text.slice(start));
	return parts.map((part) => part.trim()).filter((part) => part.length > 0);
}

const RAW_PROPERTY = /[{,]\s*(?:err|error)\s*(?=[,}])/;
/** `err` / `error` holding an error-named identifier as it is, not a call on or a read of it. */
const PROPERTY_NOT_PROJECTED = new RegExp(
	String.raw`\b(?:err|error)\s*:\s*${ERROR_NAME}\b(?!\s*[(.])`,
);
const BARE_ERROR_ARGUMENT = new RegExp(`^${ERROR_NAME}$`);
const MESSAGE_OR_STRING = new RegExp(
	String.raw`\b${ERROR_NAME}\.message\b|\bString\(\s*${ERROR_NAME}\s*\)`,
);

/** The line of every logger call in `original` that passes a caught error as it is. */
function sitesIn(original: string): number[] {
	const source = withoutComments(original);
	const lines: number[] = [];
	for (const call of source.matchAll(LOGGER_CALL)) {
		const open = (call.index ?? 0) + call[0].length - 1;
		const args = literalsBlanked(argumentsFrom(source, open));
		const positional = topLevelArguments(args).slice(1);
		if (
			RAW_PROPERTY.test(args) ||
			PROPERTY_NOT_PROJECTED.test(args) ||
			positional.some((arg) => BARE_ERROR_ARGUMENT.test(arg)) ||
			MESSAGE_OR_STRING.test(args)
		) {
			lines.push(source.slice(0, call.index).split("\n").length);
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
	it("in core, session and oauth", () => {
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
		])("does not flag %s", (_label, source) => {
			expect(flags(source)).toBe(false);
		});
	});
});
