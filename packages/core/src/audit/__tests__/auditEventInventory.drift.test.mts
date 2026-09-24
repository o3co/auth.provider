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
 * The built-in audit-event inventory, executable (#369).
 *
 * `AuditEvent.type` is an open string on purpose (consumers namespace their
 * own events), so nothing in the type system connects the documented
 * inventory to what the bundled packages actually emit — and the two had
 * drifted: the doc comment named events (`"logout"`, `"scope.denied"`,
 * `"login.success"`, `"mfa.challenge.*"`) that no shipped code emits, and
 * omitted most of the seventeen that ARE emitted. A sink implementor or a
 * dashboard author filtering on the documented names would match nothing.
 *
 * `BUILT_IN_AUDIT_EVENT_TYPES` is now the inventory, and this suite pins it
 * against the emission sites in both directions — an event emitted but not
 * listed fails, and an event listed but no longer emitted fails. Same
 * pattern as the #288 env-var drift guards and the #370 design-vocabulary
 * guard: the property is owned by a test, not by a comment.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { BUILT_IN_AUDIT_EVENT_TYPES } from "#/audit/types.mjs";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../../..");

/** Shipped sources: packages/*\/src and the standalone template, tests excluded. */
function listShippedSources(): string[] {
	const files: string[] = [];
	for (const base of ["packages", "templates/standalone/src"]) {
		walk(join(repoRoot, base), files);
	}
	return files;
}

function walk(dir: string, out: string[]): void {
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
		if (entry.isDirectory()) walk(path, out);
		else if (entry.name.endsWith(".mts") && path.includes(`${"/"}src${"/"}`)) out.push(path);
	}
}

/**
 * Every `type: "..."` literal within an emission call's argument window.
 * The window is generous (600 chars) because the event literal is usually
 * the first field but not always the first line.
 *
 * The receiver pattern is deliberately narrow — `emitAuditEvent(` (the
 * helper every module-side emission goes through) and `sink.record(` (the
 * direct calls inside the audit plumbing itself) — because a bare
 * `\.record\(` also matches `z.record(`, and a schema definition sitting
 * near an unrelated `type: "..."` literal would poison the inventory.
 * A new emission spelled differently shows up as a missing-inventory
 * failure the moment its event is added to the constant, so the narrowness
 * cannot hide events silently.
 */
function emittedEventTypes(): ReadonlySet<string> {
	const found = new Set<string>();
	for (const file of listShippedSources()) {
		const source = readFileSync(file, "utf8");
		for (const call of source.matchAll(/(?:emitAuditEvent|\bsink\.record)\(/g)) {
			const windowText = source.slice(call.index, (call.index ?? 0) + 600);
			const literal = /type:\s*"([^"]+)"/.exec(windowText);
			if (literal?.[1]) found.add(literal[1]);
		}
		for (const type of federationGrantEmissions(source)) found.add(type);
	}
	return found;
}

/**
 * #593's emissions, which the two receivers above cannot see.
 *
 * `retrieveFederationGrantToken` does not build an `AuditEvent` and does not
 * know a sink: it calls its own `audit(deps, request, "<type>", outcome, …)`
 * seam, and the branches that audit *after* answering return
 * `audits: [["<type>", outcome]]` tuples for the caller to hand over. The
 * routes package then maps whatever arrives onto `sink.record(mapped)`, with
 * `type` copied from the event — so there is no literal at the sink call
 * either, and both directions of this guard would be blind to the whole
 * family.
 *
 * Narrow on purpose, and narrow in the same way the receivers above are: a
 * `"federation.grant.*"` literal counts only where it is an argument to that
 * seam or an entry in one of those tuples. The union that declares the seven
 * type names does NOT count — a type nothing emits any more has to fail here,
 * and a declaration is not an emission.
 */
function federationGrantEmissions(source: string): readonly string[] {
	const found: string[] = [];
	// `audit(deps, request, "federation.grant.x", …)` — the seam's third argument.
	for (const call of source.matchAll(
		/\baudit\((?:[^()"]|\([^()]*\))*?"(federation\.grant\.[\w.]+)"/g,
	)) {
		if (call[1]) found.push(call[1]);
	}
	// `routeDeniedEvent({ type: "federation.grant.x", … })` — the routes
	// package's own builder for a refusal the handler never reached. Its
	// result is always handed to the sink, so a literal in one of its calls is
	// an emission. `({` and not `(` on purpose: it matches the CALLS and not
	// the declaration, whose parameter list is `(input: …)` and whose body
	// carries the default type — a declaration is not an emission.
	for (const call of source.matchAll(/\brouteDeniedEvent\(\{/g)) {
		const windowText = source.slice(call.index, (call.index ?? 0) + 600);
		const literal = /type:\s*"(federation\.grant\.[\w.]+)"/.exec(windowText);
		if (literal?.[1]) found.push(literal[1]);
	}
	// A `PendingAudit` tuple: `["federation.grant.x", "<outcome>"]`, whether it
	// sits inside an `audits: [[…]]` list or is bound to a name first. Matched
	// as "the first element of an array literal", which is what a tuple is and
	// what the `| "federation.grant.x"` members of the type union are not.
	for (const tuple of source.matchAll(/\[\s*"(federation\.grant\.[\w.]+)"/g)) {
		if (tuple[1]) found.push(tuple[1]);
	}
	return found;
}

describe("the federation-grant emission scan (#593)", () => {
	// The guard's second direction — "lists no event nothing emits any more" —
	// only means something while a DECLARATION does not count as an emission.
	// Core declares the seven type names in one union, so a scan wide enough to
	// see that union would report every one of them as emitted for ever, and
	// the day an emission site is deleted nothing would notice.
	it("does not count the type union that declares the names", () => {
		expect(
			federationGrantEmissions(
				'readonly type:\n\t\t| "federation.grant.token.success"\n\t\t| "federation.grant.revoked";',
			),
		).toEqual([]);
	});

	it("counts a call to core's audit seam", () => {
		expect(
			federationGrantEmissions(
				'audit(deps, request, "federation.grant.token.denied", outcomeOf(denial), grant)',
			),
		).toEqual(["federation.grant.token.denied"]);
	});

	it("counts a pending-audit tuple, bound to a name or inside a list", () => {
		expect(federationGrantEmissions('audits: [["federation.grant.refresh_failed", "x"]]')).toEqual([
			"federation.grant.refresh_failed",
		]);
		expect(
			federationGrantEmissions(
				'const a: PendingAudit = ["federation.grant.refreshed", "success"];',
			),
		).toEqual(["federation.grant.refreshed"]);
	});
});

describe("built-in audit event inventory (#369)", () => {
	const emitted = emittedEventTypes();

	it("finds a plausible emission surface (sanity: the guard is not vacuous)", () => {
		expect(emitted.size).toBeGreaterThan(10);
	});

	it("lists every event the shipped packages emit", () => {
		const unlisted = [...emitted].filter(
			(type) => !(BUILT_IN_AUDIT_EVENT_TYPES as readonly string[]).includes(type),
		);
		expect(unlisted, "emitted but missing from BUILT_IN_AUDIT_EVENT_TYPES").toEqual([]);
	});

	it("lists no event nothing emits any more", () => {
		const dead = (BUILT_IN_AUDIT_EVENT_TYPES as readonly string[]).filter(
			(type) => !emitted.has(type),
		);
		expect(dead, "listed but no emission site found").toEqual([]);
	});
});

/**
 * One type per `details` key, across every event (#369's inventory, extended).
 *
 * A sink that fixes a field's type the first time it sees it —
 * Elasticsearch / OpenSearch dynamic mapping, a BigQuery schema, a Datadog
 * facet — rejects every later event that carries the other type, and the
 * events it drops are whichever arrive second. `details.error` is a string
 * (an OAuth code, a reason) wherever it appears; an error an event reports
 * travels as `details.cause`, always core's `auditedError(…)` projection.
 *
 * Read from the source, at every emission whose event is an object literal:
 * `details.error` has to be written as a string (a literal, a template, a
 * name, or a call to `auditErrorText` / `String`), and `details.cause` as a
 * call to `auditedError`. `AuditEvent`'s type says the same
 * (`audit-details.types.test.mts`); this catches what a cast would let by.
 */
function detailsShapeViolations(file: string, source: string): string[] {
	const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
	const found: string[] = [];
	const at = (node: ts.Node): string =>
		`${relative(repoRoot, file)}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`;
	const stringShaped = (value: ts.Expression): boolean => {
		if (
			ts.isStringLiteral(value) ||
			ts.isNoSubstitutionTemplateLiteral(value) ||
			ts.isTemplateExpression(value) ||
			ts.isIdentifier(value) ||
			ts.isPropertyAccessExpression(value)
		)
			return true;
		if (ts.isParenthesizedExpression(value)) return stringShaped(value.expression);
		if (ts.isConditionalExpression(value))
			return stringShaped(value.whenTrue) && stringShaped(value.whenFalse);
		if (ts.isBinaryExpression(value)) return stringShaped(value.left) && stringShaped(value.right);
		return (
			ts.isCallExpression(value) &&
			ts.isIdentifier(value.expression) &&
			["auditErrorText", "String"].includes(value.expression.text)
		);
	};
	const checkDetails = (details: ts.ObjectLiteralExpression): void => {
		for (const property of details.properties) {
			if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.name)) continue;
			const value = property.initializer;
			if (property.name.text === "error" && !stringShaped(value)) {
				found.push(`${at(property)} details.error is not a string: ${value.getText(sf)}`);
			}
			if (
				property.name.text === "cause" &&
				!(
					ts.isCallExpression(value) &&
					ts.isIdentifier(value.expression) &&
					value.expression.text === "auditedError"
				)
			) {
				found.push(`${at(property)} details.cause is not auditedError(…): ${value.getText(sf)}`);
			}
		}
	};
	const visit = (node: ts.Node): void => {
		if (ts.isCallExpression(node)) {
			const callee = node.expression.getText(sf);
			const event =
				callee === "emitAuditEvent"
					? node.arguments[1]
					: /(^|\.)sink\??\.record$/.test(callee)
						? node.arguments[0]
						: undefined;
			if (event !== undefined && ts.isObjectLiteralExpression(event)) {
				for (const property of event.properties) {
					if (
						ts.isPropertyAssignment(property) &&
						ts.isIdentifier(property.name) &&
						property.name.text === "details" &&
						ts.isObjectLiteralExpression(property.initializer)
					) {
						checkDetails(property.initializer);
					}
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(sf);
	return found;
}

describe("audit details keep one type per key", () => {
	it("writes details.error as a string and details.cause as auditedError(…), in every emission", () => {
		const violations = listShippedSources().flatMap((file) =>
			detailsShapeViolations(file, readFileSync(file, "utf8")),
		);
		expect(violations).toEqual([]);
	});

	it("sees the shapes it exists for", () => {
		const flagged = (source: string): number => detailsShapeViolations("sample.mts", source).length;
		expect(
			flagged(`emitAuditEvent(sink, { type: "x", details: { error: auditedError(cause) } });`),
		).toBe(1);
		expect(flagged(`sink.record({ type: "x", details: { error: { name: "Error" } } });`)).toBe(1);
		expect(flagged(`emitAuditEvent(sink, { type: "x", details: { cause: cause.message } });`)).toBe(
			1,
		);
		expect(
			flagged(
				`emitAuditEvent(sink, { type: "x", details: { error: code, reason: "r", cause: auditedError(err) } });`,
			),
		).toBe(0);
	});
});
