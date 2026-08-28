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
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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
	}
	return found;
}

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
