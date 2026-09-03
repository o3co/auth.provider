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
 * Issue #304 — the replica-safety guard must not fall behind the modules.
 *
 * #271 shipped the guard: `deployment.mode = "multi"` with an in-process state
 * store wired refuses to boot, naming each offender and what diverges. Until
 * #455 it worked off a hand-maintained table keyed by module name, and
 * hand-maintained was the problem #304 is about: the next in-memory adapter
 * someone adds is replica-unsafe the moment it exists and silent until someone
 * remembers the table. #455 found the other edge of the same gap — a
 * composition root's *own* modules, under names core has never seen, booted
 * under `"multi"` with their state in memory.
 *
 * So the declaration now lives on the manifest (`replicaSafety`), where the
 * module is, and the guard reads it. What this suite checks is that the
 * declaration is actually made: every bundled module whose name marks it as
 * memory-backed must declare `replicaSafety` on itself, or be exempted in
 * `SAFE_MEMORY_MODULES` with a reason. Adding an adapter without doing either
 * fails this test, which is the point at which the decision is cheap.
 *
 * `REPLICA_UNSAFE_MODULES` stays exported for deployments that assert on the
 * set from their own tests. It is derived from core's bundled modules, so the
 * other check here is that it names exactly the core modules that declare —
 * a declaring module left out of the derived list would still be refused at
 * boot, but the exported set would lie about it.
 *
 * Scanned from source rather than from an import graph on purpose: a module
 * that is not yet wired into any bundle is exactly the one that would slip
 * through, and it is still a module someone can compose.
 *
 * Comments are stripped first. `defineModule` appears inside JSDoc `@example`
 * blocks — `define-module.mts` documents itself with one — and a scan that
 * counts those is picking up names no module has. Harmless today (the example
 * is called `my-module`), a false failure the day someone writes an example
 * with `memory` in the name, and quietly wrong in the other direction too:
 * an inflated list makes the exact-set assertion weaker than it reads.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	REPLICA_UNSAFE_BUNDLED_MODULES,
	REPLICA_UNSAFE_MODULES,
	replicaUnsafeReason,
} from "#/boot/replica-safety.mjs";

/** Repository root, from this file's location. */
const repoRoot = fileURLToPath(new URL("../../../../..", import.meta.url));

/**
 * Memory-backed modules that are NOT replica-unsafe, with why.
 *
 * Empty today, and that is the honest state: every in-process state store this
 * repository bundles forks per replica. The list exists so a future exemption
 * has to be written down next to its reason rather than argued in a review
 * comment and forgotten.
 */
const SAFE_MEMORY_MODULES: Readonly<Record<string, string>> = {};

/**
 * Remove block and line comments so documentation examples are not read as
 * code. Deliberately not a parser: this only has to be right about `/* … *\/`
 * and `// …`, and pulling a TypeScript AST in to find one call expression
 * would be a heavier dependency than the check is worth. The test below pins
 * that the known doc example is excluded, so a regression in this shows up
 * as a failure rather than as silence.
 */
function stripComments(source: string): string {
	return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/**
 * The balanced `{ … }` starting at `openBrace`. Brace counting rather than
 * "up to the next `});`", because a manifest built inside a factory function
 * closes indented, and a block that runs on into the next module would read
 * that module's declaration as this one's.
 */
function balancedBlock(source: string, openBrace: number): string {
	let depth = 0;
	for (let i = openBrace; i < source.length; i++) {
		const ch = source[i];
		if (ch === "{") depth++;
		else if (ch === "}") {
			depth--;
			if (depth === 0) return source.slice(openBrace, i + 1);
		}
	}
	return source.slice(openBrace);
}

interface ScannedModule {
	readonly name: string;
	/** Whether the manifest literal carries a `replicaSafety: { … }` field. */
	readonly declaresReplicaSafety: boolean;
	readonly file: string;
}

/** Every `defineModule({ name: "..." })` in the package sources under `dir`. */
function collectModules(dir: string): ScannedModule[] {
	const found: ScannedModule[] = [];
	const walk = (current: string): void => {
		for (const entry of readdirSync(current)) {
			if (entry === "node_modules" || entry === "dist" || entry === "__tests__") continue;
			const full = join(current, entry);
			if (statSync(full).isDirectory()) {
				walk(full);
				continue;
			}
			if (!entry.endsWith(".mts")) continue;
			const source = stripComments(readFileSync(full, "utf8"));
			for (const match of source.matchAll(/defineModule\(\{\s*\n?\s*name:\s*"([^"]+)"/g)) {
				const name = match[1];
				if (name === undefined || match.index === undefined) continue;
				const block = balancedBlock(source, match.index + "defineModule(".length);
				found.push({
					name,
					declaresReplicaSafety: /\breplicaSafety:\s*\{/.test(block),
					file: relative(repoRoot, full),
				});
			}
		}
	};
	walk(dir);
	return found;
}

describe("replica-safety declarations vs. the modules that exist (#304, #455)", () => {
	const allModules = collectModules(join(repoRoot, "packages"));
	const coreModules = collectModules(join(repoRoot, "packages", "core"));
	const moduleNames = [...new Set(allModules.map((m) => m.name))];

	it("does not count names from documentation examples", () => {
		// `define-module.mts` documents itself with a `defineModule({ name:
		// "my-module" })` example. Counting it would turn into a false failure
		// the day an example carries "memory" in its name.
		expect(moduleNames).not.toContain("my-module");
	});

	it("finds the bundled modules at all — the scan is not vacuously passing", () => {
		// A drift guard whose scan silently returns nothing is worse than no
		// guard: it reports success forever.
		expect(moduleNames.length).toBeGreaterThan(5);
		expect(moduleNames).toContain("core-rate-limiter-memory");
	});

	it("reads the declaration off the manifest literal, not off the file", () => {
		// `refresh-token-family/module.mts` holds the memory store next to two
		// modules that hold no state. A file-level scan would credit all three
		// with one declaration; the block scan must not.
		const byName = new Map(coreModules.map((m) => [m.name, m]));
		expect(byName.get("core-refresh-token-family-store-memory")?.declaresReplicaSafety).toBe(true);
		expect(byName.get("core-default-refresh-token-family-rotation")?.declaresReplicaSafety).toBe(
			false,
		);
	});

	it("every memory-backed module declares replicaSafety on its manifest", () => {
		// The claim: a new in-memory adapter cannot be added without either
		// declaring what forks per replica or exempting it out loud.
		const undeclared = allModules
			.filter((m) => /memory/i.test(m.name))
			.filter((m) => !m.declaresReplicaSafety && !Object.hasOwn(SAFE_MEMORY_MODULES, m.name))
			.map((m) => `${m.name} (${m.file})`);
		expect(undeclared).toEqual([]);
	});

	it("REPLICA_UNSAFE_MODULES names exactly the core modules that declare", () => {
		// Both directions. A stale entry means the guard's message names a
		// module an operator will not find; a missing one means a deployment
		// asserting on the exported set is told a module is safe when its own
		// manifest says otherwise.
		const declaring = [
			...new Set(coreModules.filter((m) => m.declaresReplicaSafety).map((m) => m.name)),
		].sort();
		expect([...REPLICA_UNSAFE_MODULES].sort()).toEqual(declaring);
	});

	it("answers undefined for a module it does not refuse", () => {
		// The other half of the accessor's contract, and the one a composition
		// root running its own check depends on: a safe module must not come
		// back with a reason attached.
		expect(replicaUnsafeReason({ name: "core-rate-limiter-redis" })).toBeUndefined();
		expect(replicaUnsafeReason({ name: "not-a-module-at-all" })).toBeUndefined();
		// Prototype keys are not entries — `in` on a table would have said
		// otherwise, and a manifest read must not either.
		expect(replicaUnsafeReason({ name: "toString" })).toBeUndefined();
		expect(replicaUnsafeReason({ name: "constructor" })).toBeUndefined();
	});

	it("gives every unsafe module a reason, not just a name", () => {
		// "use redis" is not by itself a reason. The guard's message quotes
		// these, and an operator triaging a refused boot deserves the
		// consequence rather than the instruction.
		expect(REPLICA_UNSAFE_BUNDLED_MODULES.length).toBe(REPLICA_UNSAFE_MODULES.length);
		for (const module of REPLICA_UNSAFE_BUNDLED_MODULES) {
			const reason = replicaUnsafeReason(module);
			expect(reason, module.name).toBeDefined();
			// Long enough to be a consequence rather than an instruction.
			expect((reason ?? "").length, module.name).toBeGreaterThan(40);
		}
	});
});
