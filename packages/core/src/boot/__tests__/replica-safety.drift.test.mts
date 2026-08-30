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
 * Issue #304 — the replica-safety list must not fall behind the modules.
 *
 * #271 shipped the guard: `deployment.mode = "multi"` with an in-process state
 * store wired refuses to boot, naming each offender and what diverges. It
 * works off `REPLICA_UNSAFE_MODULE_REASONS`, a hand-maintained map keyed by
 * module name.
 *
 * Hand-maintained is the problem #304 is about. The next in-memory adapter
 * someone adds is replica-unsafe the moment it exists and silent until someone
 * remembers this file — which is precisely "implementers reintroduce unsafe
 * defaults", one indirection out. The guard cannot protect a module it has
 * never heard of, and nothing was checking.
 *
 * So: every bundled module whose name marks it as memory-backed must be
 * accounted for here — listed as unsafe, or exempted in `SAFE_MEMORY_MODULES`
 * with a reason. Adding an adapter without doing either fails this test, which
 * is the point at which the decision is cheap.
 *
 * Scanned from source rather than from an import graph on purpose: a module
 * that is not yet wired into any bundle is exactly the one that would slip
 * through, and it is still a module someone can compose.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { REPLICA_UNSAFE_MODULES, replicaUnsafeReason } from "#/boot/replica-safety.mjs";

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

/** Every `defineModule({ name: "..." })` in the repository's package sources. */
function collectModuleNames(): string[] {
	const names: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir)) {
			if (entry === "node_modules" || entry === "dist" || entry === "__tests__") continue;
			const full = join(dir, entry);
			if (statSync(full).isDirectory()) {
				walk(full);
				continue;
			}
			if (!entry.endsWith(".mts")) continue;
			const source = readFileSync(full, "utf8");
			for (const match of source.matchAll(/defineModule\(\{\s*\n?\s*name:\s*"([^"]+)"/g)) {
				const name = match[1];
				if (name !== undefined) names.push(name);
			}
		}
	};
	walk(join(repoRoot, "packages"));
	return [...new Set(names)];
}

describe("replica-safety list vs. the modules that exist (#304)", () => {
	const moduleNames = collectModuleNames();

	it("finds the bundled modules at all — the scan is not vacuously passing", () => {
		// A drift guard whose scan silently returns nothing is worse than no
		// guard: it reports success forever.
		expect(moduleNames.length).toBeGreaterThan(5);
		expect(moduleNames).toContain("core-rate-limiter-memory");
	});

	it("accounts for every memory-backed module", () => {
		// The claim: a new in-memory adapter cannot be added without either
		// declaring it replica-unsafe or exempting it out loud.
		const memoryBacked = moduleNames.filter((n) => /memory/i.test(n));
		const unaccounted = memoryBacked.filter(
			(n) => !REPLICA_UNSAFE_MODULES.includes(n) && !Object.hasOwn(SAFE_MEMORY_MODULES, n),
		);
		expect(unaccounted).toEqual([]);
	});

	it("lists no module that no longer exists", () => {
		// The other direction: a stale entry means the guard's message names a
		// module an operator will not find, which sends them looking for the
		// wrong thing during a failed boot.
		const orphans = REPLICA_UNSAFE_MODULES.filter((n) => !moduleNames.includes(n));
		expect(orphans).toEqual([]);
	});

	it("answers undefined for a module it does not refuse", () => {
		// The other half of the accessor's contract, and the one a composition
		// root running its own check depends on: a safe module must not come
		// back with a reason attached.
		expect(replicaUnsafeReason("core-rate-limiter-redis")).toBeUndefined();
		expect(replicaUnsafeReason("not-a-module-at-all")).toBeUndefined();
		// Prototype keys are not entries — `in` would have said otherwise.
		expect(replicaUnsafeReason("toString")).toBeUndefined();
		expect(replicaUnsafeReason("constructor")).toBeUndefined();
	});

	it("gives every unsafe module a reason, not just a name", () => {
		// "use redis" is not by itself a reason. The guard's message quotes
		// these, and an operator triaging a refused boot deserves the
		// consequence rather than the instruction.
		for (const name of REPLICA_UNSAFE_MODULES) {
			const reason = replicaUnsafeReason(name);
			expect(reason).toBeDefined();
			// Long enough to be a consequence rather than an instruction: the
			// guard quotes these into a refused boot, and "use redis" tells an
			// operator what to type without telling them what breaks.
			expect((reason ?? "").length).toBeGreaterThan(40);
		}
	});
});
