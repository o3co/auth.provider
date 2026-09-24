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

// Every other contract suite this package copies from core is the same suite
// as core's (#626).
//
// A contract file cannot be imported across a package boundary, so the Redis
// package runs copies. The `UserSessionStore`, `FederationGrantStore` and
// `FederationGrantIntentStore` copies each have a parity test of their own;
// the rest had none, and a copy nothing compares drifts: it reads as the same
// contract while the Redis adapter is held to an older one. This holds the
// rest to the same rule.
//
// So the only difference allowed is above the first `export`: comments and
// imports. When a core suite changes, copy it again and re-run.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	callersOf,
	isPackageSpecifier,
	prologueDeclarations,
	prologueImports,
} from "./contract-parity.helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const core = (path: string): string => join(here, "../../core/src", path);

/** A core suite, its copy here, and the Redis tests that run the copy. */
const COPIES: ReadonlyArray<{
	core: string;
	copy: string;
	runners: ReadonlyArray<readonly [runner: string, caller: string]>;
}> = [
	{
		core: "challenges/__tests__/adapters.contract.mts",
		copy: "adapters.challenge-store.contract.mts",
		runners: [["runChallengeStoreContract", "challenges.test.mts"]],
	},
	{
		core: "consents/__tests__/adapters.contract.mts",
		copy: "adapters.consent-store.contract.mts",
		runners: [["runConsentStoreContract", "consent-store.test.mts"]],
	},
	{
		core: "consents/__tests__/pending.contract.mts",
		copy: "adapters.pending-consent-store.contract.mts",
		runners: [["runPendingConsentStoreContract", "consent-store.test.mts"]],
	},
	{
		core: "device-authorization/__tests__/adapters.contract.mts",
		copy: "adapters.device-code-store.contract.mts",
		runners: [["runDeviceCodeStoreContract", "device-code-store.test.mts"]],
	},
	{
		core: "refresh-token-family/__tests__/adapters.contract.mts",
		copy: "adapters.refresh-token-family.contract.mts",
		runners: [["runRefreshTokenFamilyStoreContract", "refresh-token-family.test.mts"]],
	},
	{
		core: "replay-seen-set/__tests__/adapters.contract.mts",
		copy: "adapters.replay-seen-set.contract.mts",
		runners: [["runReplaySeenSetContract", "replay-seen-set.test.mts"]],
	},
	{
		core: "user-sessions/__tests__/sessionFamilyIndex.contract.mts",
		copy: "sessionFamilyIndex.contract.mts",
		runners: [["runSessionFamilyIndexContract", "redis.sessionFamilyIndex.test.mts"]],
	},
	{
		core: "user-sessions/__tests__/sessionFederationIndex.contract.mts",
		copy: "sessionFederationIndex.contract.mts",
		runners: [["runSessionFederationIndexContract", "redis.sessionFederationIndex.test.mts"]],
	},
	{
		core: "user-sessions/__tests__/sessionRPRegistry.contract.mts",
		copy: "sessionRPRegistry.contract.mts",
		runners: [["runSessionRPRegistryContract", "redis.sessionRPRegistry.test.mts"]],
	},
	{
		core: "user-sessions/__tests__/subjectRevocation.contract.mts",
		copy: "subjectRevocation.contract.mts",
		runners: [
			["runSubjectRevocationContract", "redis.subjectRevocation.test.mts"],
			["runSessionsOnlyRevocationContract", "redis.subjectRevocation.test.mts"],
		],
	},
	{
		core: "user-sessions/__tests__/subjectSessionIndex.contract.mts",
		copy: "subjectSessionIndex.contract.mts",
		runners: [["runSubjectSessionIndexContract", "redis.subjectSessionIndex.test.mts"]],
	},
];

/** Copies held by a parity test of their own. */
const HELD_ELSEWHERE = [
	"userSessionStore.contract.mts",
	"adapters.federation-grant-store.contract.mts",
	"adapters.federation-grant-intent-store.contract.mts",
];

/** Suites with no core original: the Redis client's own contract. */
const REDIS_ONLY = ["adapters.refresh-token-family-client.contract.mts"];

describe("the Redis package's contract suites", () => {
	it("are each held to their core original, or have none", () => {
		// A copy added here and to no list would be checked by nothing.
		const accounted = new Set([
			...COPIES.map((pair) => pair.copy),
			...HELD_ELSEWHERE,
			...REDIS_ONLY,
		]);
		const unaccounted = readdirSync(here)
			.filter((name) => name.endsWith(".contract.mts"))
			.filter((name) => !accounted.has(name));
		expect(unaccounted).toEqual([]);
	});
});

/** Where the suite starts: its first line that begins with `export `. */
const firstExport = (text: string, path: string): number => {
	const from = text.search(/^export /m);
	expect(from, `${path}: the suite's first export`).toBeGreaterThan(0);
	return from;
};

describe.each(COPIES)("the contract suite copied from core/src/$core", (pair) => {
	const corePath = core(pair.core);
	const copyPath = join(here, pair.copy);

	it("is the same suite: from the first export on, line for line", () => {
		const coreText = readFileSync(corePath, "utf8");
		const copyText = readFileSync(copyPath, "utf8");
		const coreLines = coreText.slice(firstExport(coreText, corePath)).split("\n");
		const copyLines = copyText.slice(firstExport(copyText, copyPath)).split("\n");
		// Line by line rather than whole-file, so a failure says which line.
		for (let i = 0; i < Math.max(coreLines.length, copyLines.length); i += 1) {
			expect(
				copyLines[i],
				`line ${i + 1} of the suite body differs; copy packages/core/src/${pair.core} again`,
			).toBe(coreLines[i]);
		}
	});

	it("imports core from the package rather than from core's source", () => {
		const copyText = readFileSync(copyPath, "utf8");
		const imports = prologueImports(copyPath, firstExport(copyText, copyPath));
		expect(imports).toContain("@o3co/auth-provider-core");
		// A copy imports packages only. Core's `#/` alias does not resolve from
		// here, and any path — relative, absolute, `file:` — would reach into
		// core's source rather than what the package publishes.
		for (const specifier of imports) {
			expect(isPackageSpecifier(specifier), specifier).toBe(true);
		}
	});

	it("has nothing but comments and imports above that line, in either copy", () => {
		// A declaration there — a shadowed `it`, a rebound `expect` — would change
		// what the suite runs while the bodies still compare equal, and it may
		// share a line with an import.
		for (const path of [corePath, copyPath]) {
			const text = readFileSync(path, "utf8");
			expect(prologueDeclarations(path, firstExport(text, path)), path).toEqual([]);
		}
	});

	it("is run by something: a copy nothing calls cannot fail", () => {
		// A call in the syntax tree, so a commented-out call does not count.
		for (const [runner, caller] of pair.runners) {
			expect(callersOf(here, runner), runner).toContain(caller);
		}
	});
});
