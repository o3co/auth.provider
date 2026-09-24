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
 * designVocabulary.drift.test.mts — the design-vocabulary map, executable
 * (#370).
 *
 * `docs/design-vocabulary.md` binds each top-down design concept to the one
 * bottom-up module that implements it. This suite is the enforcement half:
 * for every mapped concept with a greppable definition signature, it walks
 * every package's shipped source and fails when the signature is *defined*
 * anywhere but the mapped home.
 *
 * Why this exists: the 38-commit campaign review (2026-08-28) found that
 * design erosion in this repo does not live in files — it lives in
 * vocabularies. `isLoopbackHostname` was defined twice under identical doc
 * comments with different behavior (#364), one commit after the decision not
 * to unify was written down. Per-PR review cannot catch a second definition
 * it never sees; a drift guard can. Same pattern as the #288 env-var drift
 * guards: the property is owned by a test, not by everyone's memory.
 *
 * Adding a row: implement the concept in ONE module, add it to
 * `docs/design-vocabulary.md`, and add its definition signature here.
 * Re-exports (`export { x } from ...`) and imports deliberately do not match
 * the definition patterns — consumers may re-export the mapped home freely.
 */

import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../../../..");

/**
 * One row of the vocabulary map. `definition` matches the *definition* form
 * only (`function x` / `const x =`), never an import or a re-export, so a
 * consumer package can re-export the home's symbol without tripping the
 * guard.
 */
interface VocabularyRow {
	readonly concept: string;
	/** Repo-relative path of the one module allowed to define it. */
	readonly home: string;
	readonly definition: RegExp;
	/**
	 * How many times `definition` may match inside the home itself. Absent,
	 * the home only has to match once; set, a second definition or literal
	 * added beside the first — in the home — fails too.
	 */
	readonly homeMatches?: number;
}

const VOCABULARY: readonly VocabularyRow[] = [
	{
		concept: "loopback hostname (#364)",
		home: "packages/core/src/net/loopback.mts",
		definition: /(?:function|const)\s+isLoopbackHostname\b/,
	},
	{
		concept: "trusted-proxy address vocabulary (#292)",
		home: "packages/core/src/net/trusted-proxy.mts",
		definition: /(?:function|const)\s+(?:checkTrustedProxyEntry|createTrustedProxyMatcher)\b/,
	},
	{
		concept: "canonical request URL (#292, #356)",
		home: "packages/core/src/net/request-url.mts",
		definition: /(?:function|const)\s+buildCanonicalRequestUrl\b/,
	},
	{
		concept: "cnf/token-binding comparison matrix (#324)",
		home: "packages/core/src/grants/confirmationMatch.mts",
		definition: /(?:function|const)\s+matchConfirmation\b/,
	},
	{
		concept: "rate-limit guard (#325)",
		home: "packages/core/src/ratelimit/guard.mts",
		definition: /(?:function|const)\s+createRateLimitGuard\b/,
	},
	{
		concept: "retired config key (#366)",
		home: "packages/core/src/config/removed-keys.mts",
		definition: /(?:function|const)\s+withRemovedKeys\b/,
	},
	{
		concept: "serialized origin, and the spelling of a list of them (#500)",
		home: "packages/core/src/net/origin.mts",
		definition: /(?:function|const)\s+(?:checkSerializedOrigin|normalizeAllowedOrigins)\b/,
	},
	{
		concept: "device-verification budget shape (#448)",
		home: "packages/core/src/ratelimit/deviceVerificationSpec.mts",
		definition: /(?:function|const)\s+isDeviceVerificationRateLimitSpec\b/,
	},
	{
		concept: "authentication claims a token may carry (#481)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+(?:wellFormedAmr|wellFormedAcr)\b/,
	},
	{
		concept: "secret entropy floor (#282)",
		home: "packages/core/src/keys/secretEntropy.mts",
		definition:
			/(?:function|const)\s+(?:measureSecretEntropyBytes|assertSecretEntropy|describeWeakSecret|MIN_SECRET(?:_ENTROPY)?_BYTES)\b/,
	},
	{
		// The call is the signature: a second `createRemoteJWKSet(` is a second
		// memo with its own tuning and its own (or no) fetch seam.
		concept: "remote JSON Web Key Set (#484, #525)",
		home: "packages/core/src/jwks/remoteKeySet.mts",
		definition: /(?:function|const)\s+createRemoteKeySetCache\b|\bcreateRemoteJWKSet\s*\(/,
	},
	{
		concept: "special-use address (#529)",
		home: "packages/core/src/net/special-use.mts",
		definition: /(?:function|const)\s+isSpecialUseAddress\b/,
	},
	{
		concept: "RFC 8707 resource indicator (#172, #173)",
		home: "packages/core/src/grants/resourceIndicator.mts",
		definition:
			/(?:function|const)\s+(?:extractResourceParam|deriveAudienceFromResources|unrepresentedResources)\b/,
	},
	{
		concept: "WebAuthn algorithm pin (#516)",
		home: "packages/webauthn/src/internal/options.mts",
		definition: /(?:function|const)\s+WEBAUTHN_ALGORITHM_IDS\b|supportedAlgorithmIDs\s*:\s*\[\s*-/,
		// The one `const`; a literal `supportedAlgorithmIDs: [-…]` beside it in
		// the home is a second statement of the pin too.
		homeMatches: 1,
	},
	{
		concept: "fail-closed grant-policy evaluation and its bounds (#441, #520)",
		home: "packages/core/src/grants/grantPolicy.mts",
		definition:
			/(?:function|const)\s+(?:evaluateGrantPolicy|boundPolicyAudience|policyOutOfBounds)\b/,
	},
];

/** Every shipped source file across the workspace: packages/*\/src\/**\/*.mts, tests excluded. */
function listShippedSources(): string[] {
	const files: string[] = [];
	const packagesDir = join(repoRoot, "packages");
	for (const pkg of readdirSync(packagesDir, { withFileTypes: true })) {
		if (!pkg.isDirectory()) continue;
		const srcDir = join(packagesDir, pkg.name, "src");
		walk(srcDir, files);
	}
	return files;
}

function walk(dir: string, out: string[]): void {
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return; // package without src/
	}
	for (const entry of entries) {
		if (entry.name === "__tests__" || entry.name === "node_modules") continue;
		const path = join(dir, entry.name);
		if (entry.isDirectory()) walk(path, out);
		else if (entry.name.endsWith(".mts")) out.push(path);
	}
}

/**
 * Shipped sources allowed to call `grantPolicy.evaluate(` other than the home,
 * each with why. A grant that consults the policy anywhere else re-implements
 * the home's fail-closed rules inline — which is how `refresh_token` carried a
 * full copy the definition-only guard above could not see (v0.13.0 audit).
 */
const POLICY_EVALUATE_EXEMPTIONS: Readonly<Record<string, { calls: number; reason: string }>> = {
	"packages/oauth/src/routes/authorize.mts": {
		calls: 1,
		reason:
			"answers on the redirect (RFC 6749 §4.1.2.1), not as a token-endpoint error; bounds the audience through the home",
	},
	"packages/oauth-token-exchange/src/grant.mts": {
		calls: 1,
		reason:
			"RFC 8693's contract: the ceiling is the subject token, a widening is `invalid_target`, and `access_denied` is 403",
	},
};

/** `grantPolicy.evaluate(` calls in `source`, comments removed so a mention is not a call. */
const policyEvaluateCalls = (source: string): number =>
	(
		source
			.replace(/\/\*[\s\S]*?\*\//g, "")
			.replace(/(^|[^:])\/\/.*$/gm, "$1")
			.match(/grantPolicy[\s\S]{0,40}?\.evaluate\s*\(/g) ?? []
	).length;

describe("design-vocabulary map (docs/design-vocabulary.md)", () => {
	it("consults the grant policy through the home, or says why not", () => {
		// An exemption is a count, not a whole file: a second inline call added
		// to an exempt file is the drift this exists to catch.
		const home = join(repoRoot, "packages/core/src/grants/grantPolicy.mts");
		const found = Object.fromEntries(
			listShippedSources()
				.filter((file) => file !== home)
				.map((file) => [relative(repoRoot, file).split(sep).join("/"), file] as const)
				.map(([rel, file]) => [rel, policyEvaluateCalls(readFileSync(file, "utf8"))] as const)
				.filter(([, calls]) => calls > 0),
		);
		const expected = Object.fromEntries(
			Object.entries(POLICY_EVALUATE_EXEMPTIONS).map(([rel, { calls }]) => [rel, calls]),
		);
		expect(found, "call evaluateGrantPolicy from core/src/grants/grantPolicy.mts").toEqual(
			expected,
		);
	});

	const sources = listShippedSources();

	it("walks a plausible workspace (sanity: the guard is not vacuous)", () => {
		expect(sources.length).toBeGreaterThan(50);
	});

	it("documents every enforced row", () => {
		const doc = readFileSync(join(repoRoot, "docs/design-vocabulary.md"), "utf8");
		for (const row of VOCABULARY) {
			// The doc names the home path, so map and guard cannot drift apart.
			expect(doc, `docs/design-vocabulary.md must name ${row.home}`).toContain(row.home);
		}
	});

	it.each(VOCABULARY.map((row) => [row.concept, row] as const))(
		"%s is defined only in its mapped home",
		(_concept, row) => {
			const home = join(repoRoot, row.home);
			const homeSource = readFileSync(home, "utf8");
			expect(
				row.definition.test(homeSource),
				`${row.home} must define the concept it is mapped as the home of`,
			).toBe(true);
			if (row.homeMatches !== undefined) {
				const flags = row.definition.flags.includes("g")
					? row.definition.flags
					: `${row.definition.flags}g`;
				expect(
					homeSource.match(new RegExp(row.definition.source, flags))?.length ?? 0,
					`${row.home} must state the concept exactly ${row.homeMatches} time(s)`,
				).toBe(row.homeMatches);
			}

			const offenders = sources
				.filter((file) => file !== home)
				.filter((file) => row.definition.test(readFileSync(file, "utf8")))
				.map((file) => relative(repoRoot, file));
			expect(
				offenders,
				`defined outside its mapped home — import (or re-export) ${row.home} instead`,
			).toEqual([]);
		},
	);
});
