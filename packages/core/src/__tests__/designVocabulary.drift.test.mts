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
	 * What the home itself must define, when that is narrower than what no
	 * other file may: a row that refuses a concept under either of two names
	 * still requires the home to keep the one it has.
	 */
	readonly homeDefinition?: RegExp;
	/**
	 * How many times `definition` may match inside the home itself. Absent,
	 * the home only has to match once; set, a second definition or literal
	 * added beside the first — in the home — fails too.
	 */
	readonly homeMatches?: number;
}

// One row per symbol, so the home has to define each of them: an
// alternation would pass a home that kept one and lost the others. Two rows
// still match one concept in two forms, and each pins the form the home must
// keep: the entropy floor's two spellings and the target-parameter reader's
// two names (with `homeDefinition`), and the WebAuthn algorithm pin's const or
// literal (with `homeMatches`).
const VOCABULARY: readonly VocabularyRow[] = [
	{
		concept: "loopback hostname (#364)",
		home: "packages/core/src/net/loopback.mts",
		definition: /(?:function|const)\s+isLoopbackHostname\b/,
	},
	{
		concept: "trusted-proxy address vocabulary — one entry (#292)",
		home: "packages/core/src/net/trusted-proxy.mts",
		definition: /(?:function|const)\s+checkTrustedProxyEntry\b/,
	},
	{
		concept: "trusted-proxy address vocabulary — the matcher (#292)",
		home: "packages/core/src/net/trusted-proxy.mts",
		definition: /(?:function|const)\s+createTrustedProxyMatcher\b/,
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
		concept: "serialized origin (#500)",
		home: "packages/core/src/net/origin.mts",
		definition: /(?:function|const)\s+checkSerializedOrigin\b/,
	},
	{
		concept: "serialized origin — the spelling of a list of them (#500)",
		home: "packages/core/src/net/origin.mts",
		definition: /(?:function|const)\s+normalizeAllowedOrigins\b/,
	},
	{
		concept: "device-verification budget shape (#448)",
		home: "packages/core/src/ratelimit/deviceVerificationSpec.mts",
		definition: /(?:function|const)\s+isDeviceVerificationRateLimitSpec\b/,
	},
	{
		concept: "usable rate-limit spec — what a limiter applies as written",
		home: "packages/core/src/ratelimit/usableSpec.mts",
		definition: /(?:function|const)\s+isUsableRateLimitSpec\b/,
	},
	{
		concept: "authentication claims a token may carry — amr (#481)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+wellFormedAmr\b/,
	},
	{
		concept: "authentication claims a token may carry — acr (#481)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+wellFormedAcr\b/,
	},
	{
		concept: "secret entropy floor — measuring a secret (#282)",
		home: "packages/core/src/keys/secretEntropy.mts",
		definition: /(?:function|const)\s+measureSecretEntropyBytes\b/,
	},
	{
		concept: "secret entropy floor — asserting it (#282)",
		home: "packages/core/src/keys/secretEntropy.mts",
		definition: /(?:function|const)\s+assertSecretEntropy\b/,
	},
	{
		concept: "secret entropy floor — describing a weak secret (#282)",
		home: "packages/core/src/keys/secretEntropy.mts",
		definition: /(?:function|const)\s+describeWeakSecret\b/,
	},
	{
		// Either spelling of the constant: the home defines the long one, and a
		// short `MIN_SECRET_BYTES` elsewhere is the same floor restated.
		concept: "secret entropy floor — the floor itself (#282)",
		home: "packages/core/src/keys/secretEntropy.mts",
		definition: /(?:function|const)\s+MIN_SECRET(?:_ENTROPY)?_BYTES\b/,
		homeDefinition: /(?:function|const)\s+MIN_SECRET_ENTROPY_BYTES\b/,
	},
	{
		concept: "remote JSON Web Key Set — the cache (#484, #525)",
		home: "packages/core/src/assertions/remoteKeySet.mts",
		definition: /(?:function|const)\s+createRemoteKeySetCache\b/,
	},
	{
		// The call is the signature: a second `createRemoteJWKSet(` is a second
		// memo with its own tuning and its own (or no) fetch seam — in the home
		// as anywhere else.
		concept: "remote JSON Web Key Set — the one jose key set it builds (#484, #525)",
		home: "packages/core/src/assertions/remoteKeySet.mts",
		definition: /\bcreateRemoteJWKSet\s*\(/,
		homeMatches: 1,
	},
	{
		concept: "special-use address (#529)",
		home: "packages/core/src/net/special-use.mts",
		definition: /(?:function|const)\s+isSpecialUseAddress\b/,
	},
	{
		concept: "RFC 8707 resource indicator — reading `resource` (#172, #173)",
		home: "packages/core/src/grants/resourceIndicator.mts",
		definition: /(?:function|const)\s+extractResourceParam\b/,
	},
	{
		concept: "RFC 8707 resource indicator — the audience derived from it (#173)",
		home: "packages/core/src/grants/resourceIndicator.mts",
		definition: /(?:function|const)\s+deriveAudienceFromResources\b/,
	},
	{
		concept: "RFC 8707 resource indicator — the invalid_target check (#173)",
		home: "packages/core/src/grants/resourceIndicator.mts",
		definition: /(?:function|const)\s+unrepresentedResources\b/,
	},
	{
		// Either name: the home defines `readTargetParameter`, and a
		// `normalizeArrayParam` elsewhere is the token-exchange grant's old
		// reader of `resource` and `audience` restated.
		concept: "target parameter — reading `resource` or `audience` strictly (RFC 8707, RFC 8693)",
		home: "packages/core/src/grants/resourceIndicator.mts",
		definition: /(?:function|const)\s+(?:readTargetParameter|normalizeArrayParam)\b/,
		homeDefinition: /(?:function|const)\s+readTargetParameter\b/,
	},
	{
		// RFC 6749 NQSCHAR, the whole class: a partial one (`\x21\x23-…`, the
		// scope-token class NQCHAR) is a different concept and must not trip it.
		concept: "RFC 6749 error text — the NQSCHAR class",
		home: "packages/core/src/errors/envelope.mts",
		definition: /\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E/i,
		homeMatches: 1,
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
		concept: "fail-closed grant-policy evaluation (#441)",
		home: "packages/core/src/grants/grantPolicy.mts",
		definition: /(?:function|const)\s+evaluateGrantPolicy\b/,
	},
	{
		concept: "fail-closed grant-policy evaluation — the audience bound (#520)",
		home: "packages/core/src/grants/grantPolicy.mts",
		definition: /(?:function|const)\s+boundPolicyAudience\b/,
	},
	{
		concept: "fail-closed grant-policy evaluation — the out-of-bounds answer (#441, #520)",
		home: "packages/core/src/grants/grantPolicy.mts",
		definition: /(?:function|const)\s+policyOutOfBounds\b/,
	},
	{
		concept: "key-ring sealing envelope — sealing (#593)",
		home: "packages/core/src/sealing/envelope.mts",
		definition: /(?:function|const)\s+sealWithKeyRing\b/,
	},
	{
		concept: "key-ring sealing envelope — opening (#593)",
		home: "packages/core/src/sealing/envelope.mts",
		definition: /(?:function|const)\s+openWithKeyRing\b/,
	},
	{
		concept: "key-ring sealing envelope — the ring rule (#593)",
		home: "packages/core/src/sealing/keyRing.mts",
		definition: /(?:function|const)\s+checkSealingKeyRing\b/,
	},
	{
		concept: "key-ring sealing envelope — a configured key (#593)",
		home: "packages/core/src/sealing/keyRing.mts",
		definition: /(?:function|const)\s+decodeSealingKey\b/,
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
			"its ceilings include the subject token's (scope: subject ∩ allowedScopes; audience: subject aud ∩ allowedAudiences ∪ {clientId}) and `access_denied` is 403; a policy scope or audience past them is `policyOutOfBounds` like the rest, the request's own audience past them RFC 8693 §2.2.2's `invalid_target`",
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
				(row.homeDefinition ?? row.definition).test(homeSource),
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
