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
import ts from "typescript";
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
		concept: "the amr a federated login records — fed (#481, the MFA ADR's D13)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+FEDERATED_AMR\b/,
	},
	{
		concept: "what a verified second factor adds to a session's amr (the MFA ADR's D14)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+composeAmr\b/,
	},
	{
		concept:
			"the requirement rule — the baseline and acr_values over one session (the MFA ADR's D16)",
		home: "packages/core/src/mfa/requirement.mts",
		definition: /(?:function|const)\s+decideMfaRequirement\b/,
	},
	{
		concept: "the acr table — oauth.authorize.acrValues as it is read (the MFA ADR's D15)",
		home: "packages/core/src/mfa/requirement.mts",
		definition: /(?:function|const)\s+readAcrTable\b/,
	},
	{
		concept: "D15's selection of an acr over what a session vouches for",
		home: "packages/core/src/mfa/requirement.mts",
		definition: /(?:function|const)\s+selectAcr\b/,
	},
	{
		concept: "the acr table less the entries nothing installed can satisfy (the MFA ADR's D15)",
		home: "packages/core/src/mfa/requirement.mts",
		definition: /(?:function|const)\s+vouchableAcrTable\b/,
	},
	{
		concept: "mfa.mode as a consumer reads it (the MFA ADR's D19)",
		home: "packages/core/src/mfa/requirement.mts",
		definition: /(?:function|const)\s+readMfaMode\b/,
	},
	{
		concept: "the amr a verified second factor adds when it adds mfa — mfa (the MFA ADR's D14)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+MFA_AMR\b/,
	},
	{
		concept: "how a session was established (the MFA ADR's D9)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+sessionAuthentication\b/,
	},
	{
		concept: "the amr this provider vouches for in a session (the MFA ADR's D9, D13)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+vouchedAmr\b/,
	},
	{
		concept: "the requirement rule's input, built through the D9 reading (the MFA ADR's D9, D16)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+requirementSession\b/,
	},
	{
		concept: "what a federated login records — the upstream split (the MFA ADR's D9, D13)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+federatedSessionAuthentication\b/,
	},
	{
		concept: "whether a federation's upstream amr counts — trustUpstreamAmr (the MFA ADR's D13)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+federationTrustsUpstreamAmr\b/,
	},
	{
		concept: "what a verified second factor makes of a session (the MFA ADR's D9)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+sessionAfterSecondFactor\b/,
	},
	{
		concept: "what a password login records (the MFA ADR's D9)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+passwordSessionAuthentication\b/,
	},
	{
		concept: "the event a second factor's record is refused for (the MFA ADR's D9, D14)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+checkSecondFactorEvent\b/,
	},
	{
		concept: "the authentication a session store may record (the MFA ADR's D9)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+recordableSessionAuthentication\b/,
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

/** The requirement rule's home: the one file that may call it without `requirementSession`. */
const REQUIREMENT_RULE_HOME = "packages/core/src/mfa/requirement.mts";

/**
 * The argument text of every call to the requirement rule — `decideMfaRequirement(`
 * or `selectAcr(` — in `source`, comments removed so a mention is not a call.
 * The arguments run to the matching `)`; a parenthesis inside a string literal
 * would miscount, and no call site passes one.
 */
const requirementRuleCalls = (source: string): string[] => {
	const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
	const calls: string[] = [];
	for (const match of code.matchAll(/\b(?:decideMfaRequirement|selectAcr)\s*\(/g)) {
		const start = (match.index ?? 0) + match[0].length;
		let depth = 1;
		let end = start;
		while (end < code.length && depth > 0) {
			if (code[end] === "(") depth++;
			else if (code[end] === ")") depth--;
			end++;
		}
		calls.push(code.slice(start, end - 1));
	}
	return calls;
};

/**
 * A call to the requirement rule that does not build its session input with
 * `requirementSession(` inside its own arguments. The rule reads a session
 * only as the D9 reading makes it (the MFA ADR's step-4 amendment): an input
 * built from the record's own `amr` would, after the upstream split, let an
 * untrusted upstream value meet an `acr`. Building it inline is what makes
 * that checkable here; a value built elsewhere and passed by name is flagged
 * too, so a reviewer sees it.
 */
const withoutRequirementSession = (source: string): string[] =>
	requirementRuleCalls(source).filter((args) => !/\brequirementSession\s*\(/.test(args));

/**
 * The files that read a session's own `amr` and `authentication` on purpose
 * (the MFA ADR's D9): the readers themselves, the requirement rule (whose
 * input they build), and the two bundled stores, which copy the record.
 * Their reads are pinned one by one in {@link SESSION_RECORD_READS_ALLOWED}
 * like any other file's; this list only holds the scan to finding them.
 */
const SESSION_RECORD_READERS: ReadonlySet<string> = new Set([
	"packages/core/src/user-sessions/authentication.mts",
	REQUIREMENT_RULE_HOME,
	"packages/core/src/user-sessions/memory/userSessionStore.mts",
	"packages/redis/src/userSessionStore.mts",
]);

/** A read of `amr` or `authentication` that stays: where, by what receiver, how many times, and why. */
interface AllowedSessionRecordRead {
	readonly file: string;
	/** The read as `sessionRecordReads` writes it: its source text, whitespace removed. */
	readonly read: string;
	readonly count: number;
	readonly why: string;
}

const READER_WHY = "the D9 reading itself: how a session was established and what it vouches for";
const RULE_WHY = "the requirement rule, over the input requirementSession built";
const MEMORY_STORE_WHY = "the memory store copying the record in and out, and the step-up write";
const REDIS_STORE_WHY =
	"the Redis store copying the record to and from its envelope, and the step-up write";

/**
 * Every read of a field named `amr` or `authentication` in the scanned
 * sources, each pinned to its file, its receiver's text and its exact count,
 * with why — the readers' own included. None outside the readers is a session
 * record's. The matcher cannot tell a session from anything else with the
 * field, so a read that is not here, a second one, or a swap of receiver
 * inside a listed file (`claims.amr` becoming `session.amr`) fails; an entry
 * whose read went away fails as stale.
 */
const SESSION_RECORD_READS_ALLOWED: ReadonlyArray<AllowedSessionRecordRead> = [
	// The D9 reading itself.
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "session.authentication",
		count: 3,
		why: READER_WHY,
	},
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "session.amr",
		count: 2,
		why: READER_WHY,
	},
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "event?.amr",
		count: 1,
		why: "checkSecondFactorEvent reads the event a step-up hands it, not a session",
	},
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "event.amr",
		count: 1,
		why: "sessionAfterSecondFactor adds the event's values onto what the session vouches for",
	},
	// The requirement rule.
	{ file: REQUIREMENT_RULE_HOME, read: "session?.authentication", count: 1, why: RULE_WHY },
	{ file: REQUIREMENT_RULE_HOME, read: "session.authentication", count: 1, why: RULE_WHY },
	{ file: REQUIREMENT_RULE_HOME, read: "session?.amr", count: 1, why: RULE_WHY },
	// The memory store.
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "s.amr",
		count: 3,
		why: MEMORY_STORE_WHY,
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "s.authentication",
		count: 3,
		why: MEMORY_STORE_WHY,
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "input.authentication",
		count: 1,
		why: MEMORY_STORE_WHY,
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "input.amr",
		count: 2,
		why: MEMORY_STORE_WHY,
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "next.amr",
		count: 1,
		why: MEMORY_STORE_WHY,
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "next.authentication",
		count: 1,
		why: MEMORY_STORE_WHY,
	},
	// The Redis store.
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "e.amr",
		count: 4,
		why: REDIS_STORE_WHY,
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "e.authentication",
		count: 3,
		why: REDIS_STORE_WHY,
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "input.amr",
		count: 2,
		why: REDIS_STORE_WHY,
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "input.authentication",
		count: 3,
		why: REDIS_STORE_WHY,
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "next.amr",
		count: 1,
		why: REDIS_STORE_WHY,
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "stored.authentication",
		count: 1,
		why: "the step-up write keeping what a newer release added inside authentication",
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "next.authentication",
		count: 1,
		why: REDIS_STORE_WHY,
	},
	// Reads of a field of that name that is not a session's.
	{
		file: "packages/core/src/grants/authenticationClaims.mts",
		read: "verified.amr",
		count: 2,
		why: "composeAmr reads the verified factor's own values, not a session's",
	},
	{
		file: "packages/core/src/grants/idToken.mts",
		read: "opts.amr",
		count: 1,
		why: "generateIdToken reads its caller's option, which a grant fills with vouchedAmr",
	},
	{
		file: "packages/oauth/src/grants/refreshToken.mts",
		read: "claims.amr",
		count: 1,
		why: "the refresh grant carries the amr its presented refresh token carries, minted from vouchedAmr",
	},
	{
		file: "packages/oauth/src/grants/refreshToken.mts",
		read: "...authenticationClaims",
		count: 2,
		why: "the amr and acr the presented refresh token carries, read above as claims.amr and wellFormedAcr",
	},
	{
		file: "packages/oauth/src/routes/authorize.mts",
		read: "requirementSession(session)?.amr",
		count: 1,
		why: "the amr of the requirement rule's input, built by requirementSession",
	},
	{
		file: "packages/session/src/routes/Federation.mts",
		read: "profile.amr",
		count: 3,
		why: "what the upstream IdP asserted on the profile, handed to federatedSessionAuthentication",
	},
	{
		file: "packages/session/src/routes/Federation.mts",
		read: "...federatedSessionAuthentication()",
		count: 1,
		why: "the amr and authentication core composes for a federated login, spread into create",
	},
	{
		file: "packages/session/src/routes/Session.mts",
		read: "...passwordSessionAuthentication()",
		count: 1,
		why: "the amr and authentication core composes for a password login, spread into create",
	},
	{
		file: "packages/session/src/modules/sessionStoreModule.mts",
		read: "...((storageSlice[storageSlice.type]??{})asRecord<string,unknown>)",
		count: 1,
		why: "a cookie-session store factory's create, handed its storage settings: no session record",
	},
	{
		file: "templates/standalone/src/modules.mts",
		read: "...slice",
		count: 1,
		why: "an adapter factory's create, handed its configuration slice: no session record",
	},
	// The declarations a pinned spread, or a local handed whole to what takes
	// an amr, is followed to.
	{
		file: "packages/core/src/grants/token.mts",
		read: "...(dataasRecord<string,unknown>)",
		count: 1,
		why: "generateToken's own payload, spread into the claims the signer takes: what each caller passes, which is checked at every call",
	},
	{
		file: "packages/core/src/grants/idToken.mts",
		read: "...filterClaimsByScope()",
		count: 1,
		why: "the user's claims filtered to the granted scopes: filterClaimsByScope keeps name, picture, email, email_verified and groups, never amr",
	},
	{
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "nowMs=Date.now()",
		count: 1,
		why: "the store's clock, a number, handed to sessionAfterSecondFactor",
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "nowMs=Date.now()",
		count: 1,
		why: "the store's clock, a number, handed to sessionAfterSecondFactor",
	},
	{
		file: "packages/oauth/src/routes/authorize.mts",
		read: "table=ctx.opts.oauth.acrValues",
		count: 1,
		why: "the configured acr table, handed to selectAcr: configuration, not a session",
	},
	{
		file: "packages/session/src/modules/sessionStoreModule.mts",
		read: "storageSlice=config.session.storageas{type:string}&Record<string,unknown>",
		count: 1,
		why: "the cookie-session storage settings, the base of a pinned spread into a store factory's create",
	},
	{
		file: "templates/standalone/src/modules.mts",
		read: "slice=flattenAdapterConfig((configasAppConfig).repositories.clientas{type:string}&Record<string,unknown>)",
		count: 1,
		why: "the client repository's adapter settings, handed whole to its factory's create",
	},
	{
		file: "templates/standalone/src/modules.mts",
		read: "slice=flattenAdapterConfig((configasAppConfig).repositories.codeas{type:string}&Record<string,unknown>)",
		count: 1,
		why: "the code repository's adapter settings, the base of a pinned spread into its factory's create",
	},
];

/** The names a session record's reading is kept to. */
const SESSION_RECORD_FIELDS: ReadonlySet<string> = new Set(["amr", "authentication"]);

/**
 * The functions that take an `amr` — as an option, an argument or a token
 * claim — matched by the name they are called by: a token minter
 * (`generateToken`, whose payload is the token's claims, the id_token's
 * `generateIdToken`, and the key store's `sign`, which takes the claims
 * both build — see {@link CLAIMS_ONLY_TAKERS}), the amr composer, a store's `create` and the step-up
 * (`recordSecondFactor`, `sessionAfterSecondFactor`, `checkSecondFactorEvent`),
 * the coordinator's primary (`decideAfterPrimary`, `openLoginTransaction`) and
 * the requirement rule (`decideMfaRequirement`, `selectAcr`). A spread into an
 * object handed to one of them copies a record's own `amr` without naming it.
 * `create` is also other factories' name: their spreads are pinned like reads.
 */
const AMR_TAKERS: ReadonlySet<string> = new Set([
	"sign",
	"generateToken",
	"generateIdToken",
	"composeAmr",
	"create",
	"recordSecondFactor",
	"sessionAfterSecondFactor",
	"checkSecondFactorEvent",
	"decideAfterPrimary",
	"openLoginTransaction",
	"decideMfaRequirement",
	"selectAcr",
]);

/**
 * The takers whose `amr` rides inside a property of an object argument —
 * the key store's `sign({ claims })` — rather than in the argument itself.
 * Their object arguments are checked, and the locals named in them followed;
 * a local handed whole is not, because `sign` is also the name of every
 * key-taking signer (jose's, `node:crypto`'s).
 */
const CLAIMS_ONLY_TAKERS: ReadonlySet<string> = new Set(["sign"]);

/** Whether `name` is a source file the session-read guard scans: any TypeScript or JavaScript source, no declaration file, no test. */
function isSessionReadSource(name: string): boolean {
	return (
		/\.(?:ts|mts|cts|js|mjs|cjs)$/.test(name) &&
		!/\.d\.(?:ts|mts|cts)$/.test(name) &&
		!/\.test\.(?:ts|mts|cts|js|mjs|cjs)$/.test(name)
	);
}

/** A read `sessionRecordReads` found: its 1-based line, and its text. */
interface SessionRecordRead {
	readonly line: number;
	readonly read: string;
}

/**
 * The reads of a field named `amr` or `authentication` in `source`, each with
 * its line and its text (whitespace removed, so formatting does not move it):
 *
 * - a property access on any receiver (`x.amr`, `x?.authentication`, a call's
 *   or an awaited read's), written as the access;
 * - an element access by the literal name (`x["amr"]`, `` x?.[`amr`] ``), and
 *   `Reflect.get(x, "amr")`, written as the expression;
 * - a destructuring — by declaration, by parameter, or by assignment
 *   (`({ amr } = s)`, `for ({ amr } of …)`) — renamed or not, the key a
 *   literal or a computed literal (`{ ["amr"]: a }`), written as
 *   `{key}=source`;
 * - a spread into an object handed to a function that takes an `amr`
 *   ({@link AMR_TAKERS}), unless it spreads only literals or a choice
 *   between them, written as `...` and what is spread (a call as its callee).
 *
 * A spread of a local, and a local handed whole to such a function, is
 * followed to the declaration the language resolves it to, in the same file:
 * a spread of anything but literals in its initializer is reported (and
 * followed in turn), and — for a local used whole — so is an initializer that
 * is not an object literal (`o=initializer`), so re-initialising a pinned
 * local from a session fails. The key store's `sign` is checked through its
 * object argument and the locals named in it (`sign({ claims })`).
 *
 * Read with TypeScript's parser, so a comment or a string that names the
 * field is not a read, and neither is an object literal written for a store,
 * a type or an interface member. By shape, never by what the receiver is
 * called.
 *
 * What it does not follow is left to review, and to a branded type for a
 * vouched `amr` planned for a later change: a local it cannot resolve here (a
 * parameter, a loop variable, an import, a value built in another function
 * or file); a callee reached under another name (an alias, a method taken
 * off its object); a copy that is not a spread (`Object.assign`,
 * `structuredClone`); a cast that relabels a record; and reflection with a
 * key that is not a literal. A consumer reads a session through
 * `sessionAuthentication` / `vouchedAmr`
 * (`core/src/user-sessions/authentication.mts`), because the record's own
 * `amr` still holds an untrusted IdP's values in a session written before the
 * upstream split.
 */
function sessionRecordReads(source: string, fileName = "scan.mts"): SessionRecordRead[] {
	const kind = /\.(?:js|mjs|cjs)$/.test(fileName) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
	const reads: SessionRecordRead[] = [];
	// Whitespace and a trailing comma are formatting: neither moves a pin.
	const text = (node: ts.Node): string =>
		node
			.getText(file)
			.replace(/\s+/g, "")
			.replace(/,(?=[)\]}])/g, "");
	const found = (node: ts.Node, read: string): void => {
		reads.push({ line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, read });
	};
	const literalName = (node: ts.Node | undefined): string | undefined => {
		if (node === undefined) return undefined;
		if (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) return node.text;
		if (ts.isComputedPropertyName(node) && ts.isStringLiteralLike(node.expression)) {
			return node.expression.text;
		}
		return undefined;
	};
	const named = (node: ts.Node | undefined): boolean => {
		const name = literalName(node);
		return name !== undefined && SESSION_RECORD_FIELDS.has(name);
	};
	/** What a destructuring reads from: a declaration's initializer, a loop's list, or a parameter. */
	const destructuredFrom = (node: ts.Node): string => {
		for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
			if (ts.isVariableDeclaration(current)) {
				if (current.initializer) return text(current.initializer);
				const loop = current.parent?.parent;
				if (loop && (ts.isForOfStatement(loop) || ts.isForInStatement(loop))) {
					return text(loop.expression);
				}
				return "(declaration)";
			}
			if (ts.isParameter(current)) return "(parameter)";
		}
		return "(pattern)";
	};
	/** The assignment an object or array literal is the target of, if it is one. */
	const assignedFrom = (node: ts.Node): string | undefined => {
		let current: ts.Node = node;
		for (;;) {
			const parent: ts.Node | undefined = current.parent;
			if (parent === undefined) return undefined;
			if (ts.isParenthesizedExpression(parent) || ts.isArrayLiteralExpression(parent)) {
				current = parent;
				continue;
			}
			if (ts.isSpreadElement(parent) || ts.isSpreadAssignment(parent)) {
				current = parent.parent;
				continue;
			}
			if (
				ts.isPropertyAssignment(parent) &&
				parent.initializer === current &&
				ts.isObjectLiteralExpression(parent.parent)
			) {
				current = parent.parent;
				continue;
			}
			if (
				ts.isBinaryExpression(parent) &&
				parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
				parent.left === current
			) {
				// A default inside a pattern (`{ x: { amr } = {} } = s`) is one too.
				const outer = parent.parent;
				if (outer && ts.isPropertyAssignment(outer) && outer.initializer === parent) {
					current = outer.parent;
					continue;
				}
				return text(parent.right);
			}
			if (
				(ts.isForOfStatement(parent) || ts.isForInStatement(parent)) &&
				parent.initializer === current
			) {
				return text(parent.expression);
			}
			return undefined;
		}
	};
	/** Whether a spread's operand holds only literals: an object literal, or a choice between them. */
	const literalOnly = (node: ts.Expression): boolean => {
		if (ts.isParenthesizedExpression(node)) return literalOnly(node.expression);
		if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node))
			return literalOnly(node.expression);
		if (ts.isObjectLiteralExpression(node)) {
			return node.properties.every((p) => !ts.isSpreadAssignment(p) || literalOnly(p.expression));
		}
		if (ts.isConditionalExpression(node))
			return literalOnly(node.whenTrue) && literalOnly(node.whenFalse);
		if (ts.isBinaryExpression(node)) {
			const op = node.operatorToken.kind;
			if (op === ts.SyntaxKind.AmpersandAmpersandToken) return literalOnly(node.right);
			if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
				return literalOnly(node.left) && literalOnly(node.right);
			}
		}
		return false;
	};
	const calleeName = (node: ts.Expression): string | undefined =>
		ts.isIdentifier(node)
			? node.text
			: ts.isPropertyAccessExpression(node)
				? node.name.text
				: undefined;
	/** An expression with its parentheses, type assertions and non-null assertions taken off. */
	const bare = (node: ts.Expression): ts.Expression =>
		ts.isParenthesizedExpression(node) ||
		ts.isAsExpression(node) ||
		ts.isSatisfiesExpression(node) ||
		ts.isTypeAssertionExpression(node) ||
		ts.isNonNullExpression(node)
			? bare(node.expression)
			: node;
	/**
	 * The locals an expression's value comes from: an identifier, the base of
	 * a property or element access, either side of `??` / `||`, the right of
	 * `&&`, either branch of a choice. A call, a literal or anything else is
	 * none.
	 */
	const rootsOf = (node: ts.Expression): string[] => {
		const expression = bare(node);
		if (ts.isIdentifier(expression)) return [expression.text];
		if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
			return rootsOf(expression.expression);
		}
		if (ts.isConditionalExpression(expression)) {
			return [...rootsOf(expression.whenTrue), ...rootsOf(expression.whenFalse)];
		}
		if (ts.isBinaryExpression(expression)) {
			const op = expression.operatorToken.kind;
			if (op === ts.SyntaxKind.AmpersandAmpersandToken) return rootsOf(expression.right);
			if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
				return [...rootsOf(expression.left), ...rootsOf(expression.right)];
			}
		}
		return [];
	};
	/** The declaration of `name` among `statements`, if one of them declares it. */
	const declaredIn = (
		statements: ts.NodeArray<ts.Statement>,
		name: string,
	): ts.VariableDeclaration | undefined => {
		for (const statement of statements) {
			if (!ts.isVariableStatement(statement)) continue;
			for (const declaration of statement.declarationList.declarations) {
				if (ts.isIdentifier(declaration.name) && declaration.name.text === name) return declaration;
			}
		}
		return undefined;
	};
	/**
	 * The initializer of the declaration `name` means at `from`, found as the
	 * language finds it: the nearest enclosing block, loop head or function
	 * that declares it. `undefined` for a parameter, a loop variable, an
	 * import or a name declared nowhere in the file.
	 */
	const resolve = (name: string, from: ts.Node): ts.Expression | undefined => {
		for (let scope = from.parent; scope !== undefined; scope = scope.parent) {
			if (
				ts.isBlock(scope) ||
				ts.isSourceFile(scope) ||
				ts.isModuleBlock(scope) ||
				ts.isCaseClause(scope) ||
				ts.isDefaultClause(scope)
			) {
				const declaration = declaredIn(scope.statements, name);
				if (declaration !== undefined) return declaration.initializer;
			}
			if (
				(ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) &&
				scope.initializer !== undefined &&
				ts.isVariableDeclarationList(scope.initializer) &&
				scope.initializer.declarations.some(
					(declaration) => ts.isIdentifier(declaration.name) && declaration.name.text === name,
				)
			) {
				return undefined;
			}
			if (
				ts.isFunctionLike(scope) &&
				scope.parameters.some(
					(parameter) => ts.isIdentifier(parameter.name) && parameter.name.text === name,
				)
			) {
				return undefined;
			}
		}
		return undefined;
	};
	/** The spreads already reported, so one reached twice is counted once. */
	const reported = new Set<ts.Node>();
	/** The declarations already followed, as a whole value or for their spreads. */
	const followed = new Set<string>();
	/**
	 * Follow a local to its declarations in this file. Its initializer is held
	 * to the rule a taker's argument is: a spread of anything but literals is
	 * reported (and followed in turn). When the local is used whole — spread,
	 * or handed to a taker as an argument — an initializer that is not an
	 * object literal (the session itself, a store's read) is reported too, as
	 * `name=initializer`. A parameter, a loop variable or an import has no
	 * initializer here, and is left to review.
	 */
	const follow = (name: string, whole: boolean, from: ts.Node): void => {
		const initializer = resolve(name, from);
		if (initializer === undefined) return;
		const key = `${initializer.pos}:${whole}`;
		if (followed.has(key)) return;
		followed.add(key);
		const value = bare(initializer);
		if (ts.isObjectLiteralExpression(value) || ts.isConditionalExpression(value)) {
			spreadsInto(value, false);
		} else if (whole) {
			found(initializer, `${name}=${text(initializer)}`);
		}
	};
	/**
	 * Report each spread of anything but literals in an object handed to a
	 * taker, and follow its locals. With `properties`, a local named as a
	 * property's value (`sign({ claims })`) is followed for its spreads too.
	 */
	const spreadsInto = (node: ts.Expression, properties: boolean): void => {
		const expression = bare(node);
		if (ts.isConditionalExpression(expression)) {
			spreadsInto(expression.whenTrue, properties);
			spreadsInto(expression.whenFalse, properties);
			return;
		}
		if (!ts.isObjectLiteralExpression(expression)) return;
		for (const property of expression.properties) {
			if (ts.isPropertyAssignment(property)) {
				spreadsInto(property.initializer, properties);
				const value = bare(property.initializer);
				if (properties && ts.isIdentifier(value)) follow(value.text, false, property);
			} else if (ts.isShorthandPropertyAssignment(property)) {
				if (properties) follow(property.name.text, false, property);
			} else if (ts.isSpreadAssignment(property) && !literalOnly(property.expression)) {
				const spread = bare(property.expression);
				if (!reported.has(property)) {
					reported.add(property);
					found(
						property,
						`...${ts.isCallExpression(spread) ? `${text(spread.expression)}()` : text(property.expression)}`,
					);
				}
				for (const root of rootsOf(property.expression)) follow(root, true, property);
			}
		}
	};
	const visit = (node: ts.Node): void => {
		if (ts.isPropertyAccessExpression(node) && SESSION_RECORD_FIELDS.has(node.name.text)) {
			found(node, text(node));
		} else if (ts.isElementAccessExpression(node) && named(node.argumentExpression)) {
			found(node, text(node));
		} else if (
			ts.isBindingElement(node) &&
			(node.propertyName !== undefined ? named(node.propertyName) : named(node.name))
		) {
			found(node, `{${text(node)}}=${destructuredFrom(node)}`);
		} else if (ts.isObjectLiteralExpression(node)) {
			const from = assignedFrom(node);
			if (from !== undefined) {
				for (const property of node.properties) {
					if (
						(ts.isShorthandPropertyAssignment(property) || ts.isPropertyAssignment(property)) &&
						named(property.name)
					) {
						found(property, `{${text(property)}}=${from}`);
					}
				}
			}
		} else if (ts.isCallExpression(node)) {
			const callee = node.expression;
			if (
				ts.isPropertyAccessExpression(callee) &&
				ts.isIdentifier(callee.expression) &&
				callee.expression.text === "Reflect" &&
				callee.name.text === "get" &&
				named(node.arguments[1])
			) {
				found(node, text(node));
			}
			const name = calleeName(callee);
			if (name !== undefined && AMR_TAKERS.has(name)) {
				for (const argument of node.arguments) {
					spreadsInto(argument, true);
					// A local handed whole: `generateIdToken(options)`. Not for the
					// signer, whose amr rides inside its `claims`, and whose name
					// other libraries' key-taking `sign(key)` share.
					const value = bare(argument);
					if (ts.isIdentifier(value) && !CLAIMS_ONLY_TAKERS.has(name)) {
						follow(value.text, true, argument);
					}
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return reads;
}

/**
 * The reads in `file` that `allowed` does not cover: each one not listed for
 * that file under its text, or beyond the count listed. One line per text,
 * naming the lines.
 */
function readsBeyondAllowance(
	file: string,
	reads: readonly SessionRecordRead[],
	allowed: ReadonlyArray<Pick<AllowedSessionRecordRead, "file" | "read" | "count">>,
): string[] {
	const byRead = new Map<string, number[]>();
	for (const { line, read } of reads) byRead.set(read, [...(byRead.get(read) ?? []), line]);
	const beyond: string[] = [];
	for (const [read, lines] of byRead) {
		const count = allowed.find((entry) => entry.file === file && entry.read === read)?.count ?? 0;
		if (lines.length > count)
			beyond.push(`${file}:${lines.join(",")} ${read} ×${lines.length} (allowed ${count})`);
	}
	return beyond;
}

/**
 * The product sources the session-read guard scans, `/`-separated from the
 * root: every TypeScript and JavaScript source of every package's `src` and
 * of the standalone template's, no declaration file and no test.
 */
function sessionReadScope(): string[] {
	const files: string[] = [];
	const collect = (dir: string): void => {
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
			if (entry.isDirectory()) collect(path);
			else if (isSessionReadSource(entry.name))
				files.push(relative(repoRoot, path).split(sep).join("/"));
		}
	};
	for (const pkg of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
		if (pkg.isDirectory()) collect(join(repoRoot, "packages", pkg.name, "src"));
	}
	collect(join(repoRoot, "templates", "standalone", "src"));
	return files.sort();
}

/** Each scanned file with the reads it makes. */
function sessionRecordReadSites(): Map<string, SessionRecordRead[]> {
	const sites = new Map<string, SessionRecordRead[]>();
	for (const rel of sessionReadScope()) {
		const reads = sessionRecordReads(readFileSync(join(repoRoot, rel), "utf8"), rel);
		if (reads.length > 0) sites.set(rel, reads);
	}
	return sites;
}

describe("design-vocabulary map (docs/design-vocabulary.md)", () => {
	it("flags a session's amr or authentication read off the record whatever the session is named, and by every shape", () => {
		// Each of these reads the record's own field, which in a session written
		// before the upstream split still holds an untrusted IdP's values.
		for (const read of [
			"const a = wellFormedAmr(record.amr);",
			'if (durable?.amr?.includes("hwk")) grant();',
			"const a = (await store.get(sid))?.amr;",
			"const a = live.amr;",
			'const a = userSession["amr"];',
			'const a = userSession?.["authentication"];',
			"const { amr } = userSession;",
			"const { amr: recorded } = tracked;",
			"const { authentication } = s;",
			"const stamp = ({ amr }: UserSession) => amr;",
			"const mfaAt = row.authentication?.mfaAt;",
		]) {
			expect(sessionRecordReads(read), read).toHaveLength(1);
		}
		// Naming the field is not reading it: a comment, a string, an object
		// literal written for a store, a type, and what the readers answer.
		for (const notARead of [
			"// wellFormedAmr(record.amr) — a comment",
			"/* durable?.amr */",
			'const message = "session.amr is not read here";',
			"const input = { sid, amr, authentication };",
			'const input = { sid, amr: ["pwd"], authentication: undefined };',
			'type A = UserSession["amr"];',
			"interface R { readonly amr: readonly string[] | undefined }",
			"const a = wellFormedAmr(vouchedAmr(record));",
		]) {
			expect(sessionRecordReads(notARead), notARead).toHaveLength(0);
		}
	});

	it("flags the shapes a read can also take: an assignment destructuring, a computed literal key, Reflect.get", () => {
		for (const read of [
			"({ amr } = s);",
			"({ amr: recorded } = s);",
			"[{ authentication }] = list;",
			"for ({ amr } of sessions) {}",
			'const { ["amr"]: a } = s;',
			'({ ["authentication"]: a } = s);',
			'const a = Reflect.get(s, "amr");',
			"const a = Reflect.get(s, `authentication`);",
		]) {
			expect(sessionRecordReads(read), read).toHaveLength(1);
		}
		for (const notARead of [
			'const input = { ["amr"]: value };',
			"x = { amr };",
			'const a = Reflect.get(s, "sub");',
		]) {
			expect(sessionRecordReads(notARead), notARead).toHaveLength(0);
		}
	});

	it("flags a spread into an object handed to a function that takes an amr, unless it spreads only literals", () => {
		// `{ ...session }` handed to a token minter, a store's create or the
		// amr composer copies the record's own amr without naming it.
		for (const spread of [
			"generateToken({ ...session }, options);",
			"generateIdToken({ ...claims, sub });",
			"await store.create({ ...previous, sid });",
			"composeAmr(held, { ...factor });",
			"generateToken({ family_id, ...extra.payload }, options);",
			"await sessions.recordSecondFactor(sid, { ...event });",
			"generateToken({ ...(tracked as object) } as never, options);",
			"generateIdToken(<GenerateIdTokenOptions>{ ...claims });",
		]) {
			expect(sessionRecordReads(spread), spread).toHaveLength(1);
		}
		for (const notASpread of [
			"generateToken({ ...(amr ? { amr } : {}) }, options);",
			"generateToken({ ...(sid && { sid }) }, options);",
			"generateIdToken({ ...{ sub } });",
			"unrelated({ ...session });",
		]) {
			expect(sessionRecordReads(notASpread), notASpread).toHaveLength(0);
		}
	});

	it("counts the key store's signer among what takes an amr: a token's claims reach it whole", () => {
		for (const spread of [
			"await keyStore.sign({ claims: { ...session } });",
			"const claims = { iat, ...session }; await keyStore.sign({ claims });",
		]) {
			expect(sessionRecordReads(spread), spread).toHaveLength(1);
		}
		expect(
			sessionRecordReads(
				"const claims = { iat, ...(amr ? { amr } : {}) }; await keyStore.sign({ claims, ...(typ ? { header: { typ } } : {}) });",
			),
		).toHaveLength(0);
	});

	it("follows a pinned spread to its declaration: what it is initialised from is held to the same rule", () => {
		const allowed = [{ file: "f.mts", read: "...extra", count: 1, why: "a test's" }];
		const beyond = (source: string) =>
			readsBeyondAllowance("f.mts", sessionRecordReads(source), allowed);
		expect(
			beyond("const extra = { ...(amr ? { amr } : {}) }; generateToken({ sub, ...extra }, o);"),
		).toEqual([]);
		// Re-initialised from a session, the pinned spread carries its amr.
		for (const source of [
			"const extra = { ...userSession }; generateToken({ sub, ...extra }, o);",
			"const extra = userSession; generateToken({ sub, ...extra }, o);",
			"const extra = await store.get(sid); generateToken({ sub, ...extra }, o);",
		]) {
			expect(beyond(source), source).toHaveLength(1);
		}
	});

	it("follows a local handed whole to what takes an amr to its declaration", () => {
		for (const source of [
			"const o = { ...userSession, aud }; generateIdToken(o);",
			"const o = userSession; generateIdToken(o);",
		]) {
			expect(sessionRecordReads(source), source).toHaveLength(1);
		}
		expect(sessionRecordReads("const o = { sub, aud }; generateIdToken(o);")).toHaveLength(0);
	});

	it("looks through a call that is not a taker to the object it is handed: formatObject({ … }) is checked like the literal", () => {
		for (const source of [
			"generateToken(formatObject({ family_id, ...liveSession }), o);",
			"generateToken(formatObject(merge({ ...liveSession })), o);",
			"const payload = { ...liveSession }; generateToken(formatObject(payload), o);",
		]) {
			expect(sessionRecordReads(source), source).toHaveLength(1);
		}
		expect(
			sessionRecordReads(
				"generateToken(formatObject({ family_id, ...(sid ? { sid } : {}), act: buildActClaim(actor) }), o);",
			),
		).toHaveLength(0);
	});

	it("follows a local handed whole to the signer for its spreads, and leaves a key handed to another library's sign alone", () => {
		expect(
			sessionRecordReads("const req = { claims: { ...session } }; await keyStore.sign(req);"),
		).toHaveLength(1);
		for (const source of [
			"const key = await importPKCS8(pem, alg); await new SignJWT(payload).sign(key);",
			"const key = createSecretKey(secret); crypto.sign(null, data, key);",
		]) {
			expect(sessionRecordReads(source), source).toHaveLength(0);
		}
	});

	it("pins an allowed read to its file, its receiver and its count: a swap or a second one fails", () => {
		const allowed = [{ file: "f.mts", read: "claims.amr", count: 1, why: "a test's" }];
		expect(
			readsBeyondAllowance("f.mts", sessionRecordReads("const a = claims.amr;"), allowed),
		).toEqual([]);
		for (const [file, source] of [
			["f.mts", "const a = session.amr;"],
			["f.mts", "const a = claims.amr; const b = claims.amr;"],
			["g.mts", "const a = claims.amr;"],
		] as const) {
			expect(readsBeyondAllowance(file, sessionRecordReads(source), allowed), source).toHaveLength(
				1,
			);
		}
	});

	it("scans every TypeScript and JavaScript source extension, and no declaration file or test", () => {
		for (const name of ["a.ts", "a.mts", "a.cts", "a.js", "a.mjs", "a.cjs"]) {
			expect(isSessionReadSource(name), name).toBe(true);
		}
		for (const name of [
			"a.d.ts",
			"a.d.mts",
			"a.d.cts",
			"a.test.mts",
			"a.test.ts",
			"a.json",
			"a.md",
		]) {
			expect(isSessionReadSource(name), name).toBe(false);
		}
		expect(sessionRecordReads("const a = record.amr;", "x.cjs")).toHaveLength(1);
	});

	it("reads a session's amr and authentication only through the D9 readers, each read pinned to its receiver", () => {
		const beyond = [...sessionRecordReadSites()].flatMap(([file, reads]) =>
			readsBeyondAllowance(file, reads, SESSION_RECORD_READS_ALLOWED),
		);
		expect(
			beyond,
			"read a session through sessionAuthentication / vouchedAmr (core/src/user-sessions/authentication.mts)",
		).toEqual([]);
	});

	it("has no stale entry in SESSION_RECORD_READS_ALLOWED, and scans the readers, the packages and the template", () => {
		const sites = sessionRecordReadSites();
		for (const { file, read, count, why } of SESSION_RECORD_READS_ALLOWED) {
			expect(
				sites.get(file)?.filter((found) => found.read === read).length ?? 0,
				`${file} ${read} — ${why}`,
			).toBe(count);
		}
		const scope = sessionReadScope();
		for (const reader of SESSION_RECORD_READERS) {
			expect(scope, reader).toContain(reader);
			// Not vacuous: each reader's reads are found, and pinned.
			expect(sites.get(reader)?.length ?? 0, reader).toBeGreaterThan(0);
			expect(
				SESSION_RECORD_READS_ALLOWED.some((entry) => entry.file === reader),
				reader,
			).toBe(true);
		}
		expect(scope).toContain("templates/standalone/src/buildModules.mts");
		expect(scope.filter((file) => /(^|\/)__tests__\//.test(file))).toEqual([]);
	});

	it("reads the requirement rule's calls, and flags one whose session input bypasses requirementSession", () => {
		const sample = [
			"// selectAcr(requested, session.amr, table, reach) — a comment, not a call",
			"const a = selectAcr(requested, requirementSession(session)?.amr ?? [], table, reach);",
			"const b = selectAcr(requested, session?.amr ?? [], table, stepUpReach(undefined));",
			"const c = decideMfaRequirement({ session: requirementSession(s), acrValues, mode, table, secondFactorMethods });",
			"const d = decideMfaRequirement({ session: { authentication: undefined, amr: s.amr }, acrValues, mode, table, secondFactorMethods });",
		].join("\n");
		expect(requirementRuleCalls(sample)).toHaveLength(4);
		expect(withoutRequirementSession(sample)).toEqual([
			"requested, session?.amr ?? [], table, stepUpReach(undefined)",
			"{ session: { authentication: undefined, amr: s.amr }, acrValues, mode, table, secondFactorMethods }",
		]);
	});

	it("builds the requirement rule's session input with requirementSession at every call site", () => {
		// Outside the rule's own file (where decideMfaRequirement calls
		// selectAcr on an input already built) and tests.
		const home = join(repoRoot, REQUIREMENT_RULE_HOME);
		const calls = listShippedSources()
			.filter((file) => file !== home)
			.map(
				(file) =>
					[relative(repoRoot, file).split(sep).join("/"), readFileSync(file, "utf8")] as const,
			)
			.filter(([, source]) => requirementRuleCalls(source).length > 0);
		// Not vacuous: /authorize selects its acr through the rule.
		expect(calls.map(([rel]) => rel)).toContain("packages/oauth/src/routes/authorize.mts");
		const offenders = Object.fromEntries(
			calls
				.map(([rel, source]) => [rel, withoutRequirementSession(source)] as const)
				.filter(([, bad]) => bad.length > 0),
		);
		expect(
			offenders,
			"build the requirement rule's input with requirementSession(session) (core/src/user-sessions/authentication.mts)",
		).toEqual({});
	});

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
