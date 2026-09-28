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
		definition: /(?:function|const)\s+checkSessionAuthentication\b/,
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
 * Where a session's own `amr` and `authentication` may be read, whole files
 * (the MFA ADR's D9): the readers themselves, the requirement rule (whose
 * input they build), and the two bundled stores, which copy the record.
 */
const SESSION_RECORD_READERS: ReadonlySet<string> = new Set([
	"packages/core/src/user-sessions/authentication.mts",
	REQUIREMENT_RULE_HOME,
	"packages/core/src/user-sessions/memory/userSessionStore.mts",
	"packages/redis/src/userSessionStore.mts",
]);

/**
 * The other reads of a field named `amr` or `authentication` that stay, each
 * file's count exact, with why: none of them is a session record's. The
 * matcher cannot tell a session from anything else with the field, so every
 * read outside the readers is either here, counted, or a failure — a second
 * read added to a listed file is the drift this exists to catch, and an entry
 * whose reads went away fails as stale.
 */
const SESSION_RECORD_READS_ALLOWED: ReadonlyArray<{
	readonly file: string;
	readonly reads: number;
	readonly why: string;
}> = [
	{
		file: "packages/core/src/grants/authenticationClaims.mts",
		reads: 2,
		why: "composeAmr reads the verified factor's own values (verified.amr), not a session's",
	},
	{
		file: "packages/core/src/grants/idToken.mts",
		reads: 1,
		why: "generateIdToken reads its caller's option (opts.amr), which a grant fills with vouchedAmr",
	},
	{
		file: "packages/oauth/src/grants/refreshToken.mts",
		reads: 1,
		why: "the refresh grant carries the amr its presented refresh token carries (claims.amr), minted from vouchedAmr",
	},
	{
		file: "packages/oauth/src/routes/authorize.mts",
		reads: 1,
		why: "the amr of the requirement rule's input, built by requirementSession (requirementSession(session)?.amr)",
	},
	{
		file: "packages/session/src/routes/Federation.mts",
		reads: 3,
		why: "what the upstream IdP asserted on the profile (profile.amr), handed to federatedSessionAuthentication",
	},
];

/** The names a session record's reading is kept to. */
const SESSION_RECORD_FIELDS: ReadonlySet<string> = new Set(["amr", "authentication"]);

/**
 * The 1-based lines of `source` that read a field named `amr` or
 * `authentication`: a property access (`x.amr`, `x?.authentication`, on any
 * receiver — a name, a call, an awaited read), an element access by the
 * literal name (`x["amr"]`, `x?.["authentication"]`), or a destructuring
 * binding, renamed or not, a parameter's included. Read with TypeScript's
 * parser, so a comment or a string that names the field is not a read, and
 * neither is an object literal written for a store, a type or an interface
 * member. By shape, never by what the receiver is called: a consumer reads a
 * session through `sessionAuthentication` / `vouchedAmr`
 * (`core/src/user-sessions/authentication.mts`), because the record's own
 * `amr` still holds an untrusted IdP's values in a session written before the
 * upstream split.
 */
function sessionRecordReads(source: string): number[] {
	const file = ts.createSourceFile("scan.mts", source, ts.ScriptTarget.Latest, true);
	const lines: number[] = [];
	const named = (node: ts.Node | undefined): boolean =>
		node !== undefined &&
		(ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
		SESSION_RECORD_FIELDS.has(node.text);
	const visit = (node: ts.Node): void => {
		const reads =
			(ts.isPropertyAccessExpression(node) && SESSION_RECORD_FIELDS.has(node.name.text)) ||
			(ts.isElementAccessExpression(node) && named(node.argumentExpression)) ||
			(ts.isBindingElement(node) &&
				(node.propertyName !== undefined ? named(node.propertyName) : named(node.name)));
		if (reads) lines.push(file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1);
		ts.forEachChild(node, visit);
	};
	visit(file);
	return lines;
}

/**
 * The product sources the session-read guard scans: every package's shipped
 * sources and the standalone template's, `/`-separated from the root.
 */
function sessionReadScope(): string[] {
	const files = listShippedSources();
	walk(join(repoRoot, "templates", "standalone", "src"), files);
	return files.map((file) => relative(repoRoot, file).split(sep).join("/")).sort();
}

/** Each scanned file outside the readers, with the lines it reads the fields on. */
function sessionRecordReadSites(): Map<string, number[]> {
	const sites = new Map<string, number[]>();
	for (const rel of sessionReadScope()) {
		if (SESSION_RECORD_READERS.has(rel)) continue;
		const lines = sessionRecordReads(readFileSync(join(repoRoot, rel), "utf8"));
		if (lines.length > 0) sites.set(rel, lines);
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

	it("reads a session's amr and authentication only through the D9 readers", () => {
		const unexpected: string[] = [];
		for (const [file, lines] of sessionRecordReadSites()) {
			const allowed = SESSION_RECORD_READS_ALLOWED.find((entry) => entry.file === file)?.reads ?? 0;
			if (lines.length > allowed) unexpected.push(`${file}:${lines.join(",")}`);
		}
		expect(
			unexpected,
			"read a session through sessionAuthentication / vouchedAmr (core/src/user-sessions/authentication.mts)",
		).toEqual([]);
	});

	it("has no stale entry in SESSION_RECORD_READS_ALLOWED, and scans the readers, the packages and the template", () => {
		const sites = sessionRecordReadSites();
		for (const { file, reads, why } of SESSION_RECORD_READS_ALLOWED) {
			expect(sites.get(file)?.length ?? 0, `${file} — ${why}`).toBe(reads);
		}
		const scope = sessionReadScope();
		for (const reader of SESSION_RECORD_READERS) {
			expect(scope, reader).toContain(reader);
			// Not vacuous: each reader reads the fields it is allowed to.
			expect(
				sessionRecordReads(readFileSync(join(repoRoot, reader), "utf8")).length,
				reader,
			).toBeGreaterThan(0);
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
