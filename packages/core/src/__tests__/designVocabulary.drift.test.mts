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
 * Enforces `docs/design-vocabulary.md`, which binds each design concept to the
 * one module that implements it. For every mapped concept with a greppable
 * definition signature, walks every package's shipped source and fails when
 * the signature is *defined* anywhere but the mapped home. Design erosion
 * lives in vocabularies, not files: per-PR review cannot catch a second
 * definition it never sees.
 *
 * Adding a row: implement the concept in ONE module, add it to
 * `docs/design-vocabulary.md`, and add its definition signature here.
 * Re-exports (`export { x } from ...`) and imports deliberately do not match
 * the definition patterns: consumers may re-export the mapped home freely.
 */

import { type Dirent, existsSync, readdirSync, readFileSync } from "node:fs";
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
	/**
	 * A row declared before its home defines it: the step that is to build
	 * it. No file may define it meanwhile, its home included; once the home
	 * does, the row fails until the step drops the marker.
	 */
	readonly declared?: string;
}

/** The one reading of `core.deployment.mode`; every other module requires the `deploymentMode` slot. */
const DEPLOYMENT_MODE_HOME = "packages/core/src/deployment/mode.mts";

/**
 * Where core's own section declares the paths it moved from: it names the
 * section's old path, `deployment`, and `deployment.mode`, the old path of
 * the key and of its variable, and reads neither.
 */
const DEPLOYMENT_RELOCATION_HOME = "packages/core/src/config/core-relocations.mts";

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
		concept: "the issuer as discovery advertises it (RFC 8414 §2, RFC 9207)",
		home: "packages/core/src/issuer/canonical.mts",
		definition: /(?:function|const)\s+advertisedIssuer\b/,
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
		home: "packages/device-grant/src/verificationBudget.mts",
		definition: /(?:function|const)\s+isDeviceVerificationRateLimitSpec\b/,
	},
	{
		concept: "usable rate-limit spec — what a limiter applies as written",
		home: "packages/core/src/ratelimit/usableSpec.mts",
		definition: /(?:function|const)\s+isUsableRateLimitSpec\b/,
	},
	{
		concept:
			"the budget a limiter applies to a key — its own limits entry, else the owner's contributed budget, else its default (#728)",
		home: "packages/core/src/ratelimit/budgetLookup.mts",
		definition: /(?:function|const)\s+createRateLimitBudgetLookup\b/,
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
		concept: "authentication claims a token may carry — auth_time (the MFA ADR's D18, RFC 9470 §6)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+wellFormedAuthTime\b/,
	},
	{
		concept: "an authentication instant as the auth_time claim (the MFA ADR's D18)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+authTimeClaim\b/,
	},
	{
		concept:
			"a recorded authentication instant as auth_time, never later than the clock reading it (the MFA ADR's D18)",
		home: "packages/core/src/grants/authenticationClaims.mts",
		definition: /(?:function|const)\s+authTimeAt\b/,
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
			"session admission — the decision every consumer of a session calls (the session-admission ADR's D1, D2)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+admitSession\b/,
	},
	{
		concept: "session admission — the establishment decision (the session-admission ADR's D5)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+admitPrimary\b/,
	},
	{
		concept: "session admission — resuming an interrupted login (the session-admission ADR's D5)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+resumePrimary\b/,
	},
	{
		concept:
			"session admission — establishing a federated login without asking (the session-admission ADR's D5)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+establishWithoutAsking\b/,
	},
	{
		concept:
			"session admission — the one builder a password login has (the session-admission ADR's D5)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+passwordPrimary\b/,
	},
	{
		concept: "session admission — the cookie's claim (the session-admission ADR's D2)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+cookieClaim\b/,
	},
	{
		concept:
			"session admission — a code record's claim on its first read (the session-admission ADR's D2)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+codeClaimFirstRead\b/,
	},
	{
		concept:
			"session admission — a code record's claim on its revalidation, the first read's subject required (the session-admission ADR's D2)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+codeClaimRevalidation\b/,
	},
	{
		concept: "session admission — a link transaction's claim (the session-admission ADR's D2)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+linkClaim\b/,
	},
	{
		concept: "session admission — a verified token's claim (the session-admission ADR's D2, D9)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+tokenClaim\b/,
	},
	{
		concept:
			"what a requirement is asked about a token with no live session (the session-admission ADR's D9)",
		home: "packages/core/src/user-sessions/authentication.mts",
		definition: /(?:function|const)\s+requirementSessionFromAmr\b/,
	},
	{
		concept:
			"the continuation a requirement persists and presents back, as it is checked (the session-admission ADR's D5)",
		home: "packages/core/src/session-admission/primary.mts",
		definition: /(?:function|const)\s+checkPrimaryContinuation\b/,
	},
	{
		concept: "session admission — the grades core owns (the session-admission ADR's D4)",
		home: "packages/core/src/session-admission/actions.mts",
		definition: /(?:function|const)\s+ADMISSION_GRADES\b/,
	},
	{
		concept:
			"session admission — an action's name, as a registration holds it (the session-admission ADR's D4)",
		home: "packages/core/src/session-admission/actions.mts",
		definition: /(?:function|const)\s+isAdmissionActionName\b/,
	},
	{
		// Refused under the name device verification's copy had, too.
		concept:
			"the step-up page as a browser is sent to it — resolved on the issuer, its params on the query (the session-admission ADR's D2, D8)",
		home: "packages/core/src/session-admission/requirement.mts",
		definition: /(?:function|const)\s+stepUp(?:Page)?Url\b/,
		homeDefinition: /(?:function|const)\s+stepUpPageUrl\b/,
	},
	{
		concept: "the acr table — oauth.authorize.acrValues as it is read (the MFA ADR's D15)",
		home: "packages/core/src/session-admission/acr.mts",
		definition: /(?:function|const)\s+readAcrTable\b/,
	},
	{
		concept: "D15's selection of an acr over what a session vouches for",
		home: "packages/core/src/session-admission/acr.mts",
		definition: /(?:function|const)\s+selectAcr\b/,
	},
	{
		concept:
			"what a step-up through the registered requirements can add (the session-admission ADR's D2, D6)",
		home: "packages/core/src/session-admission/acr.mts",
		definition: /(?:function|const)\s+stepUpReach\b/,
	},
	{
		concept: "what the composition can put in a session's amr (the MFA ADR's D15)",
		home: "packages/core/src/session-admission/acr.mts",
		definition: /(?:function|const)\s+producibleAmr\b/,
	},
	{
		concept: "the acr table less the entries nothing installed can satisfy (the MFA ADR's D15)",
		home: "packages/core/src/session-admission/acr.mts",
		definition: /(?:function|const)\s+vouchableAcrTable\b/,
	},
	{
		concept: "the values of mfa.mode, the MFA module's key (the MFA ADR's D19)",
		home: "packages/mfa/src/config.mts",
		definition: /(?:function|const)\s+MFA_MODES\b/,
	},
	{
		// Kept in the grants boundary's home, which admission imports: moving
		// it under `session-admission/` would close an import cycle
		// (session-admission ADR, D10).
		concept:
			"the subject-revocation boundary as it is read against an instant (the session-admission ADR's D2, D10)",
		home: "packages/core/src/federation-grants/effective-status.mts",
		definition: /(?:function|const)\s+coveredByRevocationBoundary\b/,
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
		concept: "outbound destination policy — the fetch",
		home: "packages/core/src/net/outbound-fetch.mts",
		definition: /(?:function|const)\s+createOutboundFetch\b/,
	},
	{
		concept: "outbound destination policy — the host-list grammar",
		home: "packages/core/src/net/outbound-policy.mts",
		definition: /(?:function|const)\s+readHostEntry\b/,
	},
	{
		concept: "conditional write — the store generation's type",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /\btype\s+StoreGeneration\s*=|\binterface\s+StoreGeneration\b/,
	},
	{
		concept:
			"conditional write — the bundled stores' write-lifetime bound and set-tombstone lifetime",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+BUNDLED_STORE_WRITE_LIFETIME_MS\b/,
	},
	{
		concept: "conditional write — what a store generation may be",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+isStoreGeneration\b/,
	},
	{
		concept: "conditional write — a fresh store generation",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+newStoreGeneration\b/,
	},
	{
		concept: "conditional write — reading a versioned read",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readVersioned\b/,
	},
	{
		concept: "conditional write — reading a versioned set read",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readVersionedSet\b/,
	},
	{
		concept: "conditional write — reading a conditional replace's answer",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readConditionalReplaceAnswer\b/,
	},
	{
		concept: "conditional write — reading a record-scoped conditional remove's answer",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readConditionalRemoveAnswer\b/,
	},
	{
		concept: "conditional write — reading a conditional create's answer",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readConditionalCreateAnswer\b/,
	},
	{
		concept: "conditional write — reading a set-scoped conditional remove's answer",
		home: "packages/core/src/adapters/conditionalWrite.mts",
		definition: /(?:function|const)\s+readConditionalSetRemoveAnswer\b/,
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
		concept: "fail-closed grant-policy evaluation — the one reading of a decision",
		home: "packages/core/src/grants/grantPolicy.mts",
		definition: /(?:function|const)\s+readGrantPolicyDecision\b/,
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
	{
		concept: "the login page's URL rule — a page carrying redirect_to (#728, #750)",
		home: "packages/core/src/browser-session/login-page.mts",
		definition: /(?:function|const)\s+loginPageCarriesReturn\b/,
	},
	{
		concept: "the login page's URL rule — redirect_to added (#728, #750)",
		home: "packages/core/src/browser-session/login-page.mts",
		definition: /(?:function|const)\s+loginPageUrlFor\b/,
	},
	{
		concept: "an MFA transaction's binding — the one comparison (#742)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+isMfaTransactionBoundTo\b/,
	},
	{
		concept: "an MFA transaction's binding — the bound read (#742)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+getBoundMfaTransaction\b/,
	},
	{
		concept: "an MFA store's answer, read as promised — a reservation (#809)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+readMfaAttemptReservation\b/,
	},
	{
		concept:
			"an MFA store's answer, read as promised — a subject attempt's reservation (the MFA ADR's D21)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+readMfaSubjectAttemptReservation\b/,
	},
	{
		concept: "an MFA store's answer, read as promised — a consumed transaction (#809)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+isConsumedMfaTransaction\b/,
	},
	{
		concept: "an MFA store's answer, read as promised — a factor's compare-and-set (#809)",
		home: "packages/core/src/mfa/factorStore.mts",
		definition: /(?:function|const)\s+isMfaFactorUpdateWritten\b/,
	},
	{
		concept:
			"an MFA store's answer, read as promised — a session's account-email proof (the MFA ADR's D24)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+readSessionEmailProof\b/,
	},
	{
		concept:
			"a subject's first-binding mark — what a store's answer is read as (the MFA ADR's D12)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+readFirstBindingAt\b/,
	},
	{
		concept: "a subject's first-binding mark — which of two a store keeps (the MFA ADR's D12)",
		home: "packages/core/src/mfa/transactionStore.mts",
		definition: /(?:function|const)\s+laterFirstBindingMark\b/,
	},
	{
		concept:
			"the first-binding mark as the MFA package reads it — which authentication it distrusts (the MFA ADR's D12)",
		home: "packages/mfa/src/firstBindingMark.mts",
		definition: /(?:function|const)\s+distrustedByFirstBinding\b/,
	},
	{
		concept:
			"the boundary check of a login transaction — its continuation's authTime held against the subject's sessions boundary (the MFA ADR's D8, F3)",
		home: "packages/mfa/src/coordinator.mts",
		definition: /(?:function|const)\s+pastSessionsBoundary\b/,
	},
	{
		concept:
			"a session's enrollment facts — derived from the login's User by core's primary builders (the MFA ADR's D12, D24)",
		home: "packages/core/src/session-admission/primary.mts",
		definition: /(?:function|const)\s+enrollmentFactsOf\b/,
	},
	{
		concept:
			"a session's enrollment facts — a login continuation's, derived as its rehydration derives them (the MFA ADR's D12, D24)",
		home: "packages/core/src/session-admission/primary.mts",
		definition: /(?:function|const)\s+enrollmentFactsOfContinuation\b/,
	},
	{
		concept: "a session's enrollment facts — what a store may record (the MFA ADR's D12, D24)",
		home: "packages/core/src/user-sessions/enrollmentFacts.mts",
		definition: /(?:function|const)\s+recordableEnrollmentFacts\b/,
	},
	{
		concept:
			"a session's enrollment facts — what a stored value is read back as (the MFA ADR's D12, D24)",
		home: "packages/core/src/user-sessions/enrollmentFacts.mts",
		definition: /(?:function|const)\s+readEnrollmentFacts\b/,
	},
	{
		concept: "the cookie session's user, for a route that admitted its subject (the MFA ADR's D24)",
		home: "packages/core/src/session-admission/admit.mts",
		definition: /(?:function|const)\s+cookieSessionUser\b/,
	},
	{
		concept:
			"the session renewal — the signed-in state carried to a regenerated express session id (the MFA ADR's D27)",
		home: "packages/session/src/establish-session.mts",
		definition: /(?:function|const)\s+renewSession\b/,
	},
	{
		concept:
			"the renewal nonce — what binds an escalated session to one cookie session (the MFA ADR's D27)",
		home: "packages/core/src/user-sessions/renewalNonce.mts",
		definition: /(?:function|const)\s+(?:newRenewalNonce|isRenewalNonce)\b/,
		homeMatches: 2,
	},
	{
		concept: "core.deployment.mode as core reads it — the deploymentMode slot's value",
		home: DEPLOYMENT_MODE_HOME,
		definition: /(?:function|const)\s+deploymentModeOf\b/,
	},
	{
		concept: "core.deployment.mode as core reads it — the check a reader holds the slot's value to",
		home: DEPLOYMENT_MODE_HOME,
		definition: /(?:function|const)\s+checkDeploymentMode\b/,
	},
	{
		concept: "a control character in configured text — C0, DEL or C1, but those a rule allows",
		home: "packages/core/src/security/controlCharacters.mts",
		definition: /(?:function|const)\s+hasControlCharacter\b/,
	},
	{
		concept:
			"an environment name as a development-only guard reads it — trimmed, lower case, production or staging whichever name says so",
		home: "packages/core/src/deployment/environment.mts",
		definition: /(?:function|const)\s+(?:readEnvironmentName|productionEnvironmentIn)\b/,
	},
	{
		concept: "an email address as the provider digests and compares it",
		home: "packages/core/src/mail/address.mts",
		definition: /(?:function|const)\s+normaliseMailAddress\b/,
	},
	{
		concept: "what a mail sender answered — delivered, refused at a limit, or else an outage",
		home: "packages/core/src/mail/outcome.mts",
		definition: /(?:function|const)\s+mailSendOutcome\b/,
	},
	{
		concept: "recent MFA — the credential_change grade's rule (the MFA ADR's D16)",
		home: "packages/mfa/src/requirement.mts",
		definition: /(?:function|const)\s+isRecentMfa\b/,
	},
	{
		concept:
			"MFA mail — the one place a code the provider issued is handed to the mail sender (the MFA ADR's D5, F5)",
		home: "packages/mfa/src/mail.mts",
		definition: /(?:function|const)\s+sendMfaMail\b/,
	},
	{
		concept: "the masked address a code went to, as a page may show it (the MFA ADR's D23)",
		home: "packages/mfa/src/mail.mts",
		definition: /(?:function|const)\s+maskMailAddress\b/,
	},
	{
		concept: "the long code — made (the MFA ADR's D22)",
		home: "packages/mfa/src/codes.mts",
		definition: /(?:function|const)\s+generateLongCode\b/,
	},
	{
		concept: "the long code — read as a user types or pastes it (the MFA ADR's D6, D22)",
		home: "packages/mfa/src/codes.mts",
		definition: /(?:function|const)\s+readLongCode\b/,
	},
	{
		concept: "the long code — shown in groups (the MFA ADR's D22)",
		home: "packages/mfa/src/codes.mts",
		definition: /(?:function|const)\s+formatLongCode\b/,
	},
	{
		concept: "the six-digit code — made (the MFA ADR's F5, D22)",
		home: "packages/mfa/src/codes.mts",
		definition: /(?:function|const)\s+generateSixDigitCode\b/,
	},
	{
		concept: "the six-digit code — read as a user types it (the MFA ADR's F5, D22)",
		home: "packages/mfa/src/codes.mts",
		definition: /(?:function|const)\s+readSixDigitCode\b/,
	},
	{
		concept:
			"the email factor — six-digit login codes and a long enrollment code, kept as keyed digests bound to their transaction, recording only the address digest it is handed (the MFA ADR's F5, D11, D22)",
		home: "packages/mfa/src/email/factor.mts",
		definition: /(?:function|const)\s+createEmailFactor\b/,
	},
	{
		concept:
			"a recovery-code set — issued beside a first counting factor, kept as keyed digests (the MFA ADR's D22, D25)",
		home: "packages/mfa/src/recovery/factor.mts",
		definition: /(?:function|const)\s+generateRecoveryCodes\b/,
	},
	{
		concept:
			"recovery-code verification — a code read as typed, compared with every digest of its set, and spent by the set answered without it (the MFA ADR's D22, D25)",
		home: "packages/mfa/src/recovery/factor.mts",
		definition: /(?:function|const)\s+spendRecoveryCode\b/,
	},
	{
		concept:
			"the subject lock in the verify path — a guessable proof reserves and settles one of its subject's attempts, an exempt proof passes during a hold and records an exempt success (the MFA ADR's D21, F1 step 5)",
		home: "packages/mfa/src/lock.mts",
		definition: /(?:function|const)\s+createMfaSubjectLock\b/,
	},
	{
		concept:
			"the first-binding gate — whether the account-email proof comes before a subject's first way into the account (the MFA ADR's D24, D25)",
		home: "packages/mfa/src/firstBinding.mts",
		definition: /(?:function|const)\s+firstBindingGate\b/,
	},
	{
		concept:
			"whether a factor record may count — admission's presumption, which tells a first binding (the MFA ADR's D12, F3)",
		home: "packages/mfa/src/firstBinding.mts",
		definition: /(?:function|const)\s+mayCount\b/,
	},
	{
		concept:
			"what a factor record can do — usable, unreadable, not installed, a known exhausted recovery set, an email factor whose address changed — what a transaction offers, and whether a password login asks for a second factor over it (the MFA ADR's F3, F4)",
		home: "packages/mfa/src/factorState.mts",
		definition:
			/(?:function|const)\s+(?:readFactorRecord|readFactorRecordAt|isOffered|asksForSecondFactor|holdsUsableRecord)\b/,
		homeMatches: 5,
	},
];

/**
 * What is wrong with a declared row given what `homeSource` holds — the
 * home's text, or `undefined` when the file does not exist: a home that
 * defines it is built, and the step that built it drops the marker.
 */
function declaredRowProblems(row: VocabularyRow, homeSource: string | undefined): string[] {
	if (row.declared === undefined) return [];
	return homeSource !== undefined && row.definition.test(homeSource)
		? [`${row.home} defines ${row.concept}: built — drop its declared marker`]
		: [];
}

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
 * the home's fail-closed rules inline, which the definition-only guard above
 * cannot see. Each still reads the decision with the home's
 * `readGrantPolicyDecision`, once per call.
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
			"its ceilings include the subject token's (scope: subject ∩ allowedScopes; audience: subject aud ∩ allowedAudiences ∪ {clientId}); a policy scope or audience past them is `policyOutOfBounds` like the rest, the request's own audience past them RFC 8693 §2.2.2's `invalid_target`",
	},
};

/** `source` with its comments removed, so a mention in one is not code. */
const withoutComments = (source: string): string =>
	source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

/** `grantPolicy.evaluate(` calls in `source`, comments removed so a mention is not a call. */
const policyEvaluateCalls = (source: string): number =>
	(withoutComments(source).match(/grantPolicy[\s\S]{0,40}?\.evaluate\s*\(/g) ?? []).length;

/**
 * What `source` does with a grant policy's decision outside the home, comments
 * removed: its `readGrantPolicyDecision(` calls, and its `outcome`s. A file
 * exempt from calling the home's evaluation counts every `outcome` its code
 * names: it holds a raw decision, and any read of that field is a second
 * reading. Any other file counts its comparisons of an `outcome` with the
 * string `allow` or `deny`.
 */
const policyDecisionReads = (
	source: string,
	exempt: boolean,
): { reading: number; outcome: number } => {
	const code = withoutComments(source);
	const outcome = exempt
		? /\boutcome\b/g
		: /\.outcome\s*[!=]==?\s*["'`](?:allow|deny)["'`]|["'`](?:allow|deny)["'`]\s*[!=]==?\s*[\w$.?]*\.outcome\b/g;
	return {
		reading: (code.match(/\breadGrantPolicyDecision\s*\(/g) ?? []).length,
		outcome: (code.match(outcome) ?? []).length,
	};
};

/** Session admission's home: the acr selection is its own step, over the input `requirementSession` builds. */
const REQUIREMENT_RULE_HOME = "packages/core/src/session-admission/admit.mts";

/**
 * The argument text of every call to the acr selection — `selectAcr(` — in
 * `source`, comments removed so a mention is not a call. The arguments run to
 * the matching `)`; a parenthesis inside a string literal would miscount, and
 * no call site passes one.
 */
const requirementRuleCalls = (source: string): string[] => {
	const code = withoutComments(source);
	const calls: string[] = [];
	// Its definition (`function selectAcr(`) is not a call.
	for (const match of code.matchAll(/(?<!function\s)\bselectAcr\s*\(/g)) {
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
 * A call to the acr selection that does not build its `amr` with
 * `requirementSession(` inside its own arguments. The selection reads a
 * session only as the D9 reading (MFA ADR) makes it: an input built from the
 * record's own `amr` would, given the upstream split, let an untrusted
 * upstream value meet an `acr`. Building it inline makes that checkable here;
 * a value built elsewhere and passed by name is flagged too.
 */
const withoutRequirementSession = (source: string): string[] =>
	requirementRuleCalls(source).filter((args) => !/\brequirementSession\s*\(/.test(args));

/**
 * The files that read a session's own `amr` and `authentication` on purpose
 * (the MFA ADR's D9): the readers themselves, session admission (which
 * composes a login's `recorded` and reads the `amr` of the input they
 * build), and the two bundled stores, which copy the record. Their reads are
 * pinned one by one in {@link SESSION_RECORD_READS_ALLOWED} like any other
 * file's; this list only holds the scan to finding them.
 */
const SESSION_RECORD_READERS: ReadonlySet<string> = new Set([
	"packages/core/src/user-sessions/authentication.mts",
	REQUIREMENT_RULE_HOME,
	"packages/core/src/session-admission/primary.mts",
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
const MEMORY_STORE_WHY = "the memory store copying the record in and out, and the step-up write";
const REDIS_STORE_WHY =
	"the Redis store copying the record to and from its envelope, and the step-up write";
const CODE_AMR_STORE_WHY =
	"a code repository copying the code record's amr in and out: what /authorize filled with vouchedAmr, never a session record";
const DEVICE_CODE_AMR_STORE_WHY =
	"a device-code store copying an approval's amr in and out: what device verification filled with vouchedAmr, never a session record";

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
	// The MFA ADR's D9 reading itself.
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "session.authentication",
		count: 1,
		why: READER_WHY,
	},
	{
		file: "packages/core/src/user-sessions/authentication.mts",
		read: "session.amr",
		count: 1,
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
	// Session admission.
	{
		file: REQUIREMENT_RULE_HOME,
		read: '(presented.carrier==="token"?requirementSessionFromAmr(presented.tokenAmr):requirementSession(session))?.amr',
		count: 1,
		why: "the amr of the acr selection's input, built inline by the D9 readers — a token's own amr through requirementSessionFromAmr, a record through requirementSession (D2, step 5) — handed to selectAcr",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "authentication?.amr",
		count: 1,
		why: "the same reading, as step 5 built it for the requirements, held by the merge to find the requirement whose reach finishes a reachable entry",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "primary.recorded.amr",
		count: 1,
		why: "composeRecorded starts from the amr the login route recorded for the primary — what a route hands in, never a session record",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "amr=primary.recorded.amr",
		count: 1,
		why: "the same amr, the base composeAmr composes every completed requirement's additions onto",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "entry.adds.amr",
		count: 2,
		why: "what a completed requirement added: held within its requirement's reach by resumePrimary, and composed onto the primary's amr by composeAmr",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "primary.recorded.authentication",
		count: 1,
		why: "the authentication the login route recorded for the primary, copied with the composed mfaAt — never a session record",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "read.primary.recorded.authentication",
		count: 1,
		why: "resumePrimary's check that a continuation's primary is the password kind — the only login interrupted in this release — before `recorded` is recomposed from that kind; a continuation, never a session record",
	},
	{
		file: "packages/core/src/session-admission/primary.mts",
		read: "value.amr",
		count: 5,
		why: "the establishment checks read a primary's recorded amr and a requirement's additions — what a login route or a completing requirement hands in, never a session record",
	},
	{
		file: "packages/core/src/session-admission/primary.mts",
		read: "dto.amr",
		count: 1,
		why: "additionsFromDto copies what a completed requirement added, as the continuation carries it — never a session record",
	},
	{
		file: "packages/core/src/session-admission/primary.mts",
		read: "entry.adds.amr",
		count: 2,
		why: "continuationOf copies what a completed requirement added into the DTO, and checkPrimaryContinuation counts the completions that add a second factor — a continuation, never a session record",
	},
	{
		file: "packages/core/src/session-admission/primary.mts",
		read: "value.authentication",
		count: 1,
		why: "the establishment check reads a primary's recorded authentication, what a login route hands in, never a session record",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "requested=asks?.acrValues??[]",
		count: 1,
		why: "the acr values the request asked for, handed to selectAcr: a request's, not a session's",
	},
	{
		file: REQUIREMENT_RULE_HOME,
		read: "claims.amr",
		count: 1,
		why: "tokenClaim reads the verified token's amr claim: a token's, minted from vouchedAmr, not a session record's",
	},
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
	// The MFA requirement: what admission built for it, and the primary a login route built.
	{
		file: "packages/mfa/src/requirement.mts",
		read: "{authentication}=(parameter)",
		count: 2,
		why: "the MFA requirement's input: the reading admission built with requirementSession, or requirementSessionFromAmr for a token (the session-admission ADR's D2, step 5) — never a record",
	},
	{
		file: "packages/mfa/src/requirement.mts",
		read: "authentication?.authentication",
		count: 2,
		why: "that reading's primary and mfaAt, which the baseline and recent MFA are decided on (the MFA ADR's D13, D16)",
	},
	{
		file: "packages/mfa/src/requirement.mts",
		read: "authentication?.amr",
		count: 1,
		why: "a token's own amr, as requirementSessionFromAmr read it: a factor's own second-factor value in it meets the baseline, whatever its primary (the MFA ADR's O3; a passkey token carries hwk alone)",
	},
	{
		file: "packages/mfa/src/requirement.mts",
		read: "primary.recorded.authentication",
		count: 1,
		why: "admitPrimary's check that the primary a login route built is a password login, the only one the baseline applies after (the MFA ADR's D13) — a primary, never a session record",
	},
	// The MFA escalation: a session's escalation.
	{
		file: "packages/mfa/src/escalation.mts",
		read: "{amr}=adds",
		count: 1,
		why: "the step-up write D28 names: createSessionEscalation's escalate holds what a verified second factor adds, as the ceremony built it — the factor's declared values and mfa — to the mfa requirement's sealed reach, then hands it to recordSecondFactor; never a session record",
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
		file: "packages/oauth/src/routes.mts",
		read: "claims.amr",
		count: 1,
		why: "introspection answers the amr claim of an access token this provider signed and verified — a token it vouched for, minted from vouchedAmr, never a session record",
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
		why: "the amr, acr and auth_time the presented refresh token carries, read above as claims.amr, wellFormedAcr and wellFormedAuthTime",
	},
	// The authorization code's amr: what the session vouched for at `/authorize`
	// (`vouchedAmr`), carried on the code to the exchange.
	{
		file: "packages/core/src/repositories/InMemoryCodeRepository.mts",
		read: "params.amr",
		count: 1,
		why: CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/core/src/repositories/InMemoryCodeRepository.mts",
		read: "stored.amr",
		count: 3,
		why: CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/redis/src/code-repository.mts",
		read: "{amr}=(parameter)",
		count: 1,
		why: CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/redis/src/code-repository.mts",
		read: "p.amr",
		count: 1,
		why: CODE_AMR_STORE_WHY,
	},
	// A device approval's amr: what the approving session vouched for at
	// device verification (`vouchedAmr`), carried on the record to the poll.
	{
		file: "packages/core/src/device-authorization/approval.mts",
		read: "approval.amr",
		count: 1,
		why: "what a device-code store records of an approval's amr, read once and checked: what device verification filled with vouchedAmr, never a session record",
	},
	{
		file: "packages/core/src/device-authorization/memory.mts",
		read: "{amr}=recordableDeviceApproval(input,input.nowMs)",
		count: 1,
		why: DEVICE_CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/core/src/device-authorization/memory.mts",
		read: "entry.amr",
		count: 2,
		why: DEVICE_CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/redis/src/device-code-store.mts",
		read: "{amr}=recordableDeviceApproval(input,input.nowMs)",
		count: 1,
		why: DEVICE_CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/redis/src/device-code-store.mts",
		read: "fields.amr",
		count: 1,
		why: DEVICE_CODE_AMR_STORE_WHY,
	},
	{
		file: "packages/redis/src/ioredis/clients/device-code.mts",
		read: "approval?.amr",
		count: 1,
		why: "the device-code store's client encoding an approval's amr as the approval script's argument: what device verification filled with vouchedAmr, never a session record",
	},
	{
		file: "packages/device-grant/src/grant.mts",
		read: "authorization.amr",
		count: 1,
		why: "the device grant stamps the amr the approval recorded, which device verification filled with vouchedAmr, never a session record",
	},
	{
		file: "packages/oauth/src/grants/authorization.mts",
		read: "codeData.amr",
		count: 1,
		why: "the authorization_code grant stamps the amr the code carries, which /authorize filled with vouchedAmr, never the session record's at exchange",
	},
	{
		file: "packages/session/src/routes/Federation.mts",
		read: "profile.amr",
		count: 3,
		why: "what the upstream IdP asserted on the profile, handed to establishWithoutAsking, which composes the record through federatedSessionAuthentication",
	},
	{
		file: "packages/session/src/establish-session.mts",
		read: "...recorded",
		count: 1,
		why: "the amr and authentication core composed for a login, read off the Establishment's primary (passwordPrimary through admitPrimary, establishWithoutAsking, resumePrimary) and spread into create by the login tail",
	},
	{
		file: "packages/session/src/modules/sessionStoreModule.mts",
		read: "...((storageSlice[storageSlice.type]??{})asRecord<string,unknown>)",
		count: 1,
		why: "a cookie-session store factory's create, handed its storage settings: no session record",
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
		file: "packages/core/src/user-sessions/memory/userSessionStore.mts",
		read: "s=readLive(sid)",
		count: 1,
		why: "the stored record, handed (through toSession) to sessionAfterSecondFactor, which reads it through the D9 readers",
	},
	{
		file: "packages/redis/src/userSessionStore.mts",
		read: "stored=readEnvelope(sid,raw)",
		count: 1,
		why: "the stored envelope, handed (through fromEnvelope) to sessionAfterSecondFactor, which reads it through the D9 readers",
	},
	{
		file: "packages/session/src/modules/sessionStoreModule.mts",
		read: "storageSlice=section.storageas{type:string}&Record<string,unknown>",
		count: 1,
		why: "the cookie-session storage settings, the base of a pinned spread into a store factory's create",
	},
	{
		file: "packages/redis/src/mfa-factor-store.mts",
		// biome-ignore lint/suspicious/noTemplateCurlyInString: the source text the guard matches, not a template
		read: "value=`${record.version}\\n${fixedPart(record)}\\n${mutablePart(record)}`",
		count: 1,
		why: "the MFA factor store's client create (HSETNX), handed the text of the factor record it was given: a second factor's, no session record",
	},
	{
		file: "packages/redis/src/mfa-transaction-store.mts",
		read: "record=newMfaTransactionRecord(tx)",
		count: 1,
		why: "the MFA transaction store's client create, handed (through fieldsOf) the transaction newMfaTransactionRecord checked: its continuation's recorded amr is the primary's as core's builders composed it (continuationOf, the session-admission ADR's D5), never read off a session record",
	},
	{
		file: "packages/redis/src/mfa-transaction-store.mts",
		read: 'incarnation=randomBytes(16).toString("base64url")',
		count: 1,
		why: "the random value the MFA transaction store's create writes (through fieldsOf) for its update's compare-and-set: no session record",
	},
];

/** The names a session record's reading is kept to. */
const SESSION_RECORD_FIELDS: ReadonlySet<string> = new Set(["amr", "authentication"]);

/**
 * The functions that take an `amr` (as an option, an argument or a token
 * claim), matched by the name they are called by: the token minters
 * `generateToken` and `generateIdToken`, the key store's `sign`, which takes
 * the claims both build (see {@link CLAIMS_ONLY_TAKERS}), the amr composer, a
 * store's `create`, a device-code store's `approve` and what decides its
 * record, the step-up and the acr selection. A spread into an object
 * handed to one of them copies a record's own `amr` without naming it.
 * `create` is also other factories' name: their spreads are pinned like reads.
 */
const AMR_TAKERS: ReadonlySet<string> = new Set([
	"sign",
	"generateToken",
	"generateIdToken",
	"composeAmr",
	"create",
	"approve",
	"recordableDeviceApproval",
	"recordSecondFactor",
	"sessionAfterSecondFactor",
	"checkSecondFactorEvent",
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
 * - a property access on any receiver, written as the access;
 * - an element access by the literal name (`x["amr"]`, `` x?.[`amr`] ``), and
 *   `Reflect.get(x, "amr")`, written as the expression;
 * - a destructuring by declaration, parameter or assignment, renamed or not,
 *   the key a literal or a computed literal, written as `{key}=source`;
 * - a spread into an object handed to one of {@link AMR_TAKERS}, unless it
 *   spreads only literals or a choice between them, written as `...` and
 *   what is spread (a call as its callee).
 *
 * A spread of a local, and a local handed whole to such a function, is
 * followed to the declaration the language resolves it to, in the same file:
 * a spread of anything but literals in its initializer is reported (and
 * followed in turn), and for a local used whole so is an initializer that is
 * not an object literal (`o=initializer`). The key store's `sign` is checked through its object
 * argument and the locals named in it; a local handed whole to it is followed
 * for its spreads only. A taker's argument that is a call to something else
 * (`formatObject({ … })`) is looked through, through any number of such calls.
 *
 * Parsed with TypeScript, so a comment or a string that names the field is not
 * a read, and neither is an object literal written for a store, a type or an
 * interface member. Matched by shape, never by the receiver's name.
 *
 * Left to review: a local it cannot resolve here (a parameter, a loop
 * variable, an import, a value built in another function or file); a
 * reassigned `let`, or a `var` hoisted from an inner block, whose value is not
 * the one it was declared with; a callee reached under another name; a copy
 * that is not a spread (`Object.assign`, `structuredClone`); a cast that
 * relabels a record; and reflection with a key that is not a literal. A
 * consumer reads a session through `sessionAuthentication` / `vouchedAmr`
 * (`core/src/user-sessions/authentication.mts`), because a session written
 * before the upstream split still holds an untrusted IdP's values in its own
 * `amr`.
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
	/**
	 * What a taker is handed, as an argument: an object literal's spreads and
	 * the locals it names; a local handed whole, followed to its declaration —
	 * with `whole`, an initializer that is not an object literal is reported
	 * too; without it, only its spreads are. A call to something that is not
	 * a taker (`formatObject({ … })`) is looked through to what it is handed,
	 * through any number of such calls; a call to a taker is checked where it
	 * is made.
	 */
	const inspectArgument = (argument: ts.Expression, whole: boolean): void => {
		const value = bare(argument);
		if (ts.isCallExpression(value)) {
			const inner = calleeName(value.expression);
			if (inner === undefined || !AMR_TAKERS.has(inner)) {
				for (const handed of value.arguments) inspectArgument(handed, whole);
			}
			return;
		}
		spreadsInto(argument, true);
		if (ts.isIdentifier(value)) follow(value.text, whole, argument);
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
				// A local handed whole to the signer is followed for its spreads
				// only: its amr rides inside its `claims`, and other libraries'
				// key-taking `sign(key)` share the name.
				const whole = !CLAIMS_ONLY_TAKERS.has(name);
				for (const argument of node.arguments) inspectArgument(argument, whole);
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

/**
 * Core's configuration schema: the one schema that declares `deployment` —
 * under core's own section, and presence-only at the path it moved from.
 */
const DEPLOYMENT_SCHEMA_HOME = "packages/core/src/config/application.schema.mts";

/** The literals that name the section or its key, as a helper or a reflection is handed them. */
const DEPLOYMENT_NAMES: ReadonlySet<string> = new Set([
	"deployment",
	"deployment.mode",
	"core.deployment",
	"core.deployment.mode",
]);

/** The Zod calls whose object argument names a schema's keys. `omit` names a key to drop, and is not one. */
const SHAPE_BUILDERS: ReadonlySet<string> = new Set([
	"object",
	"strictObject",
	"looseObject",
	"extend",
	"safeExtend",
	"merge",
	"pick",
]);

/** What `deploymentTouches` found: a read of the section, or a schema that declares it. */
interface DeploymentTouch {
	readonly line: number;
	readonly kind: "read" | "schema";
	readonly text: string;
}

/**
 * Where `source` touches the configuration's `deployment` section, each with
 * its 1-based line and its text (whitespace removed):
 *
 * - a read: a property access `.deployment` on any receiver (optional,
 *   non-null or through a cast alike); a destructuring that names it, by
 *   declaration, parameter or assignment, flat or nested, renamed or not,
 *   its key an identifier, a string or a computed string; and a string
 *   literal `"deployment"`, `"deployment.mode"`, `"core.deployment"` or
 *   `"core.deployment.mode"` anywhere a value goes — an
 *   element access, `Reflect.get`, a path handed to a helper, an `in` test,
 *   a type's indexed access. An alias (`const d = config.deployment`) is
 *   caught at the access that made it.
 * - a schema: a `deployment` key in the object a Zod shape builder
 *   ({@link SHAPE_BUILDERS}) is handed.
 *
 * Parsed with TypeScript, so a comment, a message that mentions the key
 * (`'deployment.mode is "multi"'`), an interface member or an object literal
 * written with the key is neither. Left to review: a key built at run time
 * (`"deploy" + "ment"`, a template with a substitution), and a schema
 * assembled other than through a shape builder's object argument.
 */
function deploymentTouches(source: string, fileName = "scan.mts"): DeploymentTouch[] {
	const kind = /\.(?:js|mjs|cjs)$/.test(fileName) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
	const touches: DeploymentTouch[] = [];
	const found = (node: ts.Node, touch: DeploymentTouch["kind"]): void => {
		touches.push({
			line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1,
			kind: touch,
			text: node.getText(file).replace(/\s+/g, ""),
		});
	};
	const literalName = (node: ts.Node | undefined): string | undefined => {
		if (node === undefined) return undefined;
		if (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) return node.text;
		if (ts.isComputedPropertyName(node) && ts.isStringLiteralLike(node.expression)) {
			return node.expression.text;
		}
		return undefined;
	};
	const namesSection = (node: ts.Node | undefined): boolean => literalName(node) === "deployment";
	/** Whether a string literal stands where a name goes — a key, a member, a module — rather than a value. */
	const inNamePosition = (node: ts.Node): boolean => {
		const parent = node.parent;
		if (parent === undefined) return false;
		if (ts.isComputedPropertyName(parent)) return true;
		if (ts.isBindingElement(parent)) return parent.propertyName === node;
		if (
			ts.isImportDeclaration(parent) ||
			ts.isExportDeclaration(parent) ||
			ts.isExternalModuleReference(parent)
		) {
			return true;
		}
		return "name" in parent && (parent as { name?: ts.Node }).name === node;
	};
	/** Whether an object literal is a destructuring target: the left of `=`, or a `for…of` / `for…in` head. */
	const isAssignmentPattern = (node: ts.ObjectLiteralExpression): boolean => {
		let current: ts.Node = node;
		for (;;) {
			const parent: ts.Node | undefined = current.parent;
			if (parent === undefined) return false;
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
				// A default inside a pattern (`{ a: { deployment } = {} } = c`) is one too.
				const outer = parent.parent;
				if (outer && ts.isPropertyAssignment(outer) && outer.initializer === parent) {
					current = outer.parent;
					continue;
				}
				return true;
			}
			return (
				(ts.isForOfStatement(parent) || ts.isForInStatement(parent)) &&
				parent.initializer === current
			);
		}
	};
	const calleeName = (node: ts.Expression): string | undefined =>
		ts.isIdentifier(node)
			? node.text
			: ts.isPropertyAccessExpression(node)
				? node.name.text
				: undefined;
	const visit = (node: ts.Node): void => {
		if (ts.isPropertyAccessExpression(node) && node.name.text === "deployment") {
			found(node, "read");
		} else if (
			ts.isBindingElement(node) &&
			ts.isObjectBindingPattern(node.parent) &&
			namesSection(node.propertyName ?? node.name)
		) {
			found(node, "read");
		} else if (
			ts.isStringLiteralLike(node) &&
			DEPLOYMENT_NAMES.has(node.text) &&
			!inNamePosition(node)
		) {
			found(node, "read");
		} else if (ts.isObjectLiteralExpression(node) && isAssignmentPattern(node)) {
			for (const property of node.properties) {
				if (
					(ts.isShorthandPropertyAssignment(property) || ts.isPropertyAssignment(property)) &&
					namesSection(property.name)
				) {
					found(property, "read");
				}
			}
		} else if (ts.isCallExpression(node)) {
			const name = calleeName(node.expression);
			if (name !== undefined && SHAPE_BUILDERS.has(name)) {
				for (const argument of node.arguments) {
					if (!ts.isObjectLiteralExpression(argument)) continue;
					for (const property of argument.properties) {
						if (
							(ts.isShorthandPropertyAssignment(property) || ts.isPropertyAssignment(property)) &&
							namesSection(property.name)
						) {
							found(property, "schema");
						}
					}
				}
			}
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return touches;
}

/**
 * The product sources the deployment guard scans, `/`-separated from the
 * root: every TypeScript and JavaScript source of every package's `src`, of
 * each template's and of `create-app`'s, no declaration file and no test.
 */
function deploymentScope(): string[] {
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
	for (const root of ["packages", "templates"]) {
		for (const dir of readdirSync(join(repoRoot, root), { withFileTypes: true })) {
			if (dir.isDirectory()) collect(join(repoRoot, root, dir.name, "src"));
		}
	}
	collect(join(repoRoot, "create-app", "src"));
	return files.sort();
}

/** Each scanned file with what it touches of `deployment`, of one kind. */
function deploymentTouchSites(touch: DeploymentTouch["kind"]): Record<string, string[]> {
	const sites: Record<string, string[]> = {};
	for (const rel of deploymentScope()) {
		const found = deploymentTouches(readFileSync(join(repoRoot, rel), "utf8"), rel).filter(
			(t) => t.kind === touch,
		);
		if (found.length > 0) sites[rel] = found.map((t) => `${t.line}:${t.text}`);
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

	it("counts a device-code store's approve among what takes an amr: a spread into it copies the session's own", () => {
		expect(
			sessionRecordReads("await store.approve({ ...session, userCode, nowMs });"),
		).toHaveLength(1);
		expect(
			sessionRecordReads(
				"await store.approve({ userCode, subject, nowMs, ...(amr ? { amr } : {}) });",
			),
		).toHaveLength(0);
	});

	it("counts what decides a device approval's record among what takes an amr", () => {
		expect(sessionRecordReads("recordableDeviceApproval({ ...session }, nowMs);")).toHaveLength(1);
		expect(
			sessionRecordReads("recordableDeviceApproval({ ...(amr ? { amr } : {}) }, nowMs);"),
		).toHaveLength(0);
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

	it("reads a session's amr and authentication only through the session readers, each read pinned to its receiver", () => {
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

	it("reads the acr selection's calls, and flags one whose amr bypasses requirementSession", () => {
		const sample = [
			"// selectAcr(requested, session.amr, table, reach) — a comment, not a call",
			"const a = selectAcr(requested, requirementSession(session)?.amr ?? [], table, reach);",
			"const b = selectAcr(requested, session?.amr ?? [], table, stepUpReach([]));",
			"const c = selectAcr(requested, vouched, table, reach);",
		].join("\n");
		expect(requirementRuleCalls(sample)).toHaveLength(3);
		expect(withoutRequirementSession(sample)).toEqual([
			"requested, session?.amr ?? [], table, stepUpReach([])",
			"requested, vouched, table, reach",
		]);
	});

	it("builds the acr selection's amr with requirementSession at every call site, admission's own included", () => {
		// Outside tests. Admission's own call is held to it too: the guard has
		// no home exemption.
		const calls = listShippedSources()
			.map(
				(file) =>
					[relative(repoRoot, file).split(sep).join("/"), readFileSync(file, "utf8")] as const,
			)
			.filter(([, source]) => requirementRuleCalls(source).length > 0);
		// Not vacuous: admission selects the acr.
		expect(calls.map(([rel]) => rel)).toContain(REQUIREMENT_RULE_HOME);
		const offenders = Object.fromEntries(
			calls
				.map(([rel, source]) => [rel, withoutRequirementSession(source)] as const)
				.filter(([, bad]) => bad.length > 0),
		);
		expect(
			offenders,
			"build the acr selection's amr with requirementSession(session) (core/src/user-sessions/authentication.mts)",
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

	it("reads a grant policy's decision through the home: an exempt file calls it once per evaluation and names no outcome, and no other file compares one", () => {
		const home = join(repoRoot, "packages/core/src/grants/grantPolicy.mts");
		const found = Object.fromEntries(
			listShippedSources()
				.filter((file) => file !== home)
				.map((file) => [relative(repoRoot, file).split(sep).join("/"), file] as const)
				.map(([rel, file]) => {
					const exempt = Object.hasOwn(POLICY_EVALUATE_EXEMPTIONS, rel);
					return [rel, exempt, policyDecisionReads(readFileSync(file, "utf8"), exempt)] as const;
				})
				.filter(([, exempt, reads]) => exempt || reads.reading > 0 || reads.outcome > 0)
				.map(([rel, , reads]) => [rel, reads] as const),
		);
		const expected = Object.fromEntries(
			Object.entries(POLICY_EVALUATE_EXEMPTIONS).map(([rel, { calls }]) => [
				rel,
				{ reading: calls, outcome: 0 },
			]),
		);
		expect(
			found,
			"read the decision with readGrantPolicyDecision (core/src/grants/grantPolicy.mts)",
		).toEqual(expected);
	});

	it("flags a read of the deployment section by every shape: member, element, destructuring, alias, helper, reflection", () => {
		const reads = (source: string) =>
			deploymentTouches(source).filter((touch) => touch.kind === "read").length;
		for (const read of [
			"const m = config.deployment?.mode;",
			"const m = cfg?.deployment.mode;",
			"const m = config.deployment!.mode;",
			"const m = (config as C).deployment.mode;",
			"const m = (config.deployment as D).mode;",
			'const m = config["deployment"]["mode"];',
			'const m = config?.["deployment"]?.mode;',
			"const { deployment } = config;",
			"const { deployment: { mode } } = config;",
			"const { deployment: d } = config;",
			'const { "deployment": d } = config;',
			'const { ["deployment"]: d } = config;',
			"const read = ({ deployment }: C) => deployment;",
			"({ deployment } = config);",
			"({ a: { deployment } } = config);",
			"({ a: { deployment } = {} } = config);",
			"for (const { deployment } of configs) use(deployment);",
			"const d = config.deployment; const m = d.mode;",
			'const m = get(config, "deployment").mode;',
			'const m = Reflect.get(config, "deployment");',
			'const m = at(config, "deployment.mode");',
			'const m = at(config, "core.deployment.mode");',
			'const m = at(config, ["deployment", "mode"]);',
			'if ("deployment" in config) use(config);',
			'type D = AppConfig["deployment"];',
			'const url = "https://a.example//b", m = config.deployment?.mode;',
		]) {
			expect(reads(read), read).toBe(1);
		}
		// Naming the key is not reading it: a comment, a message, an interface
		// member, an object written with it, a variable of that name, the reading
		// imported.
		for (const notARead of [
			"// config.deployment?.mode",
			"/* x.deployment.mode */",
			"throw new Error('deployment.mode is \"multi\"');",
			'const m = `set deployment.mode = "single"`;',
			"interface C { readonly deployment?: { readonly mode?: string } }",
			"const input = { deployment: x };",
			"const [deployment] = modes;",
			"function f(deployment: string) { return deployment; }",
			'import { deploymentModeOf } from "@o3co/auth-provider-core";',
			"const mode = deploymentModeOf(config);",
			"logger.warn({ deploymentMode }, 'x');",
		]) {
			expect(reads(notARead), notARead).toBe(0);
		}
	});

	it("flags a deployment key in the object a Zod shape builder is handed, and nowhere else", () => {
		const schemas = (source: string) =>
			deploymentTouches(source).filter((touch) => touch.kind === "schema").length;
		for (const schema of [
			"const s = z.object({ deployment: z.object({ mode: z.string() }) });",
			"const s = z.strictObject({ deployment });",
			"const s = z.looseObject({ ['deployment']: z.unknown() });",
			'const s = base.extend({ "deployment": z.unknown() });',
			"const s = base.safeExtend({ deployment: z.unknown() });",
			"const s = base.merge(z.object({ deployment: part }));",
			"const s = fullSectionsSchema.pick({ deployment: true });",
		]) {
			expect(schemas(schema), schema).toBe(1);
		}
		for (const notASchema of [
			"const s = base.omit({ deployment: true });",
			"const s = z.object({ deploymentMode: z.string() });",
			"logger.warn({ deployment: x }, 'x');",
		]) {
			expect(schemas(notASchema), notASchema).toBe(0);
		}
	});

	it("scans every package's source, each template's and create-app's", () => {
		const scope = deploymentScope();
		for (const file of [
			DEPLOYMENT_MODE_HOME,
			"packages/redis/src/federation-grant-store.mts",
			"templates/standalone/src/buildModules.mts",
			"create-app/src/cli.mts",
		]) {
			expect(scope, file).toContain(file);
		}
		expect(scope.some((file) => file.includes("/__tests__/"))).toBe(false);
	});

	it("reads the deployment section only in its home, and names its old paths only where core declares them: every other module requires the deploymentMode slot", () => {
		const counts = Object.fromEntries(
			Object.entries(deploymentTouchSites("read")).map(([file, found]) => [file, found.length]),
		);
		expect(counts, `require the deploymentMode slot (${DEPLOYMENT_MODE_HOME})`).toEqual({
			[DEPLOYMENT_MODE_HOME]: 1,
			[DEPLOYMENT_RELOCATION_HOME]: 3,
		});
	});

	it("declares a deployment key in no schema but core's configuration schema", () => {
		const counts = Object.fromEntries(
			Object.entries(deploymentTouchSites("schema")).map(([file, found]) => [file, found.length]),
		);
		expect(counts, "the section is core's: a module requires the deploymentMode slot").toEqual({
			[DEPLOYMENT_SCHEMA_HOME]: 2,
		});
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

	it("reads a declared row as built once its home defines it, and not before", () => {
		const row: VocabularyRow = {
			concept: "a declared concept",
			home: "packages/core/src/net/loopback.mts",
			definition: /(?:function|const)\s+isLoopbackHostname\b/,
			declared: "a later step",
		};
		expect(declaredRowProblems(row, "export function isLoopbackHostname() {}")).toEqual([
			"packages/core/src/net/loopback.mts defines a declared concept: built — drop its declared marker",
		]);
		expect(declaredRowProblems(row, "export function other() {}")).toEqual([]);
		expect(declaredRowProblems(row, undefined)).toEqual([]);
		expect(
			declaredRowProblems({ ...row, declared: undefined }, "function isLoopbackHostname"),
		).toEqual([]);
	});

	it.each(VOCABULARY.map((row) => [row.concept, row] as const))(
		"%s is defined only in its mapped home",
		(_concept, row) => {
			const home = join(repoRoot, row.home);
			if (row.declared !== undefined) {
				const homeSource = existsSync(home) ? readFileSync(home, "utf8") : undefined;
				expect(declaredRowProblems(row, homeSource)).toEqual([]);
				const offenders = sources
					.filter((file) => row.definition.test(readFileSync(file, "utf8")))
					.map((file) => relative(repoRoot, file));
				expect(offenders, `declared for ${row.declared}: defined before its home`).toEqual([]);
				return;
			}
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
