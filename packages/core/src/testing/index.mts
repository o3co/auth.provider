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
 * Public test-helper surface for `@o3co/auth-provider-core`, exposed via the
 * `./testing` subpath. Test code (sibling packages, downstream applications)
 * may import from here; production runtime code MUST NOT. Exports follow the
 * same semver discipline as the main `.` export.
 */

export { CORE_RELOCATIONS, type CoreRelocations } from "../config/core-relocations.mjs";
/**
 * `GrantRegistry` for tests that construct a registry directly rather than
 * through `createApp` and a module's `contributes.grants`. Not on the package
 * root: production code wires grants on a module's manifest and lets the
 * boot planner own the registry. New tests SHOULD prefer module wiring.
 */
export { GrantRegistry, GrantRegistryError } from "../grants/registry.mjs";
export {
	MERGE_ACR,
	MERGE_ACR_TABLE,
	MERGE_REACH,
	MERGE_ROW_GROUPS,
	type MergeDecision,
	type MergeFactors,
	type MergeRow,
	type MergeRowGroup,
	mergeAdmission,
	mergeSessionStore,
} from "../session-admission/testing/merge.rows.mjs";
export {
	type ContractCase,
	type RequirementContractInput,
	sessionRequirementContract,
} from "../session-admission/testing/requirement.contract.mjs";
export { resolverForTests } from "../session-admission/testing/resolver.mjs";
export {
	auditHooksModule,
	createRecordingAuditSink,
	type RecordingAuditSink,
} from "./auditSinks.mjs";
export { createTestApp, type TestAppHandle } from "./create-test-app.mjs";
// The check a package runs over its own config/reference.conf.
export { unreadableModuleLeaves } from "./environmentLeaves.mjs";
export {
	createFakeIdp,
	type FakeIdp,
	type FakeIdpAuthorizationResponse,
	type FakeIdpOptions,
	type FakeIdpRequest,
} from "./fake-idp.mjs";
// Client registrations as a registration file writes them, for an
// `InMemoryClientRepository`, which fills the schema's defaults.
export { clientEntries } from "./fixtures/clientEntries.mjs";
// A module that registers one federation type, so that boot handles the
// `core.federations` entries of that type without the package that owns it.
export {
	type FederationTypeForTestsOptions,
	federationTypeForTests,
} from "./fixtures/federationType.mjs";
export {
	type FederationEntryForTests,
	type FederationForTests,
	withFederation,
	withInsecureSessionCookie,
} from "./fixtures/sessionConfig.mjs";
export {
	type CoreConfigForTestsOptions,
	coreConfigForTests,
	makeValidAppConfig,
	makeValidCoreConfig,
} from "./fixtures/valid-config.mjs";
// The doubles a second factor's tests use: a factor with a trivial protocol,
// its proofs, and the keyed digests a factor is handed. The factor's
// conformance suite is the test kit's.
export {
	createTestMfaDigests,
	createTestMfaFactor,
	type TestMfaDigestsOptions,
	type TestMfaFactorOptions,
	testMfaFactorProofs,
} from "./mfaFactor.mjs";
// The outbound fetch over a resolver and a transport a test supplies, below
// its policy, and the builder for `core.outbound`.
export {
	createOutboundFetchForTesting,
	type OutboundAnswer,
	type OutboundExchange,
	type OutboundFetchForTestingOptions,
	type OutboundSectionForTests,
	type OutboundTransport,
	withOutbound,
} from "./outboundFetch.mjs";
export {
	createRecordingMailSender,
	type RecordingMailSender,
} from "./recordingMailSender.mjs";
export {
	type PackageReferenceCheck,
	packageReferenceProblems,
	type ReferenceConfCheck,
	referenceConfProblems,
} from "./referenceConf.mjs";
export {
	type RenamedVariableCaptureInput,
	type RenamedVariableCheck,
	renamedVariableCaptures,
	renamedVariableProblems,
} from "./renamedVariables.mjs";
// The check that each module refuses an unknown key at every level of its section.
export { type SectionStrictnessOptions, sectionStrictnessProblems } from "./sectionStrictness.mjs";
export {
	type CsrfGuardContractInput,
	createTestCsrfGuard,
	csrfGuardContract,
	type TestCsrfGuardOptions,
} from "./slots/csrfGuard.mjs";
export {
	type CsrfTokenSignerContractInput,
	createTestCsrfTokenSigner,
	csrfTokenSignerContract,
} from "./slots/csrfTokenSigner.mjs";
export {
	type DeploymentModeContractInput,
	deploymentModeContract,
} from "./slots/deploymentMode.mjs";
export {
	createTestFederationGrantPolicy,
	type FederationGrantPolicyContractInput,
	federationGrantPolicyContract,
} from "./slots/federationGrantPolicy.mjs";
export {
	createTestFederationSettings,
	type FederationSettingsContractInput,
	federationSettingsContract,
	type TestFederationEntry,
} from "./slots/federationSettings.mjs";
export {
	createTestHttpSettings,
	type HttpSettingsContractInput,
	httpSettingsContract,
	type TestHttpSettingsOverrides,
} from "./slots/httpSettings.mjs";
export {
	createRecordingLoginCompletion,
	type LoginCompletionContractInput,
	loginCompletionContract,
	type RecordingLoginCompletion,
	type RecordingLoginCompletionOptions,
} from "./slots/loginCompletion.mjs";
export {
	createTestLoginEntry,
	type LoginEntryContractInput,
	loginEntryContract,
} from "./slots/loginEntry.mjs";
export {
	createTestOAuthTokenSettings,
	type OAuthTokenSettingsContractInput,
	oauthTokenSettingsContract,
	type TestOAuthTokenSettingsOverrides,
} from "./slots/oauthTokenSettings.mjs";
export {
	createTestOutboundPolicy,
	type OutboundPolicyContractInput,
	outboundPolicyContract,
} from "./slots/outboundPolicy.mjs";
export {
	createTestRateLimiter,
	type RateLimiterContractInput,
	rateLimiterContract,
	type TestRateLimiter,
	type TestRateLimiterOptions,
} from "./slots/rateLimiter.mjs";
// The slots through which modules share what one of them owns: each
// slot's contract suite, and a test double a consumer's tests fill the slot
// with instead of importing the owner's package.
export {
	createTestSessionCookiePolicy,
	type SessionCookiePolicyContractInput,
	sessionCookiePolicyContract,
} from "./slots/sessionCookiePolicy.mjs";
export {
	createTestTokenBindingSettings,
	type TokenBindingSettingsContractInput,
	tokenBindingSettingsContract,
} from "./slots/tokenBindingSettings.mjs";
export type { TestInspect } from "./test-inspect.mjs";
