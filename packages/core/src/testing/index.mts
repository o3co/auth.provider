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
export {
	type FederationEntryForTests,
	type FederationForTests,
	withFederation,
	withInsecureSessionCookie,
} from "./fixtures/sessionConfig.mjs";
export { userRepositoryHttpOf, withUserRepositoryHttp } from "./fixtures/userRepository.mjs";
export {
	type CoreConfigForTestsOptions,
	coreConfigForTests,
	makeValidAppConfig,
	makeValidCoreConfig,
	makeValidFullSections,
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
export type { TestInspect } from "./test-inspect.mjs";
