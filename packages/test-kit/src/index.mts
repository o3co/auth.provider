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
 * `@o3co/auth-provider-test-kit`: the contract suites of the ports code
 * outside core implements, and the fakes they run against. Test code imports
 * it; production code never does. It depends on core alone.
 */

export {
	type AttemptCounterContractInput,
	type AttemptCounterHarness,
	attemptCounterContract,
	REAL_CLOCK_TOLERANCE_MS,
} from "./attempts/attemptCounter.contract.mjs";
export {
	type ConditionalRecordContractInput,
	type ConditionalRecordHarness,
	type ConditionalRecordTarget,
	type ConditionalSetContractInput,
	type ConditionalSetHarness,
	type ConditionalSetTarget,
	conditionalRecordContract,
	conditionalSetContract,
} from "./conditionalWrite/conditionalWrite.contract.mjs";
export type { ContractCase } from "./contractCase.mjs";
export {
	type HttpSettingsContractInput,
	httpSettingsContract,
} from "./deployment/httpSettings.contract.mjs";
export {
	type FederationGrantPolicyContractInput,
	federationGrantPolicyContract,
} from "./federationGrants/federationGrantPolicy.contract.mjs";
export {
	type FederationTokenStoreConditionalContractInput,
	type FederationTokenStoreConditionalHarness,
	federationTokenStoreConditionalContract,
} from "./federationTokens/federationTokenStoreConditional.contract.mjs";
export {
	MAIL_RELAY_REFUSALS,
	type MailRelayRefusal,
	type MailSenderContractInput,
	mailSenderContract,
	type RelayedMail,
} from "./mail/mailSender.contract.mjs";
export {
	type MfaEnrollmentWitnessContractInput,
	type MfaEnrollmentWitnessHarness,
	type MfaEnrollmentWitnessUser,
	mfaEnrollmentWitnessContract,
} from "./mfa/enrollmentWitness.contract.mjs";
export {
	type MfaFactorChallenge,
	type MfaFactorContractInput,
	type MfaFactorEnrollmentStart,
	mfaFactorContract,
} from "./mfa/factor.contract.mjs";
export {
	type MfaFactorStoreContractInput,
	type MfaFactorStoreHarness,
	mfaFactorStoreContract,
} from "./mfa/factorStore.contract.mjs";
export { mfaFactorStoreConditionalContract } from "./mfa/factorStoreConditional.contract.mjs";
export {
	FAKE_STORE_MAX_BODY_BYTES,
	type FakeStore,
	type FakeStoreAnswer,
	type FakeStoreAnswerer,
	type FakeStoreEndpoint,
	type FakeStoreOptions,
	type FakeStoreRequest,
	type FakeStoreUrls,
	type FakeStoreUser,
	startFakeStore,
} from "./mfa/fakeStore.mjs";
export {
	type RateLimiterContractInput,
	rateLimiterContract,
} from "./rateLimit/rateLimiter.contract.mjs";
export {
	type RequirementContractInput,
	sessionRequirementContract,
} from "./sessionAdmission/sessionRequirement.contract.mjs";
export {
	type SessionLifecycleStoreContractInput,
	type SessionLifecycleStoreHarness,
	sessionLifecycleStoreContract,
} from "./sessionLifecycle/sessionLifecycleStore.contract.mjs";
export {
	type CsrfGuardContractInput,
	csrfGuardContract,
} from "./sessionSlots/csrfGuard.contract.mjs";
export {
	type CsrfTokenSignerContractInput,
	csrfTokenSignerContract,
} from "./sessionSlots/csrfTokenSigner.contract.mjs";
export {
	type LoginCompletionContractInput,
	loginCompletionContract,
} from "./sessionSlots/loginCompletion.contract.mjs";
export {
	type LoginEntryContractInput,
	loginEntryContract,
} from "./sessionSlots/loginEntry.contract.mjs";
export {
	type SessionCookiePolicyContractInput,
	sessionCookiePolicyContract,
} from "./sessionSlots/sessionCookiePolicy.contract.mjs";
export {
	type OAuthTokenSettingsContractInput,
	oauthTokenSettingsContract,
} from "./tokenSettings/oauthTokenSettings.contract.mjs";
export {
	type WebAuthnCredentialStoreContractInput,
	type WebAuthnCredentialStoreHarness,
	webAuthnCredentialStoreContract,
} from "./webauthn/credentialStore.contract.mjs";
