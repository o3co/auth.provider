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
export { attemptCounterContract, REAL_CLOCK_TOLERANCE_MS, } from "./attempts/attemptCounter.contract.mjs";
export { conditionalRecordContract, conditionalSetContract, } from "./conditionalWrite/conditionalWrite.contract.mjs";
export { httpSettingsContract, } from "./deployment/httpSettings.contract.mjs";
export { federationGrantPolicyContract, } from "./federationGrants/federationGrantPolicy.contract.mjs";
export { federationTokenStoreConditionalContract, } from "./federationTokens/federationTokenStoreConditional.contract.mjs";
export { MAIL_RELAY_REFUSALS, mailSenderContract, } from "./mail/mailSender.contract.mjs";
export { mfaEnrollmentWitnessContract, } from "./mfa/enrollmentWitness.contract.mjs";
export { mfaFactorContract, } from "./mfa/factor.contract.mjs";
export { mfaFactorStoreContract, } from "./mfa/factorStore.contract.mjs";
export { mfaFactorStoreConditionalContract } from "./mfa/factorStoreConditional.contract.mjs";
export { FAKE_STORE_MAX_BODY_BYTES, startFakeStore, } from "./mfa/fakeStore.mjs";
export { rateLimiterContract, } from "./rateLimit/rateLimiter.contract.mjs";
export { sessionRequirementContract, } from "./sessionAdmission/sessionRequirement.contract.mjs";
export { sessionLifecycleStoreContract, } from "./sessionLifecycle/sessionLifecycleStore.contract.mjs";
export { csrfGuardContract, } from "./sessionSlots/csrfGuard.contract.mjs";
export { csrfTokenSignerContract, } from "./sessionSlots/csrfTokenSigner.contract.mjs";
export { loginCompletionContract, } from "./sessionSlots/loginCompletion.contract.mjs";
export { loginEntryContract, } from "./sessionSlots/loginEntry.contract.mjs";
export { sessionCookiePolicyContract, } from "./sessionSlots/sessionCookiePolicy.contract.mjs";
export { oauthTokenSettingsContract, } from "./tokenSettings/oauthTokenSettings.contract.mjs";
export { webAuthnCredentialStoreContract, } from "./webauthn/credentialStore.contract.mjs";
