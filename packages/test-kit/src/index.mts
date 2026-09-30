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
	type MfaEnrollmentWitnessContractInput,
	type MfaEnrollmentWitnessHarness,
	type MfaEnrollmentWitnessUser,
	mfaEnrollmentWitnessContract,
} from "./mfa/enrollmentWitness.contract.mjs";
export {
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
