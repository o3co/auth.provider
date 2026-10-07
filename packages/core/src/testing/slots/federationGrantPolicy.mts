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
 * The test double of the `federationGrantPolicy` slot.
 * `createTestFederationGrantPolicy` answers grants off unless told
 * otherwise; it checks nothing, so a test of a broken value builds it here.
 * The contract suite is `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import type { FederationGrantPolicy } from "../../federation-grants/policy.mjs";

/** Grants off and nothing kept — unless `overrides` say otherwise — frozen. */
export function createTestFederationGrantPolicy(
	overrides: Partial<FederationGrantPolicy> = {},
): FederationGrantPolicy {
	return Object.freeze({
		enabled: overrides.enabled ?? false,
		allowKeepOnSubjectRevocation: overrides.allowKeepOnSubjectRevocation ?? false,
	});
}
