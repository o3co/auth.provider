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
 * `@o3co/auth-provider-foundation/testing`: what a test uses to configure
 * this package's modules. Test code imports it; production code never does.
 */

import {
	FOUNDATION_MFA_FACTOR_STORE_SECTION,
	type FoundationMfaFactorStoreUrls,
} from "../mfa/section.mjs";

const URL_KEYS = ["listUrl", "createUrl", "updateUrl", "deleteUrl"] as const;

/**
 * The `foundation-mfa-factor-store` section as a configuration fragment to
 * lay over a test's configuration: the four URLs `urls` holds — a fake
 * Store's `urls` included, its other endpoints left behind — and `extra`
 * as given.
 */
export function foundationMfaFactorStoreConfig(
	urls: Partial<Readonly<Record<keyof FoundationMfaFactorStoreUrls, unknown>>>,
	extra: Readonly<Record<string, unknown>> = {},
): { readonly [FOUNDATION_MFA_FACTOR_STORE_SECTION]: Readonly<Record<string, unknown>> } {
	const section: Record<string, unknown> = {};
	for (const key of URL_KEYS) {
		if (urls[key] !== undefined) section[key] = urls[key];
	}
	return { [FOUNDATION_MFA_FACTOR_STORE_SECTION]: { ...section, ...extra } };
}
