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
 * The test double of the `tokenBindingSettings` slot:
 * `createTestTokenBindingSettings` answers what an unset `core.tokenBinding`
 * reads as unless told otherwise; it checks nothing.
 */

import type { TokenBindingSettings } from "../../middleware/tokenBinding.mjs";

/** The intent-explicit policy and no confidential-client binding — unless `overrides` say otherwise — frozen. */
export function createTestTokenBindingSettings(
	overrides: Partial<TokenBindingSettings> = {},
): TokenBindingSettings {
	return Object.freeze({
		dispatchPolicy: overrides.dispatchPolicy ?? "intent-explicit",
		bindConfidentialClientRefreshTokens: overrides.bindConfidentialClientRefreshTokens ?? false,
	});
}
