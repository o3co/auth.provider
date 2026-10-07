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
 * The test double of the `httpSettings` slot. `createTestHttpSettings`
 * trusts no forwarding hop and lets no origin read unless told otherwise;
 * it checks nothing. The contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import type { HttpSettings } from "../../deployment/types.mjs";

/** What a test replaces of the double's settings. */
export interface TestHttpSettingsOverrides {
	readonly trustProxy?: HttpSettings["trustProxy"];
	readonly allowedOrigins?: readonly string[];
}

/** No forwarding hop trusted and no origin allowed to read — unless `overrides` say otherwise — frozen. */
export function createTestHttpSettings(overrides: TestHttpSettingsOverrides = {}): HttpSettings {
	const trustProxy = overrides.trustProxy ?? false;
	return Object.freeze({
		trustProxy: Array.isArray(trustProxy) ? Object.freeze([...trustProxy]) : trustProxy,
		cors: Object.freeze({
			allowedOrigins: Object.freeze([...(overrides.allowedOrigins ?? [])]),
		}),
	});
}
