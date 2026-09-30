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
 * `@o3co/auth-provider-mfa/testing`: the builders a test assembles this
 * package's configuration with, so no test writes a section of this
 * package's by hand. Test code imports it; production code never does.
 */

import { mfaEmailFactorModule } from "../email/module.mjs";

/**
 * The email factor's section, keyed by its module's name, as the package's
 * `reference.conf` defaults it, with `overrides` laid over it — ready to
 * spread into a test's configuration.
 */
export function mfaEmailFactorConfig(
	overrides: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, Readonly<Record<string, unknown>>>> {
	return {
		[mfaEmailFactorModule.name]: {
			enabled: false,
			addsMfa: false,
			codeTtlSeconds: 600,
			...overrides,
		},
	};
}
