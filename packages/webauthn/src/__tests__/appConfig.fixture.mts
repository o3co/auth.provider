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
 * `makeValidAppConfig()` with what a resolution of the package's reference
 * under an environment that sets none of its variables would capture beside
 * core's: every name the WebAuthn module declares renamed, `null`.
 */

import { makeValidAppConfig, renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { webauthnModule } from "../module.mjs";

export function makeAppConfig(): ReturnType<typeof makeValidAppConfig> {
	const base = makeValidAppConfig();
	return {
		...base,
		"renamed-variables": {
			...base["renamed-variables"],
			...renamedVariableCaptures({ modules: [webauthnModule], env: {} }),
		},
	};
}
