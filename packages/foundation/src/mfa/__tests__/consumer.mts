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

/** A module that requires a factor store, and records the one it was handed. */

import { defineModule, type MfaFactorStore, type Module } from "@o3co/auth-provider-core";

export function consumer(seen: { store?: MfaFactorStore }): Module {
	return defineModule({
		name: "test-mfa-factor-store-consumer",
		requires: ["mfaFactorStore"] as const,
		contributes: {
			routes: [
				(deps) => {
					seen.store = deps.mfaFactorStore;
					return {
						id: "test-mfa-factor-store-consumer",
						mountPath: "/__test_mfa_factor_store_consumer__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});
}
