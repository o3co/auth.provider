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
 * Built-in module providing the in-process `DeviceCodeStore`.
 *
 * Development and single-replica only: `replicaSafety` makes a
 * `core.deployment.mode = "multi"` composition refuse to boot with it mounted.
 * `dispose` is registered with the lifecycle registrar so
 * `AppHandle.dispose()` stops the sweep timer; the registrar is optional.
 */
import { defineModule } from "../modules/manifest/index.mjs";
import { createMemoryDeviceCodeStore } from "./memory.mjs";

export const memoryDeviceCodeStoreModule = defineModule({
	name: "core-device-code-store-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"pending device authorizations fork per replica — the human approves a code on the replica that served the verification page, while the device polls a replica that has never heard of it and is told the code does not exist (#298)",
	},
	optional: ["lifecycleRegistrar"] as const,
	provides: {
		deviceCodeStore: (deps) => {
			const store = createMemoryDeviceCodeStore();
			deps.lifecycleRegistrar?.register(async () => {
				store.dispose();
			});
			return store;
		},
	},
});
