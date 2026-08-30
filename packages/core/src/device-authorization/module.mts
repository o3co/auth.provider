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
 * Built-in module providing the in-process `DeviceCodeStore` (#298).
 *
 * Development and single-replica only — see `memory.mts` and the entry in
 * `REPLICA_UNSAFE_MODULE_REASONS`, which is what makes a `deployment.mode =
 * "multi"` composition refuse to boot with this mounted.
 */
import { defineModule } from "../modules/manifest/index.mjs";
import { createMemoryDeviceCodeStore } from "./memory.mjs";

export const memoryDeviceCodeStoreModule = defineModule({
	name: "core-device-code-store-memory",
	provides: {
		deviceCodeStore: () => createMemoryDeviceCodeStore(),
	},
});
