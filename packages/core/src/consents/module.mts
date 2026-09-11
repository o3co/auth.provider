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

import { defineModule } from "../modules/index.mjs";
import { createMemoryConsentStore } from "./memory.mjs";

/**
 * Built-in module that provides the in-process memory {@link ConsentStore}
 * (#527). Dev and single-replica only — no persistence across restarts, and
 * refused by name under `deployment.mode = "multi"`.
 */
export const memoryConsentStoreModule = defineModule({
	name: "core-consent-store-memory",
	// #455: what forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"consent records fork per replica — a consent granted on one replica is asked for again on every other, and one revoked there stays granted here",
	},
	provides: {
		consentStore: () => createMemoryConsentStore(),
	},
});
