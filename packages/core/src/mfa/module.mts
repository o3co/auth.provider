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
 * The modules that provide core's in-process MFA stores (the MFA ADR's D7,
 * D8, D10). Both are for development and a single replica, and both are
 * refused by name under `deployment.mode = "multi"`.
 */

import { consoleLogger } from "../logging/consoleLogger.mjs";
import { defineModule } from "../modules/manifest/index.mjs";
import { warnMfaFactorStoreInMemory } from "./factory.mjs";
import { createMemoryMfaFactorStore } from "./memoryFactorStore.mjs";
import { createMemoryMfaTransactionStore } from "./memoryTransactionStore.mjs";

/**
 * Provides the in-process {@link MfaFactorStore}. Every enrollment is lost at
 * the next restart, after which each subject reads as one with nothing
 * enrolled: without the enrollment witness (D12) that lets whoever holds a
 * password bind their own authenticator, so the module warns once when it is
 * built.
 */
export const memoryMfaFactorStoreModule = defineModule({
	name: "core-mfa-factor-store-memory",
	// #455: what forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"enrolled second factors fork per replica and vanish on restart — a factor enrolled on one replica is unknown to every other, and after a restart every subject reads as one with nothing enrolled",
	},
	optional: ["logger"] as const,
	provides: {
		mfaFactorStore: (deps) => {
			warnMfaFactorStoreInMemory(deps.logger ?? consoleLogger);
			return createMemoryMfaFactorStore();
		},
	},
});

/**
 * Provides the in-process {@link MfaTransactionStore}. A restart loses the
 * ceremonies in flight — each user starts again from the password — and the
 * subject lock state, which a restart therefore lifts.
 */
export const memoryMfaTransactionStoreModule = defineModule({
	name: "core-mfa-transaction-store-memory",
	// #455: what forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"MFA transactions and attempt limits fork per replica — a transaction started on one replica is unknown to the replica that receives the verification, and the attempt limits, the lockout and the trusted browsers are counted per replica",
	},
	provides: {
		mfaTransactionStore: () => createMemoryMfaTransactionStore(),
	},
});
