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
 * The modules that provide core's in-process MFA stores. Both are for
 * development and a single replica, and are refused by name under
 * `core.deployment.mode = "multi"`.
 */

import { z } from "zod";
import { coreReference } from "../config/references.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import { defineModule } from "../modules/manifest/index.mjs";
import { configuredMaxEntries } from "../single-use/max-entries.mjs";
import { warnMfaFactorStoreInMemory, warnMfaTransactionStoreInMemory } from "./factory.mjs";
import { createMemoryMfaFactorStore } from "./memoryFactorStore.mjs";
import { createMemoryMfaTransactionStore } from "./memoryTransactionStore.mjs";

/**
 * Provides the in-process {@link MfaFactorStore}. A restart loses every
 * enrollment; without the enrollment witness, whoever holds a password could
 * then bind their own authenticator, so the module warns once when built.
 */
export const memoryMfaFactorStoreModule = defineModule({
	name: "core-mfa-factor-store-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
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
 * ceremonies in flight, lifts the subject lock state, and drops the email-proof
 * requirement an operator reset recorded, so beside a durable factor store a
 * password holder could then bind without the proof; the module warns once when
 * built. Capped at
 * `core-mfa-transaction-store-memory.maxEntries`, its own section (adapter
 * default when unset); a value that is not a positive whole number refuses the
 * boot, naming the key. The section is strict; `mfaTransactionStore.memory`,
 * its old path, refuses boot naming it.
 */
export const memoryMfaTransactionStoreModule = defineModule({
	name: "core-mfa-transaction-store-memory",
	section: {
		schema: z.object({ maxEntries: z.unknown().optional() }).strict().optional(),
		reference: coreReference(),
		relocatedFrom: { "mfaTransactionStore.memory": { to: "", environmentVariable: null } },
	},
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"MFA transactions and attempt limits fork per replica — a transaction started on one replica is unknown to the replica that receives the verification, and the attempt limits and the lockout are counted per replica; and a restart loses the email proof an operator reset required, so beside a durable factor store a password holder can then bind without it",
	},
	optional: ["logger"] as const,
	provides: {
		mfaTransactionStore: ({ section, logger }) => {
			const store = createMemoryMfaTransactionStore(
				configuredMaxEntries(section?.maxEntries, "core-mfa-transaction-store-memory.maxEntries"),
			);
			warnMfaTransactionStoreInMemory(logger ?? consoleLogger);
			return store;
		},
	},
});
