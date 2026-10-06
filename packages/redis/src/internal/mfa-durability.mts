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
 * The persistence notices both MFA store modules write at boot, once their
 * factory has passed the eviction gate (`eviction-policy.mts`). "Only a
 * subject with no record that may count opens a first binding" is only as
 * strong as the store: a restart without persistence empties a subject's
 * list, and whoever holds the password can then bind their own
 * authenticator. The email-proof requirement an operator reset records is
 * lost the same way. So:
 *
 * - RDB snapshots without AOF are one warning, no persistence at all another;
 * - what could not be read (a question the server refused, as many managed
 *   services refuse `CONFIG`, or answered without the value) is named in one
 *   warning that the check could not run, and the boot goes on;
 * - a server that cannot answer at all fails the boot, as any store outage at
 *   boot does.
 *
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D12.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";
import type { EvictableRefusal } from "./eviction-policy.mjs";

/** The two stores the check guards, by their slot. */
export type RedisMfaStoreSlot = "mfaFactorStore" | "mfaTransactionStore";

/** What each store's eviction gate says when it refuses a server. */
export const MFA_STORE_EVICTABLE: Readonly<{
	mfaFactorStore: EvictableRefusal<"mfa-factor-store-evictable">;
	mfaTransactionStore: EvictableRefusal<"mfa-transaction-store-evictable">;
}> = {
	mfaFactorStore: {
		reason: "mfa-factor-store-evictable",
		holds:
			"enrolled second factors, emptied sets' tombstones and writes' replay keys, and losing one lets an account read as never enrolled, or a resent write apply again",
	},
	mfaTransactionStore: {
		reason: "mfa-transaction-store-evictable",
		holds:
			"the email proof an operator reset requires, and each subject's lock, lease and first-binding mark, and losing one lets a password holder skip that proof, ends a lockout hold early, or lets a second writer at a subject's factors",
	},
};

const NAMES: Readonly<
	Record<
		RedisMfaStoreSlot,
		{ readonly lossy: string; readonly volatile: string; readonly unchecked: string }
	>
> = {
	mfaFactorStore: {
		lossy: "mfa_factor_store_lossy",
		volatile: "mfa_factor_store_volatile",
		unchecked: "mfa_factor_store_durability_unchecked",
	},
	mfaTransactionStore: {
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
	},
};

/**
 * Writes each persistence warning that applies to what `durability` answers
 * once on `logger`, object-first: the persistence's, then the one naming
 * what could not be read (`unread`: `appendonly`, `save`).
 */
export async function checkRedisMfaStorePersistence(
	store: RedisMfaStoreSlot,
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	const names = NAMES[store];
	const report = await durability();
	if (report.appendOnly === false && report.snapshots !== undefined) {
		logger.warn({ store, adapter: "redis" }, report.snapshots ? names.lossy : names.volatile);
	}
	const unread = [
		...(report.appendOnly === undefined ? ["appendonly"] : []),
		...(report.appendOnly === false && report.snapshots === undefined ? ["save"] : []),
	];
	if (unread.length > 0) {
		logger.warn(
			{
				store,
				adapter: "redis",
				unread,
				...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
			},
			names.unchecked,
		);
	}
}
