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
 * The boot check both MFA store modules run (the MFA ADR's D12, and its
 * step-3 amendment for the transaction store's email-proof key family).
 *
 * "Only zero records open a first binding" (F3) is only as strong as the
 * store that holds the records: an eviction, or a restart without
 * persistence, empties a subject's list, and whoever holds the password can
 * then bind their own authenticator. The email-proof requirement an operator
 * reset records is lost the same way. So, before the store is provided:
 *
 * - an `allkeys-*` `maxmemory-policy`, which may evict any key, refuses the
 *   boot. `noeviction` and the `volatile-*` policies pass: the factors and
 *   the requirement carry no TTL, so a `volatile-*` policy never picks them;
 * - RDB snapshots without AOF are one warning: a crash loses the last
 *   snapshot interval of what was written;
 * - no persistence at all is one warning: a restart loses everything;
 * - a server that refuses `CONFIG` — many managed services rename or disable
 *   it — is one warning that the check could not run, and the boot goes on;
 * - a server that cannot be asked at all fails the boot, as any store outage
 *   at boot does: it is not a refusal.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";

/** The two stores the check guards, by their slot. */
export type RedisMfaStoreSlot = "mfaFactorStore" | "mfaTransactionStore";

const NAMES: Readonly<
	Record<
		RedisMfaStoreSlot,
		{
			readonly evictable: "mfa-factor-store-evictable" | "mfa-transaction-store-evictable";
			readonly lossy: string;
			readonly volatile: string;
			readonly unchecked: string;
			/** What an eviction would lose, for the refusal's message. */
			readonly holds: string;
		}
	>
> = {
	mfaFactorStore: {
		evictable: "mfa-factor-store-evictable",
		lossy: "mfa_factor_store_lossy",
		volatile: "mfa_factor_store_volatile",
		unchecked: "mfa_factor_store_durability_unchecked",
		holds:
			"enrolled second factors, and an account whose factors are evicted reads as never enrolled",
	},
	mfaTransactionStore: {
		evictable: "mfa-transaction-store-evictable",
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
		holds:
			"the email proof an operator reset requires at the next first binding, which a password holder could then skip",
	},
};

/**
 * The refusal of a server whose `maxmemory-policy` may evict any key. Boot
 * carries it as the `cause` of a `provides-factory-failed` BootError naming
 * the module; `reason` and `maxmemoryPolicy` say what refused it. It quotes
 * the server's policy and nothing else.
 */
export class RedisMfaStoreEvictableError extends Error {
	readonly reason: "mfa-factor-store-evictable" | "mfa-transaction-store-evictable";
	readonly maxmemoryPolicy: string;

	constructor(store: RedisMfaStoreSlot, maxmemoryPolicy: string) {
		const names = NAMES[store];
		super(
			`${store}: the Redis server's maxmemory-policy is "${maxmemoryPolicy}", which may evict any key — ${names.holds}; set maxmemory-policy to "noeviction" (or a "volatile-*" policy), or give ${store} a server of its own (${names.evictable})`,
		);
		this.name = "RedisMfaStoreEvictableError";
		this.reason = names.evictable;
		this.maxmemoryPolicy = maxmemoryPolicy;
	}
}

/**
 * Runs the check for `store` on what `durability` answers: throws
 * {@link RedisMfaStoreEvictableError} for an `allkeys-*` policy, and writes
 * at most one warning on `logger`, object-first.
 */
export async function checkRedisMfaStoreDurability(
	store: RedisMfaStoreSlot,
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	const names = NAMES[store];
	const report = await durability();
	if (!report.checked) {
		logger.warn({ store, adapter: "redis", err: loggableError(report.refusal) }, names.unchecked);
		return;
	}
	if (report.maxmemoryPolicy.startsWith("allkeys-")) {
		throw new RedisMfaStoreEvictableError(store, report.maxmemoryPolicy);
	}
	if (report.appendOnly) return;
	logger.warn({ store, adapter: "redis" }, report.snapshots ? names.lossy : names.volatile);
}
