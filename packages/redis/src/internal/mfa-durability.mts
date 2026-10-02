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
 * The boot check both MFA store modules run. "Only a subject with no record
 * that may count opens a first binding" is only as strong as the store: an eviction, or a restart without
 * persistence, empties a subject's list, and whoever holds the password can
 * then bind their own authenticator. The email-proof requirement an operator
 * reset records is lost the same way. So, before the store is provided:
 *
 * - the policy is judged by an allow-list. `noeviction` passes. The three
 *   `allkeys-*`, which may evict any key, refuse the boot, whatever else could
 *   not be read. The four `volatile-*` pass: they never pick the factors or
 *   the requirement, which carry no TTL. Each store still warns on them,
 *   naming the key families an eviction fails open on. The factor store's:
 *   an emptied factor set's tombstone carries a TTL, and an evicted one reads
 *   as a set never written before the write lifetime has passed, so a first
 *   binding read before the set came and went may land; a write's replay key
 *   carries one until the write's deadline, and an evicted one lets a copy
 *   the driver resends apply again. The transaction store's: its subject
 *   lock and weekly window carry a TTL once no run is counted, and an evicted
 *   one lifts a lockout hold early; a subject's first-binding mark carries one
 *   always, and an evicted one no longer refuses a stale session's first
 *   binding; a subject's lease carries one always, and an evicted one lets a
 *   second writer in. Any other policy
 *   (empty, unknown, a future server's) cannot be judged and is named in the
 *   warning below;
 * - RDB snapshots without AOF are one warning, no persistence at all another;
 * - what could not be read (a question the server refused, as many managed
 *   services refuse `CONFIG`, or answered without the value) is named in one
 *   warning that the check could not run, and the boot goes on. The policy is
 *   read from `INFO memory` first, so a server that blocks `CONFIG` is still
 *   held to the refusal;
 * - a server that cannot answer at all fails the boot, as any store outage at
 *   boot does.
 *
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D12.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";
import {
	ALLKEYS_POLICIES,
	RedisStoreEvictableError,
	VOLATILE_POLICIES,
} from "./eviction-policy.mjs";

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
			/** The notice a `volatile-*` policy is given, where some of the store's keys carry a TTL. */
			readonly volatileEvictable: string | undefined;
			/** The key families that notice names: each carries a TTL, and losing one fails open. */
			readonly evictableFamilies: readonly string[] | undefined;
			/** What an eviction would lose, for the refusal's message. */
			readonly holds: string;
			/** What the refusal tells an operator to set. */
			readonly remedy: string;
		}
	>
> = {
	mfaFactorStore: {
		evictable: "mfa-factor-store-evictable",
		lossy: "mfa_factor_store_lossy",
		volatile: "mfa_factor_store_volatile",
		unchecked: "mfa_factor_store_durability_unchecked",
		volatileEvictable: "mfa_factor_store_tombstone_evictable",
		evictableFamilies: ["tombstone", "replay"],
		holds:
			"enrolled second factors, and an account whose factors are evicted reads as never enrolled",
		remedy: '"noeviction"',
	},
	mfaTransactionStore: {
		evictable: "mfa-transaction-store-evictable",
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
		volatileEvictable: "mfa_transaction_store_lock_evictable",
		evictableFamilies: ["lock", "week", "first-binding", "lease"],
		holds:
			"the email proof an operator reset requires at the next first binding, which a password holder could then skip",
		remedy: '"noeviction"',
	},
};

/**
 * The refusal of a server whose `maxmemory-policy` may evict any key. Boot
 * carries it as the `cause` of a `provides-factory-failed` BootError naming
 * the module; `reason` and `maxmemoryPolicy` say what refused it. It quotes
 * the server's policy and nothing else.
 */
export class RedisMfaStoreEvictableError extends RedisStoreEvictableError<
	"mfa-factor-store-evictable" | "mfa-transaction-store-evictable"
> {
	constructor(store: RedisMfaStoreSlot, maxmemoryPolicy: string) {
		const names = NAMES[store];
		super(store, maxmemoryPolicy, {
			reason: names.evictable,
			evicts: "any key",
			holds: names.holds,
			remedy: names.remedy,
		});
		this.name = "RedisMfaStoreEvictableError";
	}
}

/**
 * Runs the check for `store` on what `durability` answers: throws
 * {@link RedisMfaStoreEvictableError} for a known `allkeys-*` policy, and
 * writes each warning that applies once on `logger`, object-first — the
 * eviction policy's, then the persistence's, then the one naming a policy it
 * cannot judge (`maxmemoryPolicy`) and what could not be read (`unread`:
 * `maxmemory-policy`, `appendonly`, `save`).
 */
export async function checkRedisMfaStoreDurability(
	store: RedisMfaStoreSlot,
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	const names = NAMES[store];
	const report = await durability();
	const policy = report.maxmemoryPolicy;
	if (policy !== undefined && ALLKEYS_POLICIES.has(policy)) {
		throw new RedisMfaStoreEvictableError(store, policy);
	}
	if (
		names.volatileEvictable !== undefined &&
		policy !== undefined &&
		VOLATILE_POLICIES.has(policy)
	) {
		logger.warn(
			{
				store,
				adapter: "redis",
				maxmemoryPolicy: policy,
				evictableFamilies: names.evictableFamilies,
			},
			names.volatileEvictable,
		);
	}
	/** A policy read but not one the allow-list knows: it cannot be judged. */
	const unjudged =
		policy !== undefined && policy !== "noeviction" && !VOLATILE_POLICIES.has(policy)
			? policy
			: undefined;
	if (report.appendOnly === false && report.snapshots !== undefined) {
		logger.warn({ store, adapter: "redis" }, report.snapshots ? names.lossy : names.volatile);
	}
	const unread = [
		...(policy === undefined ? ["maxmemory-policy"] : []),
		...(report.appendOnly === undefined ? ["appendonly"] : []),
		...(report.appendOnly === false && report.snapshots === undefined ? ["save"] : []),
	];
	if (unread.length > 0 || unjudged !== undefined) {
		logger.warn(
			{
				store,
				adapter: "redis",
				...(unjudged === undefined ? {} : { maxmemoryPolicy: unjudged }),
				...(unread.length === 0 ? {} : { unread }),
				...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
			},
			names.unchecked,
		);
	}
}
