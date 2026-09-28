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
 * - for the transaction store, a `volatile-*` policy is one warning: its
 *   subject lock and weekly window carry a TTL once no run is counted, and an
 *   evicted one lifts a D21 hold early. `noeviction` is what the MFA key
 *   families are meant to run on;
 * - RDB snapshots without AOF are one warning: a crash loses the last
 *   snapshot interval of what was written;
 * - no persistence at all is one warning: a restart loses everything;
 * - the policy is judged by an allow-list: `noeviction` passes, the four
 *   `volatile-*` policies are each store's to judge, the three `allkeys-*`
 *   refuse; anything else — empty, unknown, a future server's — is a policy
 *   the check cannot judge, named in the warning below;
 * - what could not be read — a question the server refused, as many managed
 *   services refuse `CONFIG`, or answered without the value — is named in one
 *   warning that the check could not run, and the boot goes on. The policy is
 *   read from `INFO memory` first, so a server that blocks `CONFIG` is still
 *   held to the refusal, and each part is judged on its own: a known
 *   `allkeys-*` policy refuses whatever else could not be read;
 * - a server that cannot answer at all fails the boot, as any store outage at
 *   boot does: it is not a refusal.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";

/** The policies that cannot evict a key without a TTL, which is what each store's durable keys are. */
const VOLATILE_POLICIES: ReadonlySet<string> = new Set([
	"volatile-lru",
	"volatile-lfu",
	"volatile-random",
	"volatile-ttl",
]);

/** The policies that may evict any key. */
const ALLKEYS_POLICIES: ReadonlySet<string> = new Set([
	"allkeys-lru",
	"allkeys-lfu",
	"allkeys-random",
]);

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
			readonly lockEvictable: string | undefined;
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
		lockEvictable: undefined,
		holds:
			"enrolled second factors, and an account whose factors are evicted reads as never enrolled",
		remedy:
			'"noeviction" (or a "volatile-*" policy, which never picks these keys: they carry no TTL)',
	},
	mfaTransactionStore: {
		evictable: "mfa-transaction-store-evictable",
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
		lockEvictable: "mfa_transaction_store_lock_evictable",
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
export class RedisMfaStoreEvictableError extends Error {
	readonly reason: "mfa-factor-store-evictable" | "mfa-transaction-store-evictable";
	readonly maxmemoryPolicy: string;

	constructor(store: RedisMfaStoreSlot, maxmemoryPolicy: string) {
		const names = NAMES[store];
		super(
			`${store}: the Redis server's maxmemory-policy is "${maxmemoryPolicy}", which may evict any key — ${names.holds}; set maxmemory-policy to ${names.remedy}, or give ${store} a server of its own (${names.evictable})`,
		);
		this.name = "RedisMfaStoreEvictableError";
		this.reason = names.evictable;
		this.maxmemoryPolicy = maxmemoryPolicy;
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
	if (names.lockEvictable !== undefined && policy !== undefined && VOLATILE_POLICIES.has(policy)) {
		logger.warn({ store, adapter: "redis", maxmemoryPolicy: policy }, names.lockEvictable);
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
