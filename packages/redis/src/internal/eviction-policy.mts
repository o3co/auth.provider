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
 * What a Redis server's `maxmemory-policy` may evict, and the refusal a store's
 * boot check throws for a policy it cannot run under. Boot carries the refusal
 * as the `cause` of a `provides-factory-failed` BootError naming the module.
 */

/** The policies that evict only keys with a TTL. */
export const VOLATILE_POLICIES: ReadonlySet<string> = new Set([
	"volatile-lru",
	"volatile-lfu",
	"volatile-random",
	"volatile-ttl",
]);

/** The policies that may evict any key. */
export const ALLKEYS_POLICIES: ReadonlySet<string> = new Set([
	"allkeys-lru",
	"allkeys-lfu",
	"allkeys-random",
]);

/** What a store's refusal says, beside the policy. */
export interface EvictableRefusal<R extends string> {
	/** The refusal's `reason`, also named at the end of its message. */
	readonly reason: R;
	/** What the policy may evict, e.g. "any key". */
	readonly evicts: string;
	/** What an eviction would lose. */
	readonly holds: string;
	/** What the refusal tells an operator to set. */
	readonly remedy: string;
}

/**
 * The refusal of a server whose `maxmemory-policy` may evict what `store`
 * relies on. `reason` and `maxmemoryPolicy` say what refused it. It quotes the
 * server's policy and nothing else.
 */
export class RedisStoreEvictableError<R extends string = string> extends Error {
	readonly reason: R;
	readonly maxmemoryPolicy: string;

	constructor(store: string, maxmemoryPolicy: string, refusal: EvictableRefusal<R>) {
		super(
			`${store}: the Redis server's maxmemory-policy is "${maxmemoryPolicy}", which may evict ${refusal.evicts} — ${refusal.holds}; set maxmemory-policy to ${refusal.remedy}, or give ${store} a server of its own (${refusal.reason})`,
		);
		this.name = "RedisStoreEvictableError";
		this.reason = refusal.reason;
		this.maxmemoryPolicy = maxmemoryPolicy;
	}
}
