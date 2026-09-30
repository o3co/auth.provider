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
 * The federation token store's client over one ioredis connection. The index's add and its
 * expiry are one MULTI/EXEC whose reply is checked, and the lock is released only by the
 * compare-and-delete script.
 */

import type { Redis } from "ioredis";
import type { FederationTokenStoreClient } from "../../clients.mjs";
import { assertPipelineSucceeded, isNoScriptError } from "../commands.mjs";
import { LUA_COMPARE_AND_DELETE, LUA_COMPARE_AND_DELETE_SHA } from "../scripts/lock.mjs";

/**
 * Whether `LUA_COMPARE_AND_DELETE` is expected in the server's script cache: `true` lets the
 * next call use `EVALSHA`; a `NOSCRIPT` (after `SCRIPT FLUSH` or a failover) clears it, and the
 * `EVAL` fallback reloads the script and sets it again. Module-scoped, like every such flag here,
 * because the script is constant: clients in one process share the server's cache state.
 */
let scriptCached = false;

export function makeIoredisFederationTokenStoreClient(io: Redis): FederationTokenStoreClient {
	const federationTokenStoreClient: FederationTokenStoreClient = {
		get: (k) => io.get(k),
		// Cast required for overloaded `set`; see the user session store's in `./user-sessions.mts`.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as FederationTokenStoreClient["set"],
		del: (k) => io.del(k),
		unlink: (...keys) => io.unlink(...keys),
		// SADD and its expiry in one MULTI/EXEC, so the index key cannot be left without a TTL;
		// NX then GT as in the session stores' `pExpireGT`. MULTI rather than Lua: every command
		// touches one key, which stays valid on Cluster.
		sAddWithTtl: async (key, member, ttlMs) => {
			// EXEC succeeding does not mean the queued commands did: a refused PEXPIRE would void
			// the atomic-TTL guarantee.
			const reply = await io
				.multi()
				.sadd(key, member)
				.pexpire(key, ttlMs, "NX")
				.pexpire(key, ttlMs, "GT")
				.exec();
			assertPipelineSucceeded(reply, "federationTokenStoreClient.sAddWithTtl");
		},
		sRem: (key, member) => io.srem(key, member) as Promise<number>,
		sScanIterator: (key, opts) =>
			(async function* () {
				const stream = io.sscanStream(key, { count: opts?.COUNT });
				for await (const batch of stream) {
					for (const member of batch as string[]) yield member;
				}
			})(),
		scanIterator: ({ MATCH, COUNT }) =>
			(async function* () {
				const stream = io.scanStream({ match: MATCH, count: COUNT });
				for await (const batch of stream) {
					for (const key of batch as string[]) yield key;
				}
			})(),
		// Atomic compare-and-delete (advisory-lock release), EVALSHA-first; see `scriptCached`.
		async compareAndDelete(key, expectedValue) {
			if (scriptCached) {
				try {
					const r = (await io.evalsha(LUA_COMPARE_AND_DELETE_SHA, 1, key, expectedValue)) as number;
					return r === 1;
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					scriptCached = false;
					// Fall through to EVAL.
				}
			}
			const r = (await io.eval(LUA_COMPARE_AND_DELETE, 1, key, expectedValue)) as number;
			// EVAL loads the script into the server's cache, so the next EVALSHA hits.
			scriptCached = true;
			return r === 1;
		},
	};
	return federationTokenStoreClient;
}
