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

import type { RedisLikeClient } from "#/single-use-tokens/adapters/redis.mjs";

interface Slot {
	value: string;
	expiresAtMs: number;
}

/**
 * Hand-rolled fake redis client that supports just the four ops the
 * SingleUseTokenStore redis adapter calls: `set` (with NX/PX), `get`,
 * `pTTL`, and `eval` (executing the inlined Lua-equivalent JavaScript).
 *
 * Intentionally minimal — production Redis behaviour is the contract
 * the adapter targets; this fake just lets contract tests run without
 * a network dependency.
 */
export function createFakeRedis(): RedisLikeClient & { _store: Map<string, Slot> } {
	const store = new Map<string, Slot>();

	const gc = (k: string, nowMs: number): void => {
		const v = store.get(k);
		if (v !== undefined && v.expiresAtMs <= nowMs) store.delete(k);
	};

	return {
		_store: store,

		async set(key, value, opts) {
			const nowMs = Date.now();
			gc(key, nowMs);
			if (opts?.NX === true && store.has(key)) return null;
			const ttl = opts?.PX;
			if (ttl !== undefined && ttl <= 0) {
				// Match real redis behaviour: SET with non-positive PX errors.
				throw new Error("ERR invalid expire time in 'set' command");
			}
			const expiresAtMs = ttl === undefined ? Number.POSITIVE_INFINITY : nowMs + ttl;
			store.set(key, { value, expiresAtMs });
			return "OK";
		},

		async get(key) {
			gc(key, Date.now());
			return store.get(key)?.value ?? null;
		},

		async pTTL(key) {
			const nowMs = Date.now();
			gc(key, nowMs);
			const slot = store.get(key);
			if (slot === undefined) return -2;
			if (slot.expiresAtMs === Number.POSITIVE_INFINITY) return -1;
			return Math.max(0, slot.expiresAtMs - nowMs);
		},

		async eval(script, opts) {
			// We accept ONLY the consume Lua script our adapter ships. Any other
			// script means a test wrote a Lua we don't know — fail loudly so we
			// notice at adapter changes.
			if (!script.includes("issued") || !script.includes("consumed")) {
				throw new Error("fakeRedis.eval: unrecognised script");
			}
			const key = opts.keys[0];
			if (key === undefined) throw new Error("fakeRedis.eval: missing key");
			const nowMs = Date.now();
			gc(key, nowMs);
			const slot = store.get(key);
			if (slot === undefined) return "unknown";
			if (slot.value === "consumed") return "replayed";
			// issued -> consumed, preserving remaining TTL
			const pttl = slot.expiresAtMs - nowMs;
			if (pttl < 0) {
				store.delete(key);
				return "unknown";
			}
			store.set(key, { value: "consumed", expiresAtMs: slot.expiresAtMs });
			return "consumed";
		},
	};
}
