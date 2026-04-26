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

type Slot =
	| { kind: "string"; value: string; expiresAtMs: number }
	| { kind: "hash"; fields: Map<string, string>; expiresAtMs: number };

/**
 * Hand-rolled fake redis client supporting the four ops the SingleUseTokenStore
 * redis adapter calls: `set` (with NX/PX), `hSetNX`, `hGet`, `pExpire`.
 *
 * Internally distinguishes string keys (used by `markSeen`) from hash keys
 * (used by `issue`/`consume`). Mismatching the type produces a `WRONGTYPE`
 * error matching real Redis.
 *
 * Intentionally minimal — production Redis behaviour is the contract the
 * adapter targets; this fake just lets contract tests run without a network
 * dependency.
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
				throw new Error("ERR invalid expire time in 'set' command");
			}
			const expiresAtMs = ttl === undefined ? Number.POSITIVE_INFINITY : nowMs + ttl;
			store.set(key, { kind: "string", value, expiresAtMs });
			return "OK";
		},

		async hSetNX(key, field, value) {
			const nowMs = Date.now();
			gc(key, nowMs);
			const slot = store.get(key);
			if (slot === undefined) {
				const fields = new Map<string, string>();
				fields.set(field, value);
				// Default TTL: never expires until pExpire is called.
				store.set(key, { kind: "hash", fields, expiresAtMs: Number.POSITIVE_INFINITY });
				return 1;
			}
			if (slot.kind !== "hash") {
				throw new Error("WRONGTYPE Operation against a key holding the wrong kind of value");
			}
			if (slot.fields.has(field)) return 0;
			slot.fields.set(field, value);
			return 1;
		},

		async hGet(key, field) {
			gc(key, Date.now());
			const slot = store.get(key);
			if (slot === undefined) return null;
			if (slot.kind !== "hash") {
				throw new Error("WRONGTYPE Operation against a key holding the wrong kind of value");
			}
			return slot.fields.get(field) ?? null;
		},

		async pExpire(key, ms) {
			gc(key, Date.now());
			const slot = store.get(key);
			if (slot === undefined) return 0;
			slot.expiresAtMs = Date.now() + ms;
			return 1;
		},
	};
}
