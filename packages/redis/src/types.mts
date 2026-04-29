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
 * Minimal structural Redis client interface consumed by every adapter in this
 * package. The signature is shaped to match ioredis's variadic-positional
 * `set(key, value, "PX", ttlMs, "NX")` form because that is the in-tree
 * reference implementation. Consumers using a Redis library with a different
 * call shape (e.g. node-redis v4+'s options-object form
 * `client.set(key, value, { PX: ttl, NX: true })`, keyv-redis, in-cluster
 * Redis wrappers, sharded fakes) provide a thin adapter wrapper that
 * normalises the call and pass that wrapper as the `redisClient` ComponentMap
 * slot or directly to `create*(opts)` constructors.
 *
 * The shape covers ONLY the ops Phase 5+6 adapters need:
 *   - set(key, value, "PX", ttlMs, "NX") → atomic SET with TTL + NX condition
 *     (A1 ChallengeStore.issue, A1 ReplaySeenSet.markSeen, A3 registerFamily)
 *   - del(key) → returns count deleted (A1 ChallengeStore.consume)
 *   - pttl(key) → milliseconds to expiry (A1 ChallengeStore.find, A3 findFamily)
 *   - exists(key) → 1 if exists, 0 if not (A1 ReplaySeenSet.contains)
 *   - get(key) → string | null (A3 findFamily, A3 updateFamily CAS read)
 *   - watch(...keys) → CAS setup (A3 updateFamily)
 *   - unwatch() → CAS release without commit (A3 updateFamily abort)
 *   - multi() → chainable transaction pipeline (A3 updateFamily commit)
 *
 * Future cross-cutting adapters (user sessions, federation tokens) will
 * extend this surface additively per A1 §5.5.
 *
 * Per A1 §5.5 + A3 §7.2.
 */
export interface RedisClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	del(key: string): Promise<number>;
	pttl(key: string): Promise<number>;
	exists(key: string): Promise<number>;
	get(key: string): Promise<string | null>;
	watch(...keys: string[]): Promise<"OK">;
	unwatch(): Promise<"OK">;
	multi(): RedisMulti;
}

/**
 * Chainable transaction pipeline returned by `RedisClient.multi()`.
 *
 * The chainable shape (`set(...) → RedisMulti`) matches ioredis's API
 * (`pipeline.set(k, v).exec()`) and node-redis v4+'s multi API
 * (`multi.set(k, v).exec()`). Consumers wrapping a library with a
 * record-shaped command queue (e.g. older node-redis 3.x style) provide a
 * thin shim that buffers calls and replays them on `exec()`.
 *
 * `exec()` returns `unknown[] | null`:
 *   - On successful commit: an array of per-command results (the wrapper
 *     does not inspect the array contents; presence of a non-null array
 *     means the transaction committed atomically).
 *   - On CAS conflict (any WATCH'd key was modified between WATCH and
 *     EXEC): `null`. This is the A3 updateFamily retry signal.
 *
 * Per A3 §7.2.
 */
export interface RedisMulti {
	set(key: string, value: string, mode: "PX", ttlMs: number): RedisMulti;
	exec(): Promise<unknown[] | null>;
}
