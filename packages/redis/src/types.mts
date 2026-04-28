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
 * package. Consumers wrap their preferred library (ioredis, node-redis,
 * keyv-redis, etc.) and provide an instance via the `redisClient` ComponentMap
 * slot or directly to adapter `create*(opts)` constructors.
 *
 * The shape covers ONLY the ops Phase 5 adapters need:
 *   - set(key, value, "PX", ttlMs, "NX") → atomic SET with TTL + NX condition
 *   - del(key) → returns count deleted (0 or 1)
 *   - pttl(key) → milliseconds to expiry (-2 absent, -1 no-TTL, ≥0 remaining)
 *   - exists(key) → 1 if exists, 0 if not
 *
 * Future cross-cutting adapters (refresh tokens, user sessions) will extend
 * this surface additively.
 *
 * Per A1 §5.5.
 */
export interface RedisClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	del(key: string): Promise<number>;
	pttl(key: string): Promise<number>;
	exists(key: string): Promise<number>;
}
