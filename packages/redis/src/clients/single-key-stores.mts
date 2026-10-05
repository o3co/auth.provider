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
 * Clients for the stores that keep each record as one string key with a `PX` expiry:
 * challenges, the access-token denylist, the replay seen-set and authorization codes.
 */

// --- ChallengeStoreClient --------------------------------------------------

/**
 * Backing client for ChallengeStore adapters. Adapter implementations
 * (e.g. `createRedisChallengeStore`) consume exactly these methods.
 */
export interface ChallengeStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	pttl(key: string): Promise<number>;
	del(key: string): Promise<number>;
	/** Reads a challenge's value, which carries when it was issued. */
	get(key: string): Promise<string | null>;
}

// --- AccessTokenDenylistClient ---------------------------------------------

/**
 * Backing client for AccessTokenDenylist adapters
 * (`createRedisAccessTokenDenylist`).
 *
 * `set` is the plain PX form with no `NX`: re-revoking a jti is idempotent and
 * last-write-wins on the expiry, matching the memory adapter. That is also why
 * this is separate from {@link ReplaySeenSetClient}, whose whole contract
 * turns on the `NX` return value.
 */
export interface AccessTokenDenylistClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	exists(key: string): Promise<number>;
}

// --- ReplaySeenSetClient ---------------------------------------------------

/**
 * Backing client for ReplaySeenSet adapters. Adapter implementations
 * (e.g. `createRedisReplaySeenSet`) consume exactly these methods.
 */
export interface ReplaySeenSetClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	exists(key: string): Promise<number>;
}

// --- CodeRepositoryClient --------------------------------------------------

/**
 * Backing client for CodeRepository adapters: the four Redis commands
 * `RedisCodeRepository` consumes — `set` with PX expiry (always `"OK"`),
 * unconditional `get`, atomic `getDel` (Redis 6.2+), and unconditional
 * `del`. The repository consumes this externally provided wrapper (via
 * `bootstrapComponents`) instead of constructing its own client.
 */
export interface CodeRepositoryClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK">;
	get(key: string): Promise<string | null>;
	getDel(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}
