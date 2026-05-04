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

// ---------------------------------------------------------------------------
// Backing client contracts for Redis adapters in this package.
//
// These interfaces describe the methods the adapters consume, expressed in
// Redis protocol terms (`hSet`, `zAdd`, `pttl`, `multi`/`watch`/`exec`, etc.).
// They live in `@o3co/auth-provider-redis` rather than in core because the
// shape is intrinsically Redis-flavoured: a consumer wiring a non-Redis
// backend (DynamoDB, Postgres, etcd, ...) writes their own contracts and
// adapters, not implementations of these.
//
// Each interface ships with a `declare module "@o3co/auth-provider-core"`
// augmentation that adds the matching backing-client slot to ComponentMap,
// so consumers wiring redis backends via `bootstrapComponents` get the slot
// types whenever they import from this package.
//
// Per Phase 10 addendum §3 + v0.5.0 pre-tag interface review S3.
// ---------------------------------------------------------------------------

// --- ChallengeStoreClient --------------------------------------------------

/**
 * Backing client for ChallengeStore adapters. Adapter implementations
 * (e.g. `createRedisChallengeStore`) consume exactly these methods.
 */
export interface ChallengeStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	pttl(key: string): Promise<number>;
	del(key: string): Promise<number>;
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

// --- RefreshTokenFamilyClient ----------------------------------------------

/**
 * Chainable transaction pipeline returned by `RefreshTokenFamilyClient.multi()`.
 */
export interface RefreshTokenFamilyMultiClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation per A3 §7.2.
 */
export interface RefreshTokenFamilyClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	pttl(key: string): Promise<number>;
	watch(...keys: string[]): Promise<"OK">;
	unwatch(): Promise<"OK">;
	multi(): RefreshTokenFamilyMultiClient;
	duplicate(): DisposableRefreshTokenFamilyClient;
}

/**
 * A `RefreshTokenFamilyClient` that owns a single network connection and is
 * responsible for closing it. Returned by `RefreshTokenFamilyClient.duplicate()`
 * so consumer code can use `await using conn = client.duplicate()` for scoped,
 * exception-safe connection lifetime.
 */
export interface DisposableRefreshTokenFamilyClient
	extends RefreshTokenFamilyClient,
		AsyncDisposable {
	[Symbol.asyncDispose](): Promise<void>;
}

// --- UserSessionStoreClient ------------------------------------------------

/**
 * Backing client for UserSessionStore adapters. Declares only `set`, `get`,
 * `del` — the exact methods `createRedisUserSessionStore` consumes.
 * The `set` overloads cover both the plain-PX form (for future update paths)
 * and the PX+NX form used by `create` (atomic insert-only, mirrors
 * ChallengeStore.issue and RefreshTokenFamilyStore.registerFamily).
 */
export interface UserSessionStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK" | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	get(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}

// --- SessionRPRegistryClient -----------------------------------------------

/**
 * Chainable transaction pipeline returned by `SessionRPRegistryClient.multi()`.
 */
export interface SessionRPRegistryMultiClient {
	hSet(key: string, field: string, value: string): SessionRPRegistryMultiClient;
	pExpireAt(key: string, msTimestamp: number): SessionRPRegistryMultiClient;
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionRPRegistry adapters. Declares the hash ops +
 * multi pipeline that `createRedisSidHash` consumes.
 */
export interface SessionRPRegistryClient {
	del(key: string): Promise<number>;
	hSet(key: string, field: string, value: string): Promise<number>;
	hVals(key: string): Promise<string[]>;
	multi(): SessionRPRegistryMultiClient;
	pExpireAt(key: string, msTimestamp: number): Promise<number>;
}

// --- SessionSidSortedSetClient ---------------------------------------------

/**
 * Chainable transaction pipeline returned by `SessionSidSortedSetClient.multi()`.
 */
export interface SessionSidSortedSetMultiClient {
	pExpireAt(key: string, msTimestamp: number): SessionSidSortedSetMultiClient;
	zAdd(
		key: string,
		entry: { score: number; value: string },
		opts?: { NX: true },
	): SessionSidSortedSetMultiClient;
	exec(): Promise<unknown[] | null>;
}

/**
 * Backing client for SessionFamilyIndex and SessionFederationIndex adapters.
 * Both adapters share this interface (same sorted-set operations, different
 * slot identities in ComponentMap).
 */
export interface SessionSidSortedSetClient {
	del(key: string): Promise<number>;
	multi(): SessionSidSortedSetMultiClient;
	pExpireAt(key: string, msTimestamp: number): Promise<number>;
	zAdd(key: string, entry: { score: number; value: string }, opts?: { NX: true }): Promise<number>;
	zRange(key: string, start: number, stop: number): Promise<string[]>;
	zRem(key: string, member: string): Promise<number>;
}

// --- FederationTokenStoreClient --------------------------------------------

/**
 * Backing client for FederationTokenStore adapters. Declares `get`, `set`
 * (positional PX form, no NX condition), variadic `del`, and `scanIterator`
 * for the cursor-based key scan used by `deleteBySession`.
 */
export interface FederationTokenStoreClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK" | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	del(...keys: string[]): Promise<number>;
	scanIterator(opts: { MATCH: string; COUNT?: number }): AsyncIterable<string>;
}

// --- RateLimiterClient -----------------------------------------------------

/**
 * Backing client for RateLimiter adapters. Declares only `incr` and `expire`
 * — the two methods `createRedisRateLimiter` consumes.
 */
export interface RateLimiterClient {
	incr(key: string): Promise<number>;
	expire(key: string, seconds: number): Promise<number>;
}

// ---------------------------------------------------------------------------
// ComponentMap augmentations: backing-client slots consumed by redis adapters.
//
// These augmentations are visible to any TypeScript consumer that imports
// from `@o3co/auth-provider-redis`. Consumers wiring redis backends via
// `bootstrapComponents` get the slot types automatically.
// ---------------------------------------------------------------------------

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly challengeStoreClient?: ChallengeStoreClient;
		readonly replaySeenSetClient?: ReplaySeenSetClient;
		readonly refreshTokenFamilyClient?: RefreshTokenFamilyClient;
		readonly userSessionStoreClient?: UserSessionStoreClient;
		readonly sessionRPRegistryClient?: SessionRPRegistryClient;
		readonly sessionFamilyIndexClient?: SessionSidSortedSetClient;
		readonly sessionFederationIndexClient?: SessionSidSortedSetClient;
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
		readonly rateLimiterClient?: RateLimiterClient;
	}
}
