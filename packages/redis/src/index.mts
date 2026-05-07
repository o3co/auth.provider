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

export {
	createRedisChallengeStore,
	type RedisChallengeStoreOptions,
	redisChallengeStoreBuilder,
	redisChallengeStoreModule,
} from "./challenges.mjs";
// ---------------------------------------------------------------------------
// Per-purpose backing-client interfaces. These describe the methods Redis
// adapters consume, expressed in Redis protocol terms (`hSet`, `zAdd`, `pttl`,
// `multi`/`watch`/`exec`, etc.). Consumers writing custom Redis-backed clients
// (alternative to ioredis) implement these contracts. Non-Redis backends
// define their own contracts; do not implement these.
// ---------------------------------------------------------------------------
export type {
	ChallengeStoreClient,
	CodeRepositoryClient,
	DisposableRefreshTokenFamilyClient,
	FederationTokenStoreClient,
	RateLimiterClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	UserSessionStoreClient,
} from "./clients.mjs";
// makeIoredisClients lives at the `/ioredis` subpath
// (`@o3co/auth-provider-redis/ioredis`) so the main entry stays
// vendor-agnostic. Importing this main entry does NOT pull `ioredis` types
// into the consumer's TS dependency closure. Per Phase 10 addendum +
// Copilot review #102.
// ---------------------------------------------------------------------------
// CodeRepository (Phase 10 Q4 / OR-9 Wave 5d).
// Relocated from @o3co/auth-provider-foundation. v0.5.1 OR-9 added the module
// pattern + migrated to ioredis-typed `CodeRepositoryClient`; the legacy
// builder is retained one release cycle as deprecated and now requires the
// new `{ client, keyPrefix?, defaultExpiresIn? }` shape.
// ---------------------------------------------------------------------------
export {
	RedisCodeRepository,
	type RedisCodeRepositoryOptions,
	redisCodeRepositoryBuilder,
	redisCodeRepositoryModule,
} from "./code-repository.mjs";
// ---------------------------------------------------------------------------
// FederationTokenStore (Phase 10 Q1+Q5).
// Adapter relocated from core; module pattern added for declarative wiring
// parity with other v0.5.0 redis adapters.
// ---------------------------------------------------------------------------
export {
	createRedisFederationTokenStore,
	type EncryptionConfig,
	type RedisFederationTokenStoreOptions,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
} from "./federation-tokens.mjs";
export { redisSessionStoresModule } from "./modules/redisSessionStores.mjs";
// ---------------------------------------------------------------------------
// RateLimiter (Phase 10 Q3).
// Adapter relocated from core; module pattern added.
// ---------------------------------------------------------------------------
export {
	createRedisRateLimiter,
	redisRateLimiterBuilder,
	redisRateLimiterModule,
} from "./ratelimit.mjs";
export {
	createRedisRefreshTokenFamilyStore,
	type RedisRefreshTokenFamilyStoreOptions,
	redisRefreshTokenFamilyStoreBuilder,
	redisRefreshTokenFamilyStoreModule,
} from "./refresh-token-family.mjs";
export {
	createRedisReplaySeenSet,
	type RedisReplaySeenSetOptions,
	redisReplaySeenSetBuilder,
	redisReplaySeenSetModule,
} from "./replay-seen-set.mjs";
export {
	createRedisSessionFamilyIndex,
	type RedisSessionFamilyIndexOptions,
	redisSessionFamilyIndexBuilder,
} from "./sessionFamilyIndex.mjs";
export {
	createRedisSessionFederationIndex,
	type RedisSessionFederationIndexOptions,
	redisSessionFederationIndexBuilder,
} from "./sessionFederationIndex.mjs";
export {
	createRedisSessionRPRegistry,
	type RedisSessionRPRegistryOptions,
	redisSessionRPRegistryBuilder,
} from "./sessionRPRegistry.mjs";
// ---------------------------------------------------------------------------
// A4 user-session adapters (Phase 8b).
// Per A4 §8.1 + §11.2.
// ---------------------------------------------------------------------------
export {
	createRedisUserSessionStore,
	type RedisUserSessionStoreOptions,
	redisUserSessionStoreBuilder,
} from "./userSessionStore.mjs";
