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
export { createRedisChallengeStore, redisChallengeStoreBuilder, redisChallengeStoreModule, } from "./challenges.mjs";
// makeIoredisClients lives at the `/ioredis` subpath
// (`@o3co/auth-provider-redis/ioredis`) so the main entry stays
// vendor-agnostic. Importing this main entry does NOT pull `ioredis` types
// into the consumer's TS dependency closure. Per Phase 10 addendum +
// Copilot review #102.
// ---------------------------------------------------------------------------
// CodeRepository (Phase 10 Q4).
// Relocated from @o3co/auth-provider-foundation. Module pattern intentionally
// omitted in v0.5.0 (see plan §1 / Q4).
// ---------------------------------------------------------------------------
export { RedisCodeRepository, redisCodeRepositoryBuilder } from "./code-repository.mjs";
// ---------------------------------------------------------------------------
// FederationTokenStore (Phase 10 Q1+Q5).
// Adapter relocated from core; module pattern added for declarative wiring
// parity with other v0.5.0 redis adapters.
// ---------------------------------------------------------------------------
export { createRedisFederationTokenStore, redisFederationTokenStoreBuilder, redisFederationTokenStoreModule, } from "./federation-tokens.mjs";
export { redisSessionStoresModule } from "./modules/redisSessionStores.mjs";
// ---------------------------------------------------------------------------
// RateLimiter (Phase 10 Q3).
// Adapter relocated from core; module pattern added.
// ---------------------------------------------------------------------------
export { createRedisRateLimiter, redisRateLimiterBuilder, redisRateLimiterModule, } from "./ratelimit.mjs";
export { createRedisRefreshTokenFamilyStore, redisRefreshTokenFamilyStoreBuilder, redisRefreshTokenFamilyStoreModule, } from "./refresh-token-family.mjs";
export { createRedisReplaySeenSet, redisReplaySeenSetBuilder, redisReplaySeenSetModule, } from "./replay-seen-set.mjs";
export { createRedisSessionFamilyIndex, } from "./sessionFamilyIndex.mjs";
export { createRedisSessionFederationIndex, } from "./sessionFederationIndex.mjs";
export { createRedisSessionRPRegistry, } from "./sessionRPRegistry.mjs";
// ---------------------------------------------------------------------------
// A4 user-session adapters (Phase 8b).
// Per A4 §8.1 + §11.2.
// ---------------------------------------------------------------------------
export { createRedisUserSessionStore, } from "./userSessionStore.mjs";
