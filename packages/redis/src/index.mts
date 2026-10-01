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
	createRedisAccessTokenDenylist,
	type RedisAccessTokenDenylistOptions,
	redisAccessTokenDenylistBuilder,
	redisAccessTokenDenylistModule,
} from "./access-token-denylist.mjs";
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
	AccessTokenDenylistClient,
	ActivateFederationGrantInput,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentRecordFields,
	ConsentStoreClient,
	CreateDeviceCodeRecordInput,
	CreatePendingFederationGrantInput,
	DeviceCodeDecisionInput,
	DeviceCodeDecisionReply,
	DeviceCodeKeyspace,
	DeviceCodePollReply,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantConsentAnswered,
	FederationGrantHashFields,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
	FederationGrantSnapshot,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
	GrantConsentInput,
	MfaFactorRecordUpdateInput,
	MfaFactorStoreClient,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
	MfaTransactionUpdateInput,
	NameFederationGrantIntentInput,
	NoteFederationGrantRefreshFailureInput,
	NoteMfaExemptSuccessInput,
	ParkPendingConsentInput,
	PendingConsentKeyspace,
	PendingConsentStoreClient,
	RateLimiterClient,
	RateLimitIncrement,
	RedisDurability,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaceFederationGrantCredentialsInput,
	ReplaySeenSetClient,
	RequireFederationGrantReauthorizationInput,
	ReserveMfaSubjectAttemptInput,
	ReserveMfaSubjectAttemptReply,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
	SessionFamilyIndexClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "./clients.mjs";
// makeIoredisClients lives at the `/ioredis` subpath
// (`@o3co/auth-provider-redis/ioredis`) so the main entry stays
// vendor-agnostic. Importing this main entry does NOT pull `ioredis` types
// into the consumer's TS dependency closure.
// ---------------------------------------------------------------------------
// CodeRepository. The deprecated builder takes the module's
// `{ client, keyPrefix?, defaultExpiresIn? }` shape.
// ---------------------------------------------------------------------------
export {
	RedisCodeRepository,
	type RedisCodeRepositoryOptions,
	redisCodeRepositoryBuilder,
	redisCodeRepositoryModule,
} from "./code-repository.mjs";
// ---------------------------------------------------------------------------
// ConsentStore + PendingConsentStore. The Redis half of the consent
// step for clients that are not first-party: core's memory module is refused
// under `core.deployment.mode = "multi"`, so this is what lets such clients be
// served by a scaled deployment. One module provides both slots.
// ---------------------------------------------------------------------------
export {
	CONSENT_EXPIRY_SLACK_MS,
	createRedisConsentStore,
	createRedisPendingConsentStore,
	type RedisConsentStoreOptions,
	type RedisPendingConsentStoreOptions,
	redisConsentStoreBuilder,
	redisConsentStoreModule,
	redisPendingConsentStoreBuilder,
} from "./consent-store.mjs";
// ---------------------------------------------------------------------------
// DeviceCodeStore. The Redis half of the RFC 8628 device grant's
// storage: the memory adapter in core is refused under `core.deployment.mode =
// "multi"`, so this is what makes the grant usable in a scaled deployment.
// ---------------------------------------------------------------------------
export {
	createRedisDeviceCodeStore,
	type RedisDeviceCodeStoreOptions,
	redisDeviceCodeStoreBuilder,
	redisDeviceCodeStoreModule,
} from "./device-code-store.mjs";
export {
	createRedisFederationGrantIntentStore,
	FEDERATION_GRANT_RESERVATION_ALLOWANCE_MS,
	type RedisFederationGrantIntentStoreOptions,
	redisFederationGrantIntentStoreModule,
	resolveRedisFederationGrantIntentStoreOptions,
} from "./federation-grant-intent-store.mjs";
// ---------------------------------------------------------------------------
// DPoP has no adapter of its own: `@o3co/auth-provider-dpop` records every
// accepted proof in the `replaySeenSet` slot, which `redisReplaySeenSetModule`
// fills for a scaled deployment.
// ---------------------------------------------------------------------------
// FederationTokenStore, with a module for declarative wiring.
// ---------------------------------------------------------------------------
// Federation grants: the offline-delegation store, and acquisition's records
// beside it (ADR 2026-09-17-federation-grants-offline-delegation).
// ---------------------------------------------------------------------------
export {
	createRedisFederationGrantStore,
	DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS,
	type FederationGrantEncryption,
	type FederationGrantKey,
	type RedisFederationGrantStoreModuleOptions,
	type RedisFederationGrantStoreOptions,
	redisFederationGrantStoreModule,
	redisFederationGrantStoreModuleFor,
	resolveRedisFederationGrantStoreOptions,
} from "./federation-grant-store.mjs";
export {
	createRedisFederationTokenStore,
	type EncryptionConfig,
	type EncryptionGuardContext,
	type RedisFederationTokenStoreModuleOptions,
	type RedisFederationTokenStoreOptions,
	redisFederationTokenStoreBuilder,
	redisFederationTokenStoreModule,
	redisFederationTokenStoreModuleFor,
} from "./federation-tokens.mjs";
// ---------------------------------------------------------------------------
// MFA (ADR 2026-09-25-multi-factor-authentication): enrolled second
// factors, and the transactions, subject lock and email-proof requirement
// beside them. Each module checks the server's eviction policy and
// persistence at boot.
// ---------------------------------------------------------------------------
export {
	createRedisMfaFactorStore,
	DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX,
	type RedisMfaFactorStoreOptions,
	redisMfaFactorStoreModule,
} from "./mfa-factor-store.mjs";
export {
	createRedisMfaTransactionStore,
	DEFAULT_REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX,
	type RedisMfaTransactionStoreOptions,
	redisMfaTransactionStoreModule,
} from "./mfa-transaction-store.mjs";
export { redisSessionStoresModule } from "./modules/redisSessionStores.mjs";
// ---------------------------------------------------------------------------
// RateLimiter.
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
export {
	createRedisSubjectRevocation,
	type RedisSubjectRevocationOptions,
	redisSubjectRevocationBuilder,
} from "./subjectRevocation.mjs";
export {
	createRedisSubjectSessionIndex,
	type RedisSubjectSessionIndexOptions,
	redisSubjectSessionIndexBuilder,
} from "./subjectSessionIndex.mjs";
// ---------------------------------------------------------------------------
// User-session adapters.
// ---------------------------------------------------------------------------
export {
	createRedisUserSessionStore,
	type RedisUserSessionStoreOptions,
	redisUserSessionStoreBuilder,
} from "./userSessionStore.mjs";
