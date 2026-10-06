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
// ---------------------------------------------------------------------------
// AttemptCounter: the counter behind a verifier's own attempt limits, under a
// key namespace of its own.
// ---------------------------------------------------------------------------
export {
	createRedisAttemptCounter,
	DEFAULT_REDIS_ATTEMPT_COUNTER_KEY_PREFIX,
	type RedisAttemptCounterOptions,
	redisAttemptCounterModule,
} from "./attempt-counter.mjs";
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
	AcquireMfaSubjectLeaseInput,
	AcquireMfaSubjectLeaseReply,
	ActivateFederationGrantInput,
	ApplyMfaSubjectRecoveryInput,
	ApplyMfaSubjectRecoveryReply,
	AttemptCounterClient,
	AttemptCounterConsumeInput,
	AttemptCounterConsumeReply,
	AuthorizeMfaSubjectRecoveryInput,
	AuthorizeMfaSubjectRecoveryReply,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentRecordFields,
	ConsentStoreClient,
	ConsumeMfaEmailProofReply,
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
	FederationTokenAttachInput,
	FederationTokenReadInput,
	FederationTokenRemoveIfInput,
	FederationTokenReplaceIfInput,
	FederationTokenStoreClient,
	GrantConsentInput,
	MfaEmailProofKeys,
	MfaFactorRecordUpdateInput,
	MfaFactorSetCreateIfInput,
	MfaFactorSetEmptyingWriteInput,
	MfaFactorSetRemoveIfInput,
	MfaFactorSetWriteInput,
	MfaFactorStoreClient,
	MfaFirstBindingRead,
	MfaRemovedTransaction,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
	MfaTransactionUpdateInput,
	NameFederationGrantIntentInput,
	NoteFederationGrantRefreshFailureInput,
	NoteMfaExemptSuccessInput,
	NoteMfaFirstBindingInput,
	NoteMfaFirstBindingReply,
	ParkPendingConsentInput,
	PendingConsentKeyspace,
	PendingConsentStoreClient,
	RaiseMfaRecoverySetFloorInput,
	RaiseMfaRecoverySetFloorReply,
	RateLimiterClient,
	RateLimitIncrement,
	RedisDurability,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	RefundFederationGrantRotationInput,
	ReplaceFederationGrantCredentialsInput,
	ReplaySeenSetClient,
	RequireFederationGrantReauthorizationInput,
	ReserveMfaSubjectAttemptInput,
	ReserveMfaSubjectAttemptReply,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
	SessionLifecycleCloseInput,
	SessionLifecycleCompleteInput,
	SessionLifecycleJoinInput,
	SessionLifecycleKeys,
	SessionLifecycleOpenInput,
	SessionLifecycleStoreClient,
	SessionLifecycleWriteDeadline,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	TakeFederationGrantRotationInput,
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
// beside them. Each factory holds the server to `noeviction`; each module
// also checks persistence at boot.
// ---------------------------------------------------------------------------
export {
	createRedisMfaFactorStore,
	DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX,
	REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS,
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
// SessionLifecycleStore: a session's state, participants and close work in
// one key per session, spread over fixed shards that each keep a closing
// index on the records' slot. `redisSessionStoresModule` provides it.
export {
	createRedisSessionLifecycleStore,
	DEFAULT_REDIS_SESSION_LIFECYCLE_KEY_PREFIX,
	DEFAULT_REDIS_SESSION_LIFECYCLE_MAX_PARTICIPANTS,
	type RedisSessionLifecycleStoreOptions,
} from "./session-lifecycle-store.mjs";
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
