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

// Adapter factory primitives (public extension point)
export {
	type AdapterBuilder,
	type AdapterFactory,
	AdapterFactoryError,
	type BuilderContext,
	createAdapterFactory,
} from "./adapters/AdapterFactory.mjs";
// App factory (legacy — v0.4.x createApp; stays until Phase 9 / A2-γ migration)
export { type AppOptions, type AppResult, createApp } from "./app.mjs";
export {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
// Audit
export type { AuditEvent, AuditSinkBase, AuditSinkFactory } from "./audit/types.mjs";
export type {
	AppHandle,
	BootErrorDetails,
	BootErrorReason,
	BootStage,
	BootstrapComponentCollisionDetails,
	BootstrapMap,
	CircularDependencyDetails,
	CleanupRecord,
	CollectedRouteContribution,
	ConfigValidationFailedDetails,
	ContributeAndOverrideSameKeyDetails,
	ContributeFactoryFailedDetails,
	ContributionCollectorMap,
	ContributionKindMap,
	CreateAppOptions,
	DefaultBootstrapMap,
	DuplicateContributeDetails,
	DuplicateModuleNameDetails,
	DuplicateOverrideDetails,
	DuplicateProvidesDetails,
	FederationRedirectPolicyUnpairedDetails,
	InvalidRouteAdvertisementPathDetails,
	LifecycleWithoutProvidesDetails,
	ListCollector,
	ListShapedOverrideDetails,
	MissingRequiredComponentDetails,
	NameKeyedCollector,
	OrderedRouteContribution,
	OverrideTargetMissingDetails,
	ProvidesFactoryFailedDetails,
	RouteCollector,
	RouteOrderCycleDetails,
	RouteOrderTargetMissingDetails,
	SyntheticKeyCollisionDetails,
	UnknownContributionKindDetails,
} from "./boot/index.mjs";
// Boot planner — v0.5.0 createApp + AppHandle + BootError catalogue
// `createBootApp` is a temporary alias; Phase 9 drops the alias and the legacy
// createApp above, leaving a single `createApp` export from ./boot/index.mjs.
export {
	BootError,
	createApp as createBootApp,
} from "./boot/index.mjs";
// Configuration
export {
	type AppConfig,
	AppConfigSchema,
	type CoreConfig,
	CoreConfigSchema,
	composeConfigSchema,
	fullSectionsSchema,
} from "./config/application.schema.mjs";
export {
	createFederationTokenStoreFactory,
	registerBuiltinFederationTokenStores,
} from "./federation-tokens/factory.mjs";
// FederationTokenStore — TODO-F-1
export type {
	AcquireLockOptions,
	FederationTokenStoreBase,
	FederationTokenStoreFactory,
	FederationTokens,
	LockResult,
	SupportsLock,
} from "./federation-tokens/types.mjs";
export { supportsLock } from "./federation-tokens/types.mjs";
export { filterClaimsByScope } from "./grants/claimFilter.mjs";
// id_token generation (OIDC Core §2)
export {
	type GenerateIdTokenOptions,
	generateIdToken,
} from "./grants/idToken.mjs";
// logout_token generation (OIDC Back-Channel Logout 1.0 §2.4)
export {
	BACKCHANNEL_LOGOUT_EVENT_URI,
	type GenerateLogoutTokenOptions,
	generateLogoutToken,
} from "./grants/logoutToken.mjs";
// Grant types and interfaces
export { GrantRegistry, GrantRegistryError } from "./grants/registry.mjs";
// Token formatting utility (used by oauth package)
export {
	formatObject,
	type GenerateTokenOptions,
	generateToken,
	generateTokenResponse,
	type Token,
	type TokenResponse,
} from "./grants/token.mjs";
export type {
	GrantContext,
	GrantDependencies,
	GrantError,
	GrantFactory,
	GrantHandler,
	GrantHandlerResult,
	GrantModule,
	GrantResult,
	GrantSuccess,
	SessionData,
	SessionMutation,
} from "./grants/types.mjs";
export type { KeyStoreFactory } from "./keys/factory.mjs";
export { createKeyStoreFactory, registerBuiltinKeyStores } from "./keys/factory.mjs";
// Keys
export type {
	Algorithm,
	AsymmetricKeyStoreOptions,
	JWTPayload,
	KeyLike,
	KeyStore,
	ManagedKey,
	SignJwtOptions,
} from "./keys/KeyStore.mjs";
export {
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
} from "./keys/KeyStore.mjs";
// Logging
export type { Logger } from "./logging/Logger.mjs";
export { createMfaProviderFactory } from "./mfa/factory.mjs";
export type { MfaRouteDeps } from "./mfa/route.mjs";
export { createMfaRouter } from "./mfa/route.mjs";
// MFA
export type {
	EnrollResult,
	MfaChallenge,
	MfaCoordinator,
	MfaIssueContext,
	MfaPendingTransaction,
	MfaProviderBase,
	MfaProviderFactory,
	MfaResumeState,
	MfaTransactionStore,
	MfaVerifyFailureReason,
	MfaVerifyResult,
	SupportsEnrollment,
	SupportsRevocation,
} from "./mfa/types.mjs";
export { supportsEnrollment, supportsRevocation } from "./mfa/types.mjs";
// Module system — v0.5.0 manifest types + legacy types for migration.
// LegacyModule is the deprecated v0.4.x shape (init callback); will be
// removed in Phase 9 (A2-γ caller migration). New code uses Module
// (= v0.5.0 manifest type from defineModule()).
export type {
	AuditHook,
	AuditHookFactory,
	ComponentKey,
	ComponentMap,
	ConfigSchema,
	ContributesMap,
	ExchangeTokenValidator,
	ExchangeTokenValidatorFactory,
	FederationFactory,
	FederationProvider,
	FederationProviderHandle,
	// GrantFactory, GrantHandler: excluded — names collide with legacy
	// ./grants/types.mjs exports at this boundary. Import from
	// @o3co/auth-provider-core/modules/manifest directly.
	GrantHandlerResolver,
	GrantPolicyHook,
	LegacyModule,
	// GrantPolicyHookFactory: excluded — name collides with legacy
	// ./policy/types.mjs export at this boundary. Import from
	// @o3co/auth-provider-core/modules/manifest directly.
	MfaFactor,
	MfaFactorFactory,
	Module,
	ModuleContext,
	ModuleSpec,
	PathResolver,
	Provider,
	ProviderDeps,
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
	TokenExchangeValidatorResolver,
} from "./modules/index.mjs";
export {
	defineModule,
	SYNTHETIC_COMPONENT_KEYS,
} from "./modules/index.mjs";
export { createGrantPolicyHookFactory } from "./policy/factory.mjs";
// Grant policy
export type {
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyHookBase,
	GrantPolicyHookFactory,
	GrantPolicyRequest,
} from "./policy/types.mjs";
export {
	createRateLimiterFactory,
	registerBuiltinRateLimiters,
} from "./ratelimit/factory.mjs";
// Rate limiter
export type {
	RateLimitContext,
	RateLimitDecision,
	RateLimiterBase,
	RateLimiterFactory,
	RateLimitSpec,
} from "./ratelimit/types.mjs";
export { createRefreshTokenStoreFactory } from "./refresh/factory.mjs";
// Refresh token store
export type {
	RefreshTokenRotateOutcome,
	RefreshTokenStoreBase,
	RefreshTokenStoreFactory,
} from "./refresh/types.mjs";
// Repository interfaces
export type { ClientRepository, PublicClient } from "./repositories/ClientRepository.mjs";
export type { CodeRepository } from "./repositories/CodeRepository.mjs";
export {
	type ClientEntry,
	ClientEntrySchema,
	InMemoryClientRepository,
} from "./repositories/InMemoryClientRepository.mjs";
// Built-in implementations
export { InMemoryCodeRepository } from "./repositories/InMemoryCodeRepository.mjs";
export {
	InMemoryUserRepository,
	type UserEntry,
	UserEntrySchema,
} from "./repositories/InMemoryUserRepository.mjs";
export { loadYamlMap } from "./repositories/loadYamlMap.mjs";
// Default repository factories
export { createDefaultFactories } from "./repositories/RepositoryFactory.mjs";
export type { Client, Code, CodeData, User } from "./repositories/types.mjs";
export type { UserRepository } from "./repositories/UserRepository.mjs";
export { extractUserClaims } from "./user-sessions/claims.mjs";
export {
	createUserSessionStoreFactory,
	registerBuiltinUserSessionStores,
} from "./user-sessions/factory.mjs";
// UserSessionStore — TODO-F-1
export type {
	CreateUserSessionInput,
	RegisteredRP,
	UserSession,
	UserSessionClaims,
	UserSessionStoreBase,
	UserSessionStoreFactory,
} from "./user-sessions/types.mjs";

// ---------------------------------------------------------------------------
// A1 — Challenge Store + Replay Seen Set + Default Ceremony (Phase 5)
// ---------------------------------------------------------------------------

// Memory adapters (re-exported so consumers can construct without going through modules)
export { createMemoryChallengeStore } from "./challenges/adapters/memory.mjs";
// Canonical key helper (exported for integrators writing their own adapters
// to preserve cross-adapter parity per A1 §7.3)
export { canonicalKey as canonicalChallengeKey } from "./challenges/canonical-key.mjs";
// Default composition
export {
	createDefaultChallengeCeremony,
	type DefaultChallengeCeremonyDeps,
} from "./challenges/ceremony.mjs";
export type { ChallengeStorageErrorReason } from "./challenges/errors.mjs";
// Errors
export { ChallengeStorageError } from "./challenges/errors.mjs";
// Adapter factories
export {
	type ChallengeStoreFactory,
	createChallengeStoreFactory,
	registerBuiltinChallengeStores,
} from "./challenges/factory.mjs";
// Modules
export {
	defaultChallengeCeremonyModule,
	memoryChallengeStoreModule,
} from "./challenges/module.mjs";
// Types
export type {
	Challenge,
	ChallengeCeremony,
	ChallengeCeremonyOutcome,
	ChallengeStore,
} from "./challenges/types.mjs";
export { createMemoryReplaySeenSet } from "./replay-seen-set/adapters/memory.mjs";
export {
	createReplaySeenSetFactory,
	type ReplaySeenSetFactory,
	registerBuiltinReplaySeenSets,
} from "./replay-seen-set/factory.mjs";
export { memoryReplaySeenSetModule } from "./replay-seen-set/module.mjs";
export type { ReplaySeenSet } from "./replay-seen-set/types.mjs";

// ===========================================================================
// A3 — RefreshTokenFamilyStore + RefreshTokenRotation + RefreshTokenFamilyRevocation
// ===========================================================================

export { createMemoryRefreshTokenFamilyStore } from "./refresh-token-family/adapters/memory.mjs";
export {
	RefreshTokenStorageError,
	type RefreshTokenStorageErrorReason,
} from "./refresh-token-family/errors.mjs";
export {
	createRefreshTokenFamilyStoreFactory,
	type RefreshTokenFamilyStoreFactory,
	registerBuiltinRefreshTokenFamilyStores,
} from "./refresh-token-family/factory.mjs";
export {
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenRotationModule,
	memoryRefreshTokenFamilyStoreModule,
} from "./refresh-token-family/module.mjs";

export {
	createDefaultRefreshTokenFamilyRevocation,
	type DefaultRefreshTokenFamilyRevocationDeps,
} from "./refresh-token-family/revocation.mjs";
export {
	createDefaultRefreshTokenRotation,
	type DefaultRefreshTokenRotationDeps,
} from "./refresh-token-family/rotation.mjs";
export type {
	RefreshTokenFamily,
	RefreshTokenFamilyRevocation,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
	RefreshTokenRotation,
	RefreshTokenRotationOutcome,
} from "./refresh-token-family/types.mjs";
