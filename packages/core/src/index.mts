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
	type LifecycleRegistrar,
} from "./adapters/AdapterFactory.mjs";
// App factory — v0.5.0 boot planner. Re-exports from ./boot/index.mjs through
// ./app.mjs for backwards-compatible import-path stability.
export { createApp } from "./app.mjs";
export {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
// Audit
export type { AuditEvent, AuditSink, AuditSinkFactory } from "./audit/types.mjs";
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
// Boot planner — BootError catalogue. `createApp` is exported above (via app.mjs).
export { BootError } from "./boot/index.mjs";
// Configuration
export {
	type AppConfig,
	AppConfigSchema,
	type CoreConfig,
	CoreConfigSchema,
	composeConfigSchema,
	fullSectionsSchema,
} from "./config/application.schema.mjs";
// AS-1/AS-2 RFC 6749 §5.2 shared error envelope. Consumer code that builds
// custom routes outside the bundled session/oauth surfaces benefits from
// the same helper so the entire auth product surface emits a single shape.
export { type ErrorEnvelope, errorEnvelope } from "./errors/envelope.mjs";
export {
	createFederationTokenStoreFactory,
	registerBuiltinFederationTokenStores,
} from "./federation-tokens/factory.mjs";
export { memoryFederationTokenStoreModule } from "./federation-tokens/module.mjs";
// FederationTokenStore — TODO-F-1. Backing client interface
// (FederationTokenStoreClient) lives in @o3co/auth-provider-redis (S3).
export type {
	AcquireLockOptions,
	FederationTokenStore,
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
// Grant types and interfaces.
//
// `GrantRegistry` and `GrantRegistryError` (deprecated public re-exports
// in v0.5.1 per AS-8) were removed at v0.6.0 per A2-γ §3.3. The classes
// remain as internal implementation detail of the boot planner; consumer
// code wires grants via module-based `contributes.grants` declarations
// instead.
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
	AuthenticatedClient,
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
// JWT verifier (SF-1) — central verifyJwt with alg/iss/aud/typ pinning
export type {
	JwtType,
	JwtVerificationReason,
	JwtVerifyOptions,
	VerifiedJwt,
} from "./jwt/verify.mjs";
export { JwtVerificationError, verifyJwt } from "./jwt/verify.mjs";
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
	ExpiredKidError,
	UnknownKidError,
} from "./keys/KeyStore.mjs";
export { consoleLogger, createConsoleLogger } from "./logging/consoleLogger.mjs";
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
	MfaProvider,
	MfaProviderFactory,
	MfaResumeState,
	MfaTransactionStore,
	MfaVerifyFailureReason,
	MfaVerifyResult,
	SupportsEnrollment,
	SupportsRevocation,
} from "./mfa/types.mjs";
export { supportsEnrollment, supportsRevocation } from "./mfa/types.mjs";
// Module system — v0.5.0 manifest types. The v0.4.x `LegacyModule` /
// `ModuleContext` interfaces were deleted in Phase 9 (A2-γ caller migration);
// authoring code uses `Module` and `defineModule()` from
// `@o3co/auth-provider-core/modules/manifest`.
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
	// AS-7 collision resolution (v0.5.1): the manifest's contributes-map
	// placeholder previously named `GrantPolicyHook` was renamed to
	// `GrantPolicyHookContribution`. The canonical `GrantPolicyHook`
	// interface lives in `./policy/types.mjs` and is re-exported from the
	// policy block below.
	GrantPolicyHookContribution,
	// GrantPolicyHookFactory: excluded — name collides with legacy
	// ./policy/types.mjs export at this boundary. Import from
	// @o3co/auth-provider-core/modules/manifest directly.
	MfaFactor,
	MfaFactorFactory,
	Module,
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
	GrantPolicyHook,
	GrantPolicyHookFactory,
	GrantPolicyRequest,
} from "./policy/types.mjs";
export {
	createRateLimiterFactory,
	registerBuiltinRateLimiters,
} from "./ratelimit/factory.mjs";
export { memoryRateLimiterModule } from "./ratelimit/module.mjs";
// Rate limiter. Backing client interface (RateLimiterClient) lives in
// @o3co/auth-provider-redis (S3).
export type {
	RateLimitContext,
	RateLimitDecision,
	RateLimiter,
	RateLimiterFactory,
	RateLimitSpec,
} from "./ratelimit/types.mjs";
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
export { createRepositoryFactories } from "./repositories/RepositoryFactory.mjs";
export type {
	Client,
	Code,
	CodeData,
	TokenEndpointAuthMethod,
	User,
} from "./repositories/types.mjs";
export type { UserRepository } from "./repositories/UserRepository.mjs";
export {
	createSessionFamilyIndexFactory,
	createSessionFederationIndexFactory,
	createSessionRPRegistryFactory,
	createUserSessionStoreFactory,
} from "./user-sessions/factory.mjs";
export { createInMemorySessionFamilyIndex } from "./user-sessions/memory/sessionFamilyIndex.mjs";
export { createInMemorySessionFederationIndex } from "./user-sessions/memory/sessionFederationIndex.mjs";
export { createInMemorySessionRPRegistry } from "./user-sessions/memory/sessionRPRegistry.mjs";
export { createInMemoryUserSessionStore } from "./user-sessions/memory/userSessionStore.mjs";
export { memorySessionStoresModule } from "./user-sessions/modules/memory.mjs";
// ---------------------------------------------------------------------------
// A4 user-sessions (post v0.5.0 redesign): 4-way decomposition.
// Per spec §5.1-§5.7, §7.1, §8.1.
// ---------------------------------------------------------------------------
// Backing client interfaces (UserSessionStoreClient, SessionRPRegistryClient
// (+Multi), SessionSidSortedSetClient (+Multi)) live in
// @o3co/auth-provider-redis (S3).
export type {
	CreateUserSessionInput,
	RegisteredRP,
	SessionFamilyIndex,
	SessionFamilyIndexFactory,
	SessionFederationIndex,
	SessionFederationIndexFactory,
	SessionRPRegistry,
	SessionRPRegistryFactory,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
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
	type ChallengeCeremonyDeps,
	createChallengeCeremony,
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
// A3 — RefreshTokenFamilyStore + RefreshTokenFamilyRotation + RefreshTokenFamilyRevocation
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
	defaultRefreshTokenFamilyRotationModule,
	memoryRefreshTokenFamilyStoreModule,
} from "./refresh-token-family/module.mjs";

export {
	createRefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRevocationDeps,
} from "./refresh-token-family/revocation.mjs";
export {
	createRefreshTokenFamilyRotation,
	type RefreshTokenFamilyRotationDeps,
} from "./refresh-token-family/rotation.mjs";
export type {
	RefreshTokenFamily,
	RefreshTokenFamilyRevocation,
	RefreshTokenFamilyRotation,
	RefreshTokenFamilyRotationOutcome,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
} from "./refresh-token-family/types.mjs";

// SF-3 + MIN-4 (v0.5.1): timing-safe primitives. Exported from the package
// root because `packages/core/package.json#exports` does not register a
// `./security/*` subpath — Codex Delta 1 confirmed the subpath approach
// would fail at runtime under Node's exports gating.
export { constantTimeStringEqual } from "./security/timingSafe.mjs";
