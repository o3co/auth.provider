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

// Access-token extraction from the Authorization header (folded down from
// the oauth package in #324 so `protectedResourceBindingMw` shares it).
export {
	type AccessTokenAuthorization,
	type AccessTokenScheme,
	parseAccessTokenAuthorization,
	parseAccessTokenHeader,
} from "./accessTokenHeader.mjs";
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
export type {
	JwtAssertionVerifierOptions,
	SubjectHandleReader,
} from "./assertions/jwtAssertionVerifier.mjs";
export { createJwtAssertionVerifier } from "./assertions/jwtAssertionVerifier.mjs";
// #301: possession proof for the RFC 7523 jwt-bearer grant. The port is here;
// the JWT implementation is the vendor-neutral one, and a platform attestation
// (DeviceCheck, Play Integrity) is the operator's own.
export type {
	AssertionVerificationResult,
	AssertionVerifier,
} from "./assertions/types.mjs";
export {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
// Audit
export type { AuditEvent, AuditSink, AuditSinkFactory } from "./audit/types.mjs";
// Two audit constants: the declared-absence policy the bundled auditSink
// readers share (#363 — one constant, so the boot error's advice cannot
// depend on which module tripped it; the AbsencePolicy vocabulary itself is
// exported below with the manifest types), and the built-in audit-event
// inventory (#369 — pinned against the emission sites by a drift-guard test,
// so sinks and dashboards filter on names that actually occur).
export { AUDIT_SINK_ABSENCE_POLICY, BUILT_IN_AUDIT_EVENT_TYPES } from "./audit/types.mjs";
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
// #271: replica-safety guard, exported so a custom composition root can run
// the same check and so the module set is greppable from a deployment's tests.
export {
	BootError,
	type CheckReplicaSafetyInput,
	checkReplicaSafety,
	REPLICA_UNSAFE_MODULES,
} from "./boot/index.mjs";
// Configuration
export {
	type AccessTokenRevocationMode,
	type AppConfig,
	AppConfigSchema,
	type CoreConfig,
	CoreConfigSchema,
	composeConfigSchema,
	fullSectionsSchema,
	readAccessTokenRevocationMode,
} from "./config/application.schema.mjs";
// OIDC discovery aggregation — modules contribute `discoveryMetadata`
// (OidcDiscoveryContributionFactory above) and core synthesizes the
// `/.well-known/openid-configuration` document via `buildDiscoveryDocument`.
export { buildDiscoveryDocument, DiscoveryDocumentError } from "./discovery/buildDocument.mjs";
export type { OidcDiscoveryContribution } from "./discovery/types.mjs";
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
export type { Confirmation } from "./grants/confirmation.mjs";
// The ONE cnf/token-binding comparison matrix (#324) — consumed by the
// refresh and token-exchange grants, `protectedResourceBindingMw`, and the
// introspection handler; each caller keeps only its own error mapping.
export {
	type ConfirmationMatch,
	type ConfirmationMember,
	extractConfirmation,
	isCompoundConfirmation,
	matchConfirmation,
	ownedConfirmation,
} from "./grants/confirmationMatch.mjs";
export { isEmailVerified } from "./grants/emailVerifiedGate.mjs";
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
export type { SenderConstraint } from "./grants/senderConstraint.mjs";
// Grant types and interfaces.
//
// `GrantRegistry` and `GrantRegistryError` (deprecated public re-exports
// in v0.5.1 per AS-8) were removed per A2-γ §3.3. The classes
// remain as internal implementation detail of the boot planner; consumer
// code wires grants via module-based `contributes.grants` declarations
// instead.
// Token formatting utility (used by oauth package)
export {
	formatObject,
	type GenerateTokenOptions,
	type GenerateTokenResponseOptions,
	generateToken,
	generateTokenResponse,
	type Token,
	type TokenResponse,
} from "./grants/token.mjs";
export type { TokenBinding } from "./grants/tokenBinding.mjs";
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
export {
	checkCanonicalIssuer,
	describeIssuerRejection,
	type IssuerRejection,
	isCanonicalIssuer,
} from "./issuer/canonical.mjs";
// JWKS publishing — `jwksModule` mounts the route so every provider that signs
// tokens exposes its verification keys for offline validation; `createJwksRouter`
// is the underlying factory for direct composition. `DEFAULT_JWKS_PATH` /
// `resolveJwksPath` are the single source of truth for the publishing path,
// shared with oauth discovery's `jwks_uri` so the two never drift.
export { DEFAULT_JWKS_CACHE_MAX_AGE, resolveJwksCacheMaxAge } from "./jwks/cache.mjs";
export { jwksModule } from "./jwks/module.mjs";
export { DEFAULT_JWKS_PATH, resolveJwksPath } from "./jwks/path.mjs";
// JWT verifier (SF-1) — central verifyJwt with alg/iss/aud/typ pinning
export type {
	JwtRevocationSources,
	JwtType,
	JwtVerificationReason,
	JwtVerifyOptions,
	VerifiedJwt,
	VerifyRevocation,
} from "./jwt/verify.mjs";
export { isRevocationUnavailable, JwtVerificationError, verifyJwt } from "./jwt/verify.mjs";
export type { KeyStoreFactory } from "./keys/factory.mjs";
export {
	createKeyStoreFactory,
	DEFAULT_SIGNING_ALGORITHM,
	registerBuiltinKeyStores,
} from "./keys/factory.mjs";
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
// #303: the KeyStore whose private key never enters this process. Wired by a
// composition root rather than selected in config — a `RemoteSigner` is a
// function, and there is no HOCON spelling for one.
export type {
	RemoteSigner,
	RemoteSigningKeyStoreOptions,
	RemoteSigningPreviousKey,
} from "./keys/remoteSigning.mjs";
export {
	createRemoteSigningKeyStore,
	derToJoseEcdsaSignature,
} from "./keys/remoteSigning.mjs";
// Shared-secret entropy floor (#282). Exported so a composition root that
// builds its own KeyStore — or accepts any other HMAC secret from an
// operator — can apply the same check the built-in `local` builder does.
export type { SecretEntropyRequirement } from "./keys/secretEntropy.mjs";
export {
	assertSecretEntropy,
	describeWeakSecret,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
} from "./keys/secretEntropy.mjs";
export { consoleLogger, createConsoleLogger } from "./logging/consoleLogger.mjs";
// Logging
export type { EventLogger, Logger, LogLevel } from "./logging/Logger.mjs";
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
// Middleware — protected-resource sender-constraint enforcement (RFC 9449 §7.1 / RFC 8705 §3)
export {
	type ProtectedResourceBindingOptions,
	protectedResourceBindingMw,
} from "./middleware/protectedResourceBinding.mjs";
// Middleware — tokenBindingMw factory + plugin surface (Wave 2 Token-binding Cluster §4.7)
export {
	type DispatchPolicy,
	isTokenBindingMw,
	type TokenBindingExtractContext,
	type TokenBindingMechanism,
	type TokenBindingMiddlewareOptions,
	tokenBindingMw,
} from "./middleware/tokenBinding.mjs";
// Module system — v0.5.0 manifest types. The v0.4.x `LegacyModule` /
// `ModuleContext` interfaces were deleted in Phase 9 (A2-γ caller migration);
// authoring code uses `Module` and `defineModule()` from
// `@o3co/auth-provider-core/modules/manifest`.
export type {
	AbsencePolicy,
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
	GrantMiddlewareFactory,
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
	OidcDiscoveryContributionFactory,
	PathResolver,
	Provider,
	ProviderDeps,
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
	TokenBindingMechanismFactory,
	TokenExchangeValidatorResolver,
} from "./modules/index.mjs";
export {
	defineModule,
	SYNTHETIC_COMPONENT_KEYS,
} from "./modules/index.mjs";
// The single loopback-hostname vocabulary (#364) — the predicate behind every
// "http:// is accepted for loopback hosts only" carve-out
// (`checkSecureEndpoint` in foundation, `checkRedirectShape` in session).
// Exported so consumers import or re-export it rather than defining a copy;
// the designVocabulary drift guard fails any second definition.
export { isLoopbackHostname } from "./net/loopback.mjs";
// The registered-redirect-URI shape vocabulary (#395) — enforced by
// ClientEntrySchema at boot; exported so a custom ClientRepository, which
// bypasses that schema by design, can hold its registrations to the same
// rules and refuse in the same words.
export {
	checkRedirectUri,
	describeRedirectUriRejection,
	type RedirectUriRejection,
} from "./net/redirect-uri.mjs";
// The single canonical-request-URL vocabulary (#292, #356) — "the URL this
// request reached" is the configured origin plus `req.originalUrl`, never
// `req.protocol` + the `Host` header (attacker-influenced under
// `trust proxy`). DPoP htu comparison and the /authorize login round-trip
// both consume this; the designVocabulary drift guard fails any second
// definition.
export { buildCanonicalRequestUrl } from "./net/request-url.mjs";
// The single trusted-proxy address vocabulary (#292) — Express's own
// `trust proxy` forms. `http.trustProxy` validates its entries with
// `checkTrustedProxyEntry`; `@o3co/auth-provider-mtls` matches
// `req.socket.remoteAddress` with `createTrustedProxyMatcher`. Exported so a
// custom composition root, or a future mechanism that has to authenticate a
// forwarding hop, extends this list rather than starting a second dialect.
export {
	checkTrustedProxyEntry,
	createTrustedProxyMatcher,
	describeTrustedProxyEntryRejection,
	isTrustedProxyEntry,
	TRUSTED_PROXY_NAMED_RANGES,
	type TrustedProxyEntryRejection,
	type TrustedProxyMatcherOptions,
} from "./net/trusted-proxy.mjs";
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
// #325: single guard factory behind both the OAuth-endpoint throttles and
// the /session/login brute-force guard.
export {
	createRateLimitGuard,
	type RateLimitFailMode,
	type RateLimitGuardOptions,
} from "./ratelimit/guard.mjs";
export { resolveLoginLimitSpec } from "./ratelimit/loginSpec.mjs";
export {
	createMemoryRateLimiter,
	DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
	type MemoryRateLimiterOptions,
} from "./ratelimit/memory.mjs";
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
export { type RunReadinessOptions, runReadinessProbes } from "./readiness/run.mjs";
export type {
	ProbeResult,
	ReadinessProbe,
	ReadinessRegistrar,
	ReadinessReport,
} from "./readiness/types.mjs";
// Repository interfaces
export { isGrantTypeAllowed } from "./repositories/allowedGrantTypes.mjs";
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
	createRouter as createHealthcheckRouter,
	type HealthcheckRouterOptions,
} from "./routes/Healthcheck.mjs";
export { createRouter as createJwksRouter, type JwksRouterOptions } from "./routes/Jwks.mjs";
export {
	createRouter as createReadinessRouter,
	type ReadinessRouterOptions,
} from "./routes/Readiness.mjs";
export {
	createSessionFamilyIndexFactory,
	createSessionFederationIndexFactory,
	createSessionRPRegistryFactory,
	createUserSessionStoreFactory,
} from "./user-sessions/factory.mjs";
export { createInMemorySessionFamilyIndex } from "./user-sessions/memory/sessionFamilyIndex.mjs";
export { createInMemorySessionFederationIndex } from "./user-sessions/memory/sessionFederationIndex.mjs";
export { createInMemorySessionRPRegistry } from "./user-sessions/memory/sessionRPRegistry.mjs";
// #296: subject-keyed session index + per-subject access-token watermark, and
// the orchestrator a credential-change flow calls after writing the new secret.
export { createInMemorySubjectRevocation } from "./user-sessions/memory/subjectRevocation.mjs";
export { createInMemorySubjectSessionIndex } from "./user-sessions/memory/subjectSessionIndex.mjs";
export { createInMemoryUserSessionStore } from "./user-sessions/memory/userSessionStore.mjs";
export { memorySessionStoresModule } from "./user-sessions/modules/memory.mjs";
export {
	type CascadeSession,
	type RevokeAllForSubjectCapability,
	type RevokeAllForSubjectFailure,
	type RevokeAllForSubjectOptions,
	type RevokeAllForSubjectResult,
	revokeAllForSubject,
} from "./user-sessions/revokeAllForSubject.mjs";
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
	SubjectRevocation,
	SubjectRevocationFactory,
	SubjectSessionIndex,
	SubjectSessionIndexFactory,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
	UserSessionStoreFactory,
} from "./user-sessions/types.mjs";
export { SUBJECT_REVOCATION_ABSENCE_POLICY } from "./user-sessions/types.mjs";

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
export { withReason } from "./refresh-token-family/reason.mjs";
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
	RefreshTokenFamilyUpdateDecision,
	RefreshTokenFamilyUpdateResult,
} from "./refresh-token-family/types.mjs";

// ===========================================================================
// Wave 1 — AccessTokenDenylist (RFC 7009 §2.1 access-token revocation)
// ===========================================================================

export {
	type AccessTokenDenylistFactory,
	createAccessTokenDenylistFactory,
	registerBuiltinAccessTokenDenylists,
} from "./access-token-denylist/factory.mjs";
export type {
	MemoryAccessTokenDenylist,
	MemoryAccessTokenDenylistOptions,
} from "./access-token-denylist/memory.mjs";
export {
	createMemoryAccessTokenDenylist,
	DEFAULT_MEMORY_DENYLIST_SWEEP_INTERVAL,
} from "./access-token-denylist/memory.mjs";
export { memoryAccessTokenDenylistModule } from "./access-token-denylist/module.mjs";
export type { AccessTokenDenylist } from "./access-token-denylist/types.mjs";
// #375: the declared-absence policy the denylist readers share — #277's boot
// refusal, expressed through the #363 vocabulary instead of a bespoke stage.
export { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY } from "./access-token-denylist/types.mjs";

// SF-3 + MIN-4 (v0.5.1): timing-safe primitives. Exported from the package
// root because `packages/core/package.json#exports` does not register a
// `./security/*` subpath — Codex Delta 1 confirmed the subpath approach
// would fail at runtime under Node's exports gating.
export { constantTimeStringEqual } from "./security/timingSafe.mjs";

// ===========================================================================
// Device Authorization Grant — DeviceCodeStore port + codes (RFC 8628, #298)
// ===========================================================================

export {
	createMemoryDeviceCodeStore,
	type MemoryDeviceCodeStore,
	type MemoryDeviceCodeStoreOptions,
} from "./device-authorization/memory.mjs";
export { memoryDeviceCodeStoreModule } from "./device-authorization/module.mjs";
export {
	type ApproveDeviceAuthorizationInput,
	type CreateDeviceAuthorizationInput,
	DEVICE_CODE_STORE_ABSENCE_POLICY,
	type DeviceAuthorization,
	type DeviceAuthorizationStatus,
	type DeviceCodeStore,
	type DeviceDecisionOutcome,
	type DevicePollOutcome,
} from "./device-authorization/types.mjs";
export {
	formatUserCode,
	generateDeviceCode,
	generateUserCode,
	normaliseUserCode,
	USER_CODE_ALPHABET,
	USER_CODE_LENGTH,
} from "./device-authorization/userCode.mjs";

// ===========================================================================
// Wave 1 — WebAuthnCredential + WebAuthnCredentialStore (spec §2.3.1)
// ===========================================================================

export {
	WebAuthnCredentialStorageError,
	type WebAuthnCredentialStorageErrorReason,
} from "./webauthn-credentials/errors.mjs";
export {
	createWebAuthnCredentialStoreFactory,
	registerBuiltinWebAuthnCredentialStores,
	type WebAuthnCredentialStoreFactory,
} from "./webauthn-credentials/factory.mjs";
export { createMemoryWebAuthnCredentialStore } from "./webauthn-credentials/memory.mjs";
export { memoryWebAuthnCredentialStoreModule } from "./webauthn-credentials/module.mjs";
export type {
	AuthenticatorTransport,
	WebAuthnCredential,
	WebAuthnCredentialStore,
} from "./webauthn-credentials/types.mjs";
