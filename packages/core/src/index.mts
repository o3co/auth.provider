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

// Access-token extraction from the Authorization header (in core so
// `protectedResourceBindingMw` shares it).
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
	type LifecycleCleanupOptions,
	type LifecycleRegistrar,
} from "./adapters/AdapterFactory.mjs";
export {
	isStorableExpiry,
	isStorableLifetime,
	MAX_STORABLE_EXPIRY_MS,
} from "./adapters/expiry.mjs";
// App factory (the boot planner), re-exported through ./app.mjs to keep its
// import path stable.
export { createApp } from "./app.mjs";
// The trust registry behind the jwt-bearer grant — which issuers are
// accepted, on what keys, on what terms — and the verifier over it. The
// one-key `createJwtAssertionVerifier` is a one-entry registry.
export {
	type AssertionIssuerEntry,
	type AssertionIssuerEntryInput,
	type AssertionIssuerKeySource,
	type AssertionIssuerRegistry,
	checkAssertionIssuerEntry,
	createMemoryAssertionIssuerRegistry,
	type MutableAssertionIssuerRegistry,
	toAssertionIssuerEntry,
} from "./assertions/issuerRegistry.mjs";
export type {
	JwtAssertionVerifierOptions,
	SubjectHandleReader,
} from "./assertions/jwtAssertionVerifier.mjs";
export { createJwtAssertionVerifier } from "./assertions/jwtAssertionVerifier.mjs";
export {
	type AssertionLifetime,
	assertionLifetime,
	describeInvalidAssertionClockTolerance,
	isValidAssertionClockTolerance,
	MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS,
	MAX_ASSERTION_LIFETIME_SECONDS,
} from "./assertions/lifetime.mjs";
export {
	type AssertionClaimReaders,
	createRegistryAssertionVerifier,
	ID_JAG_TYP,
	type RegistryAssertionVerifierOptions,
} from "./assertions/registryAssertionVerifier.mjs";
// A remote JSON Web Key Set, memoised per uri and tuning, with a fetch seam
export {
	createRemoteKeySetCache,
	DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_REMOTE_JWKS_COOLDOWN_MS,
	DEFAULT_REMOTE_JWKS_TIMEOUT_MS,
	type RemoteKeySet,
	type RemoteKeySetCache,
	type RemoteKeySetCacheOptions,
	type RemoteKeySetTuning,
} from "./assertions/remoteKeySet.mjs";
// Possession proof for the RFC 7523 jwt-bearer grant. The port is here;
// the JWT implementation is the vendor-neutral one, and a platform attestation
// (DeviceCheck, Play Integrity) is the operator's own.
export type {
	AssertionVerificationContext,
	AssertionVerificationResult,
	AssertionVerifier,
} from "./assertions/types.mjs";
// What an audit event may carry of an error: its name and code, never its
// message (a store's or an IdP's words).
export {
	type AuditedError,
	type AuditedErrorCause,
	auditedError,
} from "./audit/auditedError.mjs";
export {
	createAuditSinkFactory,
	emitAuditEvent,
	recordAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
// Audit
export type { AuditEvent, AuditEventDetails, AuditSink, AuditSinkFactory } from "./audit/types.mjs";
// The declared-absence policy the bundled auditSink readers share (one
// constant, so the boot error's advice does not depend on which module tripped
// it), and the built-in audit-event inventory (pinned against the emission
// sites by a drift-guard test, so sinks filter on names that actually occur).
export { AUDIT_SINK_ABSENCE_POLICY, BUILT_IN_AUDIT_EVENT_TYPES } from "./audit/types.mjs";
export type {
	AppHandle,
	AuthoritativeComponentOverriddenDetails,
	AuthoritativeWithoutProvidesDetails,
	BootErrorDetails,
	BootErrorReason,
	BootStage,
	BootstrapComponentCollisionDetails,
	BootstrapMap,
	CircularDependencyDetails,
	CleanupRecord,
	CollectedRouteContribution,
	ConfigPathRelocatedDetails,
	ConfigValidationFailedDetails,
	ContributeAndOverrideSameKeyDetails,
	ContributeFactoryFailedDetails,
	ContributionCollectorMap,
	ContributionKindGuardedDetails,
	ContributionKindMap,
	ContributionMalformedDetails,
	CreateAppOptions,
	DefaultBootstrapMap,
	DuplicateContributeDetails,
	DuplicateModuleNameDetails,
	DuplicateOverrideDetails,
	DuplicateProvidesDetails,
	DuplicateSecondFactorAuthorityDetails,
	EnvironmentVariableRenamedDetails,
	FederationRedirectPolicyUnpairedDetails,
	InvalidRouteAdvertisementPathDetails,
	LifecycleWithoutProvidesDetails,
	ListCollector,
	ListShapedOverrideDetails,
	MissingRequiredComponentDetails,
	ModuleFactoryNotCalledDetails,
	ModuleSectionPathInvalidDetails,
	NameKeyedCollector,
	OrderedRouteContribution,
	OverrideTargetMissingDetails,
	ProvidesFactoryFailedDetails,
	RegisteredFederationType,
	ReservedComponentKeyDetails,
	RouteCollector,
	RouteOrderCycleDetails,
	RouteOrderTargetMissingDetails,
	SyntheticKeyCollisionDetails,
	TokenSettingsLifetimeExceedsConfigurationDetails,
	UnknownContributionKindDetails,
} from "./boot/index.mjs";
// Boot planner — BootError catalogue, and the replica-safety guard, exported so
// a custom composition root can run the same check. `replicaUnsafeReason` reads
// a module's own `replicaSafety` declaration, so a deployment asserts on its
// manifests rather than on the core-only name list.
export {
	BootError,
	type CheckReplicaSafetyInput,
	checkReplicaSafety,
	REPLICA_UNSAFE_MODULES,
	type ReplicaSafetyModuleRef,
	replicaUnsafeReason,
} from "./boot/index.mjs";
// The CSRF token's signature bounds, part of the `csrfTokenSigner` contract.
export {
	CSRF_SIGNATURE_MAX_LENGTH,
	CSRF_SIGNATURE_MIN_LENGTH,
} from "./browser-session/csrf-signature.mjs";
// The login page's URL rule: the one home of what /authorize's fallback and
// the session package's loginEntry do to a login page.
export {
	LOGIN_RETURN_PARAMETER,
	loginPageCarriesReturn,
	loginPageUrlFor,
} from "./browser-session/login-page.mjs";
// What the session package owns of the browser session that other
// packages use — the login page, the one CSRF policy, the session
// cookie's attributes — each through a slot rather than the session's
// configuration.
export type {
	CsrfGuard,
	CsrfTokenSigner,
	CsrfVerdict,
	LoginEntry,
	NavigationVerdict,
	SessionCookiePolicy,
} from "./browser-session/types.mjs";
// Configuration
export {
	type AccessTokenConfig,
	type AccessTokenLifetime,
	type AccessTokenLifetimeSource,
	type AccessTokenRevocationMode,
	type AppConfig,
	AppConfigSchema,
	type CoreConfig,
	CoreConfigSchema,
	// The four spellings an environment variable may say a boolean in,
	// for the packages outside core that read a section this file declares.
	coerceBooleanFromEnv,
	composeConfigSchema,
	// A duration read strictly from a number or the decimal string a variable
	// carries, for the packages outside core that declare a section's schema.
	durationFromEnv,
	fullSectionsSchema,
	isLifetimeSeconds,
	// The hop ceiling `http.trustProxy` is held to, which the
	// `httpSettings` contract suite holds the slot's value to as well.
	MAX_TRUST_PROXY_HOPS,
	type RefreshTokenLifetimeSource,
	readAccessTokenRevocationMode,
	resolveAccessTokenLifetime,
	resolveRefreshTokenLifetime,
	// Any other whole number read strictly from a number or a string of
	// decimal digits a variable carries, for the packages outside core that
	// declare a section's schema.
	wholeNumberFromEnv,
} from "./config/application.schema.mjs";
// Transitional: the switches that choose a composition root's modules, read
// before it knows them. `createApp` takes the resolved configuration itself,
// and parses it once.
export { readTransitionalConfig } from "./config/composed.mjs";
// How a configured value is read where its owning schema did not run, and how
// a refusal quotes it.
export { configuredNumber, shownConfigValue } from "./config/configuredValue.mjs";
export { MAX_DURATION_MS, MAX_DURATION_SECONDS } from "./config/durations.mjs";
// The reference.conf files a composition layers beneath its own
// configuration — core's, and each loaded module's package's (`section.reference`).
export { coreReference, moduleReferences } from "./config/references.mjs";
export { productionEnvironmentIn, readEnvironmentName } from "./deployment/environment.mjs";
// How the deployment runs — what its HTTP behaviour depends on of the
// `http` module's settings, and how many replicas the operator says run —
// each through a slot rather than the configuration. `deploymentModeOf` is
// the reading boot fills `deploymentMode` with, for a composition root that
// builds a reader by hand; `checkDeploymentMode` is what every reader holds
// the value it is handed to.
export { checkDeploymentMode, deploymentModeOf } from "./deployment/mode.mjs";
export type { DeploymentMode, HttpSettings } from "./deployment/types.mjs";
// OIDC discovery aggregation — modules contribute `discoveryMetadata`
// (OidcDiscoveryContributionFactory above) and core synthesizes the
// `/.well-known/openid-configuration` document via `buildDiscoveryDocument`.
export { buildDiscoveryDocument, DiscoveryDocumentError } from "./discovery/buildDocument.mjs";
export type { OidcDiscoveryContribution } from "./discovery/types.mjs";
// RFC 6749 §5.2 shared error envelope, for custom routes too, so the whole
// product surface emits a single shape.
export {
	auditErrorList,
	auditErrorText,
	type ErrorEnvelope,
	errorEnvelope,
	isWellFormedErrorCode,
	sanitizeErrorText,
} from "./errors/envelope.mjs";
export {
	createFederationTokenStoreFactory,
	registerBuiltinFederationTokenStores,
} from "./federation-tokens/factory.mjs";
export { memoryFederationTokenStoreModule } from "./federation-tokens/module.mjs";
// The federation refresh-error classifier, shared by the session-bound token
// route and the federation grant retrieval.
export {
	classifyFederationRefreshError,
	type FederationRefreshErrorClassification,
	type FederationRefreshErrorReason,
	isKnownFederationRefreshErrorCode,
} from "./federation-tokens/refresh-error.mjs";
// FederationTokenStore. Backing client interface
// (FederationTokenStoreClient) lives in @o3co/auth-provider-redis.
export type {
	AcquireLockOptions,
	FederationTokenStore,
	FederationTokenStoreFactory,
	FederationTokens,
	LockResult,
	SupportsLock,
} from "./federation-tokens/types.mjs";
export { supportsLock } from "./federation-tokens/types.mjs";
// Whether a failed upstream call is an outage: the classifier reads it before
// the codes that reject a refresh token, and the federation-grant connect
// callback on its own.
export { isFederationUpstreamOutage } from "./federation-tokens/upstreamOutage.mjs";
// The federation adapter toolkit: the pure helpers every adapter builds its
// requests with — the PKCE S256 challenge, the URL its library exchanges the
// code at (RFC 9207 `iss` and nothing else from the callback), a
// `client_secret` that may be computed per request — and the one reading of
// the token response it answers with.
export { callbackUrlForExchange } from "./federations/callback-url.mjs";
export type { FederationClientSecret } from "./federations/client-secret.mjs";
export { resolveClientSecret } from "./federations/client-secret.mjs";
export { federationsOf } from "./federations/configured.mjs";
export { codeChallenge } from "./federations/pkce.mjs";
export type { FederationResponseMode } from "./federations/response-mode.mjs";
export {
	DEFAULT_FEDERATION_RESPONSE_MODE,
	FEDERATION_RESPONSE_MODES,
	resolveFederationResponseMode,
} from "./federations/response-mode.mjs";
// RFC 6749 §3.3's scope grammar, in one place.
export {
	canonicalScope,
	isScopeToken,
	parseScopeTokens,
	readIssuedScope,
	readSpaceDelimitedParameter,
} from "./federations/scope.mjs";
// The one reading of an upstream token's lifetime, and the age of one held.
export type {
	HeldUpstreamToken,
	HeldUpstreamTokenAge,
	UpstreamLifetimeClock,
	UpstreamLifetimeFields,
	UpstreamTokenLifetime,
} from "./federations/token-lifetime.mjs";
export {
	judgeHeldUpstreamToken,
	readUpstreamTokenLifetime,
} from "./federations/token-lifetime.mjs";
export type {
	FederationTokenResponse,
	FederationTokenSnapshot,
} from "./federations/token-snapshot.mjs";
export { federationTokenSnapshot } from "./federations/token-snapshot.mjs";
// RFC 6749's `token_type`, in one place: what an upstream token may be handed
// on as, and the case-insensitive comparison (§5.1) that decides it.
export {
	BEARER_TOKEN_TYPE,
	canonicalTokenType,
	isBearerTokenType,
} from "./federations/token-type.mjs";
// The federation adapter port. An adapter implements
// `FederationProvider` and whichever capability interfaces it can honour; the
// session router drives them, `oauth` reads them off `federationProviders`,
// and `federation-grants` delegates through them. `FederationProvider` itself
// is exported with the manifest types below, where it is also the
// contribution value type. What stays in `@o3co/auth-provider-session` is
// `FederationResult` and the redirect policy its router feeds.
export type {
	DelegatedAuthorizationRequest,
	DelegatedAuthorizationResult,
	DelegatedCodeExchangeRequest,
	DelegatedRefreshRequest,
	DelegatedTokens,
	EndSessionRequest,
	EndSessionResult,
	FederationProfile,
	MappedClaims,
	RefreshedTokens,
	SupportsClaimMapping,
	SupportsDelegatedAuthorization,
	SupportsLogout,
	SupportsRefresh,
} from "./federations/types.mjs";
export {
	identityClaimsProblem,
	RESERVED_DELEGATED_AUTHORIZATION_PARAMS,
	RESERVED_IDENTITY_CLAIMS,
	selectIdentityClaims,
	supportsClaimMapping,
	supportsDelegatedAuthorization,
	supportsLogout,
	supportsRefresh,
} from "./federations/types.mjs";
// The authentication claims a token may carry
export {
	authTimeAt,
	authTimeClaim,
	composeAmr,
	EMAIL_OTP_AMR,
	FEDERATED_AMR,
	HARDWARE_KEY_AMR,
	MFA_AMR,
	OTP_AMR,
	PASSWORD_AMR,
	RECOVERY_CODE_AMR,
	SOFTWARE_KEY_AMR,
	wellFormedAcr,
	wellFormedAmr,
	wellFormedAuthTime,
} from "./grants/authenticationClaims.mjs";
export { filterClaimsByScope } from "./grants/claimFilter.mjs";
export type { Confirmation } from "./grants/confirmation.mjs";
// The ONE cnf/token-binding comparison matrix — consumed by the
// refresh and token-exchange grants, `protectedResourceBindingMw`, and the
// introspection handler; each caller keeps only its own error mapping.
export {
	type ConfirmationMatch,
	type ConfirmationMember,
	extractConfirmation,
	isCompoundConfirmation,
	matchConfirmation,
	ownedConfirmation,
	tokenTypeForConfirmation,
} from "./grants/confirmationMatch.mjs";
export { isEmailVerified } from "./grants/emailVerifiedGate.mjs";
// Grant-policy evaluation and its bounds: the one answer every minting
// path gives a policy that throws, denies, returns a decision that is
// neither allow nor deny, or exceeds its ceiling.
export {
	boundPolicyAudience,
	type EvaluateGrantPolicyOptions,
	evaluateGrantPolicy,
	type GrantPolicyAllow,
	type GrantPolicyDeny,
	type GrantPolicyOutcome,
	type GrantPolicyReading,
	logGrantPolicyUnavailable,
	type PolicyAudienceOutcome,
	type PolicyScopeCeiling,
	policyOutOfBounds,
	policyUnavailable,
	readGrantPolicyDecision,
} from "./grants/grantPolicy.mjs";
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
// RFC 8707 resource indicators: the one reading of `resource`,
// the audience derived from it, and the `invalid_target` check — shared by the
// oauth grants, `/authorize` and the WebAuthn grant. `readTargetParameter` is
// the strict reading underneath, which also reads RFC 8693's `audience`: the
// token-exchange grant reads both with it and refuses a malformed one.
export {
	deriveAudienceFromResources,
	extractResourceParam,
	readTargetParameter,
	unrepresentedResources,
} from "./grants/resourceIndicator.mjs";
export type { SenderConstraint } from "./grants/senderConstraint.mjs";
// The two ways an access token names its session: `sid` (liveness and the
// session's capabilities) and `liveness_sid` (a derived token's liveness link).
export { LIVENESS_SID_CLAIM, livenessSidOf } from "./grants/sessionClaims.mjs";
// Grant types and interfaces. Consumers wire grants through a module's
// `contributes.grants`; `GrantRegistry` is internal to the boot planner.
// Token formatting utility (used by oauth package)
export {
	formatObject,
	type GenerateTokenOptions,
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
	GrantResult,
	GrantSuccess,
	SessionData,
	SessionMutation,
} from "./grants/types.mjs";
export {
	advertisedIssuer,
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
export { createRouter as createJwksRouter, type JwksRouterOptions } from "./jwks/router.mjs";
// A JWT's exp / iat / nbf, checked before anything computes an expiry from them.
export type { NumericDateClaim } from "./jwt/numericDate.mjs";
export {
	isNumericDate,
	MAX_NUMERIC_DATE_SECONDS,
	malformedNumericDateClaim,
} from "./jwt/numericDate.mjs";
// JWT verifier — central verifyJwt with alg/iss/aud/typ pinning
export type {
	JwtRevocationSources,
	JwtType,
	JwtVerificationReason,
	JwtVerifyOptions,
	VerificationUnavailableReason,
	VerifiedJwt,
	VerifyRevocation,
} from "./jwt/verify.mjs";
export {
	isVerificationUnavailable,
	JwtVerificationError,
	REVOCATION_RETENTION_ALLOWANCE_MS,
	VERIFICATION_UNAVAILABLE_DESCRIPTION,
	verifyJwt,
} from "./jwt/verify.mjs";
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
// The one rule for a kid a keystore is built with and a kid header verifyJwt
// looks up, so a token this server signed always carries a kid it will look up.
export { isWellFormedKid, MAX_KID_LENGTH } from "./keys/kid.mjs";
// The KeyStore whose private key never enters this process. Wired by a
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
// Shared-secret entropy floor. Exported so a composition root that
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
// What a log line may carry of a library's error: never the response on its cause chain.
export {
	guardedRead,
	LOGGED_AGGREGATE_MAX_ERRORS,
	LOGGED_MAX_PROJECTIONS,
	LOGGED_PRINT_DEPTH,
	LOGGED_STACK_MAX_FRAMES,
	LOGGED_STACK_MAX_LENGTH,
	LOGGED_STRING_MAX_LENGTH,
	type LoggableError,
	lineSafeText,
	loggableError,
} from "./logging/loggableError.mjs";
export { normaliseMailAddress } from "./mail/address.mjs";
export { type MailSendOutcome, mailSendOutcome } from "./mail/outcome.mjs";
// Mail: the port a one-time code the provider issued leaves through
export {
	MAIL_PURPOSES,
	type MailPurpose,
	type MailSend,
	type MailSender,
	type MailSendResult,
} from "./mail/types.mjs";
// MFA — the second-factor contract (the manifest group below exports its
// MfaFactor name)
export type {
	MfaCeremonyContext,
	MfaChallenge,
	MfaChallengeContext,
	MfaDigestMatch,
	MfaDigests,
	MfaEnrolledFactor,
	MfaEnrollmentCompletion,
	MfaEnrollmentCompletionContext,
	MfaEnrollmentContext,
	MfaEnrollmentStart,
	MfaFactorData,
	MfaFactorMail,
	MfaFactorMailPurpose,
	MfaFactorState,
	MfaKeyedDigest,
	MfaLoginCodeMail,
	MfaVerification,
	MfaVerifyContext,
} from "./mfa/factor.mjs";
export {
	isMfaFactorId,
	isMfaFactorKind,
	isMfaFactorLabel,
	isMfaFactorUpdateWritten,
	MFA_FACTOR_LABEL_MAX_LENGTH,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorStore,
	type MfaFactorStoreFactory,
	type MfaFactorUpdateRequest,
} from "./mfa/factorStore.mjs";
export {
	createMfaFactorStoreFactory,
	createMfaTransactionStoreFactory,
	registerBuiltinMfaFactorStores,
	registerBuiltinMfaTransactionStores,
} from "./mfa/factory.mjs";
export { createMemoryMfaFactorStore } from "./mfa/memoryFactorStore.mjs";
export {
	createMemoryMfaTransactionStore,
	DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES,
	DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS,
	DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL,
	type MemoryMfaTransactionStore,
	type MemoryMfaTransactionStoreOptions,
	MfaTransactionStoreFullError,
} from "./mfa/memoryTransactionStore.mjs";
// MFA (the MFA ADR): the stores, their memory adapters, factories and
// modules
export { memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule } from "./mfa/module.mjs";
// The wire format of the Store's MFA endpoints, shared by the Store adapter
// and a Store's own implementation (or a fake of one)
export {
	fromMfaStoreFactor,
	type MfaStoreCreateRequest,
	type MfaStoreDeleteRequest,
	type MfaStoreFactor,
	type MfaStoreFactorBinding,
	type MfaStoreFactorChanges,
	type MfaStoreListAnswer,
	type MfaStoreListReading,
	type MfaStoreListRequest,
	type MfaStoreMarkEnrolledRequest,
	type MfaStoreUpdateAnswer,
	type MfaStoreUpdateRequest,
	readMfaStoreFactor,
	readMfaStoreFactorChanges,
	readMfaStoreListAnswer,
	toMfaStoreFactor,
	toMfaStoreFactorChanges,
	toMfaStoreUpdateRequest,
} from "./mfa/storeWire.mjs";
export {
	checkConfiguredMfaLockoutPolicy,
	checkFirstBindingNote,
	checkFirstBindingQuestion,
	checkMfaLockoutPolicy,
	checkMfaTransactionTransitions,
	checkRecoverySetFloorRaise,
	checkSessionEmailProof,
	checkSessionEmailProofQuestion,
	checkSubjectLeaseRelease,
	checkSubjectLeaseRequest,
	checkSubjectQuestion,
	checkSubjectRecoveryApplication,
	checkSubjectRecoveryAuthorization,
	DEFAULT_MFA_SUBJECT_LEASE_MS,
	type FirstBindingMark,
	firstBindingAnswer,
	getBoundMfaTransaction,
	isConsumedMfaTransaction,
	isMfaTransactionBoundTo,
	laterFirstBindingMark,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	MFA_LOCKOUT_MAX_BACKOFF_SECONDS,
	MFA_LOCKOUT_MAX_HARD_LIMIT,
	MFA_LOCKOUT_MIN_HARD_LIMIT,
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	MFA_SUBJECT_LEASE_MAX_MS,
	MFA_SUBJECT_LEASE_MIN_MS,
	MFA_TRANSACTION_PATCH_KEYS,
	MFA_WEEKLY_WINDOW_MS,
	type MfaLockoutPolicy,
	type MfaRecoverySetFloorAnswer,
	type MfaRecoverySetFloorRaise,
	type MfaSessionBinding,
	type MfaSubjectAttemptOutcome,
	type MfaSubjectAttemptReservation,
	type MfaSubjectHold,
	type MfaSubjectLeaseAnswer,
	type MfaSubjectLeaseRequest,
	type MfaSubjectRecoveryAnswer,
	type MfaSubjectRecoveryApplication,
	type MfaSubjectRecoveryAuthorization,
	type MfaSubjectRecoveryOperation,
	type MfaSubjectRecoveryRefusal,
	type MfaTransaction,
	type MfaTransactionBinding,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	type MfaTransactionStoreFactory,
	mfaTransactionPatchWrites,
	newMfaTransactionRecord,
	readFirstBindingAt,
	readMfaAttemptReservation,
	readMfaRecoverySetFloorAnswer,
	readMfaSubjectAttemptReservation,
	readMfaSubjectCount,
	readMfaSubjectLeaseAnswer,
	readMfaSubjectRecoveryAnswer,
	readSessionEmailProof,
	type SessionEmailProof,
	sessionEmailProofAnswer,
} from "./mfa/transactionStore.mjs";
export { checkMfaVersionAdvances } from "./mfa/version.mjs";
// Middleware — CORS for the browser-facing OAuth surface
export {
	browserFacingCorsRoutes,
	type CorsMiddlewareOptions,
	type CorsRoute,
	corsMw,
} from "./middleware/cors.mjs";
// Middleware — protected-resource sender-constraint enforcement (RFC 9449 §7.1 / RFC 8705 §3)
export {
	type ProtectedResourceBindingOptions,
	protectedResourceBindingMw,
} from "./middleware/protectedResourceBinding.mjs";
// Middleware — the answer to an error a route let through; `createApp` ends its router with it
export { terminalErrorHandler } from "./middleware/terminalError.mjs";
// Middleware — tokenBindingMw factory + plugin surface
export {
	type DispatchPolicy,
	isTokenBindingMw,
	resolveTokenBindingSettings,
	type TokenBindingExtractContext,
	type TokenBindingMechanism,
	type TokenBindingMiddlewareOptions,
	type TokenBindingRefusal,
	type TokenBindingSettings,
	tokenBindingMw,
} from "./middleware/tokenBinding.mjs";
// Module system — manifest types. Authoring code uses `Module` and
// `defineModule()` from here (also the `@o3co/auth-provider-core/modules/manifest`
// subpath).
export type {
	AbsencePolicy,
	AuditHook,
	AuditHookFactory,
	ComponentKey,
	ComponentMap,
	ConfigSchema,
	Contributed,
	ContributesMap,
	ExchangeTokenValidator,
	ExchangeTokenValidatorFactory,
	FederationFactory,
	// One configured federation as its type's factory receives it, and
	// what a federation package declares it handles, keyed by type.
	FederationInstance,
	FederationProvider,
	FederationTypeContribution,
	// GrantFactory, GrantHandler: excluded — names collide with
	// ./grants/types.mjs exports at this boundary. Import from
	// @o3co/auth-provider-core/modules/manifest directly.
	GrantHandlerResolver,
	GrantMiddlewareFactory,
	// The contributes-map entry type; the `GrantPolicyHook` interface itself is
	// re-exported from ./policy/types.mjs below.
	GrantPolicyHookContribution,
	// GrantPolicyHookFactory: excluded — name collides with the
	// ./policy/types.mjs export at this boundary. Import from
	// @o3co/auth-provider-core/modules/manifest directly.
	MfaFactor,
	MfaFactorFactory,
	MfaFactorResolver,
	Module,
	// A module's own configuration section, and what it adds to deps.
	ModuleSection,
	ModuleSpec,
	OidcDiscoveryContributionFactory,
	PathResolver,
	Provider,
	ProviderDeps,
	// A module's budget for a rate-limit prefix it owns, and the view
	// core composes the budgets into.
	RateLimitBudgetFactory,
	RateLimitBudgetResolver,
	// A relocatedFrom entry whose new path no environment variable binds.
	RelocationWithoutVariable,
	// The manifest's replica-safety declaration, so a package
	// building its manifest from config can type the value it attaches.
	ReplicaSafetyDeclaration,
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
	SectionDeps,
	SectionSchema,
	SessionRequirementFactory,
	TokenBindingMechanismFactory,
	TokenExchangeValidatorResolver,
} from "./modules/index.mjs";
export {
	// The way to author a federationTypes declaration, its entry tied to its schema.
	defineFederationType,
	defineModule,
	type FederationTypeDeclaration,
	SYNTHETIC_COMPONENT_KEYS,
} from "./modules/index.mjs";
// The one reading of a declared absence, and the one way of saying how to
// write it: for a module that checks a policy itself (a feature switched on
// at stage 4 cannot attach one), so its refusal agrees with boot's.
export {
	describeAbsenceDeclaration,
	isAbsenceDeclared,
} from "./modules/manifest/absence-policy.mjs";
// The single loopback-hostname vocabulary — the predicate behind every
// "http:// is accepted for loopback hosts only" carve-out
// (`checkSecureEndpoint` in foundation, `checkRedirectShape` in session).
// Exported so consumers import or re-export it rather than defining a copy;
// the designVocabulary drift guard fails any second definition.
export { isLoopbackHostname } from "./net/loopback.mjs";
// The serialized-origin vocabulary — what a configured browser origin
// may be. Enforced on a composition's CORS list by the schema of the module
// that provides `httpSettings`, re-applied by `corsMw`, and on every web entry
// of the WebAuthn package's `origin` / `topOrigin`; exported so a consumer
// assembling its own policy holds origins to the same rules and refuses in the
// same words. `normalizeAllowedOrigins` reads an origin list in both its
// spellings — an array, or the comma-separated string an environment variable
// carries.
export {
	checkSerializedOrigin,
	describeSerializedOriginRejection,
	normalizeAllowedOrigins,
	type SerializedOriginRejection,
} from "./net/origin.mjs";
// The registered-redirect-URI shape vocabulary, the query's parameter names
// included — enforced by ClientEntrySchema at boot; exported so a custom
// ClientRepository, which bypasses that schema by design, can hold its
// registrations to the same rules and refuse in the same words.
// `matchesRegisteredRedirectUri` is the runtime half of the same
// vocabulary — the /authorize allowlist comparison, exact except for the RFC
// 8252 §7.3 loopback port. Exported alongside the shape checker so a custom
// authorization endpoint matches the way this one does.
export {
	checkRedirectUri,
	describeRedirectUriRejection,
	matchesRegisteredRedirectUri,
	type RedirectUriRejection,
} from "./net/redirect-uri.mjs";
// The single canonical-request-URL vocabulary — "the URL this
// request reached" is the configured origin plus `req.originalUrl`, never
// `req.protocol` + the `Host` header (attacker-influenced under
// `trust proxy`). DPoP htu comparison and the /authorize login round-trip
// both consume this; the designVocabulary drift guard fails any second
// definition.
export { buildCanonicalRequestUrl } from "./net/request-url.mjs";
// The RFC 6890 special-use ranges a caller-supplied URL must not
// resolve to — the SSRF guard's one list.
export { isSpecialUseAddress } from "./net/special-use.mjs";
// The single trusted-proxy address vocabulary — Express's own
// `trust proxy` forms. `http.trustProxy` validates its entries with
// `checkTrustedProxyEntry`; `@o3co/auth-provider-mtls` matches
// `req.socket.remoteAddress` with `createTrustedProxyMatcher`. Exported so a
// custom composition root, or a future mechanism that has to authenticate a
// forwarding hop, extends this list rather than starting a second dialect.
export {
	checkTrustedProxyEntry,
	createTrustedProxyMatcher,
	describeTrustedProxyEntryRejection,
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
// The one lookup every bundled limiter takes a key's budget from.
export {
	createRateLimitBudgetLookup,
	type RateLimitBudget,
	type RateLimitBudgetLookup,
	type RateLimitBudgetLookupOptions,
} from "./ratelimit/budgetLookup.mjs";
export {
	createRateLimiterFactory,
	registerBuiltinRateLimiters,
} from "./ratelimit/factory.mjs";
// The single guard factory behind the OAuth-endpoint throttles and the
// /session/login brute-force guard, and (`checkWithFailMode`) its check and
// outage policy alone, for a route whose budget is not keyed on the IP.
export {
	checkWithFailMode,
	createRateLimitGuard,
	createRateLimitPolicy,
	type RateLimitCheckOutcome,
	type RateLimitGuardOptions,
	type RateLimitOutageLogger,
	type RateLimitPolicy,
	type RateLimitPolicyOptions,
	rateLimiterUnavailableEnvelope,
} from "./ratelimit/guard.mjs";
export {
	createMemoryRateLimiter,
	DEFAULT_MEMORY_RATE_LIMITER_MAX_BUCKETS,
	type MemoryRateLimiterOptions,
} from "./ratelimit/memory.mjs";
export { memoryRateLimiterModule } from "./ratelimit/module.mjs";
// Rate limiter. Backing client interface (RateLimiterClient) lives in
// @o3co/auth-provider-redis.
export type {
	RateLimitContext,
	RateLimitDecision,
	RateLimiter,
	RateLimiterFactory,
	RateLimitFailMode,
	RateLimitSpec,
} from "./ratelimit/types.mjs";
export {
	assertUsableRateLimitSpecs,
	isUsableRateLimitSpec,
	readConfiguredRateLimitSpec,
	requireUsableConfiguredRateLimitSpec,
} from "./ratelimit/usableSpec.mjs";
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
export type { CodeRepository, CreateCodeInput } from "./repositories/CodeRepository.mjs";
export {
	assertRegistrableClientIds,
	isWellFormedClientId,
	MAX_CLIENT_ID_LENGTH,
} from "./repositories/clientId.mjs";
export {
	type ClientRepositoryOutage,
	logClientRepositoryUnavailable,
} from "./repositories/clientRepositoryUnavailable.mjs";
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
export type {
	FederatedIdentityLink,
	FederatedIdentityLookup,
	FederatedIdentityLookupResult,
	FederatedIdentityRegistration,
	LinkFederatedIdentityResult,
	MfaEnrollmentWitness,
	SupportsMfaEnrollmentWitness,
	UserRepository,
} from "./repositories/UserRepository.mjs";
export {
	readMfaEnrollmentWitness,
	supportsMfaEnrollmentWitness,
} from "./repositories/UserRepository.mjs";
export {
	createRouter as createHealthcheckRouter,
	type HealthcheckRouterOptions,
} from "./routes/Healthcheck.mjs";
export {
	createRouter as createReadinessRouter,
	type ReadinessRouterOptions,
} from "./routes/Readiness.mjs";
// Session admission (the session-admission ADR): the one decision point every
// consumer of an authenticated browser session calls, the claims it reads, the
// actions and their grades, the requirement contract, and the acr vocabulary.
export {
	type AcrRequirement,
	type AcrSelection,
	type AcrTable,
	type ProducibleAmr,
	producibleAmr,
	readAcrTable,
	SECOND_FACTOR_AMR,
	stepUpReach,
	type UnsatisfiableAcrValue,
	vouchableAcrTable,
} from "./session-admission/acr.mjs";
// The grades core owns, and what a consumer registers for each action it
// admits (`contributes.admissionActions`).
export {
	type ActionGrade,
	ADMISSION_GRADES,
	type AdmissionAction,
	type AdmissionActionDeclaration,
	type AdmissionGrade,
} from "./session-admission/actions.mjs";
export {
	admitPrimary,
	admitSession,
	type CodeCarrier,
	type CookieCarrier,
	checkResolver,
	codeClaimFirstRead,
	codeClaimRevalidation,
	cookieClaim,
	cookieRenewedAway,
	cookieSessionUser,
	establishWithoutAsking,
	type FederatedLogin,
	isEstablishment,
	isInterruptAdmission,
	type LinkCarrier,
	linkClaim,
	type PasswordLoginFacts,
	passwordPrimary,
	resumePrimary,
	type TokenCarrier,
	tokenClaim,
} from "./session-admission/admit.mjs";
// The tail of a login, and the renewal of a signed-in session's id, as a
// contract — what a requirement's completion requires through the
// `loginCompletion` slot instead of importing the session package.
export type {
	LoginCompletion,
	LoginEstablishmentCall,
	LoginEstablishmentReporter,
	LoginEstablishmentResult,
	LoginInterruptionCall,
	LoginInterruptionReporter,
	LoginInterruptionResult,
	LoginInterruptionStep,
	SessionRenewalCall,
	SessionRenewalReporter,
	SessionRenewalResult,
	SessionRenewalStep,
} from "./session-admission/login-completion.mjs";
export {
	checkPrimaryContinuation,
	enrollmentFactsOfContinuation,
} from "./session-admission/primary.mjs";
export {
	type Admission,
	type AdmissionAsks,
	type AdmissionDeps,
	type AdmissionInfrastructureStore,
	type AdmissionRequest,
	type CompletedRequirement,
	type CompletedRequirementDto,
	checkStepUpPage,
	describeAdmissionOutage,
	type Establishment,
	type InterruptAdmission,
	type InterruptionAnswer,
	type IssuedRemediationAction,
	isHintToken,
	issuedRemediationActions,
	type PrimaryAdditions,
	type PrimaryAdditionsDto,
	type PrimaryAdmission,
	type PrimaryAuthentication,
	type PrimaryAuthenticationDto,
	type PrimaryContinuation,
	type RegisteredRequirement,
	type RegisteredStepUpPage,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementSession,
	type RequirementVerdict,
	type SessionClaim,
	type SessionRequirement,
	type SessionRequirementResolver,
	type SessionView,
	type StepUpPage,
} from "./session-admission/requirement.mjs";
// The token-exchange validator port. `ExchangeTokenValidator` is
// exported with the manifest types below, as the contribution value type.
export type {
	ExchangeTokenValidationContext,
	ValidatedToken,
} from "./token-exchange/validator.mjs";
// What other modules read of the oauth module's token settings, through
// the `oauthTokenSettings` slot rather than the oauth section.
export { checkOAuthTokenSettings } from "./token-settings/check.mjs";
export type { OAuthTokenSettings } from "./token-settings/types.mjs";
// How a session was established and what this provider vouches for, read one
// way by every consumer of a session.
export {
	checkSecondFactorEvent,
	expectsRenewalNonce,
	federatedSessionAuthentication,
	federationTrustsUpstreamAmr,
	passwordSessionAuthentication,
	type RecordedAuthentication,
	type RenewalNonces,
	readRenewalNonces,
	recordableSessionAuthentication,
	requirementSession,
	requirementSessionFromAmr,
	sessionAfterSecondFactor,
	sessionAuthentication,
	vouchedAmr,
} from "./user-sessions/authentication.mjs";
// What a session's enrollment facts may hold, read one way by every store.
export {
	readEnrollmentFacts,
	recordableEnrollmentFacts,
} from "./user-sessions/enrollmentFacts.mjs";
export {
	createSessionFamilyIndexFactory,
	createSessionFederationIndexFactory,
	createSessionRPRegistryFactory,
	createUserSessionStoreFactory,
} from "./user-sessions/factory.mjs";
export { createInMemorySessionFamilyIndex } from "./user-sessions/memory/sessionFamilyIndex.mjs";
export { createInMemorySessionFederationIndex } from "./user-sessions/memory/sessionFederationIndex.mjs";
export { createInMemorySessionRPRegistry } from "./user-sessions/memory/sessionRPRegistry.mjs";
// Subject-keyed session index + per-subject access-token watermark, and
// the orchestrator a credential-change flow calls after writing the new secret.
export { createInMemorySubjectRevocation } from "./user-sessions/memory/subjectRevocation.mjs";
export { createInMemorySubjectSessionIndex } from "./user-sessions/memory/subjectSessionIndex.mjs";
export { createInMemoryUserSessionStore } from "./user-sessions/memory/userSessionStore.mjs";
export { memorySessionStoresModule } from "./user-sessions/modules/memory.mjs";
// The nonce that binds an escalated session to the one cookie session a
// renewal moved it to: minted by the renewal, recorded with the escalation.
export {
	isRenewalNonce,
	newRenewalNonce,
	RENEWAL_NONCE_BYTES,
} from "./user-sessions/renewalNonce.mjs";
export {
	type CascadeSession,
	type RevokeAllForSubjectCapability,
	type RevokeAllForSubjectFailure,
	type RevokeAllForSubjectOptions,
	type RevokeAllForSubjectResult,
	revokeAllForSubject,
} from "./user-sessions/revokeAllForSubject.mjs";
// How a SubjectRevocation store reads its arguments, and bounds a boundary by its clock.
export {
	checkSubjectRevocationInstant,
	clampSubjectRevocationBoundary,
} from "./user-sessions/subjectRevocationBoundary.mjs";
export {
	createSubjectRevocationService,
	type FederationGrantDisposition,
	type SubjectRevocationReport,
	type SubjectRevocationRequest,
	type SubjectRevocationService,
	type SubjectRevocationServiceDeps,
} from "./user-sessions/subjectRevocationService.mjs";
// ---------------------------------------------------------------------------
// User sessions
// ---------------------------------------------------------------------------
// Backing client interfaces (UserSessionStoreClient, SessionRPRegistryClient
// (+Multi), SessionSidSortedSetClient (+Multi)) live in
// @o3co/auth-provider-redis.
export type {
	CreateUserSessionInput,
	MailAddressFact,
	RegisteredRP,
	SecondFactorEvent,
	SessionAuthentication,
	SessionEnrollmentFacts,
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
	SupportsSecondFactorUpdate,
	SupportsSessionEnd,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
	UserSessionStoreFactory,
} from "./user-sessions/types.mjs";
export {
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	supportsSecondFactorUpdate,
	supportsSessionEnd,
} from "./user-sessions/types.mjs";

// ---------------------------------------------------------------------------
// Challenge Store + Replay Seen Set + Default Ceremony
// ---------------------------------------------------------------------------

// Memory adapters (re-exported so consumers can construct without going through modules)
export {
	ChallengeStoreFullError,
	createMemoryChallengeStore,
	DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES,
	DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS,
	DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL,
	type MemoryChallengeStore,
	type MemoryChallengeStoreOptions,
} from "./challenges/adapters/memory.mjs";
// Default composition
export {
	type ChallengeCeremonyDeps,
	createChallengeCeremony,
} from "./challenges/ceremony.mjs";
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
export {
	createMemoryReplaySeenSet,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS,
	DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL,
	type MemoryReplaySeenSet,
	type MemoryReplaySeenSetOptions,
	ReplaySeenSetFullError,
} from "./replay-seen-set/adapters/memory.mjs";
export {
	createReplaySeenSetFactory,
	type ReplaySeenSetFactory,
	registerBuiltinReplaySeenSets,
} from "./replay-seen-set/factory.mjs";
export { isRecordableJti, MAX_JTI_LENGTH } from "./replay-seen-set/jti.mjs";
export { memoryReplaySeenSetModule } from "./replay-seen-set/module.mjs";
export {
	DPOP_PROOF_REPLAY_SCOPE_PREFIX,
	DPOP_PROOF_REPLAY_SHARE,
} from "./replay-seen-set/scopes.mjs";
export type { ReplaySeenSet } from "./replay-seen-set/types.mjs";
// Canonical key helper, exported so integrators' own adapters keep
// cross-adapter parity
export { canonicalKey as canonicalChallengeKey } from "./single-use/canonical-key.mjs";
export type { ChallengeStorageErrorReason } from "./single-use/errors.mjs";
// Errors
export { ChallengeStorageError } from "./single-use/errors.mjs";

// ===========================================================================
// RefreshTokenFamilyStore + RefreshTokenFamilyRotation + RefreshTokenFamilyRevocation
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
	resolveFamilyAccessTokenHorizonMs,
	revokedFamilyExpiresAtMs,
} from "./refresh-token-family/retention.mjs";
export {
	createRefreshTokenFamilyRevocation,
	REVOKED_WITHOUT_RECORD_JTI,
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
// AccessTokenDenylist (RFC 7009 §2.1 access-token revocation)
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
// The declared-absence policy the denylist readers share: a boot refusal
// expressed through the AbsencePolicy vocabulary.
export { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY } from "./access-token-denylist/types.mjs";
// Where an end-user's consent to a client that is not first-party is
// recorded. Optional — without it `/authorize` refuses such clients.
export {
	type ConsentStoreFactory,
	createConsentStoreFactory,
	createPendingConsentStoreFactory,
	type PendingConsentStoreFactory,
	registerBuiltinConsentStores,
	registerBuiltinPendingConsentStores,
} from "./consents/factory.mjs";
export {
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	type MemoryConsentStore,
	type MemoryPendingConsentStore,
} from "./consents/memory.mjs";
export { memoryConsentStoreModule } from "./consents/module.mjs";
// The record an `/authorize` request is parked in while the consent
// page asks, consumed by exactly one answer.
export {
	type ConsentRecord,
	type ConsentStore,
	consentCovers,
	PENDING_CONSENT_PER_SESSION_LIMIT,
	type PendingConsentRecord,
	type PendingConsentStore,
} from "./consents/types.mjs";
// A client's grant registration fields, read as a list or as nothing.
export { federationGrantAllowlist } from "./federation-grants/allowlist.mjs";
// What an audit event says about the grant it concerns. Its own
// module because the retrieval, the revocation library call and the routes all
// need the same answer and cannot import each other.
export { federationGrantAuditMetadata } from "./federation-grants/auditMetadata.mjs";
// Federation grants: a consented, bounded grant under which the provider holds
// an upstream refresh credential for a confidential client. See ADR
// 2026-09-17-federation-grants-offline-delegation. Every name says
// FederationGrant, apart from the OAuth grant types (GrantContext, GrantResult,
// GrantPolicy*) this barrel also exports. The store port and credential are
// exported for a Redis adapter; the retrieval result, for the routes package.
export {
	coveredByRevocationBoundary,
	type EffectiveFederationGrantStatusContext,
	effectiveFederationGrantStatus,
} from "./federation-grants/effective-status.mjs";
export {
	FEDERATION_GRANT_INTERACTION_CODES,
	type FederationGrantIntentScopes,
	type FederationGrantInteractionCode,
	federationGrantIneligibilityRetry,
	federationGrantIneligibilityStands,
	federationGrantInteractionCode,
	federationGrantRefreshFailureStands,
	isUsableMaxUpstreamAccessTokenLifetime,
	judgeUpstreamAccessToken,
	resolveFederationGrantIntentScopes,
	type UpstreamTokenJudgement,
} from "./federation-grants/eligibility.mjs";
export {
	createFederationGrantStoreFactory,
	type FederationGrantStoreFactory,
	registerBuiltinFederationGrantStores,
} from "./federation-grants/factory.mjs";
// The access token a grant's credential stores, from a finite lifetime reading:
// every writer of a credential builds it here, so each keeps the same three facts.
export { federationGrantAccessToken } from "./federation-grants/held-token.mjs";
export {
	createFederationGrantIntentStoreFactory,
	type FederationGrantIntentStoreFactory,
	registerBuiltinFederationGrantIntentStores,
} from "./federation-grants/intentFactory.mjs";
export {
	createMemoryFederationGrantIntentStore,
	MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR,
	type MemoryFederationGrantIntentStore,
} from "./federation-grants/intentMemory.mjs";
export {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantConsentAnswer,
	type FederationGrantConsentAnswerResult,
	type FederationGrantConsentRecord,
	type FederationGrantIntent,
	type FederationGrantIntentRefusal,
	type FederationGrantIntentStore,
	type FederationGrantIntentWrite,
	federationGrantConsentExpiry,
} from "./federation-grants/intentStore.mjs";
export {
	FEDERATION_GRANT_LIFETIME_CEILING_MS,
	federationGrantEffectiveExpiry,
	federationGrantExpiresAt,
	federationGrantExpiryState,
	resolveFederationGrantLifetimeMs,
	withinFederationGrantLifetimeCeiling,
} from "./federation-grants/lifetime.mjs";
export {
	type FederationGrantAcquisitionConnection,
	type FederationGrantConnectionNotConfigured,
	type FederationGrantLodged,
	type FederationGrantLodgingAbsorbedCarrier,
	type FederationGrantLodgingClient,
	type FederationGrantLodgingDeps,
	type FederationGrantLodgingFailure,
	type FederationGrantLodgingRefusal,
	type FederationGrantLodgingRefused,
	type FederationGrantLodgingRequest,
	type FederationGrantLodgingResult,
	type FederationGrantLodgingStepFailure,
	type FederationGrantReauthorizationRequest,
	type FederationGrantReauthorizationResult,
	federationGrantRedirectUriReservedParameter,
	lodgeFederationGrantIntent,
	lodgeFederationGrantReauthorization,
} from "./federation-grants/lodge.mjs";
export {
	createMemoryFederationGrantStore,
	DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS,
	type MemoryFederationGrantStore,
	type MemoryFederationGrantStoreOptions,
} from "./federation-grants/memory.mjs";
export {
	memoryFederationGrantIntentStoreModule,
	memoryFederationGrantStoreModule,
} from "./federation-grants/module.mjs";
export {
	assertFederationGrantRetrievalLimits,
	FEDERATION_GRANT_REFRESH_LOCK_MARGIN_MS,
	type FederationGrantAuditEvent,
	type FederationGrantRefresher,
	type FederationGrantRetrievalFailure,
	type FederationGrantRetrievalLimits,
	type RetrieveFederationGrantTokenDeps,
	type RetrieveFederationGrantTokenRequest,
	retrieveFederationGrantToken,
} from "./federation-grants/retrieve.mjs";
export {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "./federation-grants/revision.mjs";
// The wiring a grants deployment must have before a grant may outlive a
// session. Shared so the routes module and the subject
// revocation service module cannot hold an adapter to different rules.
export { requireFederationGrantSubjectRevocation } from "./federation-grants/revocationWiring.mjs";
// What a Store calls instead of an admin route this provider does
// not mount — ending one grant, and listing a subject's for a connected-
// applications page.
export {
	type FederationGrantAdministrationDeps,
	listFederationGrantsForSubject,
	revokeFederationGrant,
} from "./federation-grants/revoke.mjs";
// The federation-grants module's section, as an operator writes it, turned
// into the limits the retrieval takes, which core's grant domain defines.
export {
	FEDERATION_GRANT_SETTING_DEFAULTS,
	type FederationGrantSettings,
	resolveFederationGrantAcquisitionLimits,
	resolveFederationGrantKeepPolicy,
	resolveFederationGrantRetrievalLimits,
} from "./federation-grants/settings.mjs";
export type {
	FederationGrantCredentialState,
	FederationGrantInspection,
	FederationGrantIntentPointer,
	FederationGrantLockResult,
	FederationGrantOpened,
	FederationGrantStore,
	FederationGrantWrite,
} from "./federation-grants/store.mjs";
export {
	type AuthorizedFederationGrant,
	type EffectiveFederationGrantStatus,
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantBase,
	type FederationGrantConnection,
	type FederationGrantConsent,
	type FederationGrantCredentials,
	type FederationGrantCredentialsInput,
	type FederationGrantDenial,
	type FederationGrantExpiredReason,
	type FederationGrantIneligibilityMarker,
	type FederationGrantIneligibilityReason,
	type FederationGrantReauthorizationReason,
	type FederationGrantRefreshFailure,
	type FederationGrantRefreshFailureInput,
	type FederationGrantRefreshFailureKind,
	type FederationGrantRevocation,
	type FederationGrantRevokedBy,
	type FederationGrantTokenResult,
	type FederationGrantUnavailableReason,
	type FederationGrantUsage,
	hasFederationGrantAuthorization,
	type PendingFederationGrant,
	type RevokedFederationGrant,
} from "./federation-grants/types.mjs";
// The two boundaries of a subject revocation, and how long each has to be
// kept. The skews come from `jwt/verify.mts` so the grants comparison uses the
// allowance the watermark comparison does.
export {
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
} from "./jwt/verify.mjs";
// The one reading of a control character in configured text, and the
// timing-safe primitives, exported from the package root because
// `package.json#exports` registers no `./security/*` subpath.
export { hasControlCharacter } from "./security/controlCharacters.mjs";
export { constantTimeStringEqual } from "./security/timingSafe.mjs";
export {
	resolveSubjectRevocationHorizonMs,
	SUBJECT_REVOCATION_MIN_RETENTION_MS,
} from "./user-sessions/retention.mjs";
export {
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "./user-sessions/types.mjs";

// ===========================================================================
// Sealing — the key-ring envelope a store seals a value in at rest
// ===========================================================================

export {
	type OpenedSeal,
	openWithKeyRing,
	type SealBinding,
	sealWithKeyRing,
} from "./sealing/envelope.mjs";
export {
	checkSealingKeyRing,
	decodeSealingKey,
	isSealingKeyId,
	SEALING_KEY_BYTES,
	type SealingKey,
	type SealingKeyRing,
} from "./sealing/keyRing.mjs";

// ===========================================================================
// Device Authorization Grant — DeviceCodeStore port + codes (RFC 8628)
// ===========================================================================

export {
	DeviceCodeStoreError,
	type DeviceCodeStoreErrorReason,
} from "./device-authorization/errors.mjs";
export {
	createMemoryDeviceCodeStore,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL,
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
// WebAuthnCredential + WebAuthnCredentialStore
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
