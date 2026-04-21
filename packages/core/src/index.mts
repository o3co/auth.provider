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
// App factory
export { type AppOptions, type AppResult, createApp } from "./app.mjs";
export {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
// Audit
export type { AuditEvent, AuditSinkBase, AuditSinkFactory } from "./audit/types.mjs";
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
	FederationTokenStoreBase,
	FederationTokenStoreFactory,
	FederationTokens,
} from "./federation-tokens/types.mjs";
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
export { GrantRegistry } from "./grants/registry.mjs";
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
// Module system
export type { Module, ModuleContext, PathResolver } from "./modules/index.mjs";
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
