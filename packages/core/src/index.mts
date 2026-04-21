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
// Audit sink (partial exports — full export set lands in Task 24)
export {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "./audit/factory.mjs";
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
// Module system
export type { Module, ModuleContext, PathResolver } from "./modules/index.mjs";
// Grant policy hook (partial exports — full export set lands in Task 24)
export { createGrantPolicyHookFactory } from "./policy/factory.mjs";
export type {
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyHookBase,
	GrantPolicyHookFactory,
	GrantPolicyRequest,
} from "./policy/types.mjs";
// Rate limiter (partial exports — full export set lands in Task 24)
export { createRateLimiterFactory, registerBuiltinRateLimiters } from "./ratelimit/factory.mjs";
export type {
	RateLimitContext,
	RateLimitDecision,
	RateLimiterBase,
	RateLimiterFactory,
	RateLimitSpec,
} from "./ratelimit/types.mjs";
// Refresh token store (Task 24 will finalize the full export set; partial exports pulled forward here for Task 16)
export { createRefreshTokenStoreFactory } from "./refresh/factory.mjs";
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
