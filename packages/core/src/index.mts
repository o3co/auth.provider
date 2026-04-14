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

// Configuration
export {
	type AppConfig,
	AppConfigSchema,
	composeConfigSchema,
	type CoreConfig,
	CoreConfigSchema,
} from "./config/application.schema.mjs";
// Grant types and interfaces
export { GrantRegistry } from "./grants/registry.mjs";
export type { GrantModule } from "./grants/types.mjs";
export type {
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
	generateToken,
	generateTokenResponse,
	type GenerateTokenOptions,
	type Token,
	type TokenResponse,
} from "./grants/token.mjs";
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
export {
	createDefaultFactories,
	type RepositoryBuilder,
	RepositoryFactory,
} from "./repositories/RepositoryFactory.mjs";
export type { Client, Code, CodeData, User } from "./repositories/types.mjs";
export type { UserRepository } from "./repositories/UserRepository.mjs";
// Keys
export type { AsymmetricKeyStoreOptions, JwtConfig, KeyStore, ManagedKey } from "./keys/KeyStore.mjs";
export { createAsymmetricKeyStore, createKeyStoreFromConfig, createSymmetricKeyStore } from "./keys/KeyStore.mjs";
// Module system
export type { Module, ModuleContext, PathResolver } from "./modules/index.mjs";
// App factory
export { createApp, type AppOptions, type AppResult } from "./app.mjs";
// Token formatting utility (used by oauth package)
export { formatObject } from "./grants/token.mjs";
