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
export { AdapterFactoryError, createAdapterFactory, } from "./adapters/AdapterFactory.mjs";
// App factory
export { createApp } from "./app.mjs";
export { createAuditSinkFactory, emitAuditEvent, registerBuiltinAuditSinks, } from "./audit/factory.mjs";
// Configuration
export { AppConfigSchema, CoreConfigSchema, composeConfigSchema, fullSectionsSchema, } from "./config/application.schema.mjs";
export { createFederationTokenStoreFactory, registerBuiltinFederationTokenStores, } from "./federation-tokens/factory.mjs";
export { supportsLock } from "./federation-tokens/types.mjs";
export { filterClaimsByScope } from "./grants/claimFilter.mjs";
// id_token generation (OIDC Core §2)
export { generateIdToken, } from "./grants/idToken.mjs";
// logout_token generation (OIDC Back-Channel Logout 1.0 §2.4)
export { BACKCHANNEL_LOGOUT_EVENT_URI, generateLogoutToken, } from "./grants/logoutToken.mjs";
// Grant types and interfaces
export { GrantRegistry } from "./grants/registry.mjs";
// Token formatting utility (used by oauth package)
export { formatObject, generateToken, generateTokenResponse, } from "./grants/token.mjs";
export { createKeyStoreFactory, registerBuiltinKeyStores } from "./keys/factory.mjs";
export { createAsymmetricKeyStore, createSymmetricKeyStore, } from "./keys/KeyStore.mjs";
export { createMfaProviderFactory } from "./mfa/factory.mjs";
export { createMfaRouter } from "./mfa/route.mjs";
export { supportsEnrollment, supportsRevocation } from "./mfa/types.mjs";
export { createGrantPolicyHookFactory } from "./policy/factory.mjs";
export { createRateLimiterFactory, registerBuiltinRateLimiters, } from "./ratelimit/factory.mjs";
export { createRefreshTokenStoreFactory } from "./refresh/factory.mjs";
export { ClientEntrySchema, InMemoryClientRepository, } from "./repositories/InMemoryClientRepository.mjs";
// Built-in implementations
export { InMemoryCodeRepository } from "./repositories/InMemoryCodeRepository.mjs";
export { InMemoryUserRepository, UserEntrySchema, } from "./repositories/InMemoryUserRepository.mjs";
export { loadYamlMap } from "./repositories/loadYamlMap.mjs";
// Default repository factories
export { createDefaultFactories } from "./repositories/RepositoryFactory.mjs";
export { extractUserClaims } from "./user-sessions/claims.mjs";
export { createUserSessionStoreFactory, registerBuiltinUserSessionStores, } from "./user-sessions/factory.mjs";
