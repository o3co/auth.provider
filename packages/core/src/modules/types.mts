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
import type { Router } from "express";
import type { z } from "zod";

import type { AuditSinkBase } from "../audit/types.mjs";
import type { CoreConfig } from "../config/application.schema.mjs";
import type { FederationTokenStoreBase } from "../federation-tokens/types.mjs";
import type { GrantRegistry } from "../grants/registry.mjs";
import type { KeyStore } from "../keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "../mfa/types.mjs";
import type { GrantPolicyHookBase } from "../policy/types.mjs";
import type { RateLimiterBase } from "../ratelimit/types.mjs";
import type { RefreshTokenStoreBase } from "../refresh/types.mjs";
import type { UserSessionStoreBase } from "../user-sessions/types.mjs";

/**
 * Resolves a module specifier to a URL/path that can be passed to dynamic import().
 * Typically set to import.meta.resolve at the application level.
 */
export type PathResolver = (specifier: string) => string;

/**
 * Minimal structural type for a federation provider as seen from ModuleContext.
 *
 * `FederationProviderBase` is defined in `@o3co/auth-provider-session`, which depends
 * on core — a direct import would create a circular dependency. This structural alias
 * captures only the shape that consumers of `ModuleContext.federationProviders` need
 * to look up providers. Modules that need the full capability surface (e.g. `endSession`)
 * import `FederationProviderBase` and `supportsLogout` from `@o3co/auth-provider-session`
 * and narrow with `instanceof` / type guards after reading from the map.
 */
export interface FederationProviderHandle {
	readonly name: string;
}

/**
 * Context provided to each Module during initialization.
 * config is typed as CoreConfig & Record<string, unknown> to allow modules
 * to cast to their specific config shape while remaining compatible with
 * both full (AppConfig) and minimal (CoreConfig) deployments.
 */
export interface ModuleContext {
	pathResolver: PathResolver;
	config: CoreConfig & Record<string, unknown>;
	keyStore: KeyStore;
	grantRegistry: GrantRegistry;
	router: Router;
	mfaProviderFactory?: MfaProviderFactory;
	mfaCoordinator?: MfaCoordinator;
	mfaTransactionStore?: MfaTransactionStore;
	auditSink?: AuditSinkBase;
	rateLimiter?: RateLimiterBase;
	refreshTokenStore?: RefreshTokenStoreBase;
	grantPolicy?: GrantPolicyHookBase;
	userSessionStore?: UserSessionStoreBase;
	federationTokenStore?: FederationTokenStoreBase;
	/**
	 * Federation providers Map, populated by the session module during its init phase.
	 * Populated during the session module's `init` phase. Other modules that need
	 * to resolve providers (e.g. the oauth logout router) MUST read this field
	 * LAZILY — either from a callback passed at request time, or in their own
	 * handler logic — because module `init` order is not guaranteed relative to
	 * the session module. Eagerly capturing this field during another module's
	 * `init` will silently produce `undefined` when the session module inits
	 * later in the sequence.
	 *
	 * `undefined` when no federation is configured or the session module isn't
	 * registered. Writers MUST populate this exactly once during their own `init`.
	 *
	 * NOTE: This is the one non-readonly field on ModuleContext. It is intentionally
	 * mutable so the session module can populate it during its own init without the
	 * platform needing prior knowledge of which providers are configured. All other
	 * consumers treat it as read-only after init completes.
	 */
	federationProviders?: ReadonlyMap<string, FederationProviderHandle>;
}

/**
 * @deprecated v0.4.x manifest shape with imperative `init(context)` callback.
 * Will be deleted in Phase 9 (A2-γ caller migration). New code MUST use the
 * v0.5.0 `Module` from `@o3co/auth-provider-core/modules/manifest` instead,
 * authored via `defineModule({...})`.
 *
 * Renamed from `Module` to `LegacyModule` in Phase 1 to free the `Module`
 * name for the v0.5.0 manifest type at the package boundary.
 *
 * A composable unit that registers routes and/or grant handlers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 */
export interface LegacyModule {
	name: string;
	/**
	 * Optional Zod schema declaring the config shape this module requires.
	 * Used by composeConfigSchema to build the full deployment config validator.
	 */
	configSchema?: z.ZodObject<z.ZodRawShape>;
	init(context: ModuleContext): Promise<void>;
}
