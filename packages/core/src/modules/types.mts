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
}

/**
 * A composable unit that registers routes and/or grant handlers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 */
export interface Module {
	name: string;
	/**
	 * Optional Zod schema declaring the config shape this module requires.
	 * Used by composeConfigSchema to build the full deployment config validator.
	 */
	configSchema?: z.ZodObject<z.ZodRawShape>;
	init(context: ModuleContext): Promise<void>;
}
