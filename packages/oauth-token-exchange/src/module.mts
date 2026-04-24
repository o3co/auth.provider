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

import type { GrantDependencies, GrantModule } from "@o3co/auth-provider-core";
import {
	createTokenExchangeGrant,
	TOKEN_EXCHANGE_GRANT_TYPE,
	type TokenExchangeDependencies,
} from "./grant.mjs";

/**
 * GrantModule for plugin-style registration via
 * `GrantRegistry.addModule(tokenExchangeModule, deps)`. Consumers MUST supply
 * `validatorRegistry` and `clientRepository` in the deps, and pre-register at
 * least the self-issued access_token validator before calling addModule.
 *
 * At registration time, the module freezes the validator registry so post-
 * wire mutations are rejected — see `ExchangeTokenValidatorRegistry.freeze()`.
 *
 * The module object itself is frozen to prevent post-import tampering of the
 * grants record.
 *
 * Configuration is NOT driven by `oauth.grants.token_exchange.*` HOCON
 * settings — those would be dropped during addModule parsing because core's
 * GrantRegistry keys config blocks by grant-type URN, not by friendly name.
 * Instead, consumers pass expiresIn + other settings via `createTokenExchangeGrant`
 * options if they need customization.
 */
export const tokenExchangeModule: GrantModule = Object.freeze({
	grants: Object.freeze({
		[TOKEN_EXCHANGE_GRANT_TYPE]: (deps: GrantDependencies) => {
			const typedDeps = deps as unknown as Partial<TokenExchangeDependencies>;
			const hasFreezeable =
				typedDeps.validatorRegistry !== null &&
				typedDeps.validatorRegistry !== undefined &&
				typeof (typedDeps.validatorRegistry as { freeze?: unknown }).freeze === "function";
			const hasClientRepository =
				typedDeps.clientRepository !== null &&
				typedDeps.clientRepository !== undefined &&
				typeof (typedDeps.clientRepository as { findById?: unknown }).findById === "function" &&
				typeof (typedDeps.clientRepository as { authenticate?: unknown }).authenticate ===
					"function";
			if (!hasFreezeable || !hasClientRepository) {
				throw new Error(
					"tokenExchangeModule requires validatorRegistry (with freeze()) and clientRepository (with findById/authenticate) in deps. " +
						"See @o3co/auth-provider-oauth-token-exchange README for consumer registration.",
				);
			}
			// Now typedDeps.validatorRegistry and typedDeps.clientRepository are verified.
			// Freeze the registry at registration time — consumer's reference
			// can no longer mutate it after addModule returns.
			(typedDeps as TokenExchangeDependencies).validatorRegistry.freeze();
			return createTokenExchangeGrant(typedDeps as TokenExchangeDependencies);
		},
	}),
}) as GrantModule;
