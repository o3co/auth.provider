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

import type { GrantModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import {
	createTokenExchangeGrant,
	TOKEN_EXCHANGE_GRANT_TYPE,
	type TokenExchangeDependencies,
} from "./grant.mjs";

/**
 * Config shape consumed by the Token Exchange GrantModule. All fields are
 * optional. `enabled: false` disables registration via GrantRegistry.addModule.
 */
export const tokenExchangeConfigSchema = z.object({
	token_exchange: z
		.object({
			enabled: z.boolean().default(true),
			accessToken: z
				.object({
					expiresIn: z.number().int().positive().optional(),
				})
				.optional(),
		})
		.default({ enabled: true }),
});

/**
 * GrantModule for plugin-style registration via
 * `GrantRegistry.addModule(tokenExchangeModule, deps)`. Consumers MUST supply
 * `validatorRegistry` and `clientRepository` in the deps, and pre-register at
 * least the self-issued access_token validator before calling addModule.
 *
 * At registration time, the module freezes the validator registry so post-
 * wire mutations are rejected — see `ExchangeTokenValidatorRegistry.freeze()`.
 */
export const tokenExchangeModule: GrantModule = {
	grants: {
		[TOKEN_EXCHANGE_GRANT_TYPE]: (deps) => {
			const typedDeps = deps as unknown as TokenExchangeDependencies;
			// Freeze the registry at registration time — consumer's reference
			// can no longer mutate it after addModule returns.
			typedDeps.validatorRegistry.freeze();
			return createTokenExchangeGrant(typedDeps);
		},
	},
	configSchema: tokenExchangeConfigSchema,
};
