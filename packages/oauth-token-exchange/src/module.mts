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

import { defineModule, type GrantHandler, type Module } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "./grant.mjs";
import {
	ACCESS_TOKEN_TYPE,
	createSelfIssuedAccessTokenValidator,
} from "./validator/selfIssuedAccessToken.mjs";

/**
 * Token Exchange config-slice schema. Refines `oauth.jwt.issuer` from
 * CoreConfigSchema's permissive `z.string().optional()` to a required
 * non-empty string — the built-in self-issued validator and the grant's
 * issuer-equality check both depend on a known issuer, and an empty
 * string would silently disable the issuer-mismatch defense (Copilot
 * review on PR #100, Critical).
 *
 * Composed via `composeConfigSchema` at validate-manifests step 13: the
 * intersection with CoreConfigSchema produces `oauth.jwt.issuer:
 * z.string().min(1)`, so any boot whose configured `issuer` is missing
 * or empty fails with `BootError(reason: "config-validation-failed")`
 * before the validator factory is invoked.
 */
const tokenExchangeConfigSchema = z.object({
	oauth: z.object({
		jwt: z.object({
			issuer: z.string().min(1),
		}),
	}),
});

/**
 * Declarative manifest for OAuth 2.0 Token Exchange (RFC 8693).
 *
 * Per A2-γ §3.3: replaces the v0.4.x GrantModule(addModule) shape with a
 * defineModule(...) that contributes both:
 *  - the token_exchange grant handler (consumes the planner's
 *    `tokenExchangeValidatorResolver` synthetic), and
 *  - the built-in self-issued access_token validator (one entry in the
 *    contributes.tokenExchangeValidators record).
 *
 * Consumer-defined validators come from sibling modules via
 * contributes.tokenExchangeValidators per A2-α §4.5; the planner enforces
 * duplicate-token-type rejection at boot time (Theme C registry semantics).
 *
 * Caller surface: `tokenExchangeModule` is now a static module value, no
 * longer a factory taking validatorRegistry / clientRepository — both flow
 * through the typed DI graph.
 *
 * The mutable ExchangeTokenValidatorRegistry class is no longer part of
 * the public exports (per §3.3 "REMOVED"); the planner-internal collector
 * projects a TokenExchangeValidatorResolver view at activation time.
 *
 * Theme B (one responsibility per module: grant + built-in validator),
 * Theme C (no synthetic-key redeclaration; planner registers contributions),
 * Theme D (immutability — no addModule mutation, no consumer-facing freeze),
 * Theme E (typed deps; no lazy registry-getter closure).
 */
// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape; grant + validator factories use legacy GrantDependencies-narrowed signatures (plan §3.3 escape hatch)
type AnyDeps = any;

export const tokenExchangeModule: Module = defineModule({
	name: "oauth-token-exchange",
	configSchema: tokenExchangeConfigSchema,
	requires: ["tokenExchangeValidatorResolver", "clientRepository", "keyStore", "config"],
	optional: [
		// The token-exchange grant (grant.mts:212-266 family_revoked re-surface)
		// reads deps.refreshTokenStore for family revocation. Without declaring
		// it here, the planner drops the store at the contribution boundary even
		// when the composition root wires it. RFC 8693 §7.2 state 1 demands
		// family revocation be observable.
		"refreshTokenStore",
		// The built-in self-issued validator (createSelfIssuedAccessTokenValidator
		// below) reads deps.refreshTokenFamilyRevocation for the read-only
		// isFamilyRevoked check (A3 spec §5.3). Separate from refreshTokenStore
		// which the grant handler owns for full revocation authority.
		"refreshTokenFamilyRevocation",
		// The token-exchange grant reads deps.grantPolicy at grant.mts:339,362
		// to enforce the CP-18 fail-closed policy gate. Sibling grants (auth-
		// code, refresh-token) declare grantPolicy in oauthAuthorizationModule;
		// without declaring it here, token-exchange would silently sit outside
		// CP-18 enforcement while sibling grants are gated.
		"grantPolicy",
	],
	contributes: {
		grants: {
			[TOKEN_EXCHANGE_GRANT_TYPE]: ((deps: AnyDeps) => createTokenExchangeGrant(deps)) as (
				deps: AnyDeps,
			) => GrantHandler,
		},
		tokenExchangeValidators: {
			[ACCESS_TOKEN_TYPE]: (deps: AnyDeps) =>
				createSelfIssuedAccessTokenValidator({
					keyStore: deps.keyStore,
					issuer: deps.config.oauth.jwt.issuer,
					refreshTokenFamilyRevocation: deps.refreshTokenFamilyRevocation,
				}),
		},
	},
});
