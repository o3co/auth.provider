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
		// The token-exchange grant (grant.mts family_revoked re-surface) AND
		// the built-in self-issued validator (createSelfIssuedAccessTokenValidator
		// below) both read deps.refreshTokenFamilyRevocation for the read-only
		// isFamilyRevoked check (A3 spec §5.3). RFC 8693 §7.2 state 1 demands
		// family revocation be observable; the grant handler fail-closes when
		// this slot is absent.
		"refreshTokenFamilyRevocation",
		// The token-exchange grant reads deps.grantPolicy to enforce the CP-18
		// fail-closed policy gate. Sibling grants (auth-code, refresh-token)
		// declare grantPolicy in oauthAuthorizationModule; without declaring
		// it here, token-exchange would silently sit outside CP-18 enforcement
		// while sibling grants are gated.
		"grantPolicy",
		// SF-1: forwarded to the central JWT verifier so verifier rejection /
		// aud-skip warnings emit through the operator's structured logger
		// rather than being silently dropped.
		"logger",
		// #367: a subject_token is an access token presented as a credential,
		// so the exchange consults the same revocation stores every other
		// token-accepting surface does — otherwise revoking an AT and then
		// exchanging it launders the revocation away. Declaring
		// `accessTokenDenylist` here also enrolls this module in the #277
		// boot guard: a composition mounting token exchange must wire a
		// denylist or declare `oauth.revocation.accessToken = "unsupported"`.
		"accessTokenDenylist",
		"subjectRevocation",
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
					// #367: revocation stores, forwarded like every other
					// token-accepting surface. See the optional-keys comment above.
					accessTokenDenylist: deps.accessTokenDenylist,
					subjectRevocation: deps.subjectRevocation,
					// SF-1: thread legacyTypAccept through so the operator's
					// HOCON / env-var override governs the validator. Without
					// this, the validator's `?? true` fallback masked any
					// explicit `legacyTypAccept = false` configuration — the
					// strict mode would not actually engage at this site.
					legacyTypAccept: deps.config.oauth.jwt.legacyTypAccept,
					logger: deps.logger,
				}),
		},
	},
});
