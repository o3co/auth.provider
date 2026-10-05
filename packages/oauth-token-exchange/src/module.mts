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

import {
	ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
	checkOAuthTokenSettings,
	defineModule,
	type Module,
	type ProviderDeps,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "./grant.mjs";
import {
	ACCESS_TOKEN_TYPE,
	createSelfIssuedAccessTokenValidator,
} from "./validator/selfIssuedAccessToken.mjs";

/**
 * The schema of `oauth-token-exchange {}`, the module's own section. Strict:
 * a key it does not declare refuses boot. `maxActorChainDepth` bounds RFC 8693
 * actor delegation chains, so repeated exchanges cannot nest `act` claims
 * without limit; its default is in the package's `config/reference.conf`.
 */
const tokenExchangeSectionSchema = z
	.object({
		maxActorChainDepth: wholeNumberInRangeFromEnv(1),
	})
	.strict()
	.optional();

const REQUIRES = [
	"tokenExchangeValidatorResolver",
	"clientRepository",
	"keyStore",
	// What the oauth module provides of `oauth {}`: the lifetimes the grant
	// mints within, and the issuer and `legacyTypAccept` the validator holds a
	// subject token to. A composition without the oauth module fills it. The
	// whole configuration is not read.
	"oauthTokenSettings",
] as const;
const OPTIONAL = [
	// Read by the grant alone (`familyRefusal` in grant.mts) for the
	// subject_token and actor_token: a revoked family answers
	// `family_revoked`, and a family-bearing token is refused when this slot
	// is absent. The built-in validator is not handed the slot, since its
	// opaque `null` would pre-empt the grant's answer.
	"refreshTokenFamilyRevocation",
	// The grant enforces the fail-closed grant-policy gate, as the sibling
	// grants in oauthAuthorizationModule do; undeclared, token exchange would
	// silently sit outside it.
	"grantPolicy",
	// Forwarded to the JWT verifier so its rejection and aud-skip warnings
	// reach the operator's logger.
	"logger",
	// A subject_token is an access token presented as a credential, so the
	// exchange consults the same revocation stores as every other
	// token-accepting surface; otherwise exchanging a revoked AT would
	// launder the revocation. Declaring `accessTokenDenylist` also enrols this
	// module in the boot guard: the composition must wire a denylist or
	// declare `oauth.revocation.accessToken = "unsupported"`.
	"accessTokenDenylist",
	"subjectRevocation",
	// Read by the grant alone (`sessionRefusal` in grant.mts): a subject or
	// actor token carrying a `sid` is refused once its session has ended, and
	// the issued token carries the subject's `sid`, so the logout that ends
	// the one ends the other. Optional as it is on `oauthModule`: without a
	// store no surface judges a `sid`.
	"userSessionStore",
] as const;

type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
/**
 * The deps every contribution of {@link tokenExchangeModule} receives:
 * exactly its `requires` / `optional`, typed.
 */
export type TokenExchangeModuleDeps = ProviderDeps<Requires, Optional>;

/**
 * Declarative manifest for OAuth 2.0 Token Exchange (RFC 8693): contributes
 * the `token_exchange` grant and the built-in self-issued `access_token`
 * validator. Sibling modules contribute further validators through
 * `contributes.tokenExchangeValidators`; the boot planner rejects duplicate
 * token types and projects them as the grant's
 * `tokenExchangeValidatorResolver`.
 */
export const tokenExchangeModule: Module = defineModule<
	Requires,
	Optional,
	typeof tokenExchangeSectionSchema
>({
	name: "oauth-token-exchange",
	// The package's `config/reference.conf` holds this section's default and
	// binds OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH at its new path, the
	// name that path derives, so no variable is renamed.
	section: {
		schema: tokenExchangeSectionSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		relocatedFrom: {
			"oauth.tokenExchange": { to: "", environmentVariable: null },
			"oauth.tokenExchange.maxActorChainDepth": "maxActorChainDepth",
		},
	},
	requires: REQUIRES,
	optional: OPTIONAL,
	// Same policies as oauthModule: an unfilled denylist slot must be declared
	// with oauth.revocation.accessToken = "unsupported", and an unfilled
	// subject-revocation slot with oauth.revocation.subject = "unsupported",
	// or a credential change silently invalidates nothing already issued.
	absencePolicies: {
		accessTokenDenylist: ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
		subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
	},
	contributes: {
		grants: {
			[TOKEN_EXCHANGE_GRANT_TYPE]: (deps) =>
				createTokenExchangeGrant({
					...deps,
					// Core's resolver returns the contract this grant reads; no cast.
					tokenExchangeValidatorResolver: deps.tokenExchangeValidatorResolver,
				}),
		},
		tokenExchangeValidators: {
			[ACCESS_TOKEN_TYPE]: (deps: TokenExchangeModuleDeps) => {
				// The `oauthTokenSettings` slot, read whole.
				const settings = checkOAuthTokenSettings(deps.oauthTokenSettings);
				return createSelfIssuedAccessTokenValidator({
					keyStore: deps.keyStore,
					issuer: settings.issuer,
					// No `refreshTokenFamilyRevocation`: the grant owns the family
					// check (see OPTIONAL).
					accessTokenDenylist: deps.accessTokenDenylist,
					subjectRevocation: deps.subjectRevocation,
					// The operator's setting, not the validator's own default.
					legacyTypAccept: settings.legacyTypAccept,
					logger: deps.logger,
				});
			},
		},
	},
});
