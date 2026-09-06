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
import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "./grant.mjs";
import { ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator, } from "./validator/selfIssuedAccessToken.mjs";
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
export const tokenExchangeModule = defineModule({
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
    ],
    contributes: {
        grants: {
            [TOKEN_EXCHANGE_GRANT_TYPE]: ((deps) => createTokenExchangeGrant(deps)),
        },
        tokenExchangeValidators: {
            [ACCESS_TOKEN_TYPE]: (deps) => createSelfIssuedAccessTokenValidator({
                keyStore: deps.keyStore,
                issuer: deps.config.oauth.jwt.issuer,
                refreshTokenFamilyRevocation: deps.refreshTokenFamilyRevocation,
            }),
        },
    },
});
