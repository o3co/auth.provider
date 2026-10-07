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
/**
 * Core's shipped declaration, frozen with every map and entry it holds: the
 * replica count, the expected session requirements, the token-binding
 * settings and the federations' map moved into `core`, with the variables
 * bound to them renamed. A variable binds `core.deployment.mode`, the two
 * token-binding keys and each key of a federation (named after its path,
 * `CORE_FEDERATIONS_<NAME>_<KEY>`): the rest of `deployment` and
 * `tokenBinding`, and the expected session requirements, have none. Core's
 * reference binds no federation's key, so it declares none of their
 * variables renamed; a composition that bound one declares that itself.
 */
export const CORE_RELOCATIONS = Object.freeze({
    relocatedFrom: Object.freeze({
        deployment: Object.freeze({ to: "deployment", environmentVariable: null }),
        "deployment.mode": "deployment.mode",
        sessionRequirements: Object.freeze({ to: "sessionRequirements", environmentVariable: null }),
        "oauth.tokenBinding": Object.freeze({ to: "tokenBinding", environmentVariable: null }),
        "oauth.tokenBinding.dispatch-policy": "tokenBinding.dispatchPolicy",
        "oauth.tokenBinding.bindConfidentialClientRefreshTokens": "tokenBinding.bindConfidentialClientRefreshTokens",
        federations: "federations",
    }),
    renamedVariables: Object.freeze({
        DEPLOYMENT_MODE: "deployment.mode",
        OAUTH_TOKEN_BINDING_DISPATCH_POLICY: "oauth.tokenBinding.dispatch-policy",
        OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "oauth.tokenBinding.bindConfidentialClientRefreshTokens",
    }),
});
