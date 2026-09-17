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
export { ACCESS_TOKEN_TYPE, createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE, } from "./grant.mjs";
export { tokenExchangeModule } from "./module.mjs";
// Per A2-γ §3.3: ExchangeTokenValidatorRegistry / Error were the v0.4.x
// mutable consumer-facing surface and are no longer exported. The
// planner-internal collector retains the implementation; consumers read
// the resolver projection via deps.tokenExchangeValidatorResolver
// (TokenExchangeValidatorResolver) and contribute new validators via
// contributes.tokenExchangeValidators on their own modules.
export { createSelfIssuedAccessTokenValidator, } from "./validator/selfIssuedAccessToken.mjs";
