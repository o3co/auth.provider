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

export {
	ACCESS_TOKEN_TYPE,
	createTokenExchangeGrant,
	TOKEN_EXCHANGE_GRANT_TYPE,
	type TokenExchangeDependencies,
} from "./grant.mjs";
export { tokenExchangeModule } from "./module.mjs";
// No validator registry is exported, and none exists here (the v0.4.x
// mutable ExchangeTokenValidatorRegistry went with A2-γ §3.3). At runtime
// the resolver is built by core's boot planner from every module's
// contributes.tokenExchangeValidators; consumers read it via
// deps.tokenExchangeValidatorResolver (TokenExchangeValidatorResolver) and
// contribute new validators on their own modules.
export {
	type CreateSelfIssuedAccessTokenValidatorOptions,
	createSelfIssuedAccessTokenValidator,
} from "./validator/selfIssuedAccessToken.mjs";
// `ExchangeTokenValidationContext`, `ExchangeTokenValidator` and
// `ValidatedToken` are not re-exported: the contract moved to
// `@o3co/auth-provider-core` with #626 P1, and a second export path for one
// type is the thing that made the contribution type `unknown` in the first
// place. Import them from core.
