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

export type { ComponentKey, ComponentMap } from "./component-map.mjs";

export type { Provider, ProviderDeps } from "./provider.mjs";

export type {
	AuditHook,
	AuditHookFactory,
	ContributesMap,
	ExchangeTokenValidator,
	ExchangeTokenValidatorFactory,
	FederationFactory,
	FederationProvider,
	GrantFactory,
	GrantHandler,
	GrantPolicyHook,
	GrantPolicyHookFactory,
	MfaFactor,
	MfaFactorFactory,
} from "./contributes-map.mjs";

export type {
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
} from "./route-contribution.mjs";

export type { ConfigSchema, Module, ModuleSpec } from "./module-spec.mjs";

export { defineModule } from "./define-module.mjs";

export type {
	GrantHandlerResolver,
	TokenExchangeValidatorResolver,
} from "./synthetic-keys.mjs";
export { SYNTHETIC_COMPONENT_KEYS } from "./synthetic-keys.mjs";
