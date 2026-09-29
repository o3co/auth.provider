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

export type { AbsencePolicy } from "./absence-policy.mjs";
export type { ComponentKey, ComponentMap } from "./component-map.mjs";
export type {
	AuditHook,
	AuditHookFactory,
	// The answer every contribution factory may give: the value, or a promise
	// of it. Named here because a package declaring a contribution kind of its
	// own needs it to say the same thing.
	Contributed,
	ContributesMap,
	ExchangeTokenValidator,
	ExchangeTokenValidatorFactory,
	FederationFactory,
	// One configured federation as its type's factory receives it, and
	// what a federation package declares it handles, keyed by type.
	FederationInstance,
	FederationProvider,
	FederationTypeContribution,
	GrantFactory,
	GrantHandler,
	GrantMiddlewareFactory,
	// Not named `GrantPolicyHook`: the canonical `GrantPolicyHook` interface
	// lives in `../../policy/types.mts` and is exported from the package root.
	GrantPolicyHookContribution,
	GrantPolicyHookFactory,
	MfaFactor,
	MfaFactorFactory,
	OidcDiscoveryContributionFactory,
	// A module's budget for a rate-limit prefix it owns.
	RateLimitBudgetFactory,
	SessionRequirementFactory,
	TokenBindingMechanismFactory,
} from "./contributes-map.mjs";
export {
	defineFederationType,
	type FederationTypeDeclaration,
} from "./define-federation-type.mjs";
export { defineModule } from "./define-module.mjs";
export type { ModuleSection, SectionDeps, SectionSchema } from "./module-section.mjs";
export type {
	ComponentLifecycle,
	ConfigSchema,
	Module,
	ModuleSpec,
	ReplicaSafetyDeclaration,
} from "./module-spec.mjs";
export type { Provider, ProviderDeps } from "./provider.mjs";
export type {
	HttpMethod,
	RouteAdvertisement,
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
} from "./route-contribution.mjs";

export type {
	GrantHandlerResolver,
	MfaFactorResolver,
	RateLimitBudgetResolver,
	TokenExchangeValidatorResolver,
} from "./synthetic-keys.mjs";
export { SYNTHETIC_COMPONENT_KEYS } from "./synthetic-keys.mjs";
