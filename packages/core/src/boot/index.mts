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
 * boot/index.mts: internal barrel for the boot planner. Re-exports the
 * orchestrator (`createApp`) and the type surface of `types.mts`; the package
 * root `index.mts` re-exports the public subset.
 */

export { createApp } from "./create-app.mjs";
export {
	type CheckReplicaSafetyInput,
	checkReplicaSafety,
	REPLICA_UNSAFE_MODULES,
	type ReplicaSafetyModuleRef,
	replicaUnsafeReason,
} from "./replica-safety.mjs";
export type {
	AppHandle,
	AuthoritativeComponentOverriddenDetails,
	AuthoritativeWithoutProvidesDetails,
	BootErrorDetails,
	BootErrorReason,
	BootStage,
	BootstrapComponentCollisionDetails,
	BootstrapMap,
	CircularDependencyDetails,
	CleanupRecord,
	CollectedRouteContribution,
	ComponentWorld,
	ConfigPathRelocatedDetails,
	ConfigValidationFailedDetails,
	ContributeAndOverrideSameKeyDetails,
	ContributeFactoryFailedDetails,
	ContributionCollectorMap,
	ContributionEntry,
	ContributionKind,
	ContributionKindGuardedDetails,
	ContributionKindMap,
	ContributionMalformedDetails,
	CreateAppOptions,
	DefaultBootstrapMap,
	DepsBlueprint,
	DuplicateContributeDetails,
	DuplicateModuleNameDetails,
	DuplicateOverrideDetails,
	DuplicateProvidesDetails,
	DuplicateSecondFactorAuthorityDetails,
	FederationRedirectPolicyUnpairedDetails,
	FrozenWorld,
	InvalidRouteAdvertisementPathDetails,
	LifecycleWithoutProvidesDetails,
	ListCollector,
	ListShapedOverrideDetails,
	MissingRequiredComponentDetails,
	ModuleFactoryNotCalledDetails,
	ModuleSectionPathInvalidDetails,
	NameKeyedCollector,
	NormalisedModule,
	OrderedRouteContribution,
	OverrideTargetMissingDetails,
	ProviderActivation,
	ProvidesFactoryFailedDetails,
	RegisteredFederationType,
	RegistryWorld,
	ReservedComponentKeyDetails,
	RouteCollector,
	RouteOrderCycleDetails,
	RouteOrderTargetMissingDetails,
	SyntheticKeyCollisionDetails,
	TokenSettingsLifetimeExceedsConfigurationDetails,
	UnknownContributionKindDetails,
	ValidatedManifests,
	ValidatedModule,
} from "./types.mjs";
export { BootError } from "./types.mjs";
