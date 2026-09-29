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
 * Declaration-merge augmentations for `@o3co/auth-provider-core` contributed
 * by `@o3co/auth-provider-session`: the `federationRedirectPolicies`
 * contribution kind and the synthetic ComponentMap key
 * `federationRedirectPolicyResolver`.
 *
 * Trade-off: merging the synthetic key onto ComponentMap means the type system
 * does not reject `provides: { federationRedirectPolicyResolver: ... }`; boot
 * does (`BootError({ reason: "synthetic-key-collision" })`). In exchange,
 * downstream modules get a typed `requires: ["federationRedirectPolicyResolver"]`.
 */

import type { ProviderDeps } from "@o3co/auth-provider-core";
import type {
	FederationRedirectPolicy,
	FederationRedirectPolicyFactory,
} from "./redirect-policy.mjs";

declare module "@o3co/auth-provider-core" {
	/**
	 * Name-keyed contribution kind for redirect policies.
	 *
	 * - `contributes.federationRedirectPolicies[name]`: throw on duplicate.
	 * - `overrides.federationRedirectPolicies[name]`: throw if name not already registered.
	 * - Registration order does not affect dispatch (keyed by exact name match).
	 *
	 * Pairing invariant, enforced by validate-manifests: every `federations[name]`
	 * MUST have a matching `federationRedirectPolicies[name]` and vice versa.
	 * Mismatch → BootError({ reason: "federation-redirect-policy-unpaired" }).
	 */
	interface ContributesMap<Deps = ProviderDeps<never, never>> {
		readonly federationRedirectPolicies?: {
			readonly [name: string]: FederationRedirectPolicyFactory<Deps>;
		};
	}

	/**
	 * Synthetic key for the redirect-policy resolver: a read-only projection of
	 * the boot planner's `federationRedirectPolicies` collector, parallel to
	 * `federationProviders`. The `Resolver` suffix follows
	 * `tokenExchangeValidatorResolver` / `grantHandlerResolver` and keeps it
	 * apart from the contribution kind's name.
	 *
	 * Enforced at boot by validate-manifests: no module declares it in
	 * `provides`, and neither `bootstrapComponents` nor `overrideComponents`
	 * carries it. A module MAY declare it in `requires` / `optional`.
	 */
	interface ComponentMap {
		readonly federationRedirectPolicyResolver?: ReadonlyMap<string, FederationRedirectPolicy>;
	}
}
