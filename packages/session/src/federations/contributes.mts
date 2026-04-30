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
 * by `@o3co/auth-provider-session`.
 *
 * A5 adds one new contribution kind (`federationRedirectPolicies`) and one
 * new synthetic ComponentMap key (`federationRedirectPolicyResolver`).
 *
 * Per A5 §6 (ContributesMap extension) + A5 §7 (ComponentMap synthetic key).
 *
 * TRADE-OFF (same as synthetic-keys.mts NORMATIVE comment): merging
 * `federationRedirectPolicyResolver` onto ComponentMap means the type system
 * does NOT reject `provides: { federationRedirectPolicyResolver: ... }` at
 * compile time. That collision is caught at RUNTIME by validate-manifests
 * step 3a (`BootError({ reason: "synthetic-key-collision" })`). The type-level
 * benefit is typed `requires: ["federationRedirectPolicyResolver"]` for
 * downstream module authors.
 */

import type { ProviderDeps } from "@o3co/auth-provider-core";
import type {
	FederationRedirectPolicy,
	FederationRedirectPolicyFactory,
} from "./redirect-policy.mjs";

declare module "@o3co/auth-provider-core" {
	/**
	 * A5 §6: new name-keyed contribution kind for redirect policies.
	 *
	 * Per-kind duplicate policy (per A2-α §4.5):
	 * - `contributes.federationRedirectPolicies[name]`: throw on duplicate.
	 * - `overrides.federationRedirectPolicies[name]`: throw if name not already registered.
	 * - Registration order does not affect dispatch (keyed by exact name match).
	 *
	 * Pairing invariant (A5 §6 NORMATIVE, enforced by validate-manifests step 7.5):
	 * every `federations[name]` MUST have a matching `federationRedirectPolicies[name]`
	 * and vice versa. Mismatch → BootError({ reason: "federation-redirect-policy-unpaired" }).
	 */
	interface ContributesMap<Deps = ProviderDeps<never, never>> {
		readonly federationRedirectPolicies?: {
			readonly [name: string]: FederationRedirectPolicyFactory<Deps>;
		};
	}

	/**
	 * A5 §7: synthetic ComponentMap key for the redirect-policy resolver.
	 *
	 * SYNTHETIC (per A2-α §6.5). Read-only projection of the boot planner's
	 * `federationRedirectPolicies` collector. Parallel to the existing
	 * `federationProviders` synthetic key.
	 *
	 * Naming: `Resolver` suffix follows the 2-of-3 existing synthetic-key convention
	 * (`tokenExchangeValidatorResolver`, `grantHandlerResolver`) and avoids collision
	 * with the contribution kind name `federationRedirectPolicies`.
	 *
	 * Constraints (enforced at boot by validate-manifests step 3a/3b/3c):
	 * - A module MUST NOT declare `federationRedirectPolicyResolver` in `provides`.
	 * - `bootstrapComponents` MUST NOT carry this key.
	 * - `overrideComponents` MUST NOT carry this key.
	 * - A module MAY declare this key in `requires` / `optional`.
	 */
	interface ComponentMap {
		readonly federationRedirectPolicyResolver?: ReadonlyMap<string, FederationRedirectPolicy>;
	}
}
