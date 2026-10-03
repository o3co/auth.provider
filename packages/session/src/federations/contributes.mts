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
 * by `@o3co/auth-provider-session`: the `federationRedirectPolicies` key on
 * ContributesMap, which types the redirect policy, and the synthetic
 * ComponentMap key `federationRedirectPolicyResolver`.
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
	 * The kind redirect policies register under, declared at type level only:
	 * core reads this key to type the redirect policy a federation type's
	 * `redirectPolicy` answers (`FederationRedirectPolicyContribution`). It
	 * stays here until the redirect-policy contract moves into core.
	 *
	 * Boot registers one policy per enabled `core.federations` entry, built by
	 * the type the entry names, under the entry's name beside its provider. A
	 * module's `contributes` or `overrides` of this kind is refused at boot
	 * (`contribution-kind-guarded`); a deployment customising a federation's
	 * policy overrides its type (`overrides.federationTypes.<type>`).
	 */
	interface ContributesMap<Deps = ProviderDeps<never, never>> {
		readonly federationRedirectPolicies?: {
			readonly [name: string]: FederationRedirectPolicyFactory<Deps>;
		};
	}

	/**
	 * Synthetic key for the redirect-policy resolver: a read-only projection of
	 * the policies boot registers under `federationRedirectPolicies`, parallel
	 * to `federationProviders`. The `Resolver` suffix follows
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
