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

import type {
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
} from "./contributes-map.mjs";

/**
 * Read-only projection of the boot planner's `grants` collector, exposed
 * to route factories that dispatch by `grant_type` at request time. Per
 * A2-α §6.5 + Amendment 3.
 *
 * The boot planner instantiates this resolver during `applyContributions`
 * (Phase 4 / A2-β §5.4) and freezes the underlying registry; the resolver
 * exposes only `get` and `entries`, no write surface.
 */
export interface GrantHandlerResolver {
	readonly get: (grantType: string) => GrantHandler | undefined;
	readonly entries: () => IterableIterator<readonly [string, GrantHandler]>;
}

/**
 * Read-only projection of the boot planner's `tokenExchangeValidators`
 * collector. Per A2-α §6.5.
 */
export interface TokenExchangeValidatorResolver {
	readonly get: (tokenType: string) => ExchangeTokenValidator | undefined;
	readonly entries: () => IterableIterator<readonly [string, ExchangeTokenValidator]>;
}

/**
 * Re-export of FederationProvider for downstream consumers that need the
 * structural placeholder. The concrete type is wired in Phase 9 when the
 * federation packages migrate to manifest shape.
 */
export type { FederationProvider };

/**
 * The set of synthetic ComponentMap keys at v0.5.0. The boot planner
 * (Phase 4 / A2-β §5.1 step 3) consults this set to reject:
 * - any module's `provides[K]` where `K ∈ SYNTHETIC_COMPONENT_KEYS`
 * - any `bootstrapComponents[K]`
 * - any `overrideComponents[K]`
 *
 * A5 (Phase 7) added `federationRedirectPolicyResolver` — the synthetic
 * projection for `federationRedirectPolicies` contributions (typed in
 * `@o3co/auth-provider-session/src/federations/contributes.mts`).
 *
 * Per A2-α §6.5 NORMATIVE constraints. The PRIMARY immutability guard
 * is the TypeScript declared type `ReadonlySet<string>` — `.add()`,
 * `.delete()`, and `.clear()` are prevented at compile time. The
 * runtime `Object.freeze` call additionally marks the Set object as
 * frozen (no new own properties, no prototype change), but it does
 * NOT prevent the built-in Set methods from mutating the internal
 * `[[SetData]]` slot — that is a JavaScript engine constraint specific
 * to built-in collection types. A consumer casting `(s as Set<string>)`
 * to mutate is explicitly bypassing the public type contract.
 */
export const SYNTHETIC_COMPONENT_KEYS: ReadonlySet<string> = Object.freeze(
	new Set([
		"federationProviders",
		"tokenExchangeValidatorResolver",
		"grantHandlerResolver",
		"federationRedirectPolicyResolver",
		// D-5: lifecycleRegistrar is boot-planner-owned (pre-seeded into the
		// bootstrap map by createApp). Consumer-supplied values via
		// bootstrapComponents/overrideComponents would create two registrars
		// that silently diverge — the planner drains its own instance while
		// builders register cleanups on the consumer's. Reserve the key.
		"lifecycleRegistrar",
		// Same reservation for the readiness registrar: two registrars would
		// diverge silently, the planner reading its own (empty) instance while
		// builders register probes on the consumer's — `/readyz` would then
		// answer ready with nothing actually probed.
		"readinessRegistrar",
	]),
);

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge for synthetic resolver slots.
//
// The boot planner injects these projections into the working component map
// at `applyContributions` step 0 (see `boot/apply-contributions.mts`). Without
// declaration-merging them onto ComponentMap, downstream modules cannot
// declare `requires: ["grantHandlerResolver"]` etc. through the typed
// `defineModule` surface — `ComponentKey = keyof ComponentMap` would not
// include these keys and authoring would require a private augmentation.
//
// Slot-name reservation (A1 §5.5): unnamespaced names
// (grantHandlerResolver, tokenExchangeValidatorResolver, federationProviders)
// are reserved for o3co. Consumers MUST namespace their own keys.
//
// `federationProviders` is shaped as `ReadonlyMap<string, FederationProvider>`
// — same shape as the runtime view returned by `makeFederationProviders` in
// `apply-contributions.mts`.
//
// TRADE-OFF (NORMATIVE): merging these slots onto ComponentMap means the
// type system NO LONGER rejects a module that writes
// `provides: { grantHandlerResolver: () => ... }` or a host that supplies
// `bootstrapComponents.grantHandlerResolver` / `overrideComponents.
// grantHandlerResolver`. Those collisions are caught at RUNTIME by
// `validate-manifests.mts` step 3a (provides), 3b (bootstrap), and 3c
// (overrideComponents) — `BootError({ reason: "synthetic-key-collision" })`.
//
// The trade-off is deliberate: typed `requires` is the higher-value goal
// for downstream module authors (it is the read path for the resolvers).
// The write paths (provides / bootstrap / overrideComponents) are guarded
// structurally by `SYNTHETIC_COMPONENT_KEYS` membership checks at boot
// time, which is the same enforcement the planner relies on for non-typed
// languages and dynamically loaded modules. The runtime check is
// authoritative; the type system narrows the typical failure mode (typo
// in `requires`) but does not gate the deliberate-collision case.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly grantHandlerResolver?: GrantHandlerResolver;
		readonly tokenExchangeValidatorResolver?: TokenExchangeValidatorResolver;
		readonly federationProviders?: ReadonlyMap<string, FederationProvider>;
	}
}
