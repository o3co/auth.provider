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

import type { z } from "zod";
import type { AbsencePolicy } from "./absence-policy.mjs";
import type { ComponentKey, ComponentMap } from "./component-map.mjs";
import type { ContributesMap } from "./contributes-map.mjs";
import type { Provider, ProviderDeps } from "./provider.mjs";

/**
 * Optional Zod schema declaring the slice of application config a module
 * requires. The boot planner composes a single validator across all
 * modules' configSchemas via `composeConfigSchema` (Phase 4 / A2-β §5.1
 * step 13).
 *
 * Per A2-α §2.1.
 */
export type ConfigSchema = z.ZodObject<z.ZodRawShape>;

/**
 * Per-component lifecycle hooks declared by a module for one of its
 * provided component slots.
 *
 * - `eager`: When `true` the boot planner instantiates this component
 *   unconditionally during `createApp`, even if no other component
 *   declares it as a dependency. Default is `false` (lazy).
 * - `cleanup`: Called during `app.dispose()` in reverse-topological
 *   order. Errors from all cleanup functions are aggregated into an
 *   `AggregateError` that `dispose()` rejects with (§6.3).
 *
 * The `K` parameter is a `ComponentKey`; `ComponentMap[K]` resolves to
 * the exact value type for that slot, giving `cleanup` a typed `value`
 * parameter.
 *
 * Per A2-β §4.1.
 */
export interface ComponentLifecycle<K extends ComponentKey> {
	/** When `true`, eagerly instantiate this component at boot. Per A2-β §4.1. */
	readonly eager?: boolean;
	/**
	 * Called on dispose with the resolved component value. Per A2-β §4.1.
	 * Errors aggregate into the AggregateError that `dispose()` rejects with.
	 */
	readonly cleanup?: (value: ComponentMap[K]) => void | Promise<void>;
}

/**
 * Parameterised manifest type. The R / O generics are inferred at the
 * call site of `defineModule(...)` and carry the literal key sets
 * declared in `requires` / `optional` so providers and contribution
 * factories receive a typed deps object.
 *
 * Per A2-α §2.1, §3.1.
 */
export interface ModuleSpec<R extends ComponentKey = never, O extends ComponentKey = never> {
	/** Module identity — unique across all modules in a single createApp call. */
	readonly name: string;

	/** Optional Zod schema declaring this module's config slice. */
	readonly configSchema?: ConfigSchema;

	/**
	 * Component keys this module reads from DI. Required keys appear as
	 * `readonly K: ComponentMap[K]` on the typed deps object passed to
	 * every provider in `provides` and every factory in `contributes`.
	 */
	readonly requires?: readonly R[];

	/**
	 * Component keys this module reads opportunistically. Optional keys
	 * appear as `readonly K?: ComponentMap[K]` on the typed deps.
	 */
	readonly optional?: readonly O[];

	/**
	 * Declared-absence policies for optional keys (#363). A key listed here
	 * stays optional to *wire* but not optional to *decide*: when nothing
	 * fills the slot, the config must carry the policy's declared-absent
	 * value or boot refuses (`component-absence-undeclared`). Keys are
	 * constrained to `O`, so a policy on a key this module does not read is
	 * a compile-time error. See `manifest/absence-policy.mts` for what a
	 * policy is and why it is data.
	 */
	readonly absencePolicies?: { readonly [K in O]?: AbsencePolicy };

	/**
	 * Component values this module materialises into the DI graph. Each
	 * value is `(deps) => ComponentMap[K] | Promise<ComponentMap[K]>`.
	 */
	readonly provides?: {
		readonly [K in ComponentKey]?: Provider<K, ProviderDeps<R, O>>;
	};

	/**
	 * Protocol-level features this module adds (grants, routes, federations,
	 * etc.). Per A2-α §4.
	 */
	readonly contributes?: ContributesMap<ProviderDeps<R, O>>;

	/**
	 * Protocol-level features this module REPLACES on an already-registered
	 * key. Mirrors `contributes` shape. Missing target key throws at boot.
	 * Per A2-α §5.
	 */
	readonly overrides?: ContributesMap<ProviderDeps<R, O>>;

	/**
	 * Per-component lifecycle hooks. Each key `K` in this map MUST also
	 * appear in `provides`; the boot planner's validate-manifests stage
	 * throws `"lifecycle-without-provides"` for any orphaned lifecycle entry
	 * (Phase 4 §6.1).
	 *
	 * The absence of this field is valid — all existing `(deps) => value`
	 * provider forms remain unaffected.
	 *
	 * Per A2-β §4.1.
	 */
	readonly lifecycle?: {
		readonly [K in ComponentKey]?: ComponentLifecycle<K>;
	};
}

/**
 * Erased ModuleSpec — the lowest-common-denominator value the boot
 * planner accepts in `Module[]`. Per A2-α §2.1 / §3.1: authoring uses
 * `defineModule(...)` (which preserves R / O via inference); the boot
 * planner consumes the erased type.
 *
 * `R = ComponentKey` and `O = ComponentKey` (NOT the default `never`)
 * is intentional: a `ModuleSpec<R', O'>` for any `R' ⊆ ComponentKey`
 * and `O' ⊆ ComponentKey` is structurally assignable to this widened
 * type via:
 * - covariance of `requires?: readonly R[]` and `optional?: readonly O[]`
 *   in their respective generics (R' ⊆ R is allowed)
 * - contravariance of `Provider`'s `deps` parameter: a narrower
 *   `ProviderDeps<R', O'>` (= the function takes fewer keys) is
 *   assignable to a wider `ProviderDeps<R, O>` position
 *
 * Without this widening, `Module = ModuleSpec` (the default `never`
 * args) would reject every consumer-authored `defineModule({ requires: [...] })`
 * call once Phases 5–8 populate `ComponentMap` — `readonly "key"[]`
 * does not extend `readonly never[]`. Phase 1 builds compile either
 * way because `ComponentKey = never` in the empty baseline; the
 * widening is the structurally-correct erasure for all later phases.
 */
export type Module = ModuleSpec<ComponentKey, ComponentKey>;
