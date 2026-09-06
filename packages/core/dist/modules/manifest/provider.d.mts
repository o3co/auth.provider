import type { ComponentKey, ComponentMap } from "./component-map.mjs";
/**
 * Typed dependency object derived from a module's `requires` and `optional`
 * key sets.
 *
 * - Keys in `R` (required) appear as `readonly` non-optional fields whose
 *   value type is `NonNullable<ComponentMap[K]>`. The `NonNullable` strips
 *   the `| undefined` introduced by ComponentMap's optional declaration
 *   (every slot is declared `slot?: T` via declaration-merging so consumers
 *   can opt into slots additively). The boot planner's missing-required-
 *   component check at materialise-time guarantees the slot is present
 *   whenever it appears in a module's `requires`, so the runtime value is
 *   never undefined inside a `provides` callback.
 * - Keys in `O` (optional) appear as `readonly` optional fields with type
 *   `ComponentMap[K] | undefined`.
 *
 * Per A2-α §3.1.
 */
export type ProviderDeps<R extends ComponentKey = never, O extends ComponentKey = never> = {
    readonly [K in R]: NonNullable<ComponentMap[K]>;
} & {
    readonly [K in O]?: ComponentMap[K];
};
/**
 * A provider materialises a single ComponentMap slot from the module's
 * typed deps object. Per A2-α §3.1 / §3.2: a single async-or-sync factory
 * shape; no discriminated provider union; invoked at most once per
 * createApp call (boot planner enforces).
 *
 * The return type is `ComponentMap[K] | Promise<ComponentMap[K]>` — a
 * provider may return synchronously when no async work is needed.
 */
export type Provider<K extends ComponentKey, Deps> = (deps: Deps) => ComponentMap[K] | Promise<ComponentMap[K]>;
//# sourceMappingURL=provider.d.mts.map