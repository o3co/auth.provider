/**
 * boot/freeze-world.mts — Stage 5 of the A2-β boot planner pipeline.
 *
 * Takes the `RegistryWorld` from stage 4, calls `Object.freeze` on the
 * component map, and selectively calls `freeze()` on each registry/collector
 * that exposes one. Emits a `FrozenWorld`.
 *
 * Per A2-β §5.5.
 */
import type { FrozenWorld, RegistryWorld } from "./types.mjs";
/**
 * Stage 5 of the A2-β boot planner pipeline.
 *
 * Steps:
 * 1. `Object.freeze(registry.material.components)` — the component map is
 *    now structurally immutable. Consumer code that captures a reference
 *    cannot mutate the map.
 * 2. For each `(kind, collector)` in `registry.registries`: if the collector
 *    exposes a `freeze()` method, call it. Skip otherwise. This covers
 *    name-keyed registries (`GrantRegistry`, `ExchangeTokenValidatorRegistry`,
 *    consumer-defined registries), `RouteCollector` (always has `freeze()`),
 *    and opt-in `ListCollector<V>` instances.
 *
 * `AdapterFactory` is explicitly out of scope per A6+A7 §2.3 — it is
 * composition-root-shaped with no module-init activation boundary and is not
 * stored in `registry.registries`. The boot planner does NOT iterate or freeze
 * any AdapterFactory instance.
 *
 * Per A2-β §5.5.
 */
export declare function freezeWorld(registry: RegistryWorld): FrozenWorld;
//# sourceMappingURL=freeze-world.d.mts.map