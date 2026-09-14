/**
 * boot/plan-boot.mts — Stage 2 of the A2-β boot planner pipeline.
 *
 * Accepts `ValidatedManifests` (output of stage 1), `bootstrapComponents`,
 * and `overrideComponents`; runs five ordered steps:
 *  1. Build dependency graph
 *  2. Cycle detection (Tarjan's SCC)
 *  3. Topological sort (Kahn's algorithm, declaration-order tie-breaker)
 *  4. Per-component activation closure (contribute/override roots + eager seeds)
 *  5. Build `providerActivations` and `depsBlueprint`
 *
 * Returns a `BootPlan` on success. Throws `BootError` with
 * `reason: "circular-dependency"` on the first detected cycle.
 *
 * The stage is **pure**: same inputs → same output / same error.
 *
 * Per A2-β §5.2.
 */
import type { ComponentMap } from "../modules/manifest/component-map.mjs";
import type { BootPlan, BootstrapMap, ValidatedManifests } from "./types.mjs";
/**
 * Stage 2 of the A2-β boot planner pipeline.
 *
 * Takes `ValidatedManifests` (from stage 1), `bootstrapComponents`, and
 * `overrideComponents`; runs the dependency graph, cycle detection, topological
 * sort, per-component activation closure, and emits a `BootPlan`.
 *
 * The function is **pure**: same inputs → same output / same error.
 *
 * Steps:
 * 1. Build dependency graph — nodes = modules, edges from requires + optional
 *    (advisory). Bootstrap/override keys are pre-seeded virtual providers.
 * 2. Cycle detection — Tarjan's SCC; non-trivial SCCs or self-loops throw
 *    `BootError` with `reason: "circular-dependency"`, `stage: "planBoot"`.
 * 3. Topological sort — Kahn's algorithm with declaration-order tie-breaker.
 * 4. Per-component activation closure — closure roots = modules with any
 *    contributes/overrides; eager seeds = `lifecycle[K].eager === true`; both
 *    walk the requires graph recursively. Non-eager siblings do NOT piggy-back.
 * 5. Build `providerActivations` (per-component, not per-module) and
 *    `depsBlueprint` (lookup keys, not values).
 *
 * Per A2-β §5.2.
 */
export declare function planBoot(validated: ValidatedManifests, bootstrapComponents: BootstrapMap, overrideComponents: Partial<ComponentMap> | undefined): BootPlan;
//# sourceMappingURL=plan-boot.d.mts.map