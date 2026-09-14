/**
 * boot/materialize-components.mts — Stage 3 of the A2-β boot planner pipeline.
 *
 * Takes the `BootPlan` from stage 2 plus `bootstrapComponents` and
 * `overrideComponents`, runs each provider factory in topological +
 * declaration-stable order, and emits a `ComponentWorld` carrying the
 * materialised values plus per-component cleanup records.
 *
 * The function is **async** (factories may be async) but **deterministic**:
 * same inputs (and same factory side-effects) → same output / same error.
 *
 * Per A2-β §5.3.
 */
import type { ComponentMap } from "../modules/manifest/component-map.mjs";
import type { BootPlan, BootstrapMap, ComponentWorld } from "./types.mjs";
/**
 * Stage 3 of the A2-β boot planner pipeline.
 *
 * Pre-seeds `bootstrapComponents` into the working component map, applies
 * `overrideComponents` substitutions, then runs each provider factory in the
 * topological + declaration-stable order determined by `plan.providerActivations`.
 *
 * On factory failure:
 *   - Wraps the thrown value as `BootError reason="provides-factory-failed"`.
 *   - Runs a best-effort partial rollback of cleanups for components already
 *     materialised (in REVERSE order).
 *   - Cleanup errors are accumulated into `details.cleanupErrors` before the
 *     BootError propagates.
 *
 * Per A2-β §5.3.
 */
export declare function materializeComponents(plan: BootPlan, bootstrapComponents: BootstrapMap, overrideComponents: Partial<ComponentMap> | undefined): Promise<ComponentWorld>;
//# sourceMappingURL=materialize-components.d.mts.map