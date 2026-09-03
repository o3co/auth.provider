import type { Router } from "express";
import type { AppHandle, FrozenWorld } from "./types.mjs";
/**
 * Stage 6 of the A2-β boot planner pipeline.
 *
 * Takes the `FrozenWorld` from stage 5, computes mount order (Kahn's
 * topological sort over `before`/`after` route tokens with cycle detection),
 * constructs an Express Router with all routes mounted in mount-index order,
 * and builds the public `AppHandle` with `router`, `listen(port)`,
 * `dispose()`, and `components`.
 *
 * The construction phase is synchronous. `listen` and `dispose` on the
 * returned handle are async.
 *
 * Per A2-β §5.6 + §6.3 + §8.1.
 */
export declare function assembleApp(frozen: FrozenWorld, options?: {
    readonly express?: {
        Router: () => Router;
    };
}): AppHandle;
//# sourceMappingURL=assemble-app.d.mts.map