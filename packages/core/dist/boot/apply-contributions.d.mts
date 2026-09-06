import type { ComponentWorld, ContributionCollectorMap, RegistryWorld } from "./types.mjs";
/**
 * Stage 4 of the A2-β boot planner pipeline.
 *
 * Takes the `ComponentWorld` from stage 3 plus the merged
 * `ContributionCollectorMap` (built-in defaults + consumer overrides; the
 * orchestrator at Task 9 performs the merge before calling this function).
 *
 * Steps:
 *   0. `prepareSyntheticProjections` — inject stable read-side resolvers for
 *      `grants`, `tokenExchangeValidators`, `federations` into the working
 *      component map so contribution factories can capture resolver references
 *      that are fully populated at request time.
 *   2. Name-keyed pass (in `BootPlan.initOrder`):
 *        - Pre-scan phase: validate no duplicate/missing-target in collector
 *          state BEFORE running any factory for this module. The pre-scan
 *          mirrors `GrantRegistry.addModule` (commit de1ddb92) — prevents
 *          factory side-effect leak when one module's contribution set fails
 *          midway.
 *        - Materialize+register phase: invoke factories, route to
 *          `collector.register` (contributes) or `collector.replace` (overrides).
 *   3. List-shaped pass (in INPUT-ARRAY order):
 *        - auditHooks / grantPolicyHooks: invoke factory, call `collector.append`
 *          (dedup by reference identity is the collector's responsibility).
 *        - routes: invoke factory or take static value; wrap as
 *          `CollectedRouteContribution`; assign `declarationIndex`.
 *
 * On factory throw: wrap as `BootError reason="contribute-factory-failed"`,
 * `cause = thrown`, `stage = "applyContributions"`. Run stage-3 cleanups
 * from `material.cleanups` in REVERSE before propagating.
 *
 * Per A2-β §5.4.
 */
export declare function applyContributions(material: ComponentWorld, contributionKinds: ContributionCollectorMap): Promise<RegistryWorld>;
//# sourceMappingURL=apply-contributions.d.mts.map