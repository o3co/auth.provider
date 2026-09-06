import type { AppHandle, BootstrapMap, CreateAppOptions, DefaultBootstrapMap } from "./types.mjs";
/**
 * Orchestrator for the A2-β boot planner pipeline.
 *
 * Stages:
 *   1. validateManifests — normalise + validate all manifests.
 *   2. planBoot — build dependency graph, detect cycles, compute init order.
 *   3. materializeComponents — run provider factories in topological order.
 *   4. applyContributions — route contributions to collectors.
 *   5. freezeWorld — Object.freeze component map + call freeze() on registries.
 *   6. assembleApp — mount routes, build AppHandle.
 *
 * Built-in contribution kinds (grants, tokenExchangeValidators, federations,
 * mfaFactors, auditHooks, routes, grantPolicyHooks) are seeded by
 * `mergeWithBuiltins`; consumer-supplied kinds overlay on top.
 *
 * The generic `B` constrains `bootstrapComponents` to a typed subset of
 * `ComponentMap` so downstream stages receive a well-typed config/pathResolver.
 *
 * Per A2-β §6.2 / §6.4.
 */
export declare function createApp<B extends BootstrapMap = DefaultBootstrapMap>(options: CreateAppOptions<B>): Promise<AppHandle>;
//# sourceMappingURL=create-app.d.mts.map