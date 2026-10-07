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
import { BootError } from "./types.mjs";
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
/**
 * Build a typed deps object for a module from the working component map,
 * using the module's DepsBlueprint from the plan.
 *
 * `requires` keys MUST be present — if they are missing it means an invariant
 * was violated by an earlier stage (validate-manifests step 4 or planBoot's
 * activation closure). Missing required key throws a plain Error (programmer
 * error, not a BootError). Mirrors materialize-components.buildDeps for
 * symmetric defence-in-depth at the contribution-factory boundary.
 *
 * `optional` keys may be absent; they are included as `undefined`.
 *
 * Per A2-β §5.4 step 2 (deps materialisation from ComponentWorld).
 * @internal
 */
function buildDeps(components, requires, optional) {
    const deps = {};
    for (const key of requires) {
        if (!(key in components)) {
            throw new Error(`invariant violated: missing required dep "${String(key)}" for contribute factory — stage 1/2 should have caught this`);
        }
        deps[key] = components[key];
    }
    for (const key of optional) {
        deps[key] = components[key];
    }
    return deps;
}
/**
 * Run cleanup records in REVERSE order (best-effort). Returns any errors
 * encountered so they can be collected into `details.cleanupErrors`.
 *
 * Per A2-β §5.4 step 2 (partial rollback on factory failure) and §5.3.
 * @internal
 */
async function runCleanupsReverse(cleanupRecords) {
    const errors = [];
    for (let i = cleanupRecords.length - 1; i >= 0; i--) {
        // biome-ignore lint/style/noNonNullAssertion: index is bounded
        const record = cleanupRecords[i];
        try {
            await record.cleanup(record.value);
        }
        catch (err) {
            errors.push({ module: record.module, componentKey: record.componentKey, error: err });
        }
    }
    return errors;
}
/**
 * Instantiate a stable read-side `GrantHandlerResolver` backed by the given
 * `NameKeyedCollector`. The resolver's `get` / `entries` read through to the
 * collector at call time; the collector need not be populated yet when the
 * resolver reference is created.
 *
 * Per A2-β §5.4 step 0: lazy read-through means factories that capture this
 * resolver in their closure see the fully-populated view at request time.
 * @internal
 */
function makeGrantHandlerResolver(collector) {
    return {
        get: (grantType) => collector.get(grantType),
        entries: () => collector.entries(),
    };
}
/**
 * Instantiate a stable read-side `TokenExchangeValidatorResolver` backed by
 * the given `NameKeyedCollector`.
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
function makeTokenExchangeValidatorResolver(collector) {
    return {
        get: (tokenType) => collector.get(tokenType),
        entries: () => collector.entries(),
    };
}
/**
 * Instantiate a stable `ReadonlyMap`-shaped view of a federation collector.
 * Reads through at call time via the collector's `entries()`. Backed by a
 * live `Map` snapshot taken on each access so that `ReadonlyMap` typed
 * return values (including iterator shapes) are satisfied correctly.
 *
 * Per A2-β §5.4 step 0: `federations → federationProviders` projection.
 * @internal
 */
function makeFederationProviders(collector) {
    function snapshot() {
        return new Map(collector.entries());
    }
    return {
        get: (key) => collector.get(key),
        has: (key) => collector.get(key) !== undefined,
        entries: () => snapshot().entries(),
        keys: () => snapshot().keys(),
        values: () => snapshot().values(),
        forEach: (cb, thisArg) => {
            snapshot().forEach((v, k) => {
                cb.call(thisArg, v, k, snapshot());
            });
        },
        get size() {
            return snapshot().size;
        },
        [Symbol.iterator]: () => snapshot()[Symbol.iterator](),
    };
}
/**
 * Instantiate a stable collector-backed read-through view of the
 * `federationRedirectPolicies` collector — structurally
 * `ReadonlyMap<string, unknown>` whose delegates read from the live collector
 * at call time.
 *
 * Per A5 §8.1: the view reference is stable from step 0 onward; collector
 * contents become fully populated after applyContributions step 2.
 * NOT a snapshot — reads through at request time.
 * Mirrors `makeFederationProviders` in shape.
 * @internal
 */
function makeFederationRedirectPolicyResolver(collector) {
    function snapshot() {
        return new Map(collector.entries());
    }
    return {
        get: (key) => collector.get(key),
        has: (key) => collector.get(key) !== undefined,
        entries: () => snapshot().entries(),
        keys: () => snapshot().keys(),
        values: () => snapshot().values(),
        forEach: (cb, thisArg) => {
            snapshot().forEach((v, k) => {
                cb.call(thisArg, v, k, snapshot());
            });
        },
        get size() {
            return snapshot().size;
        },
        [Symbol.iterator]: () => snapshot()[Symbol.iterator](),
    };
}
/**
 * Step 0 — prepareSyntheticProjections.
 *
 * For each name-keyed collector that has a corresponding synthetic
 * `ComponentMap` projection, instantiate a stable read-side resolver and
 * write it into the working component map under the synthetic key.
 *
 * Only injects the resolver if the corresponding collector is present in the
 * `contributionKinds` map. Does NOT inject `undefined`.
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
function prepareSyntheticProjections(components, contributionKinds) {
    if (contributionKinds.grants !== undefined) {
        const resolver = makeGrantHandlerResolver(contributionKinds.grants);
        components.grantHandlerResolver = resolver;
    }
    if (contributionKinds.tokenExchangeValidators !== undefined) {
        const resolver = makeTokenExchangeValidatorResolver(contributionKinds.tokenExchangeValidators);
        components.tokenExchangeValidatorResolver = resolver;
    }
    if (contributionKinds.federations !== undefined) {
        const view = makeFederationProviders(contributionKinds.federations);
        components.federationProviders = view;
    }
    if (contributionKinds.federationRedirectPolicies !== undefined) {
        const view = makeFederationRedirectPolicyResolver(contributionKinds.federationRedirectPolicies);
        components.federationRedirectPolicyResolver = view;
    }
}
// ---------------------------------------------------------------------------
// Collector-kind discriminant helpers
// ---------------------------------------------------------------------------
/**
 * Return the collector for `kind` from the `ContributionCollectorMap`, or
 * `undefined` when the kind has no entry. Typed as the union of all three
 * collector shapes so callers can narrow via `collector.kind`.
 *
 * Per A2-β §5.4: routing MUST use `collector.kind` as discriminant so that
 * consumer-defined kinds (added via `declare module` augmentation) are
 * handled correctly without a hardcoded set lookup.
 * @internal
 */
function collectorFor(contributionKinds, kind) {
    return contributionKinds[kind];
}
// ---------------------------------------------------------------------------
// Public API — applyContributions
// ---------------------------------------------------------------------------
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
export async function applyContributions(material, contributionKinds) {
    // ---------------------------------------------------------------------------
    // Mutable working component map (stage 3 handed it as Readonly<Partial<...>>
    // but it is not yet Object.frozen — freezeWorld does that in stage 5).
    // We cast to a plain Record so we can write the synthetic projections.
    // ---------------------------------------------------------------------------
    const components = material.components;
    // ---------------------------------------------------------------------------
    // Step 0: prepareSyntheticProjections. Per A2-β §5.4 step 0.
    // ---------------------------------------------------------------------------
    prepareSyntheticProjections(components, contributionKinds);
    // ---------------------------------------------------------------------------
    // Step 2: Name-keyed pass in BootPlan.initOrder.
    // Per A2-β §5.4 step 2.
    // ---------------------------------------------------------------------------
    for (const moduleName of material.plan.initOrder) {
        const validatedModule = material.plan.validated.byName.get(moduleName);
        if (!validatedModule)
            continue;
        const blueprint = material.plan.depsBlueprint.get(moduleName);
        const deps = buildDeps(components, blueprint?.requires ?? [], blueprint?.optional ?? []);
        // Collect name-keyed contributes + overrides entries for this module.
        // Routing uses collector.kind === "name-keyed" so that consumer-defined
        // kinds (not in any hardcoded set) are handled correctly. Per A2-β §5.4.
        const nameKeyedContributes = validatedModule.normalised.contributesEntries.filter((e) => collectorFor(contributionKinds, e.kind)?.kind === "name-keyed");
        const nameKeyedOverrides = validatedModule.normalised.overridesEntries.filter((e) => collectorFor(contributionKinds, e.kind)?.kind === "name-keyed");
        // ------------------------------------------------------------------
        // Pre-scan phase (mirrors GrantRegistry.addModule fix de1ddb92 to
        // prevent factory side-effect leak).
        //
        // Validate ALL collector invariants for this module BEFORE invoking
        // any factory. If any check fails, no factory for this module runs.
        // ------------------------------------------------------------------
        for (const entry of nameKeyedContributes) {
            const collector = contributionKinds[entry.kind];
            if (collector === undefined)
                continue;
            const name = entry.key;
            if (collector.get(name) !== undefined) {
                throw new BootError({
                    message: `Pre-scan: duplicate contribution "${name}" for kind "${entry.kind}" in module "${moduleName}".`,
                    reason: "duplicate-contribute",
                    stage: "applyContributions",
                    details: {
                        reason: "duplicate-contribute",
                        kind: entry.kind,
                        identity: name,
                        identityKind: "name",
                        modules: [moduleName, moduleName],
                    },
                });
            }
        }
        for (const entry of nameKeyedOverrides) {
            const collector = contributionKinds[entry.kind];
            if (collector === undefined)
                continue;
            const name = entry.key;
            if (collector.get(name) === undefined) {
                throw new BootError({
                    message: `Pre-scan: override target "${name}" for kind "${entry.kind}" missing in module "${moduleName}".`,
                    reason: "override-target-missing",
                    stage: "applyContributions",
                    details: {
                        reason: "override-target-missing",
                        kind: entry.kind,
                        name,
                        overridingModule: moduleName,
                    },
                });
            }
        }
        // ------------------------------------------------------------------
        // Materialize+register phase.
        // ------------------------------------------------------------------
        for (const entry of nameKeyedContributes) {
            const collector = contributionKinds[entry.kind];
            if (collector === undefined)
                continue;
            const name = entry.key;
            const factory = entry.factory;
            let value;
            try {
                value = await factory(deps);
            }
            catch (thrownValue) {
                const cleanupErrors = await runCleanupsReverse(material.cleanups);
                throw new BootError({
                    message: `Module "${moduleName}" contribution factory for kind "${entry.kind}" name "${name}" failed: ${String(thrownValue)}`,
                    reason: "contribute-factory-failed",
                    stage: "applyContributions",
                    details: {
                        reason: "contribute-factory-failed",
                        module: moduleName,
                        kind: entry.kind,
                        name,
                        originalError: thrownValue,
                        ...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
                    },
                    cause: thrownValue,
                });
            }
            collector.register(name, value);
        }
        for (const entry of nameKeyedOverrides) {
            const collector = contributionKinds[entry.kind];
            if (collector === undefined)
                continue;
            const name = entry.key;
            const factory = entry.factory;
            let value;
            try {
                value = await factory(deps);
            }
            catch (thrownValue) {
                const cleanupErrors = await runCleanupsReverse(material.cleanups);
                throw new BootError({
                    message: `Module "${moduleName}" override factory for kind "${entry.kind}" name "${name}" failed: ${String(thrownValue)}`,
                    reason: "contribute-factory-failed",
                    stage: "applyContributions",
                    details: {
                        reason: "contribute-factory-failed",
                        module: moduleName,
                        kind: entry.kind,
                        name,
                        originalError: thrownValue,
                        ...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
                    },
                    cause: thrownValue,
                });
            }
            collector.replace(name, value);
        }
    }
    // ---------------------------------------------------------------------------
    // Step 3: List-shaped pass in INPUT-ARRAY order.
    // Per A2-β §5.4 step 3.
    // ---------------------------------------------------------------------------
    const routes = [];
    let declarationIndex = 0;
    for (const validatedModule of material.plan.validated.modules) {
        const moduleName = validatedModule.normalised.name;
        const blueprint = material.plan.depsBlueprint.get(moduleName);
        const deps = buildDeps(components, blueprint?.requires ?? [], blueprint?.optional ?? []);
        // List-shaped and list-routes pass: dispatch on collector.kind.
        // Handles built-in list kinds (auditHooks, grantPolicyHooks) AND any
        // consumer-defined list-shaped kinds — per A2-β §5.4 step 3.
        for (const entry of validatedModule.normalised.contributesEntries) {
            const collector = collectorFor(contributionKinds, entry.kind);
            if (collector === undefined)
                continue;
            if (collector.kind === "list-routes") {
                // Routes kind: entry.factory is a RouteContributionEntry<Deps> —
                // either a bare RouteContribution value or a factory.
                const entryValue = entry.factory;
                let contribution;
                if (typeof entryValue === "function") {
                    try {
                        contribution = await entryValue(deps);
                    }
                    catch (thrownValue) {
                        const cleanupErrors = await runCleanupsReverse(material.cleanups);
                        throw new BootError({
                            message: `Module "${moduleName}" route factory failed: ${String(thrownValue)}`,
                            reason: "contribute-factory-failed",
                            stage: "applyContributions",
                            details: {
                                reason: "contribute-factory-failed",
                                module: moduleName,
                                kind: entry.kind,
                                name: "",
                                originalError: thrownValue,
                                ...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
                            },
                            cause: thrownValue,
                        });
                    }
                }
                else {
                    // Static RouteContribution value — take directly.
                    contribution = entryValue;
                }
                const collected = {
                    contribution: contribution,
                    contributedBy: moduleName,
                    declarationIndex,
                };
                declarationIndex++;
                routes.push(collected);
                collector.append(collected);
            }
            else if (collector.kind === "list") {
                // Generic list-shaped kind (auditHooks, grantPolicyHooks, or any
                // consumer-defined kind whose collector has kind === "list").
                const factory = entry.factory;
                let value;
                try {
                    value = await factory(deps);
                }
                catch (thrownValue) {
                    const cleanupErrors = await runCleanupsReverse(material.cleanups);
                    throw new BootError({
                        message: `Module "${moduleName}" list-kind factory for "${entry.kind}" failed: ${String(thrownValue)}`,
                        reason: "contribute-factory-failed",
                        stage: "applyContributions",
                        details: {
                            reason: "contribute-factory-failed",
                            module: moduleName,
                            kind: entry.kind,
                            name: "",
                            originalError: thrownValue,
                            ...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
                        },
                        cause: thrownValue,
                    });
                }
                collector.append(value);
            }
            // kind === "name-keyed" entries are handled in step 2; skip here.
        }
    }
    // ---------------------------------------------------------------------------
    // Build registries map: kind → collector reference. Stage 5 uses this to
    // call freeze() on each collector that exposes it.
    // Per A2-β §5.4 output.
    // ---------------------------------------------------------------------------
    const registries = new Map();
    for (const [kind, collector] of Object.entries(contributionKinds)) {
        if (collector !== undefined) {
            registries.set(kind, collector);
        }
    }
    return {
        material,
        registries: registries,
        routes,
    };
}
