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

import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type { BootPlan, BootstrapMap, CleanupRecord, ComponentWorld } from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a typed deps object for a provider activation from the working
 * component map, given the activation's module DepsBlueprint.
 *
 * `requires` keys MUST be present — if they are missing it means an invariant
 * was violated in an earlier stage. Missing required key throws a plain Error
 * (programmer error, not a BootError).
 * `optional` keys may be absent; they are included as `undefined`.
 *
 * Per A2-β §5.3 step 3.
 * @internal
 */
function buildDeps(
	components: Record<string, unknown>,
	requires: readonly ComponentKey[],
	optional: readonly ComponentKey[],
): Record<string, unknown> {
	const deps: Record<string, unknown> = {};

	for (const key of requires) {
		if (!(key in components)) {
			throw new Error(
				`invariant violated: missing required dep "${String(key)}" — stage 1/2 should have caught this`,
			);
		}
		deps[key as string] = components[key as string];
	}

	for (const key of optional) {
		deps[key as string] = components[key as string];
	}

	return deps;
}

/**
 * Run a list of cleanup records in REVERSE order (best-effort).
 * Errors from individual cleanups are accumulated and returned; the loop does
 * NOT abort on a cleanup failure.
 *
 * Per A2-β §5.3 step 3 (partial rollback).
 * @internal
 */
async function runCleanupsReverse(cleanupRecords: readonly CleanupRecord[]): Promise<
	readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[]
> {
	const errors: { module: string; componentKey: ComponentKey; error: unknown }[] = [];

	for (let i = cleanupRecords.length - 1; i >= 0; i--) {
		// biome-ignore lint/style/noNonNullAssertion: i is bounded by cleanupRecords.length - 1
		const record = cleanupRecords[i]!;
		try {
			await record.cleanup(record.value);
		} catch (err) {
			errors.push({
				module: record.module,
				componentKey: record.componentKey,
				error: err,
			});
		}
	}

	return errors;
}

// ---------------------------------------------------------------------------
// Public API — materializeComponents
// ---------------------------------------------------------------------------

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
export async function materializeComponents(
	plan: BootPlan,
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
): Promise<ComponentWorld> {
	// Working component map — typed internally as a plain Record for mutation.
	const components: Record<string, unknown> = {};

	// Per-component cleanup records captured during successful materialisations.
	const cleanups: CleanupRecord[] = [];

	// Track which keys came from the host environment (bootstrap + override).
	// These are consumer-owned: the boot planner must NOT call Symbol.asyncDispose
	// on their values in AppHandle.dispose(). Per A2-β §5.3 / §8.1.
	const externalKeys = new Set<ComponentKey>();

	// Step 1: Pre-seed bootstrapComponents. Per A2-β §5.3 step 1.
	for (const [key, value] of Object.entries(bootstrapComponents)) {
		components[key] = value;
		externalKeys.add(key as ComponentKey);
	}

	// Step 2: Apply overrideComponents. Per A2-β §5.3 step 2.
	// Override entries replace the would-be provider value; the factory is
	// skipped entirely; the lifecycle[K].cleanup is NOT recorded.
	if (overrideComponents !== undefined) {
		for (const [key, value] of Object.entries(overrideComponents)) {
			components[key] = value;
			externalKeys.add(key as ComponentKey);
		}
	}

	// Step 3: Run providers in plan.providerActivations order. Per A2-β §5.3 step 3.
	for (const activation of plan.providerActivations) {
		const { module: moduleName, componentKey } = activation;

		// If K is already present (bootstrap or override), skip entirely.
		if (componentKey in components) {
			continue;
		}

		// Retrieve the validated module manifest.
		const validatedModule = plan.validated.byName.get(moduleName);
		if (!validatedModule) {
			throw new Error(
				`invariant violated: module "${moduleName}" not found in validated manifests`,
			);
		}
		const manifest = validatedModule.manifest;

		// Look up the provider factory for this component key.
		const factory = manifest.provides?.[componentKey];
		if (!factory) {
			throw new Error(
				`invariant violated: module "${moduleName}" has no provider for "${String(componentKey)}"`,
			);
		}

		// Build the typed deps object from the current working component map.
		const blueprint = plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(components, blueprint?.requires ?? [], blueprint?.optional ?? []);

		// Invoke the factory (await uniformly — handles both sync and async).
		let value: unknown;
		try {
			value = await factory(deps as never);
		} catch (thrownValue) {
			// Partial rollback: run cleanups for already-materialised components
			// in reverse order. Per A2-β §5.3 step 3 (on factory throw / reject).
			const cleanupErrors = await runCleanupsReverse(cleanups);

			throw new BootError({
				message: `Module "${moduleName}" provider factory for "${String(componentKey)}" failed: ${String(thrownValue)}`,
				reason: "provides-factory-failed",
				stage: "materializeComponents",
				details: {
					reason: "provides-factory-failed",
					module: moduleName,
					componentKey,
					originalError: thrownValue,
					...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
				},
				cause: thrownValue,
			});
		}

		// Store the materialised value.
		components[componentKey as string] = value;

		// Capture cleanup record if lifecycle[K].cleanup is defined.
		const cleanupFn = manifest.lifecycle?.[componentKey]?.cleanup;
		if (cleanupFn !== undefined) {
			cleanups.push({
				module: moduleName,
				componentKey,
				cleanup: cleanupFn as (value: unknown) => void | Promise<void>,
				value,
			});
		}
	}

	return {
		plan,
		components: components as Readonly<Partial<ComponentMap>>,
		cleanups,
		externalKeys,
	};
}
