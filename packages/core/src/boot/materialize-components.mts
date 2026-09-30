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
 * boot/materialize-components.mts: stage 3 of the boot planner. Runs each
 * provider factory of the `BootPlan` in topological, declaration-stable order
 * and emits a `ComponentWorld` of the materialised values and their cleanup
 * records. Async (factories may be) but deterministic: the same inputs and
 * factory side effects give the same output or the same error.
 */

import { deploymentModeOf } from "../deployment/mode.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import { prepareSyntheticProjections } from "./apply-contributions.mjs";
import { failureSummary } from "./failure-summary.mjs";
import type {
	BootPlan,
	BootstrapMap,
	CleanupRecord,
	ComponentWorld,
	ContributionCollectorMap,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Builds a provider activation's deps object from the working component map.
 * A missing `requires` key means an earlier stage broke an invariant, so it
 * throws a plain Error, not a BootError. Absent `optional` keys are included
 * as `undefined`. `deps.section` is the module's own configuration section,
 * parsed at stage 1, and is absent when the module declares none.
 * @internal
 */
function buildDeps(
	components: Record<string, unknown>,
	requires: readonly ComponentKey[],
	optional: readonly ComponentKey[],
	section: { readonly value: unknown } | undefined,
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

	if (section !== undefined) {
		deps.section = section.value;
	}

	return deps;
}

/**
 * Runs cleanup records in reverse order, best-effort: a failing cleanup does
 * not stop the loop, and its error is returned.
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
 * Stage 3 of the boot planner. Seeds `bootstrapComponents`, applies
 * `overrideComponents`, fills `deploymentMode` from the configuration's
 * `core.deployment.mode`, injects the synthetic projections of
 * `contributionKinds` when given (a provider that requires one reads it
 * lazily, filled once stage 4 registers the contributions), then runs each
 * provider factory in `plan.providerActivations` order.
 *
 * A factory failure becomes `BootError reason="provides-factory-failed"`, its
 * message naming the thrown value by `failureSummary` (never
 * `String(thrown)`). The cleanups of the components already materialised run
 * first, in reverse, and their errors go to `details.cleanupErrors`.
 */
export async function materializeComponents(
	plan: BootPlan,
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
	contributionKinds?: ContributionCollectorMap,
): Promise<ComponentWorld> {
	const components: Record<string, unknown> = {};

	// Per-component cleanup records captured during successful materialisations.
	const cleanups: CleanupRecord[] = [];

	// Keys from the host (bootstrap and override) are consumer-owned:
	// AppHandle.dispose() must not call Symbol.asyncDispose on their values.
	const externalKeys = new Set<ComponentKey>();

	for (const [key, value] of Object.entries(bootstrapComponents)) {
		components[key] = value;
		externalKeys.add(key as ComponentKey);
	}

	// An override replaces the provider's value: its factory is skipped and
	// its lifecycle cleanup is not recorded.
	if (overrideComponents !== undefined) {
		for (const [key, value] of Object.entries(overrideComponents)) {
			components[key] = value;
			externalKeys.add(key as ComponentKey);
		}
	}

	// The replica count, from the configuration stage 1 parsed — the value its
	// replica-safety guard decided by. Stage 1 refuses the key from every
	// other source.
	components.deploymentMode = deploymentModeOf(bootstrapComponents.config);

	// Synthetic projections are stable read-through views of the collectors
	// stage 4 fills, so a provider that requires one gets the object the world
	// keeps (the MFA coordinator reads `mfaFactorResolver`).
	if (contributionKinds !== undefined) {
		prepareSyntheticProjections(components, contributionKinds);
	}

	for (const activation of plan.providerActivations) {
		const { module: moduleName, componentKey } = activation;

		// Already present from bootstrap or override.
		if (componentKey in components) {
			continue;
		}

		const validatedModule = plan.validated.byName.get(moduleName);
		if (!validatedModule) {
			throw new Error(
				`invariant violated: module "${moduleName}" not found in validated manifests`,
			);
		}
		const manifest = validatedModule.manifest;

		const factory = manifest.provides?.[componentKey];
		if (!factory) {
			throw new Error(
				`invariant violated: module "${moduleName}" has no provider for "${String(componentKey)}"`,
			);
		}

		const blueprint = plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(
			components,
			blueprint?.requires ?? [],
			blueprint?.optional ?? [],
			validatedModule.section,
		);

		// Awaited uniformly: a factory may be sync or async.
		let value: unknown;
		try {
			value = await factory(deps as never);
		} catch (thrownValue) {
			// Partial rollback of the components already materialised.
			const cleanupErrors = await runCleanupsReverse(cleanups);

			throw new BootError({
				message: `Module "${moduleName}" provider factory for "${String(componentKey)}" failed: ${failureSummary(thrownValue)}`,
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

		components[componentKey as string] = value;

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
