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

import type { AppConfig } from "../config/application.schema.mjs";
import { deploymentModeOf } from "../deployment/mode.mjs";
import { resolveTokenBindingSettings } from "../middleware/tokenBinding.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import { outboundPolicyOf } from "../net/outbound-fetch.mjs";
import { prepareSyntheticProjections } from "./apply-contributions.mjs";
import { auditSlotFor } from "./audit-fan-out.mjs";
import { clientRecordSlotFor } from "./client-record-slot.mjs";
import { failureSummary } from "./failure-summary.mjs";
import { federationSettingsOf } from "./federation-settings.mjs";
import { tokenSettingsSlotFor } from "./token-settings-slot.mjs";
import type {
	BootPlan,
	BootstrapMap,
	CleanupRecord,
	ComponentWorld,
	ContributionCollectorMap,
} from "./types.mjs";
import { BootError } from "./types.mjs";
import { federationStoresRefusal, undeclaredAbsenceRefusal } from "./validate-manifests.mjs";

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
		if (!Object.hasOwn(components, key)) {
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

/**
 * Whether `components` holds `key` as `undefined`. A slot so filled — a host
 * map entry given as `undefined`, or a provider resolving to it — is
 * unfilled. A provider no active module reads is not run unless seeded, and
 * its slot stays unset rather than holding `undefined`.
 * @internal
 */
function holdsUndefined(components: Record<string, unknown>, key: ComponentKey): boolean {
	return Object.hasOwn(components, key) && components[key as string] === undefined;
}

/** The refusal of `module` requiring `key`, whose slot holds `undefined`. */
function requiredSlotRefusal(module: string, key: ComponentKey): BootError {
	return new BootError({
		message:
			`Missing required component "${String(key)}" — module "${module}" requires it, and what ` +
			"fills it (a bootstrapComponents or overrideComponents entry, or its provider) holds undefined.",
		reason: "missing-required-component",
		stage: "materializeComponents",
		details: {
			reason: "missing-required-component",
			missingKey: key,
			rootModule: module,
			path: [{ module, requires: key }],
		},
	});
}

/**
 * Once every provider has run, the first unfilled slot boot cannot start
 * without, or `undefined`: a slot an active module requires, a slot in
 * `undeclaredAbsenceSlots`, or an enabled federation's store.
 * @internal
 */
function unfilledSlotRefusal(
	plan: BootPlan,
	components: Record<string, unknown>,
	config: unknown,
): BootError | undefined {
	for (const [module, blueprint] of plan.depsBlueprint) {
		const key = blueprint.requires.find((k) => holdsUndefined(components, k));
		if (key !== undefined) return requiredSlotRefusal(module, key);
	}
	const absent = plan.validated.undeclaredAbsenceSlots.find((slot) =>
		holdsUndefined(components, slot.componentKey),
	);
	if (absent !== undefined) return undeclaredAbsenceRefusal(absent, "materializeComponents");
	return federationStoresRefusal(
		config as AppConfig,
		(key) => !holdsUndefined(components, key),
		"materializeComponents",
	);
}

// ---------------------------------------------------------------------------
// Public API — materializeComponents
// ---------------------------------------------------------------------------

/**
 * Stage 3 of the boot planner. Seeds `bootstrapComponents`, applies
 * `overrideComponents`, fills `deploymentMode` from the configuration's
 * `core.deployment.mode`, `tokenBindingSettings` from its
 * `core.tokenBinding`, `federationSettings` from its `core.federations` and
 * `outboundPolicy` from its `core.outbound`,
 * injects the synthetic projections of
 * `contributionKinds` when given (a provider that requires one reads it
 * lazily, filled once stage 4 registers the contributions), then runs each
 * provider factory in `plan.providerActivations` order. The `auditSink`
 * slot is `audit-fan-out.mts`'s to fill (`auditSlotFor`), and the
 * `clientRepository` slot `client-record-slot.mts`'s (`clientRecordSlotFor`,
 * core's client-record boundary over whatever fills it), and the
 * `oauthTokenSettings` slot `token-settings-slot.mts`'s
 * (`tokenSettingsSlotFor`, the checked, frozen snapshot of whatever fills
 * it); a cleanup is still handed the provider's own value.
 *
 * A factory failure becomes `BootError reason="provides-factory-failed"`, its
 * message naming the thrown value by `failureSummary` (never
 * `String(thrown)`). The cleanups of the components already materialised run
 * first, in reverse, and their errors go to `details.cleanupErrors`. A
 * provided `oauthTokenSettings` the slot refuses is reported the same way,
 * after the provider's own cleanup too, unless the refusal is already a
 * BootError (a lifetime beyond the configuration's), which is thrown as it is.
 *
 * A slot holding `undefined` (a bootstrap or override entry given as
 * `undefined`, or a factory resolving to it) is unfilled, after the cleanups
 * of what is materialised: a slot a provider requires is refused
 * (`missing-required-component`) before that provider runs; once every
 * provider has run, so is a slot any active module requires, a slot in
 * `undeclaredAbsenceSlots` (`component-absence-undeclared`) and an enabled
 * federation's store (`federation-stores-incomplete`). An override given as
 * `undefined` replaces the provider as any override does.
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
	// Core's token-binding settings, frozen, from the same configuration with
	// core's one reader of the section — what boot's dispatch policy is too.
	// Stage 1 refuses the key from every other source.
	components.tokenBindingSettings = resolveTokenBindingSettings(bootstrapComponents.config);
	// Core's view of the federations, frozen, from the same configuration with
	// core's readings of `core.federations` — the map stage 1 dispatched by.
	// Stage 1 refuses the key from every other source.
	components.federationSettings = federationSettingsOf(bootstrapComponents.config);
	// The outbound destination policy, frozen all the way down, from the same
	// configuration with core's one reader of `core.outbound`. Stage 1 refuses
	// the key from every other source.
	components.outboundPolicy = outboundPolicyOf(bootstrapComponents.config);

	// Synthetic projections are stable read-through views of the collectors
	// stage 4 fills, so a provider that requires one gets the object the world
	// keeps (the MFA coordinator reads `mfaFactorResolver`).
	if (contributionKinds !== undefined) {
		prepareSyntheticProjections(components, contributionKinds);
	}

	// The `auditSink` slot's handling, `audit-fan-out.mts`'s alone.
	const auditSlot = auditSlotFor(plan, contributionKinds, components);
	auditSlot.beforeProviders();
	// The `clientRepository` slot's handling, `client-record-slot.mts`'s alone.
	const clientRecordSlot = clientRecordSlotFor(components);
	clientRecordSlot.beforeProviders();
	// The `oauthTokenSettings` slot's handling, `token-settings-slot.mts`'s alone.
	const tokenSettingsSlot = tokenSettingsSlotFor(components, bootstrapComponents.config);
	tokenSettingsSlot.beforeProviders(
		overrideComponents !== undefined && Object.hasOwn(overrideComponents, "oauthTokenSettings"),
	);

	for (const activation of plan.providerActivations) {
		const { module: moduleName, componentKey } = activation;

		// Already present from bootstrap or override.
		if (Object.hasOwn(components, componentKey)) {
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
		const unfilledKey = (blueprint?.requires ?? []).find((key) => holdsUndefined(components, key));
		if (unfilledKey !== undefined) {
			await runCleanupsReverse(cleanups);
			throw requiredSlotRefusal(moduleName, unfilledKey);
		}
		const deps = buildDeps(
			components,
			blueprint?.requires ?? [],
			blueprint?.optional ?? [],
			validatedModule.section,
		);

		/** Rolls back what is materialised, then reports the provider's failure. */
		const providerFailed = async (thrownValue: unknown): Promise<never> => {
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
		};

		// Awaited uniformly: a factory may be sync or async.
		let value: unknown;
		try {
			value = await factory(deps as never);
		} catch (thrownValue) {
			// Partial rollback of the components already materialised.
			await providerFailed(thrownValue);
		}

		const cleanupFn = manifest.lifecycle?.[componentKey]?.cleanup;
		if (cleanupFn !== undefined) {
			cleanups.push({
				module: moduleName,
				componentKey,
				cleanup: cleanupFn as (value: unknown) => void | Promise<void>,
				value,
			});
		}

		let held: unknown;
		try {
			held = tokenSettingsSlot.provided(componentKey, value, moduleName);
		} catch (refusal) {
			// The provider's own value is rolled back with the rest.
			if (!(refusal instanceof BootError)) await providerFailed(refusal);
			await runCleanupsReverse(cleanups);
			throw refusal;
		}

		components[componentKey as string] = clientRecordSlot.provided(
			componentKey,
			auditSlot.provided(componentKey, held),
		);
	}

	const refusal = unfilledSlotRefusal(plan, components, bootstrapComponents.config);
	if (refusal !== undefined) {
		await runCleanupsReverse(cleanups);
		throw refusal;
	}

	return {
		plan,
		components: components as Readonly<Partial<ComponentMap>>,
		cleanups,
		externalKeys,
	};
}
