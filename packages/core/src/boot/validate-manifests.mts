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
 * boot/validate-manifests.mts: stage 1 of the boot planner. Checks the
 * consumer's modules and host maps with two ordered check registries around
 * the config parse, and emits `ValidatedManifests`; see `validateManifests`.
 */

import type { z } from "zod";
import { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY } from "../access-token-denylist/types.mjs";
import {
	type AppConfig,
	CoreConfigSchema,
	OAUTH_LIFETIME_PATHS,
} from "../config/application.schema.mjs";
import {
	defineConfigKey,
	isPlainConfigObject,
	operatorPath,
	overlayConfig,
} from "../config/composed.mjs";
import { CORE_RELOCATIONS, type CoreRelocations } from "../config/core-relocations.mjs";
import { environmentVariableFor } from "../config/environment-variable.mjs";
import {
	findRelocatedKeys,
	findRenamedVariables,
	type HandedConfiguration,
	pathsSetBy,
	RENAMED_VARIABLES_SECTION,
	type RelocatedPath,
	type RenamedVariable,
	relocatedKeyMessage,
	relocateKey,
	renamedVariableMessage,
	withoutRenamedVariables,
} from "../config/removed-keys.mjs";
import { describeValue } from "../errors/describe-value.mjs";
import { enabledFederationsOf } from "../federations/configured.mjs";
import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import {
	type AbsencePolicy,
	describeAbsenceDeclaration,
	isAbsenceDeclared,
} from "../modules/manifest/absence-policy.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { RouteContribution } from "../modules/manifest/route-contribution.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "../modules/manifest/synthetic-keys.mjs";
import { RATE_LIMITER_ABSENCE_POLICY } from "../ratelimit/types.mjs";
import {
	verifierLimitSetting,
	withVerifierLimitDeclarations,
} from "../ratelimit/verifierLimits.mjs";
import {
	admissionActionProblem,
	registeredAdmissionAction,
} from "../session-admission/actions.mjs";
import {
	lifetimeBeyondConfiguration,
	lifetimeBeyondConfigurationMessage,
} from "../token-settings/check.mjs";
import { SUBJECT_REVOCATION_ABSENCE_POLICY } from "../user-sessions/types.mjs";
import { contributesAuditHooks } from "./audit-fan-out.mjs";
import { type ConfigDefaults, logConfigNotices, readConfigDefaults } from "./config-notices.mjs";
import { failureSummary } from "./failure-summary.mjs";
import {
	checkFederationEntriesHandled,
	type FederationTypeSnapshot,
	federationTypeRegistration,
	federationTypeSnapshot,
	parseFederationEntries,
} from "./federation-entries.mjs";
import { snapshotHostMap } from "./host-maps.mjs";
import { unreadCorsSection } from "./http-settings.mjs";
import { frozenSection, parseSection } from "./parsed-values.mjs";
import {
	checkReplicaSafety,
	type ReplicaSafetyModuleRef,
	readReplicaSafety,
} from "./replica-safety.mjs";
import type {
	BootStage,
	BootstrapMap,
	ContributionContainer,
	ContributionEntry,
	ContributionKind,
	ContributionKindMap,
	NormalisedModule,
	UndeclaredAbsenceSlot,
	ValidatedManifests,
	ValidatedModule,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Public input type
// ---------------------------------------------------------------------------

/**
 * Input shape accepted by `validateManifests`. Mirrors `CreateAppOptions`
 * minus the generic `B` parameter (the bootstrap map is typed at the
 * `createApp` call site; stage 1 receives it erased to `BootstrapMap`).
 */
export interface ValidateManifestsInput {
	readonly modules: readonly Module[];
	readonly bootstrapComponents: BootstrapMap;
	/** The merged collectors: core's built-ins under the host's. */
	readonly contributionKinds?: ContributionKindMap;
	readonly overrideComponents?: Partial<ComponentMap>;
	/** Core's own section's relocations and renamed variables; core's shipped ones when unset. */
	readonly core?: CoreRelocations;
}

// ---------------------------------------------------------------------------
// Module normalisation
// ---------------------------------------------------------------------------

/**
 * What each `admissionActions` declaration was read as, once, at stage 1 —
 * its grade — keyed by the registration factory `nameKeyedFactory` answered
 * for it, so what is checked is what registers.
 */
const admissionActionSnapshots = new WeakMap<object, { readonly grade: unknown }>();

/**
 * What each `rateLimitBudgets` factory carrying a `verifier` declaration was
 * read as, once, at stage 1 — its setting, or what its read threw — keyed by
 * the registration factory `nameKeyedFactory` answered for it.
 */
const verifierClaimSnapshots = new WeakMap<
	object,
	{ readonly setting: unknown } | { readonly threw: string }
>();

/** Why a verifier claim's declaration, as read, is refused, or `undefined` when it is usable. */
function verifierClaimProblem(
	snapshot: { readonly setting: unknown } | { readonly threw: string },
): string | undefined {
	if ("threw" in snapshot) return `reading its verifier declaration threw: ${snapshot.threw}`;
	return typeof snapshot.setting === "string" && snapshot.setting.length > 0
		? undefined
		: "a verifier's claim declares { setting }, the setting its limit is made at, a non-empty string";
}

/**
 * The setting each prefix `modules` claim as a verifier's is made at, from
 * the declarations normalisation read: the first usable one per prefix (a
 * second claim is refused as a duplicate).
 */
function declaredVerifierLimits(modules: readonly NormalisedModule[]): ReadonlyMap<string, string> {
	const declared = new Map<string, string>();
	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			if (entry.kind !== "rateLimitBudgets" || typeof entry.key !== "string") continue;
			const snapshot = verifierClaimSnapshots.get(entry.factory as object);
			if (snapshot === undefined || verifierClaimProblem(snapshot) !== undefined) continue;
			if (!declared.has(entry.key)) {
				declared.set(entry.key, (snapshot as { readonly setting: string }).setting);
			}
		}
	}
	return declared;
}

/**
 * The factory a name-keyed entry registers through. A `federationTypes` entry
 * is a declaration, `{ entrySchema, factory, redirectPolicy }`, not a
 * factory: its members are read once, here, and what registers is a
 * `RegisteredFederationType` whose factories are bound to the deps stage 4
 * hands every factory (`federationTypeRegistration`). An `admissionActions` entry is a declaration,
 * `{ grade }`: its grade is read once, here, and what registers is the
 * action `name` with that grade. A `rateLimitBudgets` factory's `verifier`
 * declaration is read once, here, and what registers is a factory calling it.
 * `checkContributionShapes` holds each snapshot's shape; a declaration that
 * is not an object is left for it to refuse. Every other value is its own
 * factory.
 */
function nameKeyedFactory(kind: string, name: string, value: unknown): unknown {
	if (kind === "rateLimitBudgets" && typeof value === "function") {
		let snapshot: { readonly setting: unknown } | { readonly threw: string };
		try {
			const verifier: unknown = (value as { readonly verifier?: unknown }).verifier;
			if (verifier === undefined) return value;
			snapshot = {
				setting:
					typeof verifier === "object" && verifier !== null
						? (verifier as { readonly setting?: unknown }).setting
						: undefined,
			};
		} catch (thrown) {
			snapshot = { threw: failureSummary(thrown) };
		}
		const register = (deps: unknown): unknown => (value as (deps: unknown) => unknown)(deps);
		verifierClaimSnapshots.set(register, snapshot);
		return register;
	}
	if (typeof value !== "object" || value === null) return value;
	if (kind === "admissionActions") {
		if (Array.isArray(value)) return value;
		const grade: unknown = (value as { readonly grade?: unknown }).grade;
		const register = () => registeredAdmissionAction(name, { grade });
		admissionActionSnapshots.set(register, { grade });
		return register;
	}
	if (kind !== "federationTypes") return value;
	return federationTypeRegistration(value);
}

/** What a kind's container was read as, and how a refusal names it. */
function containerAsRead(container: unknown): Pick<ContributionContainer, "shape" | "given"> {
	if (Array.isArray(container)) return { shape: "list", given: "an array" };
	if (isPlainConfigObject(container)) return { shape: "record", given: "a record" };
	if (typeof container === "object" && container !== null) {
		// A record is a plain object: an instance, a Map or an object with
		// another prototype reads as one only through what it inherits.
		return { shape: "other", given: `${describeValue(container)}, not a plain object` };
	}
	return { shape: "other", given: describeValue(container) };
}

/**
 * One channel of a manifest — its `contributes` or `overrides`, read once by
 * the caller — flattened: each kind's container as read, and its entries. An
 * array files its entries under Symbol keys, an object under its names;
 * whether either is the kind's shape is `checkContributionContainers`'s to
 * judge, off `containers`.
 */
function normaliseChannel(
	m: Module,
	channel: "contributes" | "overrides",
	map: unknown,
): { readonly entries: ContributionEntry[]; readonly containers: ContributionContainer[] } {
	const entries: ContributionEntry[] = [];
	const containers: ContributionContainer[] = [];
	for (const [kind, container] of Object.entries(map ?? {})) {
		if (container === undefined) continue;
		containers.push({ kind: kind as ContributionKind, channel, ...containerAsRead(container) });
		if (Array.isArray(container)) {
			for (const factory of container) {
				entries.push({
					kind: kind as ContributionKind,
					key: Symbol(kind),
					factory,
					contributedBy: m.name,
				});
			}
		} else if (container !== null && typeof container === "object") {
			for (const [name, value] of Object.entries(container as Record<string, unknown>)) {
				entries.push({
					kind: kind as ContributionKind,
					key: name,
					factory: nameKeyedFactory(kind, name, value),
					contributedBy: m.name,
				});
			}
		}
	}
	return { entries, containers };
}

/**
 * Flatten a raw Module manifest into a NormalisedModule for fast lookup
 * by subsequent checks. Collects:
 * - `requires` / `optional` key arrays
 * - `providesKeys` from `Object.keys(module.provides ?? {})`
 * - `contributesEntries` / `overridesEntries` as flat ContributionEntry[],
 *   and `containers`, each kind's container as read
 * - `lifecycleKeys` from `Object.keys(module.lifecycle ?? {})`
 *
 * @internal
 */
function normaliseModule(m: Module): NormalisedModule {
	const requires = (m.requires ?? []) as readonly ComponentKey[];
	const optional = (m.optional ?? []) as readonly ComponentKey[];
	const providesKeys = Object.keys(m.provides ?? {}) as ComponentKey[];
	// Read once: the closure check refuses and describes what was read here.
	const authoritativeDeclared: unknown = m.authoritative;
	const authoritativeKeys: readonly ComponentKey[] = Array.isArray(authoritativeDeclared)
		? [...(authoritativeDeclared as readonly ComponentKey[])]
		: [];

	const contributes = normaliseChannel(m, "contributes", m.contributes);
	const overrides = normaliseChannel(m, "overrides", m.overrides);

	const lifecycleKeys = Object.keys(m.lifecycle ?? {}) as ComponentKey[];

	return {
		name: m.name,
		requires,
		optional,
		providesKeys,
		authoritativeDeclared,
		authoritativeKeys,
		contributesEntries: contributes.entries,
		overridesEntries: overrides.entries,
		containers: [...contributes.containers, ...overrides.containers],
		lifecycleKeys,
	};
}

// ---------------------------------------------------------------------------
// Built-in contribution kinds — auto-wired by core; no collector required
// ---------------------------------------------------------------------------

/**
 * Core's contribution kinds, each with the container it takes: a record for
 * a name-keyed kind, a list for a list-shaped one — the shapes of the
 * collectors `createApp` seeds.
 * @internal Exported for its test.
 */
export const BUILTIN_CONTRIBUTION_KINDS: ReadonlyMap<string, "record" | "list"> = new Map([
	["grants", "record"],
	["federations", "record"],
	["federationRedirectPolicies", "record"],
	["tokenExchangeValidators", "record"],
	["mfaFactors", "record"],
	["sessionRequirements", "record"],
	["auditHooks", "list"],
	["routes", "list"],
	["grantPolicyHooks", "list"],
	["grantMiddleware", "list"],
	["tokenBindingMechanisms", "list"],
	["discoveryMetadata", "list"],
	["rateLimitBudgets", "record"],
	["federationTypes", "record"],
	["admissionActions", "record"],
	["sessionCloseNotifiers", "record"],
]);

// ---------------------------------------------------------------------------
// Before step 1 — every entry is a manifest
// ---------------------------------------------------------------------------

/**
 * A `modules` entry that is a function is a module factory listed without
 * being called (`someModule` for `someModule(options)`).
 * `Module` requires only `name`, which a function has, so the compiler
 * accepts it, and every later check would read it as a manifest that
 * declares nothing: boot would succeed with the module's grants, routes and
 * refusals silently absent. Refused first, before any check reads a field of
 * it. Factories take different arguments, so the message does not guess them.
 * @internal
 */
function checkModuleEntriesAreManifests(modules: readonly Module[]): void {
	modules.forEach((entry, index) => {
		if (typeof entry !== "function") return;
		const name = (entry as { name?: unknown }).name;
		const label = typeof name === "string" && name !== "" ? name : "<anonymous>";
		throw new BootError({
			message:
				`module entry "${label}" is a function — call it with its arguments and list ` +
				`the module it returns (modules[${index}]).`,
			reason: "module-factory-not-called",
			stage: "validateManifests",
			details: { reason: "module-factory-not-called", index, name: label },
		});
	});
}

// ---------------------------------------------------------------------------
// Step 1 — Module identity uniqueness
// ---------------------------------------------------------------------------

/**
 * Step 1: Two manifests with the same `name` throw `duplicate-module-name`.
 * @internal
 */
function checkUniqueModuleNames(modules: readonly Module[]): void {
	const seen = new Map<string, string>();
	for (const m of modules) {
		const prev = seen.get(m.name);
		if (prev !== undefined) {
			throw new BootError({
				message: `Duplicate module name "${m.name}" — two modules share the same identity.`,
				reason: "duplicate-module-name",
				stage: "validateManifests",
				details: {
					reason: "duplicate-module-name",
					name: m.name,
					modules: [prev, m.name],
				},
			});
		}
		seen.set(m.name, m.name);
	}
}

// ---------------------------------------------------------------------------
// Step 2 — Provides closure check (no duplicate providers)
// ---------------------------------------------------------------------------

/**
 * Step 2: Two modules providing the same ComponentKey throw `duplicate-provides`.
 * @internal
 */
function checkProvidesClosure(modules: readonly NormalisedModule[]): void {
	const providers = new Map<ComponentKey, string>();
	for (const m of modules) {
		for (const key of m.providesKeys) {
			const prev = providers.get(key);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate provides key "${key}" — modules "${prev}" and "${m.name}" both provide it.`,
					reason: "duplicate-provides",
					stage: "validateManifests",
					details: {
						reason: "duplicate-provides",
						componentKey: key,
						modules: [prev, m.name],
					},
				});
			}
			providers.set(key, m.name);
		}
	}
}

// ---------------------------------------------------------------------------
// Authoritative keys — a module's settings slots have one source
// ---------------------------------------------------------------------------

/**
 * `authoritative` names keys of the module's own `provides`, as a list: a key
 * it does not provide — named as written, or described when it is not a
 * string — or a value that is not a list, described in `declared`, refuses
 * boot (`authoritative-without-provides`), as a lifecycle for an unprovided
 * key does. Reads what normalisation read, once.
 * @internal
 */
function checkAuthoritativeClosure(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		if (m.authoritativeDeclared === undefined) continue;
		if (!Array.isArray(m.authoritativeDeclared)) {
			const declared = describeValue(m.authoritativeDeclared);
			throw new BootError({
				message: `Module "${m.name}" declares authoritative as ${declared}, not a list of the keys it provides.`,
				reason: "authoritative-without-provides",
				stage: "validateManifests",
				details: { reason: "authoritative-without-provides", module: m.name, declared },
			});
		}
		for (const key of m.authoritativeKeys as readonly unknown[]) {
			if (typeof key === "string" && (m.providesKeys as readonly string[]).includes(key)) continue;
			const componentKey = typeof key === "string" ? key : describeValue(key);
			const named = typeof key === "string" ? JSON.stringify(key) : componentKey;
			throw new BootError({
				message: `Module "${m.name}" names ${named} authoritative but does not provide it: only a key of the module's own provides can be.`,
				reason: "authoritative-without-provides",
				stage: "validateManifests",
				details: { reason: "authoritative-without-provides", module: m.name, componentKey },
			});
		}
	}
}

/**
 * The name of the reserved bootstrap input (`ReservedBootstrapInputs`): boot
 * takes it out of `bootstrapComponents` and reads it itself, so no component
 * is named so — none is provided, required, read optionally or overridden
 * under it (`reserved-component-key`).
 */
const RESERVED_BOOTSTRAP_INPUT = "configDefaults";

/**
 * A host map carrying `__proto__` as its own key (a computed key, or parsed
 * from JSON) refuses boot (`reserved-component-key`): set on the component
 * map it would replace the prototype rather than name a component, so every
 * key of its value would read as a component no provider ran for, unseen by
 * the checks that read the map's own keys. So does an `overrideComponents`
 * entry named after the reserved bootstrap input, which names no component.
 * Runs before any row reads a component from the host maps (the pre-config
 * rows and the parse read only `config`).
 * @internal
 */
function checkReservedHostKeys(
	bootstrap: BootstrapMap,
	override: Partial<ComponentMap> | undefined,
): void {
	const maps = [
		["bootstrapComponents", bootstrap],
		["overrideComponents", override],
	] as const;
	for (const [source, map] of maps) {
		if (map === undefined || !Object.hasOwn(map, "__proto__")) continue;
		throw new BootError({
			message:
				`${source} carries "__proto__" as a key of its own: it names no component — set on the ` +
				"component map it would replace the map's prototype, and every key of its value would " +
				"read as a component no module provided. Remove the entry.",
			reason: "reserved-component-key",
			stage: "validateManifests",
			details: { reason: "reserved-component-key", componentKey: "__proto__", source },
		});
	}
	if (override !== undefined && Object.hasOwn(override, RESERVED_BOOTSTRAP_INPUT)) {
		throw new BootError({
			message: `overrideComponents carries "${RESERVED_BOOTSTRAP_INPUT}", which names no component: it is the configuration's defaults, which boot reads from bootstrapComponents itself. Hand it there, or remove the entry.`,
			reason: "reserved-component-key",
			stage: "validateManifests",
			details: {
				reason: "reserved-component-key",
				componentKey: RESERVED_BOOTSTRAP_INPUT,
				source: "overrideComponents",
			},
		});
	}
}

/**
 * An `overrideComponents` entry for a key a loaded module provides as
 * authoritative refuses boot (`authoritative-component-overridden`): the
 * module derives it from its own section and its own code reads that
 * section, so a second source would split what its readers see from what the
 * module does. A key no loaded module names authoritative may be overridden,
 * and so may this one when its module is not loaded.
 * @internal
 */
function checkAuthoritativeOverrides(
	modules: readonly NormalisedModule[],
	override: Partial<ComponentMap> | undefined,
): void {
	const overrideKeys = new Set<string>(Object.keys(override ?? {}));
	for (const m of modules) {
		for (const key of m.authoritativeKeys) {
			if (!overrideKeys.has(key)) continue;
			throw new BootError({
				message:
					`overrideComponents contains "${key}", which module "${m.name}" provides as authoritative: ` +
					"the module derives it from its own section and its own code reads that section, so a " +
					"second source would split what its readers see from what the module does. Change the " +
					`module's configuration instead, or leave the module out and fill "${key}" yourself.`,
				reason: "authoritative-component-overridden",
				stage: "validateManifests",
				details: {
					reason: "authoritative-component-overridden",
					module: m.name,
					componentKey: key,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 3 — Bootstrap closure, substitution-channel disjointness, and
//          synthetic-key constraint.
// ---------------------------------------------------------------------------

/**
 * What a `synthetic-key-collision` message adds for `key`: for a key boot
 * fills from the configuration (`deploymentMode`, `tokenBindingSettings`,
 * `federationSettings`, `outboundPolicy`), where to state its value instead.
 */
const SYNTHETIC_KEY_REMEDIES: ReadonlyMap<string, string> = new Map([
	[
		"deploymentMode",
		" Set core.deployment.mode in the configuration instead: boot fills deploymentMode from it.",
	],
	[
		"tokenBindingSettings",
		" Set core.tokenBinding in the configuration instead: boot fills tokenBindingSettings from it.",
	],
	[
		"federationSettings",
		" Set core.federations in the configuration instead: boot fills federationSettings from it.",
	],
	[
		"outboundPolicy",
		" Set core.outbound in the configuration instead: boot fills outboundPolicy from it.",
	],
]);
const syntheticKeyRemedy = (key: string): string => SYNTHETIC_KEY_REMEDIES.get(key) ?? "";

/**
 * Step 3: Check bootstrap/overrideComponents/synthetic-key constraints.
 * @internal
 */
function checkBootstrapAndSyntheticDisjointness(
	modules: readonly NormalisedModule[],
	bootstrap: BootstrapMap,
	override: Partial<ComponentMap> | undefined,
): void {
	const bootstrapKeys = new Set<string>(Object.keys(bootstrap));
	const overrideKeys = new Set<string>(Object.keys(override ?? {}));

	// 3a: synthetic keys must not appear in any module's provides
	for (const m of modules) {
		for (const key of m.providesKeys) {
			if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" attempts to provide synthetic key "${key}", which is reserved for the boot planner.${syntheticKeyRemedy(key)}`,
					reason: "synthetic-key-collision",
					stage: "validateManifests",
					details: {
						reason: "synthetic-key-collision",
						componentKey: key,
						source: "module-provides",
						module: m.name,
					},
				});
			}
		}
	}

	// 3b: synthetic keys must not appear in bootstrapComponents
	for (const key of bootstrapKeys) {
		if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
			throw new BootError({
				message: `bootstrapComponents contains synthetic key "${key}", which is reserved for the boot planner.${syntheticKeyRemedy(key)}`,
				reason: "synthetic-key-collision",
				stage: "validateManifests",
				details: {
					reason: "synthetic-key-collision",
					componentKey: key as ComponentKey,
					source: "bootstrapComponents",
				},
			});
		}
	}

	// 3c: synthetic keys must not appear in overrideComponents
	for (const key of overrideKeys) {
		if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
			throw new BootError({
				message: `overrideComponents contains synthetic key "${key}", which is reserved for the boot planner.${syntheticKeyRemedy(key)}`,
				reason: "synthetic-key-collision",
				stage: "validateManifests",
				details: {
					reason: "synthetic-key-collision",
					componentKey: key as ComponentKey,
					source: "overrideComponents",
				},
			});
		}
	}

	// 3d: a module's provides[K] for a key also in bootstrapComponents
	//     throws bootstrap-component-collision (source: "module-provides")
	for (const m of modules) {
		for (const key of m.providesKeys) {
			if (bootstrapKeys.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" provides "${key}" which is already present in bootstrapComponents.`,
					reason: "bootstrap-component-collision",
					stage: "validateManifests",
					details: {
						reason: "bootstrap-component-collision",
						componentKey: key,
						source: "module-provides",
						module: m.name,
					},
				});
			}
		}
	}

	// 3e: overrideComponents[K] whose K is also in bootstrapComponents
	//     throws bootstrap-component-collision (source: "overrideComponents")
	for (const key of overrideKeys) {
		if (bootstrapKeys.has(key)) {
			throw new BootError({
				message: `overrideComponents contains "${key}" which is already present in bootstrapComponents. These channels are mutually exclusive.`,
				reason: "bootstrap-component-collision",
				stage: "validateManifests",
				details: {
					reason: "bootstrap-component-collision",
					componentKey: key as ComponentKey,
					source: "overrideComponents",
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 4 — Requires/optional closure check + path-construction algorithm
// ---------------------------------------------------------------------------

/**
 * Build the diagnostic `path` chain from the entry-point module (`rootModule`)
 * down to the failing module `F` along the requires→provides chain.
 * @internal
 */
function buildMissingRequiredPath(
	failingModule: NormalisedModule,
	missingKey: ComponentKey,
	modules: readonly NormalisedModule[],
	providerIndex: ReadonlyMap<ComponentKey, NormalisedModule>,
): {
	rootModule: string;
	path: readonly {
		readonly module: string;
		readonly requires: ComponentKey;
		readonly satisfiedBy?: string;
	}[];
} {
	// Build index-by-name for tie-breaking (earliest input-array position)
	const indexByName = new Map<string, number>();
	for (let i = 0; i < modules.length; i++) {
		indexByName.set(modules[i].name, i);
	}

	// Backward walk: from F, step to the earliest-declared module that
	// requires a key the current one provides (ties by smallest name), until
	// there is none or it was visited. Each step records the lexicographically
	// smallest such key; reversing the links gives the forward chain
	// rootModule → … → F with every `requires` already chosen, so no second
	// forward walk can dead-end short of F.
	const backwardChain: NormalisedModule[] = [failingModule];
	const linkKeys: ComponentKey[] = []; // linkKeys[i] = key of backwardChain[i+1].requires whose provider is backwardChain[i]
	const visited = new Set<string>();
	let current = failingModule;
	visited.add(current.name);

	while (true) {
		// Find all modules that require some key that current provides
		let bestRequirer: NormalisedModule | undefined;
		let bestIndex = Number.MAX_SAFE_INTEGER;

		for (const m of modules) {
			if (visited.has(m.name)) continue;
			// Does m require a key that current provides?
			let viaKeyForM: ComponentKey | undefined;
			for (const reqKey of m.requires) {
				const provider = providerIndex.get(reqKey);
				if (provider?.name === current.name) {
					if (viaKeyForM === undefined || reqKey < viaKeyForM) {
						viaKeyForM = reqKey;
					}
				}
			}
			if (viaKeyForM === undefined) continue;
			const idx = indexByName.get(m.name) ?? Number.MAX_SAFE_INTEGER;
			if (
				idx < bestIndex ||
				(idx === bestIndex && bestRequirer !== undefined && m.name < bestRequirer.name)
			) {
				bestIndex = idx;
				bestRequirer = m;
			}
		}

		if (bestRequirer === undefined) {
			// current is the root
			break;
		}

		// Re-derive the lex-smallest viaKey for the chosen bestRequirer (cheap;
		// avoids carrying it through the bestRequirer-selection dance).
		let viaKey: ComponentKey | undefined;
		for (const reqKey of bestRequirer.requires) {
			const provider = providerIndex.get(reqKey);
			if (provider?.name === current.name) {
				if (viaKey === undefined || reqKey < viaKey) {
					viaKey = reqKey;
				}
			}
		}

		visited.add(bestRequirer.name);
		backwardChain.push(bestRequirer);
		// biome-ignore lint/style/noNonNullAssertion: bestRequirer-selection guarantees viaKey is defined
		linkKeys.push(viaKey!);
		current = bestRequirer;
	}

	const rootModule = current;

	// Forward path: reverse backwardChain to get [rootModule, ..., failingModule],
	// reverse linkKeys correspondingly. Each link i in the forward chain becomes
	// `{ module: forwardChain[i].name, requires: forwardLinkKeys[i], satisfiedBy: forwardChain[i + 1].name }`.
	const forwardChain = [...backwardChain].reverse();
	const forwardLinkKeys = [...linkKeys].reverse();

	const path: { module: string; requires: ComponentKey; satisfiedBy?: string }[] = [];
	for (let i = 0; i < forwardChain.length - 1; i++) {
		path.push({
			module: forwardChain[i].name,
			// biome-ignore lint/style/noNonNullAssertion: forwardLinkKeys.length === forwardChain.length - 1
			requires: forwardLinkKeys[i]!,
			satisfiedBy: forwardChain[i + 1].name,
		});
	}

	// Terminal link: the failing module with the missing key (no satisfiedBy)
	path.push({ module: failingModule.name, requires: missingKey });

	return { rootModule: rootModule.name, path };
}

// ---------------------------------------------------------------------------
// After step 3 — The session-requirement kind guard
// See ADR 2026-09-28-session-admission.
// ---------------------------------------------------------------------------

/** The two kinds no composition may replace the collector of, or override an entry of. */
const GUARDED_KINDS = ["sessionRequirements", "mfaFactors"] as const;

/**
 * The kinds a federation's provider and redirect policy register under. Core
 * registers them, from each enabled `core.federations` entry, with the
 * factories of the type the entry names: no module contributes or overrides
 * an entry of either (`checkFederationKindGuard`), and no host supplies their
 * collector (`refuseGuardedHostKinds`).
 */
const FEDERATION_KINDS = ["federations", "federationRedirectPolicies"] as const;

/** How the entries of the federation kinds register, as a refusal says it. */
const FEDERATION_KINDS_REGISTERED =
	"boot registers a federation's provider and redirect policy from its core.federations entry, " +
	"with the factories of the type the entry names under federationTypes";

/**
 * The kinds whose collector is the planner's alone: a host collector
 * for `rateLimitBudgets` could answer a looser budget than the owning module
 * contributed — on RFC 8628 §5.1's device-verification prefix, say —
 * `federationTypes` is what the dispatch of configured federations reads,
 * `admissionActions` is where admission reads the grade it hands the
 * requirements, and `auditHooks` is what the audit fan-out in the `auditSink`
 * slot reads at each event, the slot stage 1 counts as filled once a hook is
 * contributed; `federations` and `federationRedirectPolicies` are filled by
 * boot alone, from the dispatched entries (`FEDERATION_KINDS`). Unlike
 * `GUARDED_KINDS`, a module may override a `federationTypes` entry; no module
 * overrides a `rateLimitBudgets` prefix or an admission action
 * (`checkContributionShapes`), and `auditHooks` is list-shaped, and a list
 * kind has no override.
 */
const PLANNER_OWNED_KINDS = [
	"rateLimitBudgets",
	"sessionCloseNotifiers",
	"federationTypes",
	"admissionActions",
	"auditHooks",
	...FEDERATION_KINDS,
] as const;

/** What a refusal of a host collector for a planner-owned `kind` says of its entries. */
const plannerOwnedEntries = (kind: (typeof PLANNER_OWNED_KINDS)[number]): string => {
	switch (kind) {
		case "federations":
		case "federationRedirectPolicies":
			return FEDERATION_KINDS_REGISTERED;
		case "auditHooks":
			return "the modules that own its entries contribute them, and the audit fan-out in the auditSink slot reads them";
		case "admissionActions":
		case "rateLimitBudgets":
			return "the modules that own its entries contribute them, and no module overrides one";
		case "sessionCloseNotifiers":
			return "the module that tells relying parties contributes its notifier, which the session lifecycle reads, and no module overrides one";
		default:
			return "the modules that own its entries contribute them, and a module may override one";
	}
};

/**
 * A requirement is switched off by not installing it, never removed from
 * behind its consumers: a module's `overrides.sessionRequirements` is refused
 * here (`session-requirement-kind-guarded`). A host collector for
 * `sessionRequirements`, or for `mfaFactors` (the second-factor authority's
 * reach is recomputed from its projection), is refused for the same reason by
 * `refuseGuardedHostKinds`, in `createApp` before the kinds are merged.
 * @internal
 */
function checkSessionRequirementKindGuard(modules: readonly NormalisedModule[]): void {
	// Read off the normalised entries — what the pass applies — not the raw
	// manifest, whose `overrides` a getter could answer differently twice.
	for (const m of modules) {
		if (m.overridesEntries.some((entry) => entry.kind === "sessionRequirements")) {
			throw new BootError({
				message:
					`Module "${m.name}" overrides a sessionRequirements entry, which nothing may: a session ` +
					"requirement is switched off by not installing it, never replaced from behind the consumers.",
				reason: "session-requirement-kind-guarded",
				stage: "validateManifests",
				details: {
					reason: "session-requirement-kind-guarded",
					kind: "sessionRequirements",
					channel: "overrides",
					module: m.name,
				},
			});
		}
	}
}

/**
 * A module contributes or overrides neither `federations` nor
 * `federationRedirectPolicies`: an entry of either would serve no
 * federation, since only the module registering an enabled entry's type
 * handles it. A pre-config row, over every module — switched on or not —
 * before any factory runs: the kind as an own key of the manifest's
 * `contributes` or `overrides` is refused whatever it holds (a record, a
 * list, an empty one, `null`, a scalar, a function), and so is an entry of
 * it in the normalised manifest, which a getter answering differently
 * twice could hold without the key on this read. Refused as the kind
 * guarded (`contribution-kind-guarded`), naming the module and the channel,
 * and `name` — the first entry of the container — only when the container is
 * a record with an entry; the message points the author at
 * `federationTypes`.
 * @internal
 */
function checkFederationKindGuard(
	rawModules: readonly Module[],
	modules: readonly NormalisedModule[],
): void {
	const refuse = (
		module: string,
		channel: "contributes" | "overrides",
		kind: (typeof FEDERATION_KINDS)[number],
		name: string | undefined,
	): never => {
		throw new BootError({
			message:
				`Module "${module}" ${channel} ${kind}${name === undefined ? "" : ` ${JSON.stringify(name)}`}, ` +
				`which no module may: ${FEDERATION_KINDS_REGISTERED}. To handle a federation, register a type under federationTypes instead.`,
			reason: "contribution-kind-guarded",
			stage: "validateManifests",
			details: {
				reason: "contribution-kind-guarded",
				kind,
				channel,
				module,
				...(name === undefined ? {} : { name }),
			},
		});
	};
	rawModules.forEach((m, index) => {
		for (const channel of ["contributes", "overrides"] as const) {
			const map: unknown = m[channel];
			if ((typeof map === "object" || typeof map === "function") && map !== null) {
				for (const kind of FEDERATION_KINDS) {
					if (!Object.hasOwn(map, kind)) continue;
					const container: unknown = (map as Record<string, unknown>)[kind];
					const isRecord =
						typeof container === "object" && container !== null && !Array.isArray(container);
					refuse(m.name, channel, kind, isRecord ? Object.keys(container)[0] : undefined);
				}
			}
			const normalised = modules[index];
			const entries =
				channel === "contributes" ? normalised?.contributesEntries : normalised?.overridesEntries;
			const entry = entries?.find(({ kind }) =>
				(FEDERATION_KINDS as readonly string[]).includes(kind),
			);
			if (entry !== undefined) {
				refuse(
					m.name,
					channel,
					entry.kind as (typeof FEDERATION_KINDS)[number],
					typeof entry.key === "string" ? entry.key : undefined,
				);
			}
		}
	});
}

/**
 * The host's `contributionKinds` held to the same rule, in `createApp`
 * before the kinds are merged and before stage 1: a collector for
 * `sessionRequirements` or `mfaFactors` the host
 * supplies would sit behind the `sessionRequirementResolver` projection and
 * the `session_requirements_registered` boot line, which read the planner's.
 */
export function refuseGuardedHostKinds(host: ContributionKindMap | undefined): void {
	if (host === undefined) return;
	for (const kind of GUARDED_KINDS) {
		if (Object.hasOwn(host, kind)) {
			throw new BootError({
				message:
					`contributionKinds replaces the collector for "${kind}", which nothing may: the ` +
					"sessionRequirementResolver projection and the session_requirements_registered boot line read the planner's.",
				reason: "session-requirement-kind-guarded",
				stage: "validateManifests",
				details: { reason: "session-requirement-kind-guarded", kind, channel: "contributionKinds" },
			});
		}
	}
	for (const kind of PLANNER_OWNED_KINDS) {
		if (Object.hasOwn(host, kind)) {
			throw new BootError({
				message: `contributionKinds replaces the collector for "${kind}", which is the planner's: ${plannerOwnedEntries(kind)}.`,
				reason: "contribution-kind-guarded",
				stage: "validateManifests",
				details: { reason: "contribution-kind-guarded", kind },
			});
		}
	}
}

/**
 * What a `rateLimitBudgets`, `federationTypes`, `admissionActions` or
 * `sessionCloseNotifiers` contribution or override holds, read off the
 * entries normalisation captured, which stage 4 applies, before any factory
 * runs; each container is already its kind's shape
 * (`checkContributionContainers`):
 *
 * - a prefix is not empty and holds no `:`, since a limiter key carries it
 *   before its first `:`, whatever the budget's factory answers;
 * - a prefix names no `Object.prototype` member (`constructor`, `__proto__`),
 *   which a limiter looking budgets up on a plain object finds in its place;
 * - a prefix is claimed by the module whose routes key it, so an override of
 *   one is refused as the kind guarded (`contribution-kind-guarded`), naming
 *   the setting a verifier's prefix is limited at;
 * - a declaration, as normalisation read it (`federationTypeSnapshot`), is
 *   an object with a Zod `entrySchema` and `factory` and `redirectPolicy`
 *   functions, so one written in JavaScript is refused as itself, not as a
 *   `TypeError` at registration;
 * - an action's name and declaration, as normalisation read it
 *   (`admissionActionSnapshots`), are what registration admits
 *   (`admissionActionProblem`); an action is registered by the module that
 *   admits it, so an override of one is refused as the kind guarded
 *   (`contribution-kind-guarded`);
 * - no module overrides `sessionCloseNotifiers` (`contribution-kind-guarded`):
 *   the notifier is its contributor's, switched off only by not installing
 *   it.
 *
 * Throws `contribution-malformed`, naming the entry.
 * @internal
 */
function checkContributionShapes(modules: readonly NormalisedModule[]): void {
	const refuse = (
		m: NormalisedModule,
		kind: "rateLimitBudgets" | "federationTypes" | "admissionActions",
		name: string,
		channel: "contributes" | "overrides",
		problem: string,
	): never => {
		throw new BootError({
			message: `Module "${m.name}" ${channel} ${kind} "${name}": ${problem}.`,
			reason: "contribution-malformed",
			stage: "validateManifests",
			details: { reason: "contribution-malformed", module: m.name, kind, name, channel, problem },
		});
	};
	const declaredVerifiers = declaredVerifierLimits(modules);
	for (const m of modules) {
		for (const channel of ["contributes", "overrides"] as const) {
			const entries = channel === "contributes" ? m.contributesEntries : m.overridesEntries;
			for (const entry of entries) {
				if (entry.kind !== "rateLimitBudgets" || typeof entry.key !== "string") continue;
				const prefix = entry.key;
				if (prefix.length === 0 || prefix.includes(":")) {
					refuse(
						m,
						"rateLimitBudgets",
						prefix,
						channel,
						`a prefix is what a limiter key carries before its first ":", so it is not empty and holds no ":"`,
					);
				}
				if (Object.hasOwn(Object.prototype, prefix)) {
					refuse(
						m,
						"rateLimitBudgets",
						prefix,
						channel,
						"a prefix does not name an Object.prototype member, which a limiter looking budgets up on a plain object would find in its place",
					);
				}
			}
			for (const entry of entries) {
				if (entry.kind !== "sessionCloseNotifiers") continue;
				if (channel === "overrides") {
					throw new BootError({
						message: `Module "${m.name}" overrides sessionCloseNotifiers, which no module may: the notifier is its contributor's, switched off only by not installing it.`,
						reason: "contribution-kind-guarded",
						stage: "validateManifests",
						details: {
							reason: "contribution-kind-guarded",
							kind: "sessionCloseNotifiers",
							channel: "overrides",
							module: m.name,
						},
					});
				}
			}
			for (const entry of entries) {
				if (
					channel !== "overrides" ||
					entry.kind !== "rateLimitBudgets" ||
					typeof entry.key !== "string"
				) {
					continue;
				}
				const setting = verifierLimitSetting(entry.key, declaredVerifiers);
				throw new BootError({
					message:
						`Module "${m.name}" overrides rateLimitBudgets "${entry.key}", which no module may: a prefix is claimed by the module whose routes key it` +
						(setting === undefined
							? ", and a limiter's own limits decide what applies under it."
							: `, and "${entry.key}" is a verifier's own limit, set at ${setting}.`),
					reason: "contribution-kind-guarded",
					stage: "validateManifests",
					details: {
						reason: "contribution-kind-guarded",
						kind: "rateLimitBudgets",
						channel: "overrides",
						module: m.name,
						name: entry.key,
					},
				});
			}
			for (const entry of entries) {
				if (entry.kind !== "rateLimitBudgets" || typeof entry.key !== "string") continue;
				const snapshot = verifierClaimSnapshots.get(entry.factory as object);
				const problem = snapshot === undefined ? undefined : verifierClaimProblem(snapshot);
				if (problem !== undefined) refuse(m, "rateLimitBudgets", entry.key, channel, problem);
			}
			for (const entry of entries) {
				if (entry.kind !== "admissionActions" || typeof entry.key !== "string") continue;
				if (channel === "overrides") {
					throw new BootError({
						message: `Module "${m.name}" overrides admissionActions "${entry.key}", which no module may: an action is registered by the module that admits it, and its grade is that module's.`,
						reason: "contribution-kind-guarded",
						stage: "validateManifests",
						details: {
							reason: "contribution-kind-guarded",
							kind: "admissionActions",
							channel: "overrides",
							module: m.name,
							name: entry.key,
						},
					});
				}
				const snapshot = admissionActionSnapshots.get(entry.factory as object);
				const problem = admissionActionProblem(entry.key, snapshot ?? entry.factory);
				if (problem !== undefined) refuse(m, "admissionActions", entry.key, channel, problem);
			}
			for (const entry of entries) {
				if (entry.kind !== "federationTypes" || typeof entry.key !== "string") continue;
				const snapshot = federationTypeSnapshot(entry.factory);
				if (snapshot === undefined) {
					refuse(
						m,
						"federationTypes",
						entry.key,
						channel,
						"a declaration is an object with an entrySchema, a factory and a redirectPolicy",
					);
				}
				const { entrySchema, factory, redirectPolicy } = snapshot as FederationTypeSnapshot;
				if (typeof (entrySchema as { safeParse?: unknown } | null)?.safeParse !== "function") {
					refuse(m, "federationTypes", entry.key, channel, "its entrySchema is not a Zod schema");
				}
				if (typeof factory !== "function") {
					refuse(m, "federationTypes", entry.key, channel, "its factory is not a function");
				}
				if (typeof redirectPolicy !== "function") {
					refuse(m, "federationTypes", entry.key, channel, "its redirectPolicy is not a function");
				}
			}
		}
	}
}

/**
 * Step 4: Requires/optional closure check.
 * For each module, every key in `requires` must be planned (`plannedKeys`:
 * `bootstrapComponents`, the union of all modules' `provides`,
 * `overrideComponents`, and `auditSink` when `auditHooks` are contributed),
 * or be in the synthetic-key set (auto-satisfied).
 * @internal
 */
function checkRequiresClosure(
	modules: readonly NormalisedModule[],
	plannedKeys: ReadonlySet<string>,
): void {
	// Build a map: ComponentKey → providing NormalisedModule
	const providerIndex = new Map<ComponentKey, NormalisedModule>();
	for (const m of modules) {
		for (const key of m.providesKeys) {
			providerIndex.set(key, m);
		}
	}

	const isSatisfied = (key: ComponentKey): boolean =>
		plannedKeys.has(key) || SYNTHETIC_COMPONENT_KEYS.has(key);

	// Find the first module in input order whose requires contains an unsatisfied key
	for (const m of modules) {
		for (const key of m.requires) {
			if (!isSatisfied(key)) {
				const { rootModule, path } = buildMissingRequiredPath(m, key, modules, providerIndex);
				throw new BootError({
					message: `Missing required component "${key}" — module "${m.name}" requires it but no provider was found.`,
					reason: "missing-required-component",
					stage: "validateManifests",
					details: {
						reason: "missing-required-component",
						missingKey: key,
						rootModule,
						path,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 5 — Contribution kind / collector closure
// ---------------------------------------------------------------------------

/**
 * Step 5: Every contribution kind referenced by a module must have a
 * collector (built-in kinds are auto-wired; custom kinds need a
 * `contributionKinds` entry).
 * @internal
 */
function checkContributionKindCoverage(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap | undefined,
): void {
	const customKinds = new Set<string>(Object.keys(contributionKinds ?? {}));

	// Collect all kinds used across modules
	const kindToModules = new Map<string, string[]>();
	for (const m of modules) {
		const allEntries = [...m.contributesEntries, ...m.overridesEntries];
		for (const entry of allEntries) {
			const kind = entry.kind;
			let kindModules = kindToModules.get(kind);
			if (kindModules === undefined) {
				kindModules = [];
				kindToModules.set(kind, kindModules);
			}
			kindModules.push(m.name);
		}
	}

	for (const [kind, contributedBy] of kindToModules) {
		if (!BUILTIN_CONTRIBUTION_KINDS.has(kind) && !customKinds.has(kind)) {
			// Deduplicate module names
			const unique = [...new Set(contributedBy)];
			throw new BootError({
				message: `Unknown contribution kind "${kind}" — modules [${unique.join(", ")}] contribute it but no collector was provided.`,
				reason: "unknown-contribution-kind",
				stage: "validateManifests",
				details: {
					reason: "unknown-contribution-kind",
					kind,
					contributedBy: unique,
				},
			});
		}
	}
}

/**
 * The container `kind` takes: a record when its collector is name-keyed, a
 * list when it is list-shaped — the collector's own `kind`, as stage 4
 * dispatches on it, so a consumer's kinds are held to the same rule — or, for
 * one of core's kinds with no collector in `contributionKinds`, its built-in
 * shape. `undefined` for a kind nothing names a shape for.
 */
function containerTaken(
	kind: string,
	contributionKinds: ContributionKindMap | undefined,
): "record" | "list" | undefined {
	const collector =
		contributionKinds !== undefined && Object.hasOwn(contributionKinds, kind)
			? ((contributionKinds as Record<string, unknown>)[kind] as { kind?: unknown } | undefined)
			: undefined;
	switch (collector?.kind) {
		case "name-keyed":
			return "record";
		case "list":
		case "list-routes":
			return "list";
		default:
			return BUILTIN_CONTRIBUTION_KINDS.get(kind);
	}
}

/**
 * Every kind's container, in `contributes` and in `overrides`, is the shape
 * its kind takes (`containerTaken`): a record — a plain object — for a
 * name-keyed kind, an array for a list-shaped one. Anything else is
 * `contribution-malformed`, naming the module, the kind, the channel and
 * what it was given: an array under a name-keyed kind would file its entries
 * under Symbol keys no name-keyed check reads and no reader reaches, and a
 * record under a list-shaped kind holds no list to append. Read off the
 * containers normalisation read, once — the ones its entries came from. A
 * kind no shape is known for has no container rule: the coverage check
 * refuses its entries, if it has any.
 * @internal
 */
function checkContributionContainers(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap | undefined,
): void {
	for (const m of modules) {
		for (const { kind, channel, shape, given } of m.containers) {
			const taken = containerTaken(kind, contributionKinds);
			if (taken === undefined || taken === shape) continue;
			const problem =
				taken === "record"
					? `the kind takes a record keyed by name, not ${given}`
					: `the kind takes a list, not ${given}`;
			throw new BootError({
				message: `Module "${m.name}" ${channel} ${kind}: ${problem}.`,
				reason: "contribution-malformed",
				stage: "validateManifests",
				details: { reason: "contribution-malformed", module: m.name, kind, channel, problem },
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 6 — Per-kind duplicate contributes check (name-keyed kinds)
// ---------------------------------------------------------------------------

/**
 * Step 6: for name-keyed kinds, a (kind, name) collision across modules
 * throws `duplicate-contribute`. List-shaped kinds are checked in step 7
 * (routes) or deduplicated (auditHooks, grantPolicyHooks). Dispatches on
 * `collector.kind === "name-keyed"`, not a built-in name set, so
 * consumer-defined name-keyed kinds are checked too, as in
 * `apply-contributions.mts`.
 * @internal
 */
function checkPerKindContributeDuplicates(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap,
): void {
	// Track (kind, name) → first contributing module
	const seen = new Map<string, string>(); // key: `${kind}:${name}`

	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			const kind = entry.kind;
			// Look up the collector for this kind; only name-keyed collectors
			// participate in the (kind, name) duplicate check.
			const collector = (contributionKinds as Record<string, unknown>)[kind] as
				| { kind?: string }
				| undefined;
			if (collector?.kind !== "name-keyed") continue;
			if (typeof entry.key !== "string") continue;

			const compoundKey = `${kind}:${entry.key}`;
			const prev = seen.get(compoundKey);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate contribution "${entry.key}" for kind "${kind}" — modules "${prev}" and "${m.name}" both contribute it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind,
						identity: entry.key as string,
						identityKind: "name",
						modules: [prev, m.name],
					},
				});
			}
			seen.set(compoundKey, m.name);
		}
	}
}

/**
 * At most one session-close notifier per composition, read off the
 * manifests: two contributions, under any names, refuse boot
 * (`duplicate-contribute`), since the session lifecycle tells relying parties
 * through one.
 * @internal
 */
function checkOneSessionCloseNotifier(modules: readonly NormalisedModule[]): void {
	const contributions = modules.flatMap((m) =>
		m.contributesEntries
			.filter((entry) => entry.kind === "sessionCloseNotifiers")
			.map((entry) => ({ module: m.name, name: String(entry.key) })),
	);
	const [first, second] = contributions;
	if (first === undefined || second === undefined) return;
	throw new BootError({
		message: `sessionCloseNotifiers is contributed more than once — "${first.name}" by module "${first.module}" and "${second.name}" by module "${second.module}"; a composition tells relying parties through one notifier.`,
		reason: "duplicate-contribute",
		stage: "validateManifests",
		details: {
			reason: "duplicate-contribute",
			kind: "sessionCloseNotifiers",
			identity: second.name,
			identityKind: "name",
			modules: [first.module, second.module],
		},
	});
}

// ---------------------------------------------------------------------------
// Step 7 — RouteContribution collision check
// ---------------------------------------------------------------------------

/**
 * Collect all RouteContribution objects from modules' contributes.routes
 * (static values only: factories are not invoked in this stage).
 * @internal
 */
function collectRouteContributions(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
): { route: RouteContribution; module: string }[] {
	const result: { route: RouteContribution; module: string }[] = [];
	for (const rawMod of rawModules) {
		const routeEntries = rawMod.contributes?.routes ?? [];
		for (const entry of routeEntries) {
			// At validate-manifests time, only static RouteContribution values can
			// be inspected. Factory entries (functions) are opaque until
			// materializeComponents runs deps. We only inspect static entries.
			if (typeof entry === "object" && entry !== null && !Array.isArray(entry)) {
				result.push({ route: entry as RouteContribution, module: rawMod.name });
			}
		}
	}
	void modules;
	return result;
}

/**
 * Step 7: RouteContribution collision check — id collision, mountPath
 * collision (no id), effective (method, mountPath+adv.path) collision, and
 * RouteAdvertisement.path leading-slash validation.
 * @internal
 */
function checkRouteCollisions(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
): void {
	// Collect all static route contributions
	const routes = collectRouteContributions(modules, rawModules);

	// 7a: Duplicate id check
	const seenIds = new Map<string, string>(); // id → module
	for (const { route, module } of routes) {
		if (route.id !== undefined) {
			const prev = seenIds.get(route.id);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate route id "${route.id}" — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: route.id,
						identityKind: "id",
						modules: [prev, module],
					},
				});
			}
			seenIds.set(route.id, module);
		}
	}

	// 7b: Duplicate mountPath (no id) check
	const seenMountPaths = new Map<string, string>(); // mountPath → module
	for (const { route, module } of routes) {
		if (route.id === undefined) {
			const prev = seenMountPaths.get(route.mountPath);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate mountPath "${route.mountPath}" (no id) — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: route.mountPath,
						identityKind: "mountPath",
						modules: [prev, module],
					},
				});
			}
			seenMountPaths.set(route.mountPath, module);
		}
	}

	// 7c + 7d: RouteAdvertisement checks
	// Check: advertisement.path must start with "/"
	// Check: effective (method, mountPath+adv.path) collision
	const seenEffective = new Map<string, { module: string; mountPath: string }>(); // identity → { module }

	for (const { route, module } of routes) {
		if (!route.routes) continue;
		for (const adv of route.routes) {
			// 7d: leading-slash check
			if (!adv.path.startsWith("/")) {
				throw new BootError({
					message: `RouteAdvertisement.path "${adv.path}" in module "${module}" (mountPath "${route.mountPath}") must start with "/".`,
					reason: "invalid-route-advertisement-path",
					stage: "validateManifests",
					details: {
						reason: "invalid-route-advertisement-path",
						module,
						mountPath: route.mountPath,
						path: adv.path,
						identityKind: "missing-leading-slash",
					},
				});
			}

			// 7c: effective method+path collision
			const effectiveIdentity = `${adv.method} ${route.mountPath}${adv.path}`;
			const prev = seenEffective.get(effectiveIdentity);
			if (prev !== undefined) {
				throw new BootError({
					message: `Effective route collision "${effectiveIdentity}" — modules "${prev.module}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: effectiveIdentity,
						identityKind: "effective-method-path",
						modules: [prev.module, module],
					},
				});
			}
			seenEffective.set(effectiveIdentity, { module, mountPath: route.mountPath });
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13.5 — grantPolicy / jwt.issuer consistency invariant
//
// When `grantPolicy` is wired through any of the three component sources
// (module `provides`, `bootstrapComponents`, `overrideComponents`), the
// configured issuer must be a canonical issuer (`checkCanonicalIssuer`): the
// policy hook signs decisions against it, and an empty value silently disables
// fail-closed enforcement at the JWT layer. Core's schema does not declare
// `oauth {}`, so the check holds the value to the rule itself: where the oauth
// module is loaded its section schema has refused a bad issuer already, and
// where it is not, nothing else has. Runs after step 13
// (validateAndComposeConfig) so the parsed config is available.
// ---------------------------------------------------------------------------

function checkGrantPolicyIssuerInvariant(
	modules: readonly NormalisedModule[],
	parsedConfig: unknown,
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
): void {
	// Resolve the wiring source in priority: module provides → override →
	// bootstrap. The detail's `providedBy` field reports the first source
	// found; step 2 (checkProvidesClosure) guarantees module-side uniqueness,
	// and the bootstrap/override sentinels are deliberately distinct strings
	// so downstream tooling can tell them apart.
	const moduleProvider = modules.find((m) =>
		(m.providesKeys as readonly string[]).includes("grantPolicy"),
	);
	const overrideHasGrantPolicy =
		overrideComponents !== undefined &&
		(overrideComponents as Record<string, unknown>).grantPolicy !== undefined;
	const bootstrapHasGrantPolicy =
		(bootstrapComponents as Record<string, unknown>).grantPolicy !== undefined;

	let providedBy: string | undefined;
	if (moduleProvider) providedBy = moduleProvider.name;
	else if (overrideHasGrantPolicy) providedBy = "<overrideComponents>";
	else if (bootstrapHasGrantPolicy) providedBy = "<bootstrapComponents>";

	if (providedBy === undefined) return;

	const issuer = (parsedConfig as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth
		?.jwt?.issuer;
	const rejection = checkCanonicalIssuer(issuer);
	if (rejection === null) return;

	throw new BootError({
		message: `CP-20 invariant: config.oauth.jwt.issuer must be a canonical issuer when grantPolicy is wired (provided by "${providedBy}"), and it ${describeIssuerRejection(rejection)}. Empty issuer turns CP-18 fail-closed enforcement into silent allow-all at the JWT layer.`,
		reason: "grant-policy-without-issuer",
		stage: "validateManifests",
		details: {
			reason: "grant-policy-without-issuer",
			providedBy,
		},
	});
}

// ---------------------------------------------------------------------------
// Step 13.7 — Federation stores wiring guard
// ---------------------------------------------------------------------------

const FEDERATION_REQUIRED_STORES = [
	"userSessionStore",
	"sessionLifecycle",
	"federationTokenStore",
	"refreshTokenFamilyRevocation",
] as const;

/**
 * The slots an enabled federation needs: all four when any
 * `core.federations` entry is enabled, else none.
 */
function federationStoreSlotsOf(config: AppConfig): readonly ComponentKey[] {
	return enabledFederationsOf(config).length > 0 ? FEDERATION_REQUIRED_STORES : [];
}

/**
 * If any `core.federations.<name>.enabled === true`, the user-session
 * store, the session lifecycle, the federation-token store and the
 * refresh-token-family revocation must be wired. A missing one makes
 * federation routes either fail at runtime with an opaque 503 (the session
 * and federation-token stores) or never mount, surfacing as
 * unexpected 404s (refreshTokenFamilyRevocation, per the `logoutSupported` /
 * `federationTokenSupported` gates in `packages/oauth/src/routes.mts`).
 * Refusing at boot makes both visible. Stage 1 counts a planned slot as
 * wired; stage 2 builds every provider of one (`federationStoreSlots`), read
 * or not; stage 3 refuses one that holds `undefined`.
 */
export function checkFederationStoresWiring(
	config: AppConfig,
	plannedKeys: ReadonlySet<string>,
): void {
	const refusal = federationStoresRefusal(
		config,
		(key) => plannedKeys.has(key),
		"validateManifests",
	);
	if (refusal !== undefined) throw refusal;
}

/**
 * The `federation-stores-incomplete` refusal of the first enabled federation
 * whose stores `isWired` does not answer for, or `undefined`.
 * @internal
 */
export function federationStoresRefusal(
	config: AppConfig,
	isWired: (key: ComponentKey) => boolean,
	stage: BootStage,
): BootError | undefined {
	for (const [name] of enabledFederationsOf(config)) {
		const missing = FEDERATION_REQUIRED_STORES.filter((k) => !isWired(k));
		if (missing.length > 0) {
			return new BootError({
				stage,
				reason: "federation-stores-incomplete",
				message: `core.federations.${name} is enabled but required federation stores are missing: ${missing.join(", ")}`,
				details: { reason: "federation-stores-incomplete", federationName: name, missing },
			});
		}
	}
	return undefined;
}

// ---------------------------------------------------------------------------
// Declared-absence guard
// ---------------------------------------------------------------------------

/**
 * Read a dotted path off the parsed config without asserting its shape. Each
 * key is read as an own property: one an object inherits (`constructor`,
 * `toString`) is not configuration anyone wrote, and reads as absent.
 */
function readConfigPath(config: unknown, path: readonly string[]): unknown {
	let value: unknown = config;
	for (const segment of path) {
		if (value === null || typeof value !== "object" || !Object.hasOwn(value, segment)) {
			return undefined;
		}
		value = (value as Record<string, unknown>)[segment];
	}
	return value;
}

/**
 * The policies core attaches to slots it declares, wherever a module reads the
 * slot: its readers need not attach it. A module that does attaches the same
 * policy, or is refused as disagreeing.
 */
const CORE_SLOT_ABSENCE_POLICIES: Readonly<Record<string, AbsencePolicy>> = {
	rateLimiter: RATE_LIMITER_ABSENCE_POLICY,
};

/** Who a core-attached policy is declared by, as the disagreement refusal names it. */
const CORE_POLICY_OWNER = "core";

/**
 * The slots `ModuleSpec.absencePolicies`, and the policies core attaches to
 * its own slots (`CORE_SLOT_ABSENCE_POLICIES`), govern, in the order the
 * policies are met, with the modules that read each. Refuses, with
 * `component-absence-undeclared`, a policy on a key its module does not read,
 * and two modules attaching different policies to one key even when the
 * absence is declared, so the advice does not depend on module order; the
 * bundled modules share one policy constant per key
 * (`AUDIT_SINK_ABSENCE_POLICY`) so this cannot happen by accident.
 *
 * `consumedBy` is every module naming the key in `requires` / `optional`, the
 * evidence that the slot is part of this app's surface. New absence rules
 * attach an `AbsencePolicy` rather than adding a bespoke check.
 */
function absenceGovernedSlots(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
): UndeclaredAbsenceSlot[] {
	interface Collected {
		readonly policy: AbsencePolicy;
		readonly declaredBy: string[];
	}
	const byKey = new Map<string, Collected>();
	// Step 1 (checkUniqueModuleNames) has run, so the name lookup is total.
	const normalisedByName = new Map(modules.map((nm) => [nm.name, nm]));
	const readersOf = (key: string): string[] =>
		modules
			.filter(
				(m) =>
					(m.requires as readonly string[]).includes(key) ||
					(m.optional as readonly string[]).includes(key),
			)
			.map((m) => m.name);
	for (const [key, policy] of Object.entries(CORE_SLOT_ABSENCE_POLICIES)) {
		if (readersOf(key).length > 0) byKey.set(key, { policy, declaredBy: [CORE_POLICY_OWNER] });
	}

	for (const m of rawModules) {
		// biome-ignore lint/style/noNonNullAssertion: every raw module was normalised under its (unique) name
		const normalised = normalisedByName.get(m.name)!;
		for (const [key, policy] of Object.entries(m.absencePolicies ?? {})) {
			if (policy === undefined) continue;
			// The manifest types constrain policy keys to the module's own `O`,
			// but `defineModule`'s `const O` inference lets `absencePolicies`
			// itself widen `O` — a policy on a key the module never listed in
			// `requires` / `optional` still compiles. That policy would then
			// govern a slot its module does not read, which is a manifest
			// authoring bug; refuse it by name rather than enforcing it.
			const reads =
				(normalised.requires as readonly string[]).includes(key) ||
				(normalised.optional as readonly string[]).includes(key);
			if (!reads) {
				throw new BootError({
					message:
						`Module "${m.name}" attaches an absence policy to "${key}" but does ` +
						"not list it in requires or optional. A policy belongs on a key its " +
						"module actually reads — add the key to the manifest, or remove the policy.",
					reason: "component-absence-undeclared",
					stage: "validateManifests",
					details: {
						reason: "component-absence-undeclared",
						componentKey: key as ComponentKey,
						consumedBy: [m.name],
						configKey: policy.configKey.join("."),
						absentValue: policy.absentValue,
					},
				});
			}
			const existing = byKey.get(key);
			if (existing === undefined) {
				byKey.set(key, { policy, declaredBy: [m.name] });
				continue;
			}
			// `hint` participates deliberately: it is interpolated into the boot
			// error, so two policies differing only there would still make the
			// operator-facing advice depend on module input order.
			const agrees =
				existing.policy.absentValue === policy.absentValue &&
				existing.policy.hint === policy.hint &&
				existing.policy.configKey.length === policy.configKey.length &&
				existing.policy.configKey.every((seg, i) => seg === policy.configKey[i]);
			if (!agrees) {
				throw new BootError({
					message:
						`Absence policies for "${key}" disagree — modules ` +
						`[${[...existing.declaredBy, m.name].join(", ")}] declare different ` +
						"policy details (config key, absent value, or hint) for the same " +
						"slot, so the boot error's advice would depend on module order. " +
						"Share one policy constant.",
					reason: "component-absence-undeclared",
					stage: "validateManifests",
					details: {
						reason: "component-absence-undeclared",
						componentKey: key as ComponentKey,
						consumedBy: [...existing.declaredBy, m.name],
						configKey: existing.policy.configKey.join("."),
						absentValue: existing.policy.absentValue,
					},
				});
			}
			existing.declaredBy.push(m.name);
		}
	}

	return [...byKey].map(([key, { policy }]) => ({
		componentKey: key as ComponentKey,
		consumedBy: readersOf(key),
		policy,
	}));
}

/**
 * The governed slots whose absence `config` does not declare: each must hold
 * a value, from one of the three component sources.
 */
function undeclaredAbsenceSlotsOf(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
	config: unknown,
): UndeclaredAbsenceSlot[] {
	return absenceGovernedSlots(modules, rawModules).filter(
		(slot) => !isAbsenceDeclared(config, slot.policy),
	);
}

/**
 * The refusal of `slot` holding no value: a capability slot (token
 * revocation, an audit sink, a rate limiter) must never be a silent no-op.
 * @internal
 */
export function undeclaredAbsenceRefusal(slot: UndeclaredAbsenceSlot, stage: BootStage): BootError {
	const { componentKey: key, consumedBy, policy } = slot;
	return new BootError({
		message:
			`Component "${key}" is read by ` +
			`${consumedBy.length === 1 ? `module "${consumedBy[0]}"` : `modules [${consumedBy.join(", ")}]`} ` +
			"but nothing provides it, and its absence is not declared. " +
			`Wire a provider, or ${describeAbsenceDeclaration(policy)} to declare ` +
			`the capability absent on purpose. ${policy.hint}`,
		reason: "component-absence-undeclared",
		stage,
		details: {
			reason: "component-absence-undeclared",
			componentKey: key,
			consumedBy,
			configKey: policy.configKey.join("."),
			absentValue: policy.absentValue,
		},
	});
}

/**
 * Enforces the absence policies at stage 1: every governed slot must be
 * planned from one of the three component sources, or the config must carry
 * the policy's declared-absent value. A planned slot that holds `undefined`
 * once its sources have answered is refused at stage 3, from
 * `ValidatedManifests.undeclaredAbsenceSlots`.
 */
function checkDeclaredAbsence(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
	config: unknown,
	plannedKeys: ReadonlySet<string>,
): void {
	for (const slot of undeclaredAbsenceSlotsOf(modules, rawModules, config)) {
		if (!plannedKeys.has(slot.componentKey)) {
			throw undeclaredAbsenceRefusal(slot, "validateManifests");
		}
	}
}

// ---------------------------------------------------------------------------
// Step 8 — Override target existence
// ---------------------------------------------------------------------------

/**
 * Step 8: every `overrides[kind][name]` needs a target: some module's
 * `contributes[kind][name]`, or an entry already in the host's name-keyed
 * collector (`contributionKinds[kind].get(name) !== undefined`). The second
 * keeps this stage in agreement with stage 4, whose
 * `collector.replace(name, value)` succeeds for any existing entry, so a host
 * extending a pre-loaded collector is not refused here.
 * @internal
 */
function checkOverrideTargets(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap,
): void {
	// Build set of all contributes (kind, name) pairs across modules.
	const contributed = new Set<string>(); // `${kind}:${name}`
	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			if (typeof entry.key === "string") {
				contributed.add(`${entry.kind}:${entry.key}`);
			}
		}
	}

	for (const m of modules) {
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			if (contributed.has(compoundKey)) continue;

			// Fallback: consumer-seeded name-keyed collector with a pre-existing
			// entry under this name is also a valid override target.
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| { kind: string; get?: (name: string) => unknown }
				| undefined;
			if (collector?.kind === "name-keyed" && collector.get?.(entry.key) !== undefined) {
				continue;
			}

			throw new BootError({
				message: `Override target missing — module "${m.name}" overrides "${entry.kind}.${entry.key}" but no module contributes it and no consumer-seeded collector pre-loaded it.`,
				reason: "override-target-missing",
				stage: "validateManifests",
				details: {
					reason: "override-target-missing",
					kind: entry.kind,
					name: entry.key,
					overridingModule: m.name,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 9 — Override duplicate check
// ---------------------------------------------------------------------------

/**
 * Step 9: Two modules overriding the same (kind, name) throw
 * `duplicate-override`.
 * @internal
 */
function checkOverrideDuplicates(modules: readonly NormalisedModule[]): void {
	const seen = new Map<string, string>(); // `${kind}:${name}` → module
	for (const m of modules) {
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			const prev = seen.get(compoundKey);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate override for "${entry.kind}.${entry.key}" — modules "${prev}" and "${m.name}" both override it.`,
					reason: "duplicate-override",
					stage: "validateManifests",
					details: {
						reason: "duplicate-override",
						kind: entry.kind,
						name: entry.key,
						modules: [prev, m.name],
					},
				});
			}
			seen.set(compoundKey, m.name);
		}
	}
}

// ---------------------------------------------------------------------------
// Step 10 — Same-module contribute-and-override collision
// ---------------------------------------------------------------------------

/**
 * Step 10: A single module declaring both `contributes[kind][name]` and
 * `overrides[kind][name]` for the same (kind, name) throws
 * `contribute-and-override-same-key`.
 * @internal
 */
function checkSameModuleContributeOverride(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		const contributed = new Set<string>();
		for (const entry of m.contributesEntries) {
			if (typeof entry.key === "string") {
				contributed.add(`${entry.kind}:${entry.key}`);
			}
		}
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			if (contributed.has(compoundKey)) {
				throw new BootError({
					message: `Module "${m.name}" both contributes and overrides "${entry.kind}.${entry.key}" — these are mutually exclusive.`,
					reason: "contribute-and-override-same-key",
					stage: "validateManifests",
					details: {
						reason: "contribute-and-override-same-key",
						kind: entry.kind,
						name: entry.key,
						module: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 11 — List-shaped override rejection
// ---------------------------------------------------------------------------

/**
 * Step 11: a module's `overrides` carrying any list-shaped kind throws
 * `list-shaped-override-not-allowed`. Dispatches on
 * `collector.kind === "list" | "list-routes"`, as `apply-contributions.mts`
 * does, so consumer-defined list-shaped kinds are caught too; their name is
 * cast into `details.kind`, whose type models only the built-in kinds.
 * @internal
 */
function checkListShapedOverrides(
	rawModules: readonly Module[],
	contributionKinds: ContributionKindMap,
): void {
	for (const m of rawModules) {
		const overrides = m.overrides ?? {};
		for (const kind of Object.keys(overrides)) {
			const collector = (contributionKinds as Record<string, unknown>)[kind] as
				| { kind?: string }
				| undefined;
			if (collector?.kind !== "list" && collector?.kind !== "list-routes") continue;
			throw new BootError({
				message: `Module "${m.name}" attempts to override list-shaped kind "${kind}", which is not allowed.`,
				reason: "list-shaped-override-not-allowed",
				stage: "validateManifests",
				details: {
					reason: "list-shaped-override-not-allowed",
					kind: kind as
						| "routes"
						| "auditHooks"
						| "grantPolicyHooks"
						| "grantMiddleware"
						| "tokenBindingMechanisms",
					module: m.name,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 12 — Lifecycle / provides closure
// ---------------------------------------------------------------------------

/**
 * Step 12: A `lifecycle[K]` entry whose `K` does not appear in the same
 * module's `provides` throws `lifecycle-without-provides`.
 * @internal
 */
function checkLifecycleClosure(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		const providesSet = new Set<ComponentKey>(m.providesKeys);
		for (const key of m.lifecycleKeys) {
			if (!providesSet.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" declares lifecycle for "${key}" but does not provide it.`,
					reason: "lifecycle-without-provides",
					stage: "validateManifests",
					details: {
						reason: "lifecycle-without-provides",
						componentKey: key,
						module: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13 — the one composed parse
// ---------------------------------------------------------------------------

/**
 * Issues as the operator reads them: each path joined with dots, the whole
 * configuration named as such.
 */
function namedIssues(issues: readonly z.core.$ZodIssue[]): string {
	return issues
		.map((issue) => `${operatorPath(issue.path) || "(the configuration)"}: ${issue.message}`)
		.join("; ");
}

/** The names of `Object.prototype`'s members: reserved, with `prototype`, as configuration keys. */
const OBJECT_PROTOTYPE_MEMBERS: ReadonlySet<string> = new Set(
	Object.getOwnPropertyNames(Object.prototype),
);

/** Why `key` is reserved as a configuration key, or `undefined` when it is not. */
function reservedKeyReason(key: string): string | undefined {
	if (OBJECT_PROTOTYPE_MEMBERS.has(key)) return "is named after an Object.prototype member";
	if (key === "prototype") return 'is "prototype"';
	return undefined;
}

/**
 * One issue per reserved key of the configuration as written — one named
 * after an `Object.prototype` member, or `prototype` — at the key's full
 * path. A schema drops a `__proto__` key unvalidated, and code reading any
 * such key may meet an inherited member instead. The walk covers the own data properties of
 * plain objects and lists, which is everything a parsed HOCON file holds;
 * a getter is read by the parse that follows, not by this walk, and
 * anything else is a value. An object reached by several paths is named
 * under each; only its ancestors stop a cycle.
 */
function reservedKeyIssues(
	value: unknown,
	path: readonly PropertyKey[] = [],
	ancestors = new Set<object>(),
): z.core.$ZodIssue[] {
	if (!Array.isArray(value) && !isPlainConfigObject(value)) return [];
	if (ancestors.has(value)) return [];
	ancestors.add(value);
	const issues = Object.keys(value).flatMap((key) => {
		const at = [...path, Array.isArray(value) ? Number(key) : key];
		const below = Object.getOwnPropertyDescriptor(value, key);
		const reason = reservedKeyReason(key);
		return [
			...(reason !== undefined
				? [
						{
							code: "custom",
							path: at,
							message: `the key "${key}" ${reason}, which configuration cannot carry`,
							input: undefined,
						} as z.core.$ZodIssue,
					]
				: []),
			...(below !== undefined && "value" in below
				? reservedKeyIssues(below.value, at, ancestors)
				: []),
		];
	});
	ancestors.delete(value);
	return issues;
}

/**
 * The sections of another owner core reads keys of by path, loaded or not:
 * `oauth {}`, for the issuer the grant-policy check and the discovery document
 * are built on, the token lifetimes revoking records and a host's token
 * settings are bounded by, and the revocation modes two absence policies are
 * keyed in. The oauth module owns the section; while those readers move to its
 * `oauthTokenSettings` slot, core reads the section where it is written.
 */
const SECTIONS_CORE_READS = ["oauth"] as const;

/**
 * The keys of `oauth {}` core reads by path (`SECTIONS_CORE_READS`), each as
 * its segments, and no other: the issuer the grant-policy check and
 * `compositionIssuer` read, the token lifetimes core's resolvers read
 * (`OAUTH_LIFETIME_PATHS`), and the revocation modes the subject-revocation
 * and access-token denylist absence policies are keyed in.
 */
const OAUTH_ISSUER_PATH = ["oauth", "jwt", "issuer"] as const;
const OAUTH_PATHS_CORE_READS: readonly (readonly string[])[] = [
	OAUTH_ISSUER_PATH,
	...OAUTH_LIFETIME_PATHS,
	SUBJECT_REVOCATION_ABSENCE_POLICY.configKey,
	ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY.configKey,
];

/** Whether `path` starts with every segment of `prefix`. */
const startsWith = (path: readonly string[], prefix: readonly string[]): boolean =>
	prefix.length <= path.length && prefix.every((segment, index) => path[index] === segment);

/** Whether `path` is one core reads, segment for segment. */
const isPathCoreReads = (path: readonly string[]): boolean =>
	OAUTH_PATHS_CORE_READS.some((read) => read.length === path.length && startsWith(path, read));

/** The value at `path` of `node`, read as own properties; `undefined` where there is none. */
function ownValueAt(node: unknown, path: readonly string[]): unknown {
	let value: unknown = node;
	for (const key of path) {
		if (value === null || typeof value !== "object" || !Object.hasOwn(value, key)) return undefined;
		value = (value as Record<string, unknown>)[key];
	}
	return value;
}

/** A custom issue at `path` with `message`. */
const issueAt = (path: readonly string[], message: string): z.core.$ZodIssue =>
	({ code: "custom", path: [...path], message, input: undefined }) as z.core.$ZodIssue;

const UNREAD_OAUTH_KEY =
	"is read only by oauthEndpointsModule, which owns oauth {} and is not loaded: load oauthEndpointsModule to use this key (the oauth grant modules need it too), or remove the key";

/**
 * Where no loaded module's section is `oauth` — the oauth endpoints module is
 * not loaded — the issues of core's reading of `oauth {}` in `config`, the
 * frozen plain-data copy stage 1 took of what was handed over
 * (`snapshotHostMap`): a section that is not an object, every key set that
 * core does not read (`OAUTH_PATHS_CORE_READS`, segment for segment, by the
 * reading of what a configuration sets the relocation refusal uses:
 * `pathsSetBy`), and an issuer present that is not a canonical issuer,
 * whatever its shape. A key named after an `Object.prototype` member, or
 * `prototype`, is left to `reservedKeyIssues`. Nothing else would read such a
 * key, so it would be accepted unread: a retired key, a misspelt one, one only
 * the module reads. Where the module is loaded, its own strict section
 * refuses instead.
 */
function oauthIssuesWithoutItsModule(
	config: unknown,
	modules: readonly Module[],
): z.core.$ZodIssue[] {
	const [name] = SECTIONS_CORE_READS;
	if (modules.some((m) => m.section !== undefined && m.name === name)) return [];
	const section = ownValueAt(config, [name]);
	if (section === undefined) return [];
	if (!isPlainConfigObject(section)) {
		return [issueAt([name], `must be a section: ${UNREAD_OAUTH_KEY}`)];
	}
	const issues: z.core.$ZodIssue[] = [];
	const issuer = ownValueAt(section, OAUTH_ISSUER_PATH.slice(1));
	if (issuer !== undefined) {
		const rejection = checkCanonicalIssuer(issuer);
		if (rejection !== null) {
			issues.push(
				issueAt(
					OAUTH_ISSUER_PATH,
					`${OAUTH_ISSUER_PATH.join(".")} ${describeIssuerRejection(rejection)}`,
				),
			);
		}
	}
	for (const path of pathsSetBy(section, [name])) {
		if (startsWith(path, OAUTH_ISSUER_PATH) && issuer !== undefined) continue;
		if (path.some((segment) => reservedKeyReason(segment) !== undefined)) continue;
		if (isPathCoreReads(path)) continue;
		issues.push(issueAt(path, UNREAD_OAUTH_KEY));
	}
	return issues;
}

/**
 * Step 13: parses the configuration the composition root handed over
 * (`bootstrapComponents.config`) once, with every schema that reads it:
 *
 * 1. core's base (`CoreConfigSchema`): core's own sections. Every other
 *    section is a module's, validated by that module's schema when it is
 *    loaded and by nothing when it is not;
 * 2. laid over what was written (`overlayConfig`), so a key no schema
 *    declares is kept.
 *
 * Returns the composed configuration, which becomes the `config` slot once
 * `parseModuleSections` writes each section back. Refused values make one
 * `config-validation-failed` naming each operator path: every reserved key
 * (`reservedKeyIssues`: an `Object.prototype` member's name, or
 * `prototype`), every key of `oauth {}` nothing reads where its module is not
 * loaded (`oauthIssuesWithoutItsModule`), a `cors` section that sets anything while
 * no loaded module's section is `cors` (`unreadCorsSection`: core reads its CORS
 * origins from the `httpSettings` slot alone), then the base's issues. No
 * module is named: a module's own configuration is its section, parsed after
 * this.
 * @internal
 */
function validateAndComposeConfig(bootstrap: BootstrapMap, modules: readonly Module[]): unknown {
	const issues: z.core.$ZodIssue[] = [];
	const raw: unknown = (bootstrap as Record<string, unknown>).config;

	issues.push(...reservedKeyIssues(raw));
	issues.push(...oauthIssuesWithoutItsModule(raw, modules));
	// The sections a loaded module owns, at its name: an absence policy keyed
	// in `cors` does not make the section read.
	const unreadCors = unreadCorsSection(
		raw,
		new Set(modules.filter((m) => m.section !== undefined).map((m) => m.name)),
	);
	if (unreadCors !== undefined) {
		issues.push({ code: "custom", path: ["cors"], message: unreadCors, input: undefined });
	}
	// Through `parseSection`: a parse that throws instead of answering — a
	// getter in a configuration built in code that throws — is one more issue
	// naming the schema, not an error escaping stage 1.
	const base = parseSection(CoreConfigSchema, raw, "core's configuration schema");
	if ("issues" in base) issues.push(...(base.issues as z.core.$ZodIssue[]));

	if (issues.length > 0) {
		throw new BootError({
			message: `Config validation failed — ${issues.length} issue(s) found: ${namedIssues(issues)}.`,
			reason: "config-validation-failed",
			stage: "validateManifests",
			details: { reason: "config-validation-failed", issues: issues as z.ZodIssue[], modules: [] },
		});
	}
	return overlayConfig(raw, (base as { readonly data: unknown }).data);
}

/**
 * The top-level sections something loaded reads: every section core's base
 * declares, the sections core reads keys of by path (`SECTIONS_CORE_READS`),
 * every loaded module's section, at its name, and the section each absence
 * policy a loaded module attaches is keyed in, which the declared-absence
 * guard reads as written whether or not the module owning it is loaded. What
 * the configuration sets outside them is what stage 1's notices name
 * (`logConfigNotices`).
 * @internal
 */
function ownedSections(modules: readonly Module[]): ReadonlySet<string> {
	const owned = new Set<string>([...Object.keys(CoreConfigSchema.shape), ...SECTIONS_CORE_READS]);
	for (const m of modules) {
		if (m.section !== undefined) owned.add(m.name);
		for (const policy of Object.values(m.absencePolicies ?? {})) {
			const section = policy?.configKey[0];
			if (section !== undefined) owned.add(section);
		}
	}
	return owned;
}

// ---------------------------------------------------------------------------
// Step 13, second half — each module's own configuration section
// ---------------------------------------------------------------------------

/** What `writeSection` writes to remove the section. */
const REMOVED: unique symbol = Symbol("removed");

/**
 * `config` with `value` laid over the section at `name` (`overlayConfig`: a
 * key the value does not hold is kept, one it holds as `undefined` goes), or
 * with the section removed for `REMOVED`. A copy: `config` is not changed.
 * The configuration is what `validateAndComposeConfig` answers —
 * `overlayConfig`'s output, a plain object whatever the composition root
 * handed over — so the copy is one too.
 */
function writeSection(config: unknown, name: string, value: unknown): unknown {
	const target = config as Record<string, unknown>;
	const copy: Record<string, unknown> = {};
	for (const key of Object.keys(target)) defineConfigKey(copy, key, target[key]);
	if (value === REMOVED) delete copy[name];
	else {
		const current = Object.hasOwn(target, name) ? target[name] : undefined;
		defineConfigKey(copy, name, overlayConfig(current, value));
	}
	return copy;
}

/** How a value is named in a refusal: its kind, never the value (it may be a secret). */
function kindOf(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "a list";
	if (typeof value === "object") return "an object that is not plain data";
	return `a ${typeof value}`;
}

/**
 * Parses every declared section and writes each back into the configuration.
 * A module's section is read at its name out of the composed configuration
 * (coerced where core's schema coerces, whole where no schema declares it)
 * and parsed synchronously with the section's schema.
 *
 * The module gets its schema's output as `deps.section`, deeply frozen
 * (`frozenSection`). The `config` slot gets the same output laid over what is
 * at the module's name (`writeSection`), so a narrower schema never strips a
 * loaded module's section. An output of `undefined` removes what is written
 * there.
 *
 * When a schema refuses its value, every section is still parsed, and one
 * `config-validation-failed` names them all; each issue's path is prefixed
 * with its section's, so it names the path the operator wrote, and
 * `details.modules` lists each refused module with its section's path, its
 * name. Every module in `modules` is parsed, whether or not a factory of it
 * will run.
 * @internal
 */
function parseModuleSections(
	modules: readonly Module[],
	composedConfig: unknown,
): {
	readonly config: unknown;
	readonly sections: ReadonlyMap<string, { readonly value: unknown }>;
} {
	const parsed: { readonly module: Module; readonly data: unknown }[] = [];
	const issues: z.ZodIssue[] = [];
	const refused: { readonly module: string; readonly schemaPath: string }[] = [];

	for (const m of modules) {
		if (m.section === undefined) continue;
		const result = parseSection(m.section.schema, readConfigPath(composedConfig, [m.name]));
		if ("data" in result) {
			parsed.push({ module: m, data: result.data });
			continue;
		}
		for (const issue of result.issues) {
			issues.push({ ...issue, path: [m.name, ...issue.path] } as z.ZodIssue);
		}
		refused.push({ module: m.name, schemaPath: m.name });
	}
	if (issues.length > 0) throw moduleSectionsRefusal(issues, refused);

	let config = composedConfig;
	for (const { module, data } of parsed) {
		// A schema that made nothing of the value written there removes it; with
		// nothing written there, there is nothing to write.
		if (data === undefined && readConfigPath(config, [module.name]) === undefined) continue;
		config = writeSection(config, module.name, data === undefined ? REMOVED : data);
	}

	const sections = new Map<string, { readonly value: unknown }>();
	for (const { module, data } of parsed) sections.set(module.name, { value: frozenSection(data) });
	return { config, sections };
}

/**
 * The names of the modules their own section switches off: `section.isEnabled`
 * answers `false` for the section the module is handed. A switch that throws
 * or answers anything but a boolean is one more issue at its section's path,
 * all of them refused together as `config-validation-failed`.
 * @internal
 */
function switchedOffModules(
	modules: readonly Module[],
	sections: ReadonlyMap<string, { readonly value: unknown }>,
): ReadonlySet<string> {
	const off = new Set<string>();
	const issues: z.ZodIssue[] = [];
	const refused: { readonly module: string; readonly schemaPath: string }[] = [];
	for (const m of modules) {
		const isEnabled: unknown = m.section?.isEnabled;
		if (isEnabled === undefined) continue;
		let problem: string;
		if (typeof isEnabled !== "function") {
			problem = "it is not a function";
		} else {
			try {
				const answer: unknown = isEnabled.call(m.section, sections.get(m.name)?.value);
				if (answer === false) off.add(m.name);
				if (typeof answer === "boolean") continue;
				problem = `it answered ${kindOf(answer)}`;
			} catch (thrown) {
				problem = `it threw: ${failureSummary(thrown)}`;
			}
		}
		issues.push({
			code: "custom",
			path: [m.name],
			message: `module "${m.name}"'s isEnabled did not answer whether its section switches it on: ${problem}`,
		} as z.ZodIssue);
		refused.push({ module: m.name, schemaPath: m.name });
	}
	if (issues.length > 0) throw moduleSectionsRefusal(issues, refused);
	return off;
}

/**
 * Each module's replica-safety declaration as the guard reads it
 * (`readReplicaSafety`): a static one as written, one made from the section
 * answered once for the section the module is handed. A declaration that
 * throws or answers a malformed value is one more issue — at its section's
 * path, or naming the module alone when it has no section — all of them
 * refused together as `config-validation-failed`.
 * @internal
 */
function replicaSafetyAsRead(
	modules: readonly Module[],
	sections: ReadonlyMap<string, { readonly value: unknown }>,
): readonly ReplicaSafetyModuleRef[] {
	const read: ReplicaSafetyModuleRef[] = [];
	const issues: z.ZodIssue[] = [];
	const refused: { readonly module: string; readonly schemaPath?: string }[] = [];
	for (const m of modules) {
		const answer = readReplicaSafety(m, sections.get(m.name));
		if ("declaration" in answer) {
			read.push({
				name: m.name,
				...(answer.declaration === undefined ? {} : { replicaSafety: answer.declaration }),
			});
			continue;
		}
		const sectioned = m.section !== undefined;
		issues.push({
			code: "custom",
			path: sectioned ? [m.name] : [],
			message: `module "${m.name}"'s replicaSafety did not answer what ${sectioned ? "its section holds" : "it holds"} per replica: ${answer.problem}`,
		} as z.ZodIssue);
		refused.push(sectioned ? { module: m.name, schemaPath: m.name } : { module: m.name });
	}
	if (issues.length > 0) throw moduleSectionsRefusal(issues, refused);
	return read;
}

/**
 * The one refusal of what module sections answered — a section's parse, a
 * switch, a replica-safety declaration made from the section: every issue
 * together, each at its path (an issue with no path names its module
 * itself), as `config-validation-failed`.
 * @internal
 */
function moduleSectionsRefusal(
	issues: readonly z.ZodIssue[],
	refused: readonly { readonly module: string; readonly schemaPath?: string }[],
): BootError {
	const named = issues.map((issue) =>
		issue.path.length === 0 ? issue.message : `${operatorPath(issue.path)}: ${issue.message}`,
	);
	return new BootError({
		message: `Config validation failed — ${issues.length} issue(s) found in module sections: ${named.join("; ")}.`,
		reason: "config-validation-failed",
		stage: "validateManifests",
		details: { reason: "config-validation-failed", issues: [...issues], modules: [...refused] },
	});
}

/**
 * What a switched-off module is to every stage after the parse: its name and
 * its section, nothing it would register.
 */
const switchedOff = (m: Module): Module => ({ name: m.name, section: m.section }) as Module;

// ---------------------------------------------------------------------------
// Step 14 — Route-order edge sanity
// ---------------------------------------------------------------------------

/**
 * Step 14: every `RouteContribution.before` / `after` token must name an `id`
 * some other `RouteContribution` declares. A factory-shaped route
 * (`(deps) => RouteContribution`) has its `id` only once materialised, so
 * when any module has one, unknown references are left to assembleApp's
 * mount-order pass, which sees every id; this keeps mixed static and factory
 * route ordering possible. Apps with only static routes get the early typo
 * check.
 * @internal
 */
function checkRouteOrderEdges(rawModules: readonly Module[]): void {
	// Detect any factory-shaped routes entries across all modules. A single
	// factory route anywhere defers all unknown-ref checks to assembleApp.
	let anyFactoryRouteEntry = false;
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry === "function") {
				anyFactoryRouteEntry = true;
				break;
			}
		}
		if (anyFactoryRouteEntry) break;
	}
	if (anyFactoryRouteEntry) return;

	// Collect all declared route ids (pure-static path)
	const declaredIds = new Set<string>();
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry === "object" && entry !== null) {
				const route = entry as RouteContribution;
				if (route.id !== undefined) {
					declaredIds.add(route.id);
				}
			}
		}
	}

	// Check all before/after references
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry !== "object" || entry === null) continue;
			const route = entry as RouteContribution;

			const checkRefs = (tokens: readonly string[] | undefined, direction: "before" | "after") => {
				if (!tokens) return;
				for (const token of tokens) {
					if (!declaredIds.has(token)) {
						throw new BootError({
							message: `Route order edge "${direction}: ${token}" in module "${m.name}" references an unknown id.`,
							reason: "route-order-target-missing",
							stage: "validateManifests",
							details:
								route.id !== undefined
									? {
											reason: "route-order-target-missing",
											id: token,
											referencedBy: route.id,
											referencedByModule: m.name,
											direction,
										}
									: {
											reason: "route-order-target-missing",
											id: token,
											referencedBy: null,
											referencedByMountPath: route.mountPath,
											referencedByModule: m.name,
											direction,
										},
						});
					}
				}
			};

			checkRefs(route.before, "before");
			checkRefs(route.after, "after");
		}
	}
}

// ---------------------------------------------------------------------------
// The module section's manifest rules
// ---------------------------------------------------------------------------

/**
 * The key a module's own configuration section is set under on its deps
 * object, beside its slots.
 */
const SECTION_DEPS_KEY = "section";

/**
 * A module that declares a section may not also require or optionally read a
 * component named `section`: its deps would carry both under one name, the
 * section shadowing the slot. Only that module is refused; elsewhere
 * `section` is an ordinary slot (provided, read by a module without a
 * section, bootstrapped or overridden). No module may provide, require or
 * optionally read a component named after the reserved bootstrap input,
 * which no component carries. Throws `reserved-component-key`.
 * @internal
 */
function checkReservedComponentKeys(
	rawModules: readonly Module[],
	modules: readonly NormalisedModule[],
): void {
	for (const m of modules) {
		const sources = [
			["module-provides", m.providesKeys, "provides"],
			["module-requires", m.requires, "requires"],
			["module-optional", m.optional, "optionally reads"],
		] as const;
		for (const [source, keys, verb] of sources) {
			if (!(keys as readonly string[]).includes(RESERVED_BOOTSTRAP_INPUT)) continue;
			throw new BootError({
				message: `Module "${m.name}" ${verb} a component named "${RESERVED_BOOTSTRAP_INPUT}", which no component carries: it is the configuration's defaults, which boot reads from bootstrapComponents itself. Name the component otherwise.`,
				reason: "reserved-component-key",
				stage: "validateManifests",
				details: {
					reason: "reserved-component-key",
					componentKey: RESERVED_BOOTSTRAP_INPUT,
					source,
					module: m.name,
				},
			});
		}
	}
	modules.forEach((m, index) => {
		if (rawModules[index]?.section === undefined) return;
		const sources = [
			["module-requires", m.requires, "requires"],
			["module-optional", m.optional, "optionally reads"],
		] as const;
		for (const [source, keys, verb] of sources) {
			if (!(keys as readonly string[]).includes(SECTION_DEPS_KEY)) continue;
			throw new BootError({
				message: `Module "${m.name}" declares its own section and ${verb} a component named "${SECTION_DEPS_KEY}": its deps carry the section under that name. Name the component otherwise.`,
				reason: "reserved-component-key",
				stage: "validateManifests",
				details: {
					reason: "reserved-component-key",
					componentKey: SECTION_DEPS_KEY,
					source,
					module: m.name,
				},
			});
		}
	});
}

/** A plain map: an object whose prototype is `Object.prototype` or none — not an array, a Date, a Map or a class instance. */
const isPlainRecord = (value: unknown): value is Readonly<Record<string, unknown>> => {
	if (typeof value !== "object" || value === null) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/** Whether `value` is a dot-separated path of non-empty keys. */
const isKeyPath = (value: unknown): value is string =>
	typeof value === "string" && value.split(".").every((key) => key.length > 0);

/**
 * A `relocatedFrom` entry's value as boot reads it: the new path inside the
 * section (`""` the section itself, `null` removed), and whether it was
 * written `{ to, environmentVariable: null }`, for a path no variable binds;
 * `undefined` for any other value.
 */
function relocationEntry(
	value: unknown,
): { readonly inside: string | null; readonly withoutVariable: boolean } | undefined {
	if (value === "" || value === null || isKeyPath(value)) {
		return { inside: value, withoutVariable: false };
	}
	if (
		isPlainRecord(value) &&
		Object.keys(value).length === 2 &&
		Object.hasOwn(value, "to") &&
		Object.hasOwn(value, "environmentVariable") &&
		value.environmentVariable === null &&
		(value.to === "" || isKeyPath(value.to))
	) {
		return { inside: value.to, withoutVariable: true };
	}
	return undefined;
}

/** One old path a module's section moved from, as boot reads its `relocatedFrom`. */
interface SectionRelocation extends RelocatedPath {
	readonly module: string;
	/** The old path as the manifest wrote it. */
	readonly entry: string;
}

/**
 * The new path of a `relocatedFrom` entry: the section's path as it is read
 * (the module's name) followed by the entry's path inside it — none
 * for a list entry or a map entry of `""` — or `null` for an entry of
 * `null`, a key removed rather than moved.
 */
const relocationTarget = (
	section: readonly string[],
	inside: string | null,
): readonly string[] | null =>
	inside === null ? null : inside === "" ? section : [...section, ...inside.split(".")];

/**
 * A module's `relocatedFrom` as relocations: each old path, and where it went
 * (`relocationTarget`). An entry written `{ to, environmentVariable: null }`
 * declares its new path bound to no variable, so its relocation names none.
 * Read after `checkModuleSectionPaths` held their shape.
 */
function sectionRelocationsOf(m: Module): readonly SectionRelocation[] {
	const relocatedFrom = m.section?.relocatedFrom;
	if (relocatedFrom === undefined) return [];
	const section = [m.name];
	const entries: readonly (readonly [string, unknown])[] = Array.isArray(relocatedFrom)
		? relocatedFrom.map((from: string) => [from, ""] as const)
		: Object.entries(relocatedFrom);
	return entries.map(([from, value]) => {
		const { inside, withoutVariable } = relocationEntry(value) as NonNullable<
			ReturnType<typeof relocationEntry>
		>;
		return {
			module: m.name,
			entry: from,
			from: from.split("."),
			to: relocationTarget(section, inside),
			...(withoutVariable ? { unbound: true } : {}),
			...(inside === "" ? { toSection: true } : {}),
		};
	});
}

/**
 * The declarations boot reads relocations and renamed variables from: core's
 * own section's, as a module named "core" whose section is `core`, when it
 * declares any, then `modules`. Only those checks read the "core" entry.
 */
function withCoreRelocations(modules: readonly Module[], core: CoreRelocations): readonly Module[] {
	if (core.relocatedFrom === undefined && core.renamedVariables === undefined) return modules;
	return [{ name: "core", section: { schema: undefined as never, ...core } } as Module, ...modules];
}

/**
 * A module's section is at its name, and its configuration is its section: a
 * manifest is plain data at run time, so one may still carry `configSchema`,
 * or a `section` carrying `at`, whatever the value — `null`, `false` and the
 * module's own name included. Either is refused rather than ignored, since
 * ignoring it would hand the module its configuration somewhere other than
 * where it reads it, unparsed by the schema it declared. The message names
 * the module, the field and the module's name; `details.at` holds the `at`
 * written (a string quoted in the message, anything else named by its type:
 * rendering it could throw), or for `configSchema` the section's path, the
 * module's name (`undefined` without a section). A field whose read throws
 * (an accessor) is refused the same way, `details.at` `undefined`. Throws
 * `module-section-path-invalid`.
 */
function refuseRemovedSectionFields(rawModules: readonly Module[]): void {
	for (const m of rawModules) {
		const unreadable = (field: string, thrown: unknown): BootError =>
			new BootError({
				message: `Module "${m.name}" declares ${field}, which could not be read (${failureSummary(thrown)}): a module's section is at its name, "${m.name}".`,
				reason: "module-section-path-invalid",
				stage: "validateManifests",
				details: {
					reason: "module-section-path-invalid",
					module: m.name,
					at: undefined,
					problem: `reading ${field} threw`,
				},
			});
		let configSchema: unknown;
		try {
			configSchema = (m as { readonly configSchema?: unknown }).configSchema;
		} catch (thrown) {
			throw unreadable("configSchema", thrown);
		}
		if (configSchema !== undefined) {
			throw new BootError({
				message: `Module "${m.name}" declares configSchema, which is removed: a module reads its configuration as its section, which is at its name, "${m.name}".`,
				reason: "module-section-path-invalid",
				stage: "validateManifests",
				details: {
					reason: "module-section-path-invalid",
					module: m.name,
					at: m.section === undefined ? undefined : m.name,
					problem:
						"configSchema is removed: a module reads its configuration as its section, at its name",
				},
			});
		}
		let at: unknown;
		try {
			at = (m.section as { readonly at?: unknown } | undefined)?.at;
		} catch (thrown) {
			throw unreadable("section.at", thrown);
		}
		if (at === undefined) continue;
		const shown =
			typeof at === "string"
				? JSON.stringify(at)
				: at === null
					? "null"
					: typeof at === "object"
						? "an object"
						: `a ${typeof at}`;
		throw new BootError({
			message: `Module "${m.name}" declares section.at (${shown}), which is removed: a module's section is at its name, "${m.name}".`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: {
				reason: "module-section-path-invalid",
				module: m.name,
				at,
				problem: "section.at is removed: a module's section is at its name",
			},
		});
	}
}

/**
 * No module is named after a key configuration cannot carry
 * (`reservedKeyReason`: an `Object.prototype` member's name, or
 * `prototype`): its section, at its name, would be such a key — refused
 * wherever the configuration writes it, and found inherited where it does
 * not. Throws `module-section-path-invalid`, naming the module.
 */
function refuseReservedModuleNames(rawModules: readonly Module[]): void {
	for (const m of rawModules) {
		const reason = reservedKeyReason(m.name);
		if (reason === undefined) continue;
		const problem = `the key its section is read at, its name, ${reason}, which configuration cannot carry`;
		throw new BootError({
			message: `Module "${m.name}" is named after a key configuration cannot carry: ${problem}.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: {
				reason: "module-section-path-invalid",
				module: m.name,
				at: m.section === undefined ? undefined : m.name,
				problem,
			},
		});
	}
}

/**
 * Every section path a manifest writes is one it can have written:
 *
 * - `section.relocatedFrom` is a list of such paths, read at every index (a
 *   hole is refused, not skipped), or a plain map (prototype
 *   `Object.prototype` or `null`) from such paths to `""`, a path inside the
 *   section, `null` (removed), or `{ to, environmentVariable: null }` with
 *   `to` either of the first two, for a new path no variable binds.
 * - No old path is a loaded module's section, its own or another's: a
 *   configuration setting that section would then be refused.
 * - No old path is or lies under `core`, core's own section, unless core
 *   declares it: a module does not relocate core's keys, whatever core's
 *   declaration (`relocating`) holds.
 * - No two loaded modules claim overlapping old paths (the same one, or one
 *   under the other), since a key set there would have two new paths; one
 *   module may cover its own old path with a more specific one. The later
 *   module is refused, and `problem` names both.
 * - No new path lies at, under or over an old path: its own, where a key
 *   written right would be refused, or another loaded module's (or another
 *   entry of its own), which would chain moves. The module whose new path it
 *   is is refused, and `problem` names the other old path and its module.
 *
 * `details.relocatedFrom` names the entry, or the value when it is neither
 * form or has a hole. First `refuseRemovedSectionFields` holds each
 * section at its module's name, and `refuseReservedModuleNames` each name to
 * a key configuration can carry. Core's own section's declaration is held
 * with the modules', as module "core" (`relocating`), so no loaded module is
 * named `core`. No section is read at, and no old path lies under,
 * `renamed-variables`, the section reserved for the captures of renamed
 * variables. Then `declaredRenames` holds the variables renamed with the
 * moves. Throws `module-section-path-invalid`.
 * @internal
 */
function checkModuleSectionPaths(
	rawModules: readonly Module[],
	relocating: readonly Module[],
): void {
	refuseRemovedSectionFields(rawModules);
	refuseReservedModuleNames(rawModules);
	for (const m of rawModules) {
		if (m.name !== "core") continue;
		const problem = `"core" is reserved: core's own section, and the name boot gives core's declarations`;
		throw new BootError({
			message: `Module "${m.name}" declares the name core: ${problem}.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: {
				reason: "module-section-path-invalid",
				module: m.name,
				at: m.section === undefined ? undefined : m.name,
				problem,
			},
		});
	}
	for (const m of rawModules) {
		if (m.section === undefined || m.name !== RENAMED_VARIABLES_SECTION) continue;
		const problem = `${RENAMED_VARIABLES_SECTION} is reserved for the captures of renamed variables`;
		throw new BootError({
			message: `Module "${m.name}" declares its section at "${m.name}": ${problem}.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: { reason: "module-section-path-invalid", module: m.name, at: m.name, problem },
		});
	}
	const refusal = (m: Module, relocatedFrom: unknown, problem: string): BootError => {
		const shown =
			typeof relocatedFrom === "string"
				? JSON.stringify(relocatedFrom)
				: `a ${typeof relocatedFrom}`;
		return new BootError({
			message: `Module "${m.name}" declares its section moved from ${shown}: ${problem}.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: { reason: "module-section-path-invalid", module: m.name, relocatedFrom, problem },
		});
	};
	const sections = relocating
		.filter((m) => m.section !== undefined)
		.map((m) => ({ module: m.name, path: [m.name] }));
	/** Whether `path` is `prefix` or lies under it. Keys are non-empty, so a shorter path never matches. */
	const under = (path: readonly string[], prefix: readonly string[]): boolean =>
		prefix.every((key, i) => path[i] === key);
	/** Whether one path is the other or lies under it, in either direction. */
	const overlaps = (a: readonly string[], b: readonly string[]): boolean =>
		under(a, b) || under(b, a);
	/** The old paths the modules before this one claimed. */
	const claimed: {
		readonly module: string;
		readonly from: string;
		readonly path: readonly string[];
	}[] = [];
	/**
	 * A `relocatedFrom`'s entries: a list's, read at every index — a hole is
	 * refused, not skipped — each moved to `""`; or a plain map's own. Any
	 * other value — a Date, a Map, a class instance — is refused rather than
	 * read as a map of whatever it enumerates.
	 */
	const entriesOf = (
		m: Module,
		relocatedFrom: unknown,
	): readonly (readonly [unknown, unknown])[] => {
		if (Array.isArray(relocatedFrom)) {
			const entries: (readonly [unknown, unknown])[] = [];
			for (let index = 0; index < relocatedFrom.length; index += 1) {
				if (!Object.hasOwn(relocatedFrom, index)) {
					throw refusal(
						m,
						relocatedFrom,
						`the list has a hole at index ${index}: every index names an old path`,
					);
				}
				entries.push([relocatedFrom[index], ""]);
			}
			return entries;
		}
		if (isPlainRecord(relocatedFrom)) return Object.entries(relocatedFrom);
		throw refusal(
			m,
			relocatedFrom,
			"relocatedFrom is a list of old paths, or a map from each old path to its path in the section, whose prototype is Object.prototype or null",
		);
	};
	for (const m of relocating) {
		const relocatedFrom: unknown = m.section?.relocatedFrom;
		if (relocatedFrom === undefined) continue;
		const entries = entriesOf(m, relocatedFrom);
		for (const [from, value] of entries) {
			if (!isKeyPath(from)) {
				throw refusal(m, from, "an old path is a dot-separated path of non-empty keys");
			}
			if (from.split(".")[0] === RENAMED_VARIABLES_SECTION) {
				throw refusal(
					m,
					from,
					`${RENAMED_VARIABLES_SECTION} is reserved for the captures of renamed variables`,
				);
			}
			const inside = relocationEntry(value)?.inside;
			if (inside === undefined) {
				throw refusal(
					m,
					from,
					'its new path is "" (the section itself), a dot-separated path of non-empty keys inside the section, null (removed), or { to, environmentVariable: null } with to one of the first two, for a new path no variable binds',
				);
			}
			const old = from.split(".");
			// Core's pseudo-module alone relocates its own keys.
			if (m.name !== "core" && old[0] === "core") {
				throw refusal(
					m,
					from,
					"it is or lies under core, core's own section, whose keys no module relocates",
				);
			}
			// A section is one key, so an old path that reaches one is it.
			const held = sections.find(({ path }) => under(path, old));
			if (held !== undefined) {
				throw refusal(
					m,
					from,
					held.module === m.name
						? "it is the path the section is read at, so every configuration that sets the section would be refused"
						: `it is the section of module "${held.module}", so every configuration that sets that section would be refused`,
				);
			}
			const target = relocationTarget([m.name], inside);
			if (target !== null && overlaps(target, old)) {
				throw refusal(
					m,
					from,
					under(target, old)
						? `its new path "${target.join(".")}" lies at or under the old path, so a key written there would be refused`
						: `its new path "${target.join(".")}" holds the old path, so a key moved up from under it could land under it again and be refused in turn`,
				);
			}
			const other = claimed.find(({ path }) => overlaps(path, old));
			if (other !== undefined) {
				throw refusal(
					m,
					from,
					`module "${other.module}" moved its section from "${other.from}" and module "${m.name}" from "${from}", which overlap: a key set there would have two new paths`,
				);
			}
		}
		for (const [from] of entries) {
			claimed.push({ module: m.name, from: from as string, path: (from as string).split(".") });
		}
	}
	// A chain: a new path at, under or over another relocation's old path —
	// any loaded module's, this one's other entries included — sends a key
	// to a path that is refused in turn. (A new path against its own old
	// path was held above.)
	const relocations = relocating.flatMap((m) =>
		sectionRelocationsOf(m).map((relocation) => ({ m, relocation })),
	);
	for (const { m, relocation: moved } of relocations) {
		const target = moved.to;
		if (target === null) continue;
		const chained = relocations.find(
			({ relocation: other }) => other !== moved && overlaps(target, other.from),
		)?.relocation;
		if (chained === undefined) continue;
		throw refusal(
			m,
			moved.entry,
			under(target, chained.from)
				? `its new path "${target.join(".")}" lies at or under "${chained.entry}", an old path of module "${chained.module}", so a key moved there would be refused in turn`
				: `its new path "${target.join(".")}" holds "${chained.entry}", an old path of module "${chained.module}", so a key moved under it could be refused in turn`,
		);
	}
	declaredRenames(relocating);
}

/** A variable name as an environment carries one: a letter or `_`, then letters, digits and `_`. */
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A variable a loaded module declares renamed with its section, as boot reads it. */
export interface SectionRename extends RenamedVariable {
	readonly module: string;
}

/** Whether `path` is `prefix` or lies under it. Keys are non-empty, so a shorter path never matches. */
const isUnder = (path: readonly string[], prefix: readonly string[]): boolean =>
	prefix.every((key, index) => path[index] === key);

/**
 * The rename a `renamedVariables` entry of `m` declares, or why boot cannot
 * hold it. An old path the module's `relocatedFrom` covers moves as it maps
 * (`relocateKey`): a removed key has no new name; a moved one is renamed to
 * the variable its new path is bound to. An old path in the module's own
 * section, which no relocation covers, stays where it is and is renamed to
 * the variable that path is bound to. Either way the new name differs from
 * the old one, and a variable binds the new path.
 */
function renameOf(
	m: Module,
	from: string,
	oldPath: unknown,
	relocations: readonly SectionRelocation[],
): RenamedVariable | { readonly problem: string } {
	if (!VARIABLE_NAME.test(from)) {
		return {
			problem:
				"an old variable name is a letter or underscore followed by letters, digits and underscores",
		};
	}
	// A capture is a key of a plain object; `__proto__` cannot be one of its own.
	if (from === "__proto__") {
		return { problem: "an old variable name is not __proto__, which no capture can hold" };
	}
	if (!isKeyPath(oldPath)) {
		return { problem: "its old path is a dot-separated path of non-empty keys" };
	}
	const old = oldPath.split(".");
	const moved = relocateKey(old, relocations);
	if (moved === undefined && !isUnder(old, [m.name])) {
		return {
			problem: `its old path "${oldPath}" lies under none of the paths the section moved from (relocatedFrom), nor in the section`,
		};
	}
	if (moved?.to === null) return { from, oldPath, to: null, path: null };
	const path = moved?.to ?? oldPath;
	const to = moved === undefined ? environmentVariableFor(old) : moved.environmentVariable;
	if (moved?.relocation.unbound === true) {
		return {
			problem: `its new path "${path}" is declared bound to no variable ({ to, environmentVariable: null }): no variable binds it`,
		};
	}
	if (to === undefined) {
		return { problem: `its new path "${path}" is the section itself, which no variable binds` };
	}
	if (to === from) {
		return {
			problem: `it is the variable its new path "${path}" is bound to: its name did not change`,
		};
	}
	return { from, oldPath, to, path };
}

/**
 * The renames `relocating` declare — core's first, as module "core", then each
 * loaded module's — in module and declaration order, each one boot can hold:
 * a plain map (prototype `Object.prototype` or `null`) from variable names to
 * old paths (`renameOf`); no old name that two of them declare (the later
 * refused), or that is one's new name, which would refuse the operator who
 * set it. Throws `module-section-path-invalid`, `details.renamedVariable`
 * naming the entry, or the value when it is not a plain map. Read after
 * `relocatedFrom` is held.
 * @internal
 */
function declaredRenames(relocating: readonly Module[]): readonly SectionRename[] {
	const refusal = (m: Module, renamedVariable: unknown, problem: string): BootError =>
		new BootError({
			message:
				typeof renamedVariable === "string"
					? `Module "${m.name}" declares the variable ${JSON.stringify(renamedVariable)} renamed: ${problem}.`
					: `Module "${m.name}" declares renamedVariables as a ${typeof renamedVariable}: ${problem}.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: { reason: "module-section-path-invalid", module: m.name, renamedVariable, problem },
		});
	const renames: { readonly m: Module; readonly rename: SectionRename }[] = [];
	for (const m of relocating) {
		const declared: unknown = m.section?.renamedVariables;
		if (declared === undefined) continue;
		if (!isPlainRecord(declared)) {
			throw refusal(
				m,
				declared,
				"renamedVariables is a map from each old variable name to the old path it was bound to, whose prototype is Object.prototype or null",
			);
		}
		const relocations = sectionRelocationsOf(m);
		for (const [from, oldPath] of Object.entries(declared)) {
			const rename = renameOf(m, from, oldPath, relocations);
			if ("problem" in rename) throw refusal(m, from, rename.problem);
			const other = renames.find((earlier) => earlier.rename.from === from)?.rename;
			if (other !== undefined) {
				throw refusal(
					m,
					from,
					`module "${other.module}" and module "${m.name}" both declare it renamed: its value would have two new names`,
				);
			}
			renames.push({ m, rename: { module: m.name, ...rename } });
		}
	}
	for (const { m, rename } of renames) {
		const chained = renames.find((other) => other.rename.to === rename.from)?.rename;
		if (chained === undefined) continue;
		throw refusal(
			m,
			rename.from,
			`it is the new name of "${chained.from}", renamed by module "${chained.module}", so the operator who set it would be refused`,
		);
	}
	return renames.map(({ rename }) => rename);
}

/**
 * The renames `modules` — and `core`, for core's own section — declare, as
 * boot derives them, in module and declaration order; throws
 * `module-section-path-invalid` for a declaration boot cannot hold. For the
 * testing entry's binding checks.
 * @internal
 */
export function renamedVariablesOf(
	modules: readonly Module[],
	core: CoreRelocations = {},
): readonly SectionRename[] {
	return declaredRenames(withCoreRelocations(modules, core));
}

/**
 * The variable names `relocating` — core, as module "core", and the loaded
 * modules — declare renamed: each rename's old name and its new one. Boot
 * judges these by their captures; a capture of any other name is what no
 * loaded module applies. Read after the declarations are held.
 * @internal
 */
function judgedVariables(relocating: readonly Module[]): ReadonlySet<string> {
	return new Set(
		declaredRenames(relocating).flatMap((rename) =>
			rename.to === null ? [rename.from] : [rename.from, rename.to],
		),
	);
}

/**
 * A configuration still setting a key at or under a path a loaded module's
 * section moved from refuses boot (`config-path-relocated`) before it is
 * parsed: the old path may be in no section any loaded module reads, and what
 * a schema would make of its value is beside the point. Reads the
 * configuration as handed to `createApp`, and names every such key in module
 * order with its new path and environment variable (`findRelocatedKeys`).
 * @internal
 */
function checkRelocatedConfigPaths(rawModules: readonly Module[], bootstrap: BootstrapMap): void {
	const relocations = rawModules.flatMap(sectionRelocationsOf);
	if (relocations.length === 0) return;
	const found = findRelocatedKeys((bootstrap as { readonly config?: unknown }).config, relocations);
	if (found.length === 0) return;
	throw new BootError({
		message: `Configuration sets ${found.length} path(s) that moved: ${found.map(relocatedKeyMessage).join(" ")}`,
		reason: "config-path-relocated",
		stage: "validateManifests",
		details: {
			reason: "config-path-relocated",
			relocated: found.map(({ relocation, from, to, environmentVariable }) => ({
				module: relocation.module,
				from,
				to,
				...(environmentVariable === undefined ? {} : { environmentVariable }),
			})),
		},
	});
}

/**
 * A variable a loaded module — or core — declares renamed refuses boot
 * (`environment-variable-renamed`) by what the resolution captured of it in
 * the configuration's reserved section (`findRenamedVariables`): the old name
 * set, whether or not the new one is set and whatever either holds; a removed
 * key's variable set; or a name not captured, which cannot be told from one
 * set. Only the new name set boots. Names every such variable in
 * module and declaration order, with its new name and the path that name is
 * bound to, and no value.
 * @internal
 */
function checkRenamedEnvironmentVariables(
	relocating: readonly Module[],
	bootstrap: BootstrapMap,
): void {
	const renames = declaredRenames(relocating);
	if (renames.length === 0) return;
	const config: unknown = (bootstrap as { readonly config?: unknown }).config;
	const found = findRenamedVariables(config, renames);
	if (found.length === 0) return;
	const handed: HandedConfiguration =
		config === undefined
			? "none"
			: typeof config === "object" && config !== null
				? "object"
				: "not-an-object";
	throw new BootError({
		message: `Boot refuses ${found.length} variable(s) renamed with a moved key: ${found.map((rename) => renamedVariableMessage(rename, handed)).join(" ")}`,
		reason: "environment-variable-renamed",
		stage: "validateManifests",
		details: {
			reason: "environment-variable-renamed",
			renamed: found.map(({ module, from, to, path, state }) => ({
				module,
				from,
				to,
				path,
				state,
			})),
		},
	});
}

/**
 * Where stage 1's warnings go — the replica-safety warning and the notices of
 * configuration nothing loaded reads (`logConfigNotices`), one rule for both:
 * the logger the composition root wired as a bootstrap component. A
 * composition that wired none hears nothing from stage 1.
 */
function warningLogger(bootstrap: BootstrapMap): BootstrapMap["logger"] {
	return bootstrap.logger;
}

/**
 * The bootstrap map without `configDefaults`, and that input read once into a
 * copy of its plain data (`readConfigDefaults`): boot reads it at stage 1 for
 * the notices and seeds no component from it. The map itself, and no
 * defaults, when it holds no such key. A value that is not plain data — not
 * an object of sections, a getter, a throw as it is read — refuses boot
 * (`config-defaults-invalid`), before any check, naming the path and no value.
 */
function takeConfigDefaults(bootstrap: BootstrapMap): {
	readonly bootstrapComponents: BootstrapMap;
	readonly configDefaults: ConfigDefaults | undefined;
} {
	if (!Object.hasOwn(bootstrap, RESERVED_BOOTSTRAP_INPUT)) {
		return { bootstrapComponents: bootstrap, configDefaults: undefined };
	}
	const { configDefaults: handed, ...bootstrapComponents } = bootstrap;
	const read = readConfigDefaults(handed);
	if ("problem" in read) {
		throw new BootError({
			message: `bootstrapComponents.${[RESERVED_BOOTSTRAP_INPUT, ...read.path].join(".")} ${read.problem}. Hand boot the configuration's defaults as the composition resolves its configuration: the loaded modules' reference.conf files and core's, with no file of its own and no environment, as plain data.`,
			reason: "config-defaults-invalid",
			stage: "validateManifests",
			details: { reason: "config-defaults-invalid", path: [...read.path], problem: read.problem },
		});
	}
	return { bootstrapComponents, configDefaults: read.defaults };
}

// ---------------------------------------------------------------------------
// The stage-1 check registries
// ---------------------------------------------------------------------------

/**
 * Everything a stage-1 check may read. One shape for every check, so a row is
 * `(ctx) => void` and adding a guard is appending a row. `parsedConfig` is
 * `undefined` for the pre-config registry, whose checks run before the config
 * parse that produces it; that is what splits the two registries.
 */
interface StageOneContext {
	readonly rawModules: readonly Module[];
	readonly modules: readonly NormalisedModule[];
	readonly bootstrapComponents: BootstrapMap;
	readonly overrideComponents: Partial<ComponentMap> | undefined;
	readonly contributionKinds: ContributionKindMap | undefined;
	/**
	 * The declarations of where sections moved from: core's own section's, as
	 * module "core", when it declares any, then `rawModules`.
	 */
	readonly relocating: readonly Module[];
	readonly parsedConfig: unknown;
	/**
	 * Each switched-on module's replica-safety declaration as stage 1 read it,
	 * once, right after the switches; empty before the parse.
	 */
	readonly replicaSafety: readonly ReplicaSafetyModuleRef[];
	/** The modules their section switches off; empty before the parse. */
	readonly switchedOff: ReadonlySet<string>;
	/**
	 * Provides ∪ bootstrapComponents ∪ overrideComponents, the three component
	 * sources, and `auditSink` when a module contributes `auditHooks` (core
	 * fills it then). Wiring guards must test all three, or a composition root
	 * wiring through bootstrap or override is falsely rejected.
	 */
	readonly plannedKeys: ReadonlySet<string>;
}

/**
 * An `oauthTokenSettings` a host fills (through `bootstrapComponents` or
 * `overrideComponents`) may name no token lifetime longer than the one core
 * resolves from the configuration (`lifetimeBeyondConfiguration`, the rule
 * every reader's `checkOAuthTokenSettings` applies). A host map is known
 * before any provider runs, so it is refused here
 * (`token-settings-lifetime-exceeds-configuration`), naming the map, the
 * member and both values; a module-provided value is refused the same way
 * as stage 3 materialises it (`token-settings-slot.mts`), which also holds a
 * host's value to the contract and stores the frozen snapshot every reader
 * reads. A member that is not a number is left to that check. A
 * configuration that resolves no lifetime to bound the slot by — no
 * `oauth {}`, which only the oauth module's reference sets, or a value no
 * section schema read — is refused as the configuration it is
 * (`config-validation-failed`), naming the key.
 * @internal
 */
function checkHostTokenSettingsLifetimes(
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
	parsedConfig: unknown,
): void {
	const sources = [
		["bootstrapComponents", (bootstrapComponents as Record<string, unknown>).oauthTokenSettings],
		[
			"overrideComponents",
			(overrideComponents as Record<string, unknown> | undefined)?.oauthTokenSettings,
		],
	] as const;
	for (const [source, value] of sources) {
		if (typeof value !== "object" || value === null) continue;
		let found: ReturnType<typeof lifetimeBeyondConfiguration>;
		try {
			found = lifetimeBeyondConfiguration(value, parsedConfig);
		} catch (err) {
			// The resolvers' refusal of the configuration, the only throw here:
			// the slot's members are read without throwing, and the configuration
			// is stage 1's plain-data copy. A RangeError naming the key.
			const issues = [
				{
					code: "custom",
					path: [],
					message: (err as RangeError).message,
					input: undefined,
				} as z.core.$ZodIssue,
			];
			throw new BootError({
				message: `Config validation failed — 1 issue(s) found: ${namedIssues(issues)}. The oauthTokenSettings in ${source} is bounded by the token lifetimes the configuration resolves.`,
				reason: "config-validation-failed",
				stage: "validateManifests",
				details: {
					reason: "config-validation-failed",
					issues: issues as z.ZodIssue[],
					modules: [],
				},
				cause: err,
			});
		}
		if (found === undefined) continue;
		throw new BootError({
			stage: "validateManifests",
			reason: "token-settings-lifetime-exceeds-configuration",
			message: lifetimeBeyondConfigurationMessage(found, source),
			details: {
				reason: "token-settings-lifetime-exceeds-configuration",
				componentKey: "oauthTokenSettings",
				source,
				member: found.member,
				slotSeconds: found.slotSeconds,
				configurationSeconds: found.configurationSeconds,
			},
		});
	}
}

/** One stage-1 check: an id for humans, a spec pointer, and the run. */
export interface StageOneCheck {
	readonly id: string;
	/** Where the check's contract lives: a spec section, or an issue. */
	readonly spec: string;
	readonly run: (ctx: StageOneContext) => void;
}

/**
 * The registries are exported, so tooling and tests can read the plan, and
 * are the live structures `validateManifests` iterates, so they are frozen,
 * rows included: boot-time security validation must not be mutable by
 * anything running in-process.
 */
const freezeChecks = (checks: readonly StageOneCheck[]): readonly StageOneCheck[] =>
	Object.freeze(checks.map((check) => Object.freeze(check)));

/**
 * The checks that run before the config parse, in order: what the parse
 * itself relies on — manifests, unique names, section paths — and the
 * refusal of old paths and renamed variables. The registry order is the
 * execution order, so the first violation is the first failing row; each
 * row's `spec` names its step.
 */
export const STAGE_ONE_PRE_CONFIG_CHECKS: readonly StageOneCheck[] = freezeChecks([
	{
		id: "module-entries-are-manifests",
		spec: "A2-β §5.1 step 1 (precondition: each entry is a manifest, not its factory)",
		run: (ctx) => checkModuleEntriesAreManifests(ctx.rawModules),
	},
	{
		id: "unique-module-names",
		spec: "A2-β §5.1 step 1",
		run: (ctx) => checkUniqueModuleNames(ctx.rawModules),
	},
	{
		id: "federation-kind-guard",
		spec: "issue #728 (a federation registers through the type its entry names, whatever a module declares, switched on or not)",
		run: (ctx) => checkFederationKindGuard(ctx.rawModules, ctx.modules),
	},
	{
		id: "module-section-paths",
		spec: "issue #728 (a section is at its module's name; the paths it moved from, and the variables renamed with them)",
		run: (ctx) => checkModuleSectionPaths(ctx.rawModules, ctx.relocating),
	},
	{
		id: "relocated-config-paths",
		spec: "issue #728 (B10: a relocated path refuses boot)",
		run: (ctx) => checkRelocatedConfigPaths(ctx.relocating, ctx.bootstrapComponents),
	},
	{
		id: "renamed-environment-variables",
		spec: "issue #728 (a variable renamed with a move refuses boot while its old name is set)",
		run: (ctx) => checkRenamedEnvironmentVariables(ctx.relocating, ctx.bootstrapComponents),
	},
]);

/**
 * The checks that run after the config parse (step 13, a distinct stage in
 * `validateManifests` because it produces the parsed config and the sections
 * that say which modules are switched on), in order, over the modules switched
 * on alone: the manifest rows of steps 2–12, the wiring guards, then the
 * step-14 route-order check. A new wiring guard is a row appended before
 * `route-order-edges`.
 */
export const STAGE_ONE_POST_CONFIG_CHECKS: readonly StageOneCheck[] = freezeChecks([
	{
		id: "provides-closure",
		spec: "A2-β §5.1 step 2",
		run: (ctx) => checkProvidesClosure(ctx.modules),
	},
	{
		id: "authoritative-closure",
		spec: "issue #728 (a module's authoritative keys are keys it provides)",
		run: (ctx) => checkAuthoritativeClosure(ctx.modules),
	},
	{
		id: "reserved-host-keys",
		spec: "issue #728 (a host map's own __proto__ names no component)",
		run: (ctx) => checkReservedHostKeys(ctx.bootstrapComponents, ctx.overrideComponents),
	},
	{
		id: "bootstrap-synthetic-disjointness",
		spec: "A2-β §5.1 step 3",
		run: (ctx) =>
			checkBootstrapAndSyntheticDisjointness(
				ctx.modules,
				ctx.bootstrapComponents,
				ctx.overrideComponents,
			),
	},
	{
		id: "authoritative-overrides",
		spec: "issue #728 (a loaded module's authoritative keys have one source)",
		run: (ctx) => checkAuthoritativeOverrides(ctx.modules, ctx.overrideComponents),
	},
	{
		id: "reserved-component-keys",
		spec: "issue #728 (the module section's deps key)",
		run: (ctx) => checkReservedComponentKeys(ctx.rawModules, ctx.modules),
	},
	{
		id: "session-requirement-kind-guard",
		spec: "A2-β §5.1 (after step 3): the session-admission ADR's D3",
		run: (ctx) => checkSessionRequirementKindGuard(ctx.modules),
	},
	{
		id: "requires-closure",
		spec: "A2-β §5.1 step 4",
		run: (ctx) => checkRequiresClosure(ctx.modules, ctx.plannedKeys),
	},
	{
		id: "contribution-kind-coverage",
		spec: "A2-β §5.1 step 5",
		run: (ctx) => checkContributionKindCoverage(ctx.modules, ctx.contributionKinds),
	},
	{
		id: "contribution-containers",
		spec: "A2-β §5.1 step 5 (each kind's container is its collector's shape)",
		run: (ctx) => checkContributionContainers(ctx.modules, ctx.contributionKinds),
	},
	{
		id: "contribution-shapes",
		spec: "issue #728 (a rate-limit prefix; a federation type's declaration)",
		run: (ctx) => checkContributionShapes(ctx.modules),
	},
	{
		id: "per-kind-contribute-duplicates",
		spec: "A2-β §5.1 step 6",
		run: (ctx) => checkPerKindContributeDuplicates(ctx.modules, ctx.contributionKinds ?? {}),
	},
	{
		id: "one-session-close-notifier",
		spec: "issue #1030 (one session-close notifier; ADR 2026-10-05-session-lifecycle D16)",
		run: (ctx) => checkOneSessionCloseNotifier(ctx.modules),
	},
	{
		id: "route-collisions",
		spec: "A2-β §5.1 step 7",
		run: (ctx) => checkRouteCollisions(ctx.modules, ctx.rawModules),
	},
	{
		id: "override-targets",
		spec: "A2-β §5.1 step 8",
		run: (ctx) => checkOverrideTargets(ctx.modules, ctx.contributionKinds ?? {}),
	},
	{
		id: "override-duplicates",
		spec: "A2-β §5.1 step 9",
		run: (ctx) => checkOverrideDuplicates(ctx.modules),
	},
	{
		id: "same-module-contribute-override",
		spec: "A2-β §5.1 step 10",
		run: (ctx) => checkSameModuleContributeOverride(ctx.modules),
	},
	{
		id: "list-shaped-overrides",
		spec: "A2-β §5.1 step 11",
		run: (ctx) => checkListShapedOverrides(ctx.rawModules, ctx.contributionKinds ?? {}),
	},
	{
		id: "lifecycle-closure",
		spec: "A2-β §5.1 step 12",
		run: (ctx) => checkLifecycleClosure(ctx.modules),
	},
	{
		id: "grant-policy-issuer",
		spec: "CP-20 (restored v0.4.x guard; step 13.5)",
		run: (ctx) =>
			checkGrantPolicyIssuerInvariant(
				ctx.modules,
				ctx.parsedConfig,
				ctx.bootstrapComponents,
				ctx.overrideComponents,
			),
	},
	{
		id: "federation-stores-wiring",
		spec: "issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05 (step 13.7)",
		run: (ctx) => checkFederationStoresWiring(ctx.parsedConfig as AppConfig, ctx.plannedKeys),
	},
	{
		id: "federation-entries-handled",
		spec: "issue #728 (an enabled core.federations entry is handled by the module registering its type)",
		run: (ctx) => checkFederationEntriesHandled(ctx.modules, ctx.parsedConfig),
	},
	{
		id: "declared-absence",
		spec: "issue #363 (step 13.10)",
		run: (ctx) =>
			checkDeclaredAbsence(ctx.modules, ctx.rawModules, ctx.parsedConfig, ctx.plannedKeys),
	},
	{
		id: "replica-safety",
		spec: "issue #271 (step 13.8)",
		// The logger comes from bootstrapComponents rather than a parameter: a
		// composition root that configured one has already put it there, and
		// the warning is worthless if it goes somewhere the operator is not
		// reading.
		//
		// The declarations are each manifest's own, which normalisation does not
		// carry, read right after the switches (made from the section where a
		// module declares so): a switched-off module holds no state, whatever
		// its name, and its declaration is not read.
		run: (ctx) => {
			const bootLogger = warningLogger(ctx.bootstrapComponents);
			checkReplicaSafety({
				modules: ctx.replicaSafety,
				config: ctx.parsedConfig,
				...(bootLogger !== undefined ? { logger: bootLogger } : {}),
			});
		},
	},
	{
		id: "host-token-settings-lifetimes",
		spec: "issue #728 (a host-filled oauthTokenSettings lifetime is at most the configuration's)",
		run: (ctx) =>
			checkHostTokenSettingsLifetimes(
				ctx.bootstrapComponents,
				ctx.overrideComponents,
				ctx.parsedConfig,
			),
	},
	{
		id: "route-order-edges",
		spec: "A2-β §5.1 step 14",
		run: (ctx) => checkRouteOrderEdges(ctx.rawModules),
	},
]);

// ---------------------------------------------------------------------------
// Public API — validateManifests
// ---------------------------------------------------------------------------

/**
 * Stage 1 of the boot planner: runs {@link STAGE_ONE_PRE_CONFIG_CHECKS}, then
 * step 13 (`validateAndComposeConfig`, the one composed parse, and
 * `parseModuleSections`, which writes each module's section back into the
 * parsed config), then reads each module's switch (`section.isEnabled`) and
 * each switched-on module's replica-safety declaration, then
 * runs {@link STAGE_ONE_POST_CONFIG_CHECKS} over the modules switched on: a
 * module switched off is, from there on, its name and its section alone, so
 * it registers nothing. Last, it parses each enabled `core.federations` entry
 * of a registered type with that type's schema (`parseFederationEntries`). Returns `ValidatedManifests`, or throws a `BootError`
 * for the first violation in input order.
 *
 * Deterministic: the same inputs give the same output or error. Its only side
 * effects are boot notices to the wired logger: the configuration nothing
 * loaded reads (`logConfigNotices`) and the replica-safety warning.
 */
export function validateManifests(input: ValidateManifestsInput): ValidatedManifests {
	const { modules } = input;
	// The host maps read once, at the one boundary (`host-maps.mts`), before
	// anything else reads them: the configuration copied as frozen plain data,
	// every slot a data property. A map createApp already read is taken as is.
	const overrideComponents = snapshotHostMap(input.overrideComponents, "overrideComponents");
	const contributionKinds = snapshotHostMap(input.contributionKinds, "contributionKinds");
	// `configDefaults` is read here and is no component: no check and no later
	// stage sees it.
	const { bootstrapComponents, configDefaults } = takeConfigDefaults(
		snapshotHostMap(input.bootstrapComponents, "bootstrapComponents"),
	);

	// Normalise all modules first for efficient lookup across checks
	const normalisedModules = modules.map(normaliseModule);

	const plannedKeysOf = (normalised: readonly NormalisedModule[]): ReadonlySet<string> =>
		new Set<string>([
			...normalised.flatMap((m) => m.providesKeys as string[]),
			...Object.keys(bootstrapComponents),
			...Object.keys(overrideComponents ?? {}),
			...(contributesAuditHooks(normalised) ? ["auditSink"] : []),
		]);

	const baseContext: StageOneContext = {
		rawModules: modules,
		modules: normalisedModules,
		bootstrapComponents,
		overrideComponents,
		contributionKinds,
		relocating: withCoreRelocations(modules, input.core ?? CORE_RELOCATIONS),
		parsedConfig: undefined,
		replicaSafety: [],
		switchedOff: new Set<string>(),
		plannedKeys: plannedKeysOf(normalisedModules),
	};

	for (const check of STAGE_ONE_PRE_CONFIG_CHECKS) {
		check.run(baseContext);
	}

	// Step 13, config composition and validation, is not a registry row: it
	// produces the parsed config (Zod defaults and transforms applied) that
	// replaces the original in the returned bootstrapComponents and that every
	// post-config row reads.
	// The captures of renamed variables were judged above, and are no section.
	const rawConfig: unknown = (bootstrapComponents as Record<string, unknown>).config;
	const config = withoutRenamedVariables(rawConfig);
	const parseInput: BootstrapMap =
		config === rawConfig
			? bootstrapComponents
			: { ...bootstrapComponents, config: config as BootstrapMap["config"] };
	const composedConfig = validateAndComposeConfig(parseInput, modules);
	// Each module's own section, parsed out of that configuration by
	// the module's schema and written back at its path — before any
	// post-config row, which may assume the configuration is valid.
	// A limiter section refuses the prefixes every loaded module claims as a
	// verifier's, switched on or not: no switch is read before the parse.
	const { config: writtenConfig, sections } = withVerifierLimitDeclarations(
		declaredVerifierLimits(normalisedModules),
		() => parseModuleSections(modules, composedConfig),
	);
	// The `config` slot, and what every later row and stage reads: a frozen
	// copy (`frozenSection`), so no module changes what another — or core —
	// reads, and the host's own objects are left as it made them.
	const parsedConfig = frozenSection(writtenConfig);
	const substitutedBootstrap: BootstrapMap = {
		...bootstrapComponents,
		config: parsedConfig as BootstrapMap["config"],
	};
	// The top-level sections nothing loaded owns stay in the config slot, and
	// they and the captured variables nothing loaded declares are named once,
	// to the logger the composition wired.
	logConfigNotices(warningLogger(bootstrapComponents), {
		config: rawConfig,
		owned: ownedSections(modules),
		defaults: configDefaults,
		judged: judgedVariables(baseContext.relocating),
	});

	// A module its section switches off stays its name and its section: what
	// it would register is out of every row below and every later stage.
	const off = switchedOffModules(modules, sections);
	// Each switched-on module's replica-safety declaration, read once here, so
	// one that cannot answer is refused with what the sections answered,
	// before any wiring row.
	const replicaSafety = replicaSafetyAsRead(
		modules.filter((m) => !off.has(m.name)),
		sections,
	);
	const switchedOn = modules.map((m) => (off.has(m.name) ? switchedOff(m) : m));
	const switchedOnNormalised = normalisedModules.map((normalised, i) =>
		off.has(normalised.name) ? normaliseModule(switchedOn[i] as Module) : normalised,
	);

	const postConfigContext: StageOneContext = {
		...baseContext,
		rawModules: switchedOn,
		modules: switchedOnNormalised,
		parsedConfig,
		replicaSafety,
		switchedOff: off,
		plannedKeys: plannedKeysOf(switchedOnNormalised),
	};
	for (const check of STAGE_ONE_POST_CONFIG_CHECKS) {
		check.run(postConfigContext);
	}

	// Step 15, like step 13, is not a registry row: it produces the enabled
	// `core.federations` entries dispatched to a registered type, each parsed
	// by its type's schema, which stage 4 builds providers from. It reads the
	// declarations the rows above held, over the modules switched on.
	const dispatchedFederations = parseFederationEntries(switchedOnNormalised, parsedConfig);

	// Build output indices
	const validatedModules: ValidatedModule[] = switchedOnNormalised.map((normalised, i) => {
		const section = sections.get(normalised.name);
		return {
			manifest: switchedOn[i] as Module,
			normalised,
			...(section === undefined ? {} : { section }),
		};
	});

	const byName = new Map<string, ValidatedModule>();
	const providers = new Map<ComponentKey, ValidatedModule>();
	const usedKindsSet = new Set<ContributionKind>();

	for (const vm of validatedModules) {
		byName.set(vm.manifest.name, vm);

		for (const key of vm.normalised.providesKeys) {
			providers.set(key, vm);
		}

		for (const entry of vm.normalised.contributesEntries) {
			usedKindsSet.add(entry.kind);
		}
		for (const entry of vm.normalised.overridesEntries) {
			usedKindsSet.add(entry.kind);
		}
	}

	return {
		modules: validatedModules,
		byName,
		providers,
		usedKinds: usedKindsSet,
		bootstrapComponents: substitutedBootstrap,
		dispatchedFederations,
		undeclaredAbsenceSlots: undeclaredAbsenceSlotsOf(
			switchedOnNormalised,
			switchedOn,
			parsedConfig,
		),
		federationStoreSlots: federationStoreSlotsOf(parsedConfig as AppConfig),
	};
}
