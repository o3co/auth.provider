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
 * boot/validate-manifests.mts — Stage 1 of the A2-β boot planner pipeline.
 *
 * Accepts the consumer's `Module[]`, `bootstrapComponents`,
 * `contributionKinds`, and `overrideComponents`; runs the two ordered check
 * registries below against the manifests — the first row refusing an entry
 * that is a module factory rather than the manifest it builds; emits
 * `ValidatedManifests` on success or throws a typed `BootError` on the first
 * violation in input-array order.
 *
 * The stage is **deterministic and side-effect-free**: same inputs → same
 * output / same error.
 *
 * Per A2-β §5.1.
 */

import { isDeepStrictEqual } from "node:util";
import type { z } from "zod";
import type { AppConfig } from "../config/application.schema.mjs";
import {
	defineConfigKey,
	isPlainConfigObject,
	operatorPath,
	overlayConfig,
	TransitionalConfigSchema,
} from "../config/composed.mjs";
import {
	findRelocatedKeys,
	type RelocatedPath,
	relocatedKeyMessage,
} from "../config/removed-keys.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type {
	FederationInstance,
	FederationTypeContribution,
} from "../modules/manifest/contributes-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { RouteContribution } from "../modules/manifest/route-contribution.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "../modules/manifest/synthetic-keys.mjs";
import { failureSummary } from "./failure-summary.mjs";
import { checkReplicaSafety } from "./replica-safety.mjs";
import type {
	BootstrapMap,
	ContributionEntry,
	ContributionKind,
	ContributionKindMap,
	NormalisedModule,
	RegisteredFederationType,
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
 *
 * Per A2-β §5.1.
 */
export interface ValidateManifestsInput {
	readonly modules: readonly Module[];
	readonly bootstrapComponents: BootstrapMap;
	/** The merged collectors: core's built-ins under the host's. */
	readonly contributionKinds?: ContributionKindMap;
	readonly overrideComponents?: Partial<ComponentMap>;
}

// ---------------------------------------------------------------------------
// Module normalisation (per plan §3.3 normaliseModule)
// ---------------------------------------------------------------------------

/**
 * What each `federationTypes` declaration was read as, once, at stage 1 — its
 * `entrySchema` and `factory` — keyed by the registration factory
 * `nameKeyedFactory` answered for it. The shape check reads these, and the
 * registration closes over the same values, so what is checked is what
 * registers, and a declaration changed afterwards changes neither.
 */
const federationTypeSnapshots = new WeakMap<
	object,
	{ readonly entrySchema: unknown; readonly factory: unknown }
>();

/**
 * The factory a name-keyed entry registers through. A `federationTypes`
 * entry is a declaration, `{ entrySchema, factory }` (#728), not a factory of
 * the value it registers: its schema and factory are read once, here, and
 * what registers is `RegisteredFederationType` — that schema, and `create`,
 * that factory bound to the module's deps, which the stage-4 pass builds from
 * the deps it hands every factory. The snapshot's shape is held at stage 1
 * (`checkContributionShapes`). A declaration that is not an object is left as
 * it is, for that check to refuse. Every other value is its own factory.
 */
function nameKeyedFactory(kind: string, value: unknown): unknown {
	if (kind !== "federationTypes" || typeof value !== "object" || value === null) return value;
	const { entrySchema, factory } = value as {
		readonly entrySchema?: unknown;
		readonly factory?: unknown;
	};
	const register = (deps: Record<string, unknown>): RegisteredFederationType =>
		Object.freeze({
			entrySchema: entrySchema as z.ZodType,
			// Called as the method it was declared as, on the declaration.
			create: (instance: FederationInstance<unknown>) =>
				(factory as FederationTypeContribution<Record<string, unknown>>["factory"]).call(
					value,
					deps,
					instance,
				),
		});
	federationTypeSnapshots.set(register, { entrySchema, factory });
	return register;
}

/**
 * Flatten a raw Module manifest into a NormalisedModule for fast lookup
 * by subsequent checks. Collects:
 * - `requires` / `optional` key arrays
 * - `providesKeys` from `Object.keys(module.provides ?? {})`
 * - `contributesEntries` / `overridesEntries` as flat ContributionEntry[]
 * - `lifecycleKeys` from `Object.keys(module.lifecycle ?? {})`
 *
 * @internal
 */
function normaliseModule(m: Module): NormalisedModule {
	const requires = (m.requires ?? []) as readonly ComponentKey[];
	const optional = (m.optional ?? []) as readonly ComponentKey[];
	const providesKeys = Object.keys(m.provides ?? {}) as ComponentKey[];

	const contributesEntries: ContributionEntry[] = [];
	for (const [kind, kindMap] of Object.entries(m.contributes ?? {})) {
		if (Array.isArray(kindMap)) {
			// List-shaped kinds: auditHooks, routes, grantPolicyHooks, grantMiddleware
			for (const factory of kindMap) {
				contributesEntries.push({
					kind: kind as ContributionKind,
					key: Symbol(kind),
					factory,
					contributedBy: m.name,
				});
			}
		} else if (kindMap !== null && typeof kindMap === "object") {
			// Name-keyed kinds: grants, federations, tokenExchangeValidators, mfaFactors, …
			for (const [name, value] of Object.entries(kindMap as Record<string, unknown>)) {
				contributesEntries.push({
					kind: kind as ContributionKind,
					key: name,
					factory: nameKeyedFactory(kind, value),
					contributedBy: m.name,
				});
			}
		}
	}

	const overridesEntries: ContributionEntry[] = [];
	for (const [kind, kindMap] of Object.entries(m.overrides ?? {})) {
		if (Array.isArray(kindMap)) {
			for (const factory of kindMap) {
				overridesEntries.push({
					kind: kind as ContributionKind,
					key: Symbol(kind),
					factory,
					contributedBy: m.name,
				});
			}
		} else if (kindMap !== null && typeof kindMap === "object") {
			for (const [name, value] of Object.entries(kindMap as Record<string, unknown>)) {
				overridesEntries.push({
					kind: kind as ContributionKind,
					key: name,
					factory: nameKeyedFactory(kind, value),
					contributedBy: m.name,
				});
			}
		}
	}

	const lifecycleKeys = Object.keys(m.lifecycle ?? {}) as ComponentKey[];

	return {
		name: m.name,
		requires,
		optional,
		providesKeys,
		contributesEntries,
		overridesEntries,
		lifecycleKeys,
	};
}

// ---------------------------------------------------------------------------
// Built-in contribution kinds — auto-wired by core; no collector required
// ---------------------------------------------------------------------------

const BUILTIN_CONTRIBUTION_KINDS = new Set<string>([
	"grants",
	"federations",
	"federationRedirectPolicies",
	"tokenExchangeValidators",
	"mfaFactors",
	"sessionRequirements",
	"auditHooks",
	"routes",
	"grantPolicyHooks",
	"grantMiddleware",
	"tokenBindingMechanisms",
	"discoveryMetadata",
	"rateLimitBudgets",
	"federationTypes",
]);

// ---------------------------------------------------------------------------
// Before step 1 — every entry is a manifest
// ---------------------------------------------------------------------------

/**
 * A `modules` entry that is a function is a module factory listed without
 * being called — `deviceGrantModule` where `deviceGrantModule({ config })`
 * was meant, or `sessionStoreModuleFor` for `sessionStoreModuleFor(config)`.
 * Factories take different arguments, so the message does not guess them.
 * `Module` requires only `name`, and a function has one, so the compiler
 * accepts the entry; every other check below would then read it as
 * a manifest that declares nothing, and boot would succeed with the module's
 * grants, routes and refusals all silently absent. Refused first, before any
 * check reads a field of it.
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
// Per A2-β §5.1 step 1.
// ---------------------------------------------------------------------------

/**
 * Step 1: Two manifests with the same `name` throw `duplicate-module-name`.
 * Per A2-β §5.1 step 1.
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
// Per A2-β §5.1 step 2.
// ---------------------------------------------------------------------------

/**
 * Step 2: Two modules providing the same ComponentKey throw `duplicate-provides`.
 * Per A2-β §5.1 step 2.
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
// Step 3 — Bootstrap closure, substitution-channel disjointness, and
//          synthetic-key constraint.
// Per A2-β §5.1 step 3.
// ---------------------------------------------------------------------------

/**
 * Step 3: Check bootstrap/overrideComponents/synthetic-key constraints.
 * Per A2-β §5.1 step 3.
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
					message: `Module "${m.name}" attempts to provide synthetic key "${key}", which is reserved for the boot planner.`,
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
				message: `bootstrapComponents contains synthetic key "${key}", which is reserved for the boot planner.`,
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
				message: `overrideComponents contains synthetic key "${key}", which is reserved for the boot planner.`,
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
// Per A2-β §5.1 step 4.
// ---------------------------------------------------------------------------

/**
 * Build the diagnostic `path` chain from the entry-point module (`rootModule`)
 * down to the failing module `F` along the requires→provides chain.
 *
 * Per A2-β §5.1 step 4 normative algorithm.
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

	// Backward walk: from F, find the "root" by stepping to the earliest-
	// input-array requirer (the module whose requires is satisfied by F's
	// provides). Tie-break by lexicographically smallest name. Halt when no
	// requirer exists or visited-set hit.
	//
	// During the walk, record each step as a parent-pointer link
	// `{ child, parent, viaKey }` where `viaKey` is the lexicographically
	// smallest key in `child.requires` whose provider is `parent`. Reversing
	// the recorded links yields the forward chain rootModule → ... → F with
	// each link's `requires` key already chosen — no second forward walk is
	// needed (and no chance the walk dead-ends short of F, which was the
	// failure mode of the previous greedy reconstruction). Per multi-agent
	// review (Claude S2).
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
		// viaKey is guaranteed non-undefined: bestRequirer was selected because
		// some key of its requires has provider === current. The biome-ignore
		// reflects that invariant.
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
// The session-admission ADR's D3.
// ---------------------------------------------------------------------------

/** The two kinds no composition may replace the collector of, or override an entry of (the session-admission ADR's D3). */
const GUARDED_KINDS = ["sessionRequirements", "mfaFactors"] as const;

/**
 * The kinds whose collector is the planner's alone (#728): a host collector
 * for `rateLimitBudgets` could answer a looser budget than the owning module
 * contributed — on RFC 8628 §5.1's device-verification prefix, say — and
 * `federationTypes` is what the dispatch of configured federations will read.
 * Unlike `GUARDED_KINDS`, a module may override an entry of either.
 */
const PLANNER_OWNED_KINDS = ["rateLimitBudgets", "federationTypes"] as const;

/**
 * A requirement is switched off by not installing it, and nothing may
 * quietly remove one from behind the consumers: a module's
 * `overrides.sessionRequirements` is refused here, at stage 1 —
 * `session-requirement-kind-guarded`. A host collector for
 * `sessionRequirements` — or for `mfaFactors`, whose projection the MFA
 * requirement's reach is recomputed from — is refused under the same reason
 * by `refuseGuardedHostKinds`, in `createApp` before the kinds are merged.
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
 * The host's `contributionKinds` held to the same rule, in `createApp`
 * before the kinds are merged and before stage 1 (the session-admission
 * ADR's D3): a collector for `sessionRequirements` or `mfaFactors` the host
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
				message: `contributionKinds replaces the collector for "${kind}", which is the planner's: the modules that own its entries contribute them, and a module may override one.`,
				reason: "contribution-kind-guarded",
				stage: "validateManifests",
				details: { reason: "contribution-kind-guarded", kind },
			});
		}
	}
}

/** What a container that is not a record is called in a refusal. */
const containerShape = (container: unknown): string =>
	container === null ? "null" : Array.isArray(container) ? "an array" : `a ${typeof container}`;

/**
 * What a `rateLimitBudgets` or `federationTypes` contribution must be, read off
 * the manifest before any factory runs (#728), for contributions and
 * overrides alike:
 *
 * - the kind's container, a record keyed by prefix or by type — not an array,
 *   which normalisation would read as list-shaped and file under Symbol keys,
 *   not a function nor `null`, which it would pass over;
 * - a prefix a limiter key can carry before its first `:` — not empty,
 *   holding no `:` — whatever the budget's factory will answer, a `null`
 *   included;
 * - a declaration that is an object with a Zod `entrySchema` and a `factory`
 *   function, as normalisation read it once (`federationTypeSnapshots`), so
 *   one written in JavaScript is refused as itself rather than as a
 *   `TypeError` at registration.
 *
 * Throws `contribution-malformed`; `name` is absent for a container.
 * @internal
 */
function checkContributionShapes(
	rawModules: readonly Module[],
	modules: readonly NormalisedModule[],
): void {
	const refuse = (
		m: Module,
		kind: "rateLimitBudgets" | "federationTypes",
		name: string | undefined,
		channel: "contributes" | "overrides",
		problem: string,
	): never => {
		throw new BootError({
			message: `Module "${m.name}" ${channel} ${kind}${name === undefined ? "" : ` "${name}"`}: ${problem}.`,
			reason: "contribution-malformed",
			stage: "validateManifests",
			details: {
				reason: "contribution-malformed",
				module: m.name,
				kind,
				...(name === undefined ? {} : { name }),
				channel,
				problem,
			},
		});
	};
	rawModules.forEach((m, index) => {
		for (const channel of ["contributes", "overrides"] as const) {
			const map = m[channel] as Readonly<Record<string, unknown>> | undefined;
			for (const [kind, keyedBy] of [
				["rateLimitBudgets", "prefix"],
				["federationTypes", "type"],
			] as const) {
				const container = map?.[kind];
				if (container === undefined) continue;
				if (typeof container !== "object" || container === null || Array.isArray(container)) {
					refuse(
						m,
						kind,
						undefined,
						channel,
						`the kind takes a record keyed by ${keyedBy}, not ${containerShape(container)}`,
					);
				}
			}
			for (const prefix of Object.keys(m[channel]?.rateLimitBudgets ?? {})) {
				if (prefix.length === 0 || prefix.includes(":")) {
					refuse(
						m,
						"rateLimitBudgets",
						prefix,
						channel,
						`a prefix is what a limiter key carries before its first ":", so it is not empty and holds no ":"`,
					);
				}
			}
			const normalised = modules[index];
			const entries =
				channel === "contributes" ? normalised?.contributesEntries : normalised?.overridesEntries;
			for (const entry of entries ?? []) {
				if (entry.kind !== "federationTypes" || typeof entry.key !== "string") continue;
				const snapshot = federationTypeSnapshots.get(entry.factory as object);
				if (snapshot === undefined) {
					refuse(
						m,
						"federationTypes",
						entry.key,
						channel,
						"a declaration is an object with an entrySchema and a factory",
					);
				}
				const { entrySchema, factory } = snapshot as {
					readonly entrySchema: unknown;
					readonly factory: unknown;
				};
				if (typeof (entrySchema as { safeParse?: unknown } | null)?.safeParse !== "function") {
					refuse(m, "federationTypes", entry.key, channel, "its entrySchema is not a Zod schema");
				}
				if (typeof factory !== "function") {
					refuse(m, "federationTypes", entry.key, channel, "its factory is not a function");
				}
			}
		}
	});
}

/**
 * Step 4: Requires/optional closure check.
 * For each module, every key in `requires` must appear in either
 * `bootstrapComponents`, the union of all modules' `provides`, or
 * `overrideComponents`, or be in the synthetic-key set (auto-satisfied).
 * Per A2-β §5.1 step 4.
 * @internal
 */
function checkRequiresClosure(
	modules: readonly NormalisedModule[],
	bootstrap: BootstrapMap,
	override: Partial<ComponentMap> | undefined,
): void {
	const bootstrapKeys = new Set<string>(Object.keys(bootstrap));
	const overrideKeys = new Set<string>(Object.keys(override ?? {}));

	// Build a map: ComponentKey → providing NormalisedModule
	const providerIndex = new Map<ComponentKey, NormalisedModule>();
	for (const m of modules) {
		for (const key of m.providesKeys) {
			providerIndex.set(key, m);
		}
	}

	const isSatisfied = (key: ComponentKey): boolean =>
		bootstrapKeys.has(key) ||
		overrideKeys.has(key) ||
		providerIndex.has(key) ||
		SYNTHETIC_COMPONENT_KEYS.has(key);

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
// Per A2-β §5.1 step 5.
// ---------------------------------------------------------------------------

/**
 * Step 5: Every contribution kind referenced by a module must have a
 * collector (built-in kinds are auto-wired; custom kinds need a
 * `contributionKinds` entry).
 * Per A2-β §5.1 step 5.
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

// ---------------------------------------------------------------------------
// Step 6 — Per-kind duplicate contributes check (name-keyed kinds)
// Per A2-β §5.1 step 6.
// ---------------------------------------------------------------------------

/**
 * Step 6: For name-keyed kinds, (kind, name) collisions across modules throw
 * `duplicate-contribute`. List-shaped kinds are handled in step 7 (routes)
 * or silently deduplicated (auditHooks, grantPolicyHooks per A2-α §4.5).
 *
 * Dispatches on `collector.kind === "name-keyed"` rather than a hardcoded
 * built-in name set, so consumer-defined name-keyed kinds (added via
 * declare-module augmentation of ContributionCollectorMap) are also
 * duplicate-checked. Mirrors the Task 6 fixup applied in
 * apply-contributions.mts (commit 4d03cc0b).
 *
 * Per A2-β §5.1 step 6.
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

// ---------------------------------------------------------------------------
// Step 7 — RouteContribution collision check
// Per A2-β §5.1 step 7.
// ---------------------------------------------------------------------------

/**
 * Collect all RouteContribution objects from modules' contributes.routes
 * (only static values at validate-manifests time; factories are not invoked
 * in this stage per A2-β §5.1).
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
 * Per A2-β §5.1 step 7.
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
// Step 7.5 — Federation / federationRedirectPolicies pairing invariant
// Per A5 §8.2.
// ---------------------------------------------------------------------------

/**
 * Step 7.5: Every `federations[name]` contribution MUST have a matching
 * `federationRedirectPolicies[name]` contribution and vice versa.
 *
 * Throws BootError({ reason: "federation-redirect-policy-unpaired" }).
 * Per A5 §8.2.
 * @internal
 */
function checkFederationRedirectPolicyPairing(modules: readonly NormalisedModule[]): void {
	const federationNames = new Map<string, string>(); // name → first contributing module
	const policyNames = new Map<string, string>(); // name → first contributing module

	// Inspect both contributes and overrides: a name is considered "registered"
	// for pairing-invariant purposes if EITHER side declares it (per spec §8.2
	// intent — "policy is registered for this name from somewhere"). Walking
	// only contributesEntries would mis-diagnose the case where Module A
	// contributes federations[google] and Module B overrides
	// federationRedirectPolicies[google]: pairing would fire
	// "federation-without-policy" for google before step 8 (override-target-
	// missing) could surface the more precise "override has no contribute
	// target" error.
	for (const m of modules) {
		const allEntries = [...m.contributesEntries, ...m.overridesEntries];
		for (const entry of allEntries) {
			if (entry.kind === "federations" && typeof entry.key === "string") {
				if (!federationNames.has(entry.key)) {
					federationNames.set(entry.key, m.name);
				}
			} else if (entry.kind === "federationRedirectPolicies" && typeof entry.key === "string") {
				if (!policyNames.has(entry.key)) {
					policyNames.set(entry.key, m.name);
				}
			}
		}
	}

	for (const [name, contributedBy] of federationNames) {
		if (!policyNames.has(name)) {
			throw new BootError({
				message: `Federation "${name}" (contributed by "${contributedBy}") has no matching federationRedirectPolicies["${name}"] contribution.`,
				reason: "federation-redirect-policy-unpaired",
				stage: "validateManifests",
				details: {
					reason: "federation-redirect-policy-unpaired",
					name,
					side: "federation-without-policy",
					contributedBy,
				},
			});
		}
	}

	for (const [name, contributedBy] of policyNames) {
		if (!federationNames.has(name)) {
			throw new BootError({
				message: `federationRedirectPolicies["${name}"] (contributed by "${contributedBy}") has no matching federations["${name}"] contribution.`,
				reason: "federation-redirect-policy-unpaired",
				stage: "validateManifests",
				details: {
					reason: "federation-redirect-policy-unpaired",
					name,
					side: "policy-without-federation",
					contributedBy,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13.5 — CP-20 grantPolicy / jwt.issuer consistency invariant
//
// Restores the v0.4.x guard. When `grantPolicy` is wired through ANY of the
// three supported component sources — module `provides`, `bootstrapComponents`,
// or `overrideComponents` — the configured issuer must be a non-empty string.
// The policy hook signs decisions against that issuer; an empty value silently
// disables CP-18 fail-closed enforcement at the JWT layer. Runs after step 13
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
	if (typeof issuer === "string" && issuer.length > 0) return;

	throw new BootError({
		message: `CP-20 invariant: config.oauth.jwt.issuer must be a non-empty string when grantPolicy is wired (provided by "${providedBy}"). Empty issuer turns CP-18 fail-closed enforcement into silent allow-all at the JWT layer.`,
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
// Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05.
// ---------------------------------------------------------------------------

const FEDERATION_REQUIRED_STORES = [
	"userSessionStore",
	"sessionRPRegistry",
	"sessionFamilyIndex",
	"sessionFederationIndex",
	"federationTokenStore",
	"refreshTokenFamilyRevocation",
] as const;

/**
 * If any `config.federations.<name>.enabled === true`, all 6 session/
 * federation/refresh-token-family slots MUST be present in the planned
 * component set. A missing store causes federation routes either to 503 at
 * runtime with an opaque error (session/federationToken stores) or to never
 * mount at all (refreshTokenFamilyRevocation — see packages/oauth/src/routes.mts
 * `logoutSupported` / `federationTokenSupported` gates), surfacing as
 * unexpected 404s. Both failure modes are equally opaque from the operator's
 * perspective; the validator surfaces them at boot time.
 *
 * Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05; refreshTokenFamilyRevocation
 * gating added per #103 review (alignment with route-level gating in oauth/routes.mts).
 */
export function checkFederationStoresWiring(
	config: AppConfig,
	plannedKeys: ReadonlySet<string>,
): void {
	const federations = (config.federations ?? {}) as Record<string, { enabled?: boolean }>;
	for (const [name, fed] of Object.entries(federations)) {
		if (fed?.enabled !== true) continue;
		const missing = FEDERATION_REQUIRED_STORES.filter((k) => !plannedKeys.has(k));
		if (missing.length > 0) {
			throw new BootError({
				stage: "validateManifests",
				reason: "federation-stores-incomplete",
				message: `federations.${name} is enabled but required federation stores are missing: ${missing.join(", ")}`,
				details: { reason: "federation-stores-incomplete", federationName: name, missing },
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Declared-absence guard
// Per issue #363; #375 folded #277's access-token check onto it.
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
 * Generic enforcement for `ModuleSpec.absencePolicies` (#363): every optional
 * key carrying a policy must be filled from one of the three component
 * sources, or the config must carry the policy's declared-absent value.
 * Otherwise boot refuses with `component-absence-undeclared` — the capability
 * slot cannot be a silent no-op, which is the failure mode #277 (revocation),
 * #287 (audit sink) and #322 (subject revocation) all shipped.
 *
 * Two modules attaching *different* policies to the same key is refused
 * outright, even when the absence is declared: the boot error's advice must
 * not depend on module input order, and the bundled modules share one policy
 * constant per key (e.g. `AUDIT_SINK_ABSENCE_POLICY`) precisely so this
 * cannot happen by accident.
 *
 * `consumedBy` follows `checkAccessTokenRevocationWiring`'s reading: every
 * module naming the key in `requires` / `optional` is the evidence that the
 * slot is part of this app's surface. That check (#277, step 13.9) predates
 * this vocabulary and keeps its spec-pinned reason; new absence rules attach
 * an `AbsencePolicy` instead of adding another bespoke stage.
 */
function checkDeclaredAbsence(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
	config: unknown,
	plannedKeys: ReadonlySet<string>,
): void {
	interface Collected {
		readonly policy: {
			readonly configKey: readonly string[];
			readonly absentValue: string;
			readonly hint: string;
		};
		readonly declaredBy: string[];
	}
	const byKey = new Map<string, Collected>();
	// Step 1 (checkUniqueModuleNames) has run, so the name lookup is total.
	const normalisedByName = new Map(modules.map((nm) => [nm.name, nm]));

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

	for (const [key, { policy }] of byKey) {
		if (plannedKeys.has(key)) continue;
		if (readConfigPath(config, policy.configKey) === policy.absentValue) continue;

		const consumedBy = modules
			.filter(
				(m) =>
					(m.requires as readonly string[]).includes(key) ||
					(m.optional as readonly string[]).includes(key),
			)
			.map((m) => m.name);
		const configKeyDotted = policy.configKey.join(".");

		throw new BootError({
			message:
				`Component "${key}" is read by ` +
				`${consumedBy.length === 1 ? `module "${consumedBy[0]}"` : `modules [${consumedBy.join(", ")}]`} ` +
				"but nothing provides it, and its absence is not declared. " +
				`Wire a provider, or set ${configKeyDotted} = "${policy.absentValue}" to declare ` +
				`the capability absent on purpose. ${policy.hint}`,
			reason: "component-absence-undeclared",
			stage: "validateManifests",
			details: {
				reason: "component-absence-undeclared",
				componentKey: key as ComponentKey,
				consumedBy,
				configKey: configKeyDotted,
				absentValue: policy.absentValue,
			},
		});
	}
}

// ---------------------------------------------------------------------------
// Step 8 — Override target existence
// Per A2-β §5.1 step 8.
// ---------------------------------------------------------------------------

/**
 * Step 8: Every `overrides[kind][name]` must have a matching target. The
 * target is satisfied by EITHER:
 *   1. some module's `contributes[kind][name]`, OR
 *   2. an entry pre-seeded in the consumer-supplied name-keyed collector
 *      (`contributionKinds[kind].get(name) !== undefined`).
 *
 * Carve-out (2) keeps validate-stage and apply-stage in agreement: §5.4
 * step 2 routes overrides through `collector.replace(name, value)`, which
 * succeeds whenever the collector already has an entry for `name` —
 * regardless of whether that entry came from a module or from a host-
 * supplied pre-seeded collector. Without this carve-out, the documented
 * "consumer extension via pre-loaded collector" path is rejected at
 * validate-stage and would never reach apply-stage. Per multi-agent
 * review (Codex P2).
 *
 * Per A2-β §5.1 step 8.
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
// Per A2-β §5.1 step 9.
// ---------------------------------------------------------------------------

/**
 * Step 9: Two modules overriding the same (kind, name) throw
 * `duplicate-override`.
 * Per A2-β §5.1 step 9.
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
// Per A2-β §5.1 step 10.
// ---------------------------------------------------------------------------

/**
 * Step 10: A single module declaring both `contributes[kind][name]` and
 * `overrides[kind][name]` for the same (kind, name) throws
 * `contribute-and-override-same-key`.
 * Per A2-β §5.1 step 10.
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
// Per A2-β §5.1 step 11.
// ---------------------------------------------------------------------------

/**
 * Step 11: A module's `overrides` carrying any list-shaped kind throws
 * `list-shaped-override-not-allowed`.
 *
 * Dispatches on `collector.kind === "list" | "list-routes"` so consumer-
 * defined list-shaped kinds are also caught. Mirrors the Task 6 fixup
 * applied in apply-contributions.mts (commit 4d03cc0b). The built-in
 * list-shaped kinds (routes, auditHooks, grantPolicyHooks, grantMiddleware)
 * match by collector identity; consumer-defined kinds with list-shaped
 * collectors match the same way.
 *
 * The `details.kind` literal is typed as the built-in union
 * `"routes" | "auditHooks" | "grantPolicyHooks" | "grantMiddleware"` per
 * spec §6.1 `ListShapedOverrideDetails`; a consumer-defined kind name is
 * widened via cast since the Details type does not yet model consumer
 * extensions.
 *
 * Per A2-β §5.1 step 11.
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
// Per A2-β §5.1 step 12.
// ---------------------------------------------------------------------------

/**
 * Step 12: A `lifecycle[K]` entry whose `K` does not appear in the same
 * module's `provides` throws `lifecycle-without-provides`.
 * Per A2-β §5.1 step 12.
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
// Step 13 — the one composed parse (#728)
// Per A2-β §5.1 step 13.
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

/**
 * Step 13: parse the configuration a composition root handed over —
 * `bootstrapComponents.config`, as it resolved it — once, with every schema
 * that reads it:
 *
 * 1. the transitional base (`TransitionalConfigSchema`): core's own sections
 *    and every section core's schema still mirrors for a package, each
 *    optional, with the coercions and checks they always applied — so a
 *    mirrored section is validated when the configuration carries it,
 *    whether or not the module that reads it is loaded, until the move pull
 *    requests take the mirrors out (#728);
 * 2. laid over what was written (`overlayConfig`), so a key no schema
 *    declares — at the top or under a section core declares — is kept;
 * 3. then each module's `configSchema`, over the base's output rather than
 *    what was written — so a module's schema reads an environment variable's
 *    string as the base coerced it — each laid over the result the same way.
 *
 * Returns the composed configuration: what the `config` slot holds once
 * each module's section is written back into it (`parseModuleSections`).
 * Every refused value is one `config-validation-failed` naming each operator
 * path: the base's alone when the base refuses — the modules' schemas read
 * its output, and there is none — else every module schema's.
 * Per A2-β §5.1 step 13.
 * @internal
 */
function validateAndComposeConfig(modules: readonly Module[], bootstrap: BootstrapMap): unknown {
	const participants: { readonly module: string; readonly schemaPath?: string }[] = [];
	const issues: z.core.$ZodIssue[] = [];
	const raw: unknown = (bootstrap as Record<string, unknown>).config;

	for (const m of modules) if (m.configSchema) participants.push({ module: m.name });

	const base = TransitionalConfigSchema.safeParse(raw);
	// The modules' schemas read the base's output. Without one there is
	// nothing for them to read: over what was written they would refuse the
	// environment strings the base coerces, errors nobody made.
	if (!base.success) issues.push(...base.error.issues);
	const overlaid = base.success ? overlayConfig(raw, base.data) : raw;

	let composed = overlaid;
	const outputs: { readonly module: string; readonly data: unknown }[] = [];
	for (const m of base.success ? modules : []) {
		if (!m.configSchema) continue;
		const result = m.configSchema.safeParse(overlaid);
		if (!result.success) {
			issues.push(...result.error.issues);
			continue;
		}
		outputs.push({ module: m.name, data: result.data });
		composed = overlayConfig(composed, result.data);
	}
	issues.push(...conflictingOutputs(outputs));

	if (issues.length > 0) {
		throw new BootError({
			message: `Config validation failed — ${issues.length} issue(s) found: ${namedIssues(issues)}.`,
			reason: "config-validation-failed",
			stage: "validateManifests",
			details: {
				reason: "config-validation-failed",
				issues: issues as z.ZodIssue[],
				modules: participants,
			},
		});
	}
	return composed;
}

/**
 * Every key two modules' `configSchema`s make different values of, as one
 * issue each at its path naming both modules — never the values, which may be
 * secrets. Their outputs are laid over each other in module order, so a
 * disagreement would otherwise go to whichever module is listed later: the
 * refusal Zod's intersection gave (`Unmergable intersection`) when the
 * schemas were composed into one. A leaf is a value that is not a plain
 * object (a list is one value); a leaf one output holds where another holds
 * keys under it disagrees too. Equal values (`isDeepStrictEqual`) agree.
 */
function conflictingOutputs(
	outputs: readonly { readonly module: string; readonly data: unknown }[],
): z.core.$ZodIssue[] {
	const leaves = new Map<string, { readonly module: string; readonly value: unknown }>();
	const branches = new Map<string, string>();
	const conflicts = new Map<
		string,
		{ readonly path: readonly string[]; readonly modules: [string, string] }
	>();
	const conflict = (path: readonly string[], first: string, second: string) => {
		const key = JSON.stringify(path);
		if (first !== second && !conflicts.has(key))
			conflicts.set(key, { path, modules: [first, second] });
	};
	const walk = (module: string, value: unknown, path: readonly string[]) => {
		const key = JSON.stringify(path);
		if (isPlainConfigObject(value) && Object.keys(value).length > 0) {
			const leaf = leaves.get(key);
			if (leaf !== undefined) conflict(path, leaf.module, module);
			if (!branches.has(key)) branches.set(key, module);
			for (const name of Object.keys(value)) walk(module, value[name], [...path, name]);
			return;
		}
		const branch = branches.get(key);
		if (branch !== undefined) conflict(path, branch, module);
		const leaf = leaves.get(key);
		if (leaf === undefined) leaves.set(key, { module, value });
		else if (!isDeepStrictEqual(leaf.value, value)) conflict(path, leaf.module, module);
	};
	for (const { module, data } of outputs) walk(module, data, []);
	return [...conflicts.values()].map(
		({ path, modules: [first, second] }) =>
			({
				code: "custom",
				path: [...path],
				message: `module "${first}"'s configSchema and module "${second}"'s make different values of it`,
				input: undefined,
			}) as z.core.$ZodIssue,
	);
}

/**
 * The top-level sections of the configuration as written that nothing owns
 * (#728 B8), sorted: not a section core's transitional base declares — its
 * own, or one it mirrors — not a top-level key of a loaded module's
 * `configSchema`, and not the first key of a loaded module's section path.
 * Boot keeps them in the `config` slot and names them once in the log; a
 * misspelt section name is what an operator finds there.
 * @internal
 */
function ignoredSections(modules: readonly Module[], raw: unknown): readonly string[] {
	if (!isPlainConfigObject(raw)) return [];
	const owned = new Set<string>(Object.keys(TransitionalConfigSchema.shape));
	for (const m of modules) {
		for (const key of Object.keys(m.configSchema?.shape ?? {})) owned.add(key);
		if (m.section !== undefined) owned.add(sectionSegmentsOf(m)[0] as string);
	}
	return Object.keys(raw)
		.filter((key) => !owned.has(key))
		.sort();
}

// ---------------------------------------------------------------------------
// Step 13, second half — each module's own configuration section (#728)
// ---------------------------------------------------------------------------

/**
 * The dot-separated path a module's section is read at: its manifest's
 * `section.at`, or else the module's name, whole — a module's name is the
 * section's key as the manifest writes it, and is not split on dots.
 */
function sectionPathOf(m: Module): string {
	return m.section?.at ?? m.name;
}

/** The keys of a dot-separated section path; a module's own name is one key. */
function sectionSegmentsOf(m: Module): readonly string[] {
	return m.section?.at === undefined ? [m.name] : m.section.at.split(".");
}

/**
 * A parsed section as every factory of its module receives it: plain data —
 * arrays, and objects whose prototype is `Object.prototype` or `null` —
 * copied and frozen all the way down, so no factory can change what another
 * reads, and a subtree the schema passed through (`z.unknown()`) is not the
 * `config` slot's own object. Anything else — a `URL`, a `Buffer`, a class
 * instance a transform built — is handed over as the schema made it: freezing
 * a typed array throws, and copying an instance would lose what it is.
 */
function frozenSection(value: unknown, copies = new Map<object, unknown>()): unknown {
	if (value === null || typeof value !== "object") return value;
	const known = copies.get(value);
	if (known !== undefined) return known;
	if (Array.isArray(value)) {
		const copy: unknown[] = [];
		copies.set(value, copy);
		for (const item of value) copy.push(frozenSection(item, copies));
		return Object.freeze(copy);
	}
	const prototype: unknown = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) return value;
	// The same prototype as the original: `Object.prototype`, or none.
	const copy: object = prototype === null ? Object.setPrototypeOf({}, null) : {};
	copies.set(value, copy);
	for (const key of Reflect.ownKeys(value)) {
		if (!Object.prototype.propertyIsEnumerable.call(value, key)) continue;
		// Defined, not assigned: a key named `__proto__` stays a key.
		Object.defineProperty(copy, key, {
			value: frozenSection((value as Record<PropertyKey, unknown>)[key], copies),
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return Object.freeze(copy);
}

/**
 * Parse one section with its schema. A schema that throws instead of
 * answering — an async refinement (Zod cannot finish it synchronously), or a
 * transform that throws — is one more issue at the section's own path, so it
 * refuses boot the way a refused value does, naming the path, rather than
 * escaping stage 1 as a bare error.
 */
function parseSection(
	schema: z.ZodType,
	value: unknown,
): { readonly data: unknown } | { readonly issues: readonly z.ZodIssue[] } {
	try {
		const result = schema.safeParse(value);
		return result.success ? { data: result.data } : { issues: result.error.issues };
	} catch (thrown) {
		return {
			issues: [
				{
					code: "custom",
					path: [],
					message: `the section's schema threw instead of answering, so it could not be parsed synchronously: ${failureSummary(thrown)}`,
				} as z.ZodIssue,
			],
		};
	}
}

/** What `writeConfigPath` writes to remove the key at the path. */
const REMOVED: unique symbol = Symbol("removed");

/** What stands in the way of writing a section back: the path, and what it holds. */
interface WriteBlocked {
	readonly blockedAt: readonly string[];
	readonly holding: unknown;
}

/**
 * `target` with `value` laid over what is at `segments` (`overlayConfig`: a
 * key the value does not hold is kept, one it holds as `undefined` goes),
 * copied on the way down — no object of `target` is changed, and every object
 * on the path is a new one with the same prototype. `REMOVED` removes the key
 * at the path instead. A missing object on the path is created; anything else
 * on it — a scalar, a list, an instance — is where the write is blocked.
 */
function writeConfigPath(
	target: unknown,
	segments: readonly string[],
	value: unknown,
	walked: readonly string[] = [],
): { readonly written: unknown } | WriteBlocked {
	// `value` may be `REMOVED`: the key at the path goes.
	if (segments.length === 0)
		return { written: value === REMOVED ? value : overlayConfig(target, value) };
	if (target !== undefined && !isPlainConfigObject(target)) {
		return { blockedAt: walked, holding: target };
	}
	const [key, ...rest] = segments as [string, ...string[]];
	const current = target !== undefined && Object.hasOwn(target, key) ? target[key] : undefined;
	const below = writeConfigPath(current, rest, value, [...walked, key]);
	if (!("written" in below)) return below;
	const copy: Record<string, unknown> =
		target !== undefined && Object.getPrototypeOf(target) === null
			? Object.setPrototypeOf({}, null)
			: {};
	if (target !== undefined) {
		for (const name of Object.keys(target)) defineConfigKey(copy, name, target[name]);
	}
	if (below.written === REMOVED) delete copy[key];
	else defineConfigKey(copy, key, below.written);
	return { written: copy };
}

/** How a blocked write's obstacle is named: its kind, never its value (it may be a secret). */
function kindOf(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "a list";
	if (typeof value === "object") return "an object that is not plain data";
	return `a ${typeof value}`;
}

/**
 * Parse every declared section and write each back into the configuration:
 * for each module whose manifest has a `section`, read the value at its path
 * out of the composed configuration — the base laid over what was written,
 * so the value arrives coerced where core's schema coerces it and whole
 * where no schema declares it — and parse it with the section's schema,
 * synchronously.
 *
 * Each module is handed its schema's output as `deps.section`, a deeply
 * frozen copy (`frozenSection`). The `config` slot gets the same output
 * laid over what is at the section's path (`overlayConfig`), so a section
 * schema narrower than what is there drops nothing — a loaded module's
 * section is never stripped — outer sections before inner ones: every section is read before
 * any is written, so an outer schema that keeps only its own keys does not
 * take an inner module's section from it, and an inner section's output
 * lands inside the outer's. A section whose output is `undefined` removes
 * what is written at its path — its schema made nothing of it — and writes
 * nothing where nothing is. A section a scalar, a list or an instance stands
 * in the way of —
 * the outer section's output left no object where the inner path goes — is
 * refused at its path.
 *
 * When a schema refuses its value, every section is still parsed, and one
 * `config-validation-failed` names every refused one: each issue's path is
 * prefixed with its section's, so the message and `details.issues` name the
 * path the operator wrote (`legacy.fixture.retries`), and `details.modules`
 * lists each refused module with the path its section is read at. Every
 * module in `modules` is parsed, whether or not a factory of it will run.
 * @internal
 */
function parseModuleSections(
	modules: readonly Module[],
	composedConfig: unknown,
): {
	readonly config: unknown;
	readonly sections: ReadonlyMap<string, { readonly value: unknown }>;
} {
	const parsed: {
		readonly module: Module;
		readonly segments: readonly string[];
		readonly data: unknown;
	}[] = [];
	const issues: z.ZodIssue[] = [];
	const refused: { readonly module: string; readonly schemaPath: string }[] = [];
	const refuse = () => {
		const named = issues.map((issue) => `${operatorPath(issue.path)}: ${issue.message}`);
		return new BootError({
			message: `Config validation failed — ${issues.length} issue(s) found in module sections: ${named.join("; ")}.`,
			reason: "config-validation-failed",
			stage: "validateManifests",
			details: {
				reason: "config-validation-failed",
				issues,
				modules: refused,
			},
		});
	};

	for (const m of modules) {
		if (m.section === undefined) continue;
		const segments = sectionSegmentsOf(m);
		const result = parseSection(m.section.schema, readConfigPath(composedConfig, segments));
		if ("data" in result) {
			parsed.push({ module: m, segments, data: result.data });
			continue;
		}
		for (const issue of result.issues) {
			issues.push({ ...issue, path: [...segments, ...issue.path] } as z.ZodIssue);
		}
		refused.push({ module: m.name, schemaPath: sectionPathOf(m) });
	}
	if (issues.length > 0) throw refuse();

	// Outer sections first; `sort` is stable, so equal depths keep module order.
	let config = composedConfig;
	const byDepth = [...parsed].sort((a, b) => a.segments.length - b.segments.length);
	for (const { module, segments, data } of byDepth) {
		// A schema that made nothing of the value written there removes it; with
		// nothing written there, there is nothing to write.
		if (data === undefined && readConfigPath(config, segments) === undefined) continue;
		const result = writeConfigPath(config, segments, data === undefined ? REMOVED : data);
		if ("written" in result) {
			config = result.written;
			continue;
		}
		issues.push({
			code: "custom",
			path: [...segments],
			message: `module "${module.name}"'s section cannot be written back: ${operatorPath(result.blockedAt) || "the configuration"} holds ${kindOf(result.holding)}, not an object`,
		} as z.ZodIssue);
		refused.push({ module: module.name, schemaPath: sectionPathOf(module) });
	}
	if (issues.length > 0) throw refuse();

	const sections = new Map<string, { readonly value: unknown }>();
	for (const { module, data } of parsed) sections.set(module.name, { value: frozenSection(data) });
	return { config, sections };
}

// ---------------------------------------------------------------------------
// Step 14 — Route-order edge sanity
// Per A2-β §5.1 step 14.
// ---------------------------------------------------------------------------

/**
 * Step 14: For each `RouteContribution.before` / `after` token, the
 * referenced `id` must exist among the `id`s declared by some other
 * `RouteContribution`.
 *
 * Factory-shaped routes (`(deps) => RouteContribution`) produce their `id`
 * at materialise time, so their ids are opaque at validate-stage. When at
 * least one module declares a function-shaped routes entry anywhere,
 * unknown refs are deferred to assembleApp's mount-order pass (§5.6
 * step 1), which sees the full materialised id set. This carve-out keeps
 * the documented mixed static/factory route ordering scenario reachable.
 * Per multi-agent review (Codex P2).
 *
 * Pure-static apps (no factory route entries anywhere) get the typo-catch
 * benefit of the early check.
 *
 * Per A2-β §5.1 step 14.
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
// #728 — the module section's manifest rules
// ---------------------------------------------------------------------------

/**
 * The key a module's own configuration section is set under on its deps
 * object, beside its slots.
 */
const SECTION_DEPS_KEY = "section";

/**
 * A module that declares a section may not also require or optionally read a
 * component named `section`: its deps would carry both under one name, the
 * section shadowing the slot. Only that module is refused. A component named
 * `section` is otherwise an ordinary slot — provided, read by a module that
 * declares no section, bootstrapped or overridden — so a composition that
 * had one before sections existed boots as it did.
 * Throws `reserved-component-key`.
 * @internal
 */
function checkReservedComponentKeys(
	rawModules: readonly Module[],
	modules: readonly NormalisedModule[],
): void {
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

/** One old path a module's section moved from, as boot reads its `relocatedFrom`. */
interface SectionRelocation extends RelocatedPath {
	readonly module: string;
	/** The old path as the manifest wrote it. */
	readonly entry: string;
}

/**
 * The new path of a `relocatedFrom` entry: the section's path as it is read
 * today (`sectionSegmentsOf`) followed by the entry's path inside it — none
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
 * (`relocationTarget`). A section still read at a transitional `at` is bound
 * to no environment variable yet, so its relocations name none. Read after
 * `checkModuleSectionPaths` held their shape.
 */
function sectionRelocationsOf(m: Module): readonly SectionRelocation[] {
	const relocatedFrom = m.section?.relocatedFrom;
	if (relocatedFrom === undefined) return [];
	const section = sectionSegmentsOf(m);
	const entries: readonly (readonly [string, string | null])[] = Array.isArray(relocatedFrom)
		? relocatedFrom.map((from: string) => [from, ""] as const)
		: Object.entries(relocatedFrom as Readonly<Record<string, string | null>>);
	return entries.map(([from, inside]) => ({
		module: m.name,
		entry: from,
		from: from.split("."),
		to: relocationTarget(section, inside),
		...(m.section?.at === undefined ? {} : { unbound: true }),
	}));
}

/**
 * Every section path a manifest writes is one it can have written (#728),
 * for every module:
 *
 * - `section.at` is a dot-separated path of non-empty keys. `""`, `"a..b"`,
 *   `".a"` and `"a."` — or a value that is not a string — name no section
 *   anyone wrote. A string is quoted in the message, anything else named by
 *   its type — rendering it could throw (a bigint, a cyclic object) before
 *   the refusal exists — and the value itself is in `details.at`.
 * - `section.relocatedFrom` is a list of such paths, read at every index — a
 *   hole is refused, not skipped — or a plain map (its prototype
 *   `Object.prototype` or `null`; a Date, a Map or a class instance is
 *   neither form) from such paths to `""`, such a path inside the section,
 *   or `null` (removed); no old path is, or holds, a loaded module's
 *   section — its own or another's — which a configuration that sets that
 *   section would then be refused for; and no two loaded modules claim
 *   overlapping old paths — the same one, or one under the other's — since
 *   a key set there would have two new paths. (One module may cover its own
 *   old path with a more specific one: a subtree, and a key renamed in it.)
 *   The later module in `modules` is the one refused, and `problem` names
 *   both.
 * - No new path lies at, under or over an old path: its own, where a key
 *   written right would be refused, or any other a loaded module declares —
 *   another entry of its own included — where a key moved there would be
 *   refused in turn, a chain of moves. The module whose new path it is is
 *   refused, and `problem` names the other old path and its module.
 *
 * `details.relocatedFrom` names the entry, or the value when it is neither
 * form or has a hole, and `details.problem` what is wrong with it. A section
 * is known here only by a manifest's `section`: a module that reads its
 * settings through a `configSchema` alone declares no path to hold against.
 * Then no two modules' sections may be read at the same path
 * (`checkModuleSectionOwners`).
 *
 * Throws `module-section-path-invalid`.
 * @internal
 */
function checkModuleSectionPaths(rawModules: readonly Module[]): void {
	for (const m of rawModules) {
		const at: unknown = m.section?.at;
		if (at === undefined || isKeyPath(at)) continue;
		const shown = typeof at === "string" ? JSON.stringify(at) : `a ${typeof at}`;
		throw new BootError({
			message: `Module "${m.name}" declares its section at ${shown}, which is not a dot-separated path of non-empty keys.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: { reason: "module-section-path-invalid", module: m.name, at },
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
	const sections = rawModules
		.filter((m) => m.section !== undefined)
		.map((m) => ({ module: m.name, path: sectionSegmentsOf(m) }));
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
	for (const m of rawModules) {
		const relocatedFrom: unknown = m.section?.relocatedFrom;
		if (relocatedFrom === undefined) continue;
		const entries = entriesOf(m, relocatedFrom);
		for (const [from, inside] of entries) {
			if (!isKeyPath(from)) {
				throw refusal(m, from, "an old path is a dot-separated path of non-empty keys");
			}
			if (inside !== "" && inside !== null && !isKeyPath(inside)) {
				throw refusal(
					m,
					from,
					'its new path is "" (the section itself), a dot-separated path of non-empty keys inside the section, or null (removed)',
				);
			}
			const old = from.split(".");
			const held = sections.find(({ path }) => under(path, old));
			if (held !== undefined) {
				const is = held.path.length === old.length ? "is" : "holds";
				throw refusal(
					m,
					from,
					held.module === m.name
						? `it ${is} the path the section is read at, so every configuration that sets the section would be refused`
						: `it ${is} the section of module "${held.module}", so every configuration that sets that section would be refused`,
				);
			}
			const target = relocationTarget(sectionSegmentsOf(m), inside as string | null);
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
	const relocations = rawModules.flatMap((m) =>
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
	checkModuleSectionOwners(rawModules);
}

/**
 * A configuration still setting a key at or under a path a loaded module's
 * section moved from refuses boot (#728 B10), before the configuration is
 * parsed — the old path may be in no section any loaded module reads, and
 * what a schema would make of its value is beside the point. Reads the
 * configuration as it was handed to `createApp`. Every such key is named, in
 * module order, with the path it moved to and the environment variable bound
 * there (`findRelocatedKeys`, beside the removed-key refusals). Throws
 * `config-path-relocated`.
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
 * A section has one owner (#728): two modules whose sections are read at the
 * same path — the same keys, a module's name counting as one key — would
 * each be handed the other's configuration and each write it back. The later
 * module in `modules` is refused with `module-section-path-invalid`, and
 * `problem` names the earlier one. A section inside another module's is not
 * shared: it is written back inside the outer one (`parseModuleSections`).
 * @internal
 */
function checkModuleSectionOwners(rawModules: readonly Module[]): void {
	const owners = new Map<string, string>();
	for (const m of rawModules) {
		if (m.section === undefined) continue;
		const key = JSON.stringify(sectionSegmentsOf(m));
		const owner = owners.get(key);
		if (owner === undefined) {
			owners.set(key, m.name);
			continue;
		}
		const at = sectionPathOf(m);
		const problem = `module "${owner}" declares its section there too, and a section has one owner`;
		throw new BootError({
			message: `Module "${m.name}" declares its section at "${at}": ${problem}. Declare each module's section at a path of its own.`,
			reason: "module-section-path-invalid",
			stage: "validateManifests",
			details: { reason: "module-section-path-invalid", module: m.name, at, problem },
		});
	}
}

// ---------------------------------------------------------------------------
// The stage-1 check registries (#368)
// ---------------------------------------------------------------------------

/**
 * Everything a stage-1 check may read. One shape for every check, so a row
 * is `(ctx) => void` and adding a guard is appending a row — not choosing a
 * fraction between two existing step numbers and finding the right brace in
 * `validateManifests` (which is how this file accreted steps 7.5 and
 * 13.5–13.10 before #368).
 *
 * `parsedConfig` is `undefined` for the pre-config registry: those checks
 * run before the config-parse stage that produces it, which is exactly what
 * splits the two registries.
 */
interface StageOneContext {
	readonly rawModules: readonly Module[];
	readonly modules: readonly NormalisedModule[];
	readonly bootstrapComponents: BootstrapMap;
	readonly overrideComponents: Partial<ComponentMap> | undefined;
	readonly contributionKinds: ContributionKindMap | undefined;
	readonly parsedConfig: unknown;
	/**
	 * Provides ∪ bootstrapComponents ∪ overrideComponents — the three
	 * supported component sources. Wiring guards MUST test against all three
	 * or a composition root wiring via bootstrap/override is falsely rejected
	 * (multi-agent-review I1+P2 convergence, 2026-05-01).
	 */
	readonly plannedKeys: ReadonlySet<string>;
}

/** One stage-1 check: an id for humans, a spec pointer, and the run. */
export interface StageOneCheck {
	readonly id: string;
	/** Where the check's contract lives (A2-β section, or the issue). */
	readonly spec: string;
	readonly run: (ctx: StageOneContext) => void;
}

/**
 * The checks that run BEFORE config parse, in order. These are A2-β §5.1's
 * numbered steps 1–12 (7.5 sits between 7 and 8 per A5 §8.2); the numbers
 * live in `spec`, so file order and spec order can never disagree with each
 * other silently — the registry order IS the execution order, and the
 * first-violation semantics follow from running rows in sequence.
 */
/**
 * The registries are exported (so tooling and tests can read the plan) and
 * are the live structures `validateManifests` iterates — so they are frozen,
 * rows included: an execution plan for boot-time security validation must
 * not be mutable by anything running in-process. Per Copilot review on #380.
 */
const freezeChecks = (checks: readonly StageOneCheck[]): readonly StageOneCheck[] =>
	Object.freeze(checks.map((check) => Object.freeze(check)));

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
		id: "provides-closure",
		spec: "A2-β §5.1 step 2",
		run: (ctx) => checkProvidesClosure(ctx.modules),
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
		run: (ctx) =>
			checkRequiresClosure(ctx.modules, ctx.bootstrapComponents, ctx.overrideComponents),
	},
	{
		id: "contribution-kind-coverage",
		spec: "A2-β §5.1 step 5",
		run: (ctx) => checkContributionKindCoverage(ctx.modules, ctx.contributionKinds),
	},
	{
		id: "contribution-shapes",
		spec: "issue #728 (a rate-limit prefix; a federation type's declaration)",
		run: (ctx) => checkContributionShapes(ctx.rawModules, ctx.modules),
	},
	{
		id: "per-kind-contribute-duplicates",
		spec: "A2-β §5.1 step 6",
		run: (ctx) => checkPerKindContributeDuplicates(ctx.modules, ctx.contributionKinds ?? {}),
	},
	{
		id: "route-collisions",
		spec: "A2-β §5.1 step 7",
		run: (ctx) => checkRouteCollisions(ctx.modules, ctx.rawModules),
	},
	{
		id: "federation-redirect-policy-pairing",
		spec: "A5 §8.2 (step 7.5)",
		run: (ctx) => checkFederationRedirectPolicyPairing(ctx.modules),
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
		id: "module-section-paths",
		spec: "issue #728 (a section's transitional path, the paths it moved from, and its one owner)",
		run: (ctx) => checkModuleSectionPaths(ctx.rawModules),
	},
	{
		id: "relocated-config-paths",
		spec: "issue #728 (B10: a relocated path refuses boot)",
		run: (ctx) => checkRelocatedConfigPaths(ctx.rawModules, ctx.bootstrapComponents),
	},
]);

/**
 * The checks that run AFTER config parse (A2-β §5.1 step 13, which stays a
 * distinct stage in `validateManifests` because it *produces* the parsed
 * config these rows read), in order. This is where wiring guards live —
 * the rows that used to be hand-numbered 13.5–13.10 — plus the step-14
 * route-order sanity check that always ran last.
 *
 * Adding a wiring guard = appending a row before `route-order-edges`.
 */
export const STAGE_ONE_POST_CONFIG_CHECKS: readonly StageOneCheck[] = freezeChecks([
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
		// `rawModules`, not the normalised view: the guard reads each manifest's
		// own `replicaSafety` declaration (#455), which normalisation does not
		// carry.
		run: (ctx) => {
			const bootLogger = ctx.bootstrapComponents.logger;
			checkReplicaSafety({
				modules: ctx.rawModules,
				config: ctx.parsedConfig,
				...(bootLogger !== undefined ? { logger: bootLogger } : {}),
			});
		},
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
 * Stage 1 of the A2-β boot planner pipeline. Accepts the consumer's
 * `Module[]`, `bootstrapComponents`, `contributionKinds`, and
 * `overrideComponents` and runs the two check registries around the
 * config-parse stage: {@link STAGE_ONE_PRE_CONFIG_CHECKS}, then A2-β §5.1
 * step 13 (`validateAndComposeConfig`, the one composed parse, and
 * `parseModuleSections`, which writes each module's section back into the
 * parsed config), then {@link STAGE_ONE_POST_CONFIG_CHECKS}.
 *
 * Returns a `ValidatedManifests` on success. Throws a typed `BootError`
 * on the first violation in input-array order.
 *
 * The stage is **deterministic**: same inputs → same output / same error.
 * Its only side effects are boot notices to the wired logger — the
 * top-level sections nothing owns (`config_sections_ignored`, #728 B8) and
 * the replica-safety warning. Per A2-β §5.1.
 */
export function validateManifests(input: ValidateManifestsInput): ValidatedManifests {
	const { modules, bootstrapComponents, contributionKinds, overrideComponents } = input;

	// Normalise all modules first for efficient lookup across checks
	const normalisedModules = modules.map(normaliseModule);

	const baseContext: StageOneContext = {
		rawModules: modules,
		modules: normalisedModules,
		bootstrapComponents,
		overrideComponents,
		contributionKinds,
		parsedConfig: undefined,
		plannedKeys: new Set<string>([
			...normalisedModules.flatMap((m) => m.providesKeys as string[]),
			...Object.keys(bootstrapComponents),
			...Object.keys(overrideComponents ?? {}),
		]),
	};

	for (const check of STAGE_ONE_PRE_CONFIG_CHECKS) {
		check.run(baseContext);
	}

	// A2-β §5.1 step 13: config schema composition and validation. Not a
	// registry row because it PRODUCES a value — the parsed config (with Zod
	// defaults / transforms applied) that replaces the original config in the
	// returned bootstrapComponents, and that every post-config row reads.
	const composedConfig = validateAndComposeConfig(modules, bootstrapComponents);
	// Each module's own section (#728), parsed out of that configuration by
	// the module's schema and written back at its path — before any
	// post-config row, which may assume the configuration is valid.
	const { config: parsedConfig, sections } = parseModuleSections(modules, composedConfig);
	const substitutedBootstrap: BootstrapMap = {
		...bootstrapComponents,
		config: parsedConfig as BootstrapMap["config"],
	};
	// #728 B8: the top-level sections nothing loaded owns, kept in the config
	// slot and named once — to the logger the composition wired, as every
	// boot notice is.
	const ignored = ignoredSections(modules, (bootstrapComponents as Record<string, unknown>).config);
	if (ignored.length > 0) {
		const logger = overrideComponents?.logger ?? bootstrapComponents.logger ?? consoleLogger;
		logger.warn({ sections: [...ignored] }, "config_sections_ignored");
	}

	const postConfigContext: StageOneContext = { ...baseContext, parsedConfig };
	for (const check of STAGE_ONE_POST_CONFIG_CHECKS) {
		check.run(postConfigContext);
	}

	// Build output indices
	const validatedModules: ValidatedModule[] = normalisedModules.map((normalised, i) => {
		const section = sections.get(normalised.name);
		return {
			manifest: modules[i],
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
	};
}
