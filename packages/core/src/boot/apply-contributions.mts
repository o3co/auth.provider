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
 * boot/apply-contributions.mts — Stage 4 of the A2-β boot planner pipeline.
 *
 * Takes the `ComponentWorld` from stage 3 plus the merged
 * `ContributionCollectorMap`, and:
 *   - Step 0: prepares synthetic read-side projections (`grantHandlerResolver`,
 *     `tokenExchangeValidatorResolver`, `federationProviders`,
 *     `federationRedirectPolicyResolver`, `mfaFactorResolver`,
 *     `sessionRequirementResolver`) into the working component map before any
 *     factory runs.
 *   - Step 2: iterates modules in `BootPlan.initOrder`, pre-scanning for
 *     collector conflicts, then invoking name-keyed contribution factories and
 *     routing results to `collector.register` or `collector.replace`.
 *   - Step 2b: the session-requirement checks of the session-admission ADR's
 *     D3 and D7, once every name-keyed contribution has registered and before
 *     any list-shaped factory reads a requirement's reach — each reach and
 *     page, the name `mfa` bound to core's MFA ports, the declaration
 *     `sessionRequirements.expected`, `mfa.mode` asking for a requirement that
 *     is not installed — and the boot line `session_requirements_registered`.
 *   - Step 3: iterates modules in input-array order, invoking list-shaped
 *     contribution factories and routing results to `collector.append`.
 *
 * Per A2-β §5.4.
 */

import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { readMfaMode } from "../mfa/mode.mjs";
import { isTokenBindingMw } from "../middleware/tokenBinding.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type { MfaFactor } from "../modules/manifest/contributes-map.mjs";
import type {
	GrantHandlerResolver,
	MfaFactorResolver,
	RateLimitBudgetResolver,
	TokenExchangeValidatorResolver,
} from "../modules/manifest/synthetic-keys.mjs";
import type { RateLimitSpec } from "../ratelimit/types.mjs";
import { isUsableRateLimitSpec, shownConfigValue } from "../ratelimit/usableSpec.mjs";
import { sessionRequirementResolverOver } from "../session-admission/admit.mjs";
import {
	MFA_REQUIREMENT_NAME,
	type RegisteredRequirement,
	registeredRequirement,
	sealRegisteredReach,
} from "../session-admission/requirement.mjs";
import { failureSummary } from "./failure-summary.mjs";
import type {
	CleanupRecord,
	CollectedRouteContribution,
	ComponentWorld,
	ContributionCollectorMap,
	ContributionKind,
	ListCollector,
	NameKeyedCollector,
	RegistryWorld,
	RouteCollector,
} from "./types.mjs";
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
 * `section`, the module's own configuration section parsed at stage 1
 * (#728), is set as `deps.section` when the module declares one, and the key
 * is absent otherwise.
 *
 * Per A2-β §5.4 step 2 (deps materialisation from ComponentWorld).
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
				`invariant violated: missing required dep "${String(key)}" for contribute factory — stage 1/2 should have caught this`,
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
 * Run cleanup records in REVERSE order (best-effort). Returns any errors
 * encountered so they can be collected into `details.cleanupErrors`.
 *
 * Per A2-β §5.4 step 2 (partial rollback on factory failure) and §5.3.
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
		// biome-ignore lint/style/noNonNullAssertion: index is bounded
		const record = cleanupRecords[i]!;
		try {
			await record.cleanup(record.value);
		} catch (err) {
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
function makeGrantHandlerResolver(collector: NameKeyedCollector<unknown>): GrantHandlerResolver {
	return {
		get: (grantType: string) => collector.get(grantType) as ReturnType<GrantHandlerResolver["get"]>,
		entries: () => collector.entries() as ReturnType<GrantHandlerResolver["entries"]>,
	};
}

/**
 * Instantiate a stable read-side `TokenExchangeValidatorResolver` backed by
 * the given `NameKeyedCollector`.
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
function makeTokenExchangeValidatorResolver(
	collector: NameKeyedCollector<unknown>,
): TokenExchangeValidatorResolver {
	return {
		get: (tokenType: string) =>
			collector.get(tokenType) as ReturnType<TokenExchangeValidatorResolver["get"]>,
		entries: () => collector.entries() as ReturnType<TokenExchangeValidatorResolver["entries"]>,
	};
}

/**
 * Instantiate a stable `ReadonlyMap`-shaped view of a federation collector,
 * in the collector's own value type — `unknown` used to be laundered through
 * here into the `federationProviders` slot's declared type (#626 P1).
 * Reads through at call time via the collector's `entries()`. Backed by a
 * live `Map` snapshot taken on each access so that `ReadonlyMap` typed
 * return values (including iterator shapes) are satisfied correctly.
 *
 * Per A2-β §5.4 step 0: `federations → federationProviders` projection.
 * @internal
 */
function makeFederationProviders<T>(collector: NameKeyedCollector<T>): ReadonlyMap<string, T> {
	function snapshot(): Map<string, T> {
		return new Map(collector.entries());
	}
	return {
		get: (key: string) => collector.get(key),
		has: (key: string) => collector.get(key) !== undefined,
		entries: () => snapshot().entries(),
		keys: () => snapshot().keys(),
		values: () => snapshot().values(),
		forEach: (
			cb: (value: T, key: string, map: ReadonlyMap<string, T>) => void,
			thisArg?: unknown,
		) => {
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
function makeFederationRedirectPolicyResolver(
	collector: NameKeyedCollector<unknown>,
): ReadonlyMap<string, unknown> {
	function snapshot(): Map<string, unknown> {
		return new Map(collector.entries());
	}
	return {
		get: (key: string) => collector.get(key),
		has: (key: string) => collector.get(key) !== undefined,
		entries: () => snapshot().entries(),
		keys: () => snapshot().keys(),
		values: () => snapshot().values(),
		forEach: (
			cb: (value: unknown, key: string, map: ReadonlyMap<string, unknown>) => void,
			thisArg?: unknown,
		) => {
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
 * Instantiate a stable read-side `MfaFactorResolver` over the `mfaFactors`
 * collector. A kind whose factory answered `null` — the factor switched off
 * by its configuration — is registered in the collector, so a second
 * contribution of it is still a duplicate, and is absent from what the
 * resolver answers. Reads through at call time, like the other resolvers.
 * @internal
 */
function makeMfaFactorResolver(collector: NameKeyedCollector<MfaFactor | null>): MfaFactorResolver {
	return {
		get: (kind: string) => collector.get(kind) ?? undefined,
		entries: function* (): IterableIterator<readonly [string, MfaFactor]> {
			for (const [kind, factor] of collector.entries()) {
				if (factor !== null) yield [kind, factor] as const;
			}
		},
	};
}

/**
 * Instantiate a stable read-side `RateLimitBudgetResolver` over the
 * `rateLimitBudgets` collector (#728). A prefix whose factory answered
 * `null` — switched off by its module's settings — is registered in the
 * collector, so a second contribution of it is still a duplicate, and is
 * absent from what the resolver answers. Reads through at call time, like
 * the other resolvers.
 * @internal
 */
function makeRateLimitBudgetResolver(
	collector: NameKeyedCollector<RateLimitSpec | null>,
): RateLimitBudgetResolver {
	return {
		get: (prefix: string) => collector.get(prefix) ?? undefined,
		entries: function* (): IterableIterator<readonly [string, RateLimitSpec]> {
			for (const [prefix, budget] of collector.entries()) {
				if (budget !== null) yield [prefix, budget] as const;
			}
		},
	};
}

/**
 * Whether the projections of one boot's working map may be read: closed while
 * stage 3 runs the `provides` factories, open from stage 4 on. Keyed by the
 * working map, which stages 3 and 4 share.
 */
const projectionGates = new WeakMap<object, { open: boolean }>();

/**
 * A projection that refuses a read of its contents while its gate is closed.
 * Read during stage 3 it would be empty — the contributions behind it
 * register in stage 4 — so a provider that computed something from it then
 * would keep an empty answer; the read throws instead, and the boot is
 * refused (`provides-factory-failed`). Only the view's own members — `get`,
 * `entries`, a map view's `size` and iterator — are its contents: `then`
 * (which `await` reads; it answers `undefined`, so the view is not
 * thenable), `Symbol.toStringTag`, `Symbol.toPrimitive` and what
 * `Object.prototype` supplies pass, so a factory may hold, await, return or
 * print it. Reading it at request time is the contract.
 */
function readableFromStage4<T extends object>(view: T, key: string, gate: { open: boolean }): T {
	return new Proxy(view, {
		get(target, property, receiver) {
			if (property === "then") return undefined;
			if (!gate.open && Object.hasOwn(target, property)) {
				throw new Error(
					`${key} was read while the provides factories run: it fills as the contributions register, so read it at request time`,
				);
			}
			return Reflect.get(target, property, receiver);
		},
	});
}

/**
 * Stage 4 opens the projections of `components` for reading (step 0).
 * @internal
 */
export function openSyntheticProjections(components: Record<string, unknown>): void {
	const gate = projectionGates.get(components);
	if (gate !== undefined) gate.open = true;
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
 * `createApp` runs it before stage 3 (`materializeComponents`), so a
 * `provides` factory that requires a synthetic key is handed the projection
 * the world keeps, which fills as stage 4 registers the contributions. A
 * provider holds it and reads it at request time: a read while the provides
 * factories run throws (see `readableFromStage4`) and refuses the boot,
 * rather than answer an empty view. A projection already in the map is kept,
 * so the pass in stage 4 does not replace the object a provider holds; that
 * pass opens them for reading (`openSyntheticProjections`).
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
export function prepareSyntheticProjections(
	components: Record<string, unknown>,
	contributionKinds: ContributionCollectorMap,
): void {
	let gate = projectionGates.get(components);
	if (gate === undefined) {
		gate = { open: false };
		projectionGates.set(components, gate);
	}
	const readGate = gate;
	const inject = (key: string, make: () => object): void => {
		if (!Object.hasOwn(components, key)) {
			components[key] = readableFromStage4(make(), key, readGate);
		}
	};
	const {
		grants,
		tokenExchangeValidators,
		federations,
		federationRedirectPolicies,
		mfaFactors,
		sessionRequirements,
		rateLimitBudgets,
	} = contributionKinds;
	if (grants !== undefined) {
		inject("grantHandlerResolver", () =>
			makeGrantHandlerResolver(grants as NameKeyedCollector<unknown>),
		);
	}
	if (tokenExchangeValidators !== undefined) {
		inject("tokenExchangeValidatorResolver", () =>
			makeTokenExchangeValidatorResolver(tokenExchangeValidators as NameKeyedCollector<unknown>),
		);
	}
	if (federations !== undefined) {
		inject("federationProviders", () =>
			makeFederationProviders(federations as NameKeyedCollector<unknown>),
		);
	}
	if (federationRedirectPolicies !== undefined) {
		inject("federationRedirectPolicyResolver", () =>
			makeFederationRedirectPolicyResolver(
				federationRedirectPolicies as NameKeyedCollector<unknown>,
			),
		);
	}
	if (mfaFactors !== undefined) {
		inject("mfaFactorResolver", () => makeMfaFactorResolver(mfaFactors));
	}
	if (rateLimitBudgets !== undefined) {
		inject("rateLimitBudgetResolver", () => makeRateLimitBudgetResolver(rateLimitBudgets));
	}
	// The session-requirement resolver is branded by its home: the object the
	// planner records is the gated view a consumer is handed, so `admitSession`
	// knows it and a home-made object forges nothing (the session-admission
	// ADR's D1).
	if (
		sessionRequirements !== undefined &&
		!Object.hasOwn(components, "sessionRequirementResolver")
	) {
		components.sessionRequirementResolver = sessionRequirementResolverOver(
			{
				get: (name) => sessionRequirements.get(name),
				entries: () => sessionRequirements.entries(),
			},
			(view) => readableFromStage4(view, "sessionRequirementResolver", readGate),
		);
	}
}

/** `oauth.jwt.issuer` as the parsed configuration carries it, for the pages a requirement declares; `undefined` when it is not a string. */
const issuerOf = (config: unknown): string | undefined => {
	const issuer = (config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth?.jwt
		?.issuer;
	return typeof issuer === "string" && issuer.length > 0 ? issuer : undefined;
};

/**
 * The value a name-keyed contribution registers, or a `RangeError` — which
 * the caller reports as a failed contribution factory — for one its kind's
 * projection could not answer for:
 *
 * - an `mfaFactors` factor whose `kind` is not the key it is contributed or
 *   overridden under — the resolver answers by key, and a record's kind is
 *   read back through it, so a factor filed under another kind would verify
 *   that kind's records. `null` (switched off by its configuration) passes,
 *   and stays claimed;
 * - a `sessionRequirements` value that is `null` — a requirement is switched
 *   off by not installing it, never by answering nothing — or whose `name`
 *   is not the key; what registers is the copy `registeredRequirement`
 *   makes, its page held to the issuer's origin (the session-admission ADR's
 *   D3). Its `reach` is not read here: the end of the name-keyed pass reads
 *   it once (`checkSessionRequirements`);
 * - a `rateLimitBudgets` budget no limiter can apply as written
 *   (`isUsableRateLimitSpec`) — a string, `undefined` and fractions included
 *   (#728). What registers is a frozen copy of the budget's `limit` and
 *   `windowSeconds`, each read once here — the copy that was validated; `null` (switched off by its module's
 *   settings) passes, and stays claimed. The prefix was held at stage 1.
 * @internal
 */
function checkNameKeyedValue(kind: string, name: string, value: unknown, config: unknown): unknown {
	if (kind === "mfaFactors") {
		if (value === null) return value;
		if ((value as { kind?: unknown } | undefined)?.kind !== name) {
			throw new RangeError(
				`mfaFactors "${name}": the factor's kind must be the key it is contributed under`,
			);
		}
		// The values the MFA requirement's reach is recomputed from (D3): held
		// here, so a factor written in JavaScript fails as a contribution, not
		// as a raw TypeError at the end of the pass.
		const amrValues = (value as { amrValues?: unknown }).amrValues;
		if (
			!Array.isArray(amrValues) ||
			!amrValues.every((entry) => typeof entry === "string" && entry.length > 0)
		) {
			throw new RangeError(
				`mfaFactors "${name}": the factor's amrValues must be a list of non-empty strings`,
			);
		}
		// A frozen copy of the list read here, validated: what the reach is
		// recomputed from — never a second read of the factor, which a getter
		// or a list mutated after registration could answer differently.
		const snapshot = Object.freeze([...(amrValues as readonly string[])]);
		for (const entry of snapshot) {
			if (entry === PASSWORD_AMR || entry === FEDERATED_AMR || entry === MFA_AMR) {
				throw new RangeError(
					`mfaFactors "${name}": the factor's amrValues name "${entry}", which no factor produces — a primary's marker, or mfa, which addsMfa says`,
				);
			}
		}
		factorSnapshots.set(value as object, {
			amrValues: snapshot,
			addsMfa: (value as { addsMfa?: unknown }).addsMfa === true,
		});
		return value;
	}
	if (kind === "rateLimitBudgets") {
		// The prefix itself was held at stage 1 (`contribution-shapes`).
		if (value === null) return value;
		// Each field read once, into the one object that is validated, frozen
		// and registered: a getter or a proxy answering differently on a second
		// read cannot pass the check with one budget and register another.
		const read =
			typeof value === "object"
				? {
						limit: (value as { readonly limit?: unknown }).limit,
						windowSeconds: (value as { readonly windowSeconds?: unknown }).windowSeconds,
					}
				: { limit: undefined, windowSeconds: undefined };
		if (typeof value !== "object" || !isUsableRateLimitSpec(read)) {
			throw new RangeError(
				`rateLimitBudgets "${name}": a budget is { limit, windowSeconds }, a positive whole limit and a positive whole number of seconds that ends within the Date range (got limit ${shownConfigValue(read.limit)}, windowSeconds ${shownConfigValue(read.windowSeconds)})`,
			);
		}
		return Object.freeze(read);
	}
	if (kind === "sessionRequirements") {
		if (value === null || value === undefined) {
			throw new RangeError(
				`sessionRequirements "${name}": a requirement is never null — switch it off by not installing it`,
			);
		}
		if ((value as { name?: unknown }).name !== name) {
			throw new RangeError(
				`sessionRequirements "${name}": the requirement's name must be the key it is contributed under`,
			);
		}
		return registeredRequirement(value, issuerOf(config));
	}
	return value;
}

/** One registered session requirement, with the module that contributed it. */
interface RequirementRegistration {
	readonly name: string;
	readonly module: string;
	readonly requirement: RegisteredRequirement;
}

/** The three ports an MFA implementation is wired to (the session-admission ADR's D3). */
const MFA_PORTS = ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"] as const;
/** The remediation the MFA requirement's step-up route admits with (D4). */
const MFA_STEP_UP = "mfa.step_up";

/**
 * What each registered factor said at registration, read once there and
 * validated: its `amrValues` (frozen) and whether it adds `mfa` — keyed by
 * the value the factory returned, which is what the resolver answers.
 */
const factorSnapshots = new WeakMap<
	object,
	{ readonly amrValues: readonly string[]; readonly addsMfa: boolean }
>();

/**
 * The reach core recomputes from the enabled factors — each one's
 * `amrValues`, and `mfa` when one adds it — read from the snapshots taken at
 * registration alone, never from the factor again. Every factor the resolver
 * answers registered through the name-keyed pass (both of its paths run
 * `checkNameKeyedValue`, and a host collector for the kind is refused), so
 * every one has a snapshot.
 */
function reachOfFactors(resolver: MfaFactorResolver): ReadonlySet<string> {
	const reach = new Set<string>();
	for (const [, factor] of resolver.entries()) {
		// biome-ignore lint/style/noNonNullAssertion: every registered factor was snapshotted at registration
		const snapshot = factorSnapshots.get(factor as object)!;
		for (const value of snapshot.amrValues) reach.add(value);
		if (snapshot.addsMfa) reach.add(MFA_REQUIREMENT_NAME);
	}
	return reach;
}

const sameSet = (a: ReadonlySet<string>, b: ReadonlySet<string>): boolean =>
	a.size === b.size && [...a].every((value) => b.has(value));

/**
 * Step 2b (the session-admission ADR's D3, D7): over every registered
 * session requirement, once the name-keyed pass is done and before any
 * list-shaped factory reads a reach —
 *
 * - each `reach`, read once (`sealRegisteredReach`): a Set of non-empty
 *   strings, no primary's marker, a second-factor value under the name `mfa`
 *   alone, a page when the reach is not empty, and empty under any name but
 *   `mfa` in this release — `contribute-factory-failed`, naming the module
 *   and the requirement — and sealed on the registered
 *   copy as a frozen snapshot, which is what the resolver answers from then
 *   on: the `acr` drop and admission read what was checked here;
 * - the name `mfa`, reserved and bound to core's MFA ports: accepted only
 *   from a module whose `requires` lists `mfaFactorResolver`, `mfaFactorStore`
 *   and `mfaTransactionStore`, whose reach equals what core recomputes from
 *   the enabled factors, and whose `remediations` include `mfa.step_up` —
 *   `contribute-factory-failed`, naming the module;
 * - `mfa.mode` other than `off` with no requirement named `mfa` —
 *   `session-requirement-missing`, before the declaration is compared, so a
 *   composition that asks for MFA without the module is told to install it;
 * - the declaration: whenever a module requires or reads
 *   `sessionRequirementResolver`, `sessionRequirements.expected` must be the
 *   set of registered names — `session-requirements-undeclared`;
 *
 * and the one boot line, `session_requirements_registered` at info with each
 * requirement's name, module and remediations in order, when a consumer or a
 * requirement is installed. A failure runs the stage-3 cleanups first, as a
 * failed factory does.
 * @internal
 */
async function checkSessionRequirements(
	material: ComponentWorld,
	components: Record<string, unknown>,
	collector: NameKeyedCollector<RegisteredRequirement> | undefined,
): Promise<void> {
	if (collector === undefined) return;
	const registrations: RequirementRegistration[] = [];
	// An override of the kind never reaches here: stage 1's guard refuses it
	// off the same normalised entries this pass reads.
	for (const moduleName of material.plan.initOrder) {
		// biome-ignore lint/style/noNonNullAssertion: every module in the init order was validated under its name
		const validatedModule = material.plan.validated.byName.get(moduleName)!;
		for (const entry of validatedModule.normalised.contributesEntries) {
			if (entry.kind !== "sessionRequirements" || typeof entry.key !== "string") continue;
			// biome-ignore lint/style/noNonNullAssertion: the name-keyed pass registered every contributed entry, a null refused
			const requirement = collector.get(entry.key)!;
			registrations.push({ name: entry.key, module: moduleName, requirement });
		}
	}
	const failed = async (registration: RequirementRegistration, cause: unknown): Promise<never> => {
		const cleanupErrors = await runCleanupsReverse(material.cleanups);
		throw new BootError({
			message: `Module "${registration.module}" contribution factory for kind "sessionRequirements" name "${registration.name}" failed: ${failureSummary(cause)}`,
			reason: "contribute-factory-failed",
			stage: "applyContributions",
			details: {
				reason: "contribute-factory-failed",
				module: registration.module,
				kind: "sessionRequirements",
				name: registration.name,
				originalError: cause,
				...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
			},
			cause,
		});
	};
	for (const registration of registrations) {
		let reach: ReadonlySet<string>;
		try {
			reach = sealRegisteredReach(registration.requirement);
		} catch (cause) {
			return failed(registration, cause);
		}
		// Any other name reaches nothing in this release (the seal refused it).
		if (registration.name !== MFA_REQUIREMENT_NAME) continue;
		// biome-ignore lint/style/noNonNullAssertion: the plan has a blueprint for every module it planned
		const blueprint = material.plan.depsBlueprint.get(registration.module)!;
		const requires = blueprint.requires as readonly string[];
		const missing = MFA_PORTS.filter((port) => !requires.includes(port));
		if (missing.length > 0) {
			return failed(
				registration,
				new RangeError(
					`a requirement named "${MFA_REQUIREMENT_NAME}" is accepted only from a module whose requires list ${MFA_PORTS.join(", ")}: it does not require ${missing.join(", ")}`,
				),
			);
		}
		// Read from the registration snapshots alone: nothing here reads a
		// factor again, so nothing here can throw. The resolver is present —
		// the module requires it, and the planner satisfied the requirement.
		const recomputed = reachOfFactors(components.mfaFactorResolver as MfaFactorResolver);
		if (!sameSet(reach, recomputed)) {
			return failed(
				registration,
				new RangeError(
					`the "${MFA_REQUIREMENT_NAME}" requirement's reach must be what the installed factors reach — [${[...recomputed].join(", ")}] — and is [${[...reach].join(", ")}]`,
				),
			);
		}
		if (!registration.requirement.remediations.includes(MFA_STEP_UP)) {
			return failed(
				registration,
				new RangeError(
					`the "${MFA_REQUIREMENT_NAME}" requirement must declare "${MFA_STEP_UP}" among its remediations`,
				),
			);
		}
	}
	const registered = registrations.map((registration) => registration.name);
	// Who consults admission: the validated manifests' `requires` and
	// `optional`, as each module declared them.
	const consumedBy = material.plan.initOrder.filter((moduleName) => {
		// biome-ignore lint/style/noNonNullAssertion: every module in the init order was validated under its name
		const normalised = material.plan.validated.byName.get(moduleName)!.normalised;
		return [
			...(normalised.requires as readonly string[]),
			...(normalised.optional as readonly string[]),
		].includes("sessionRequirementResolver");
	});
	const config = components.config;
	// Before the declaration: a composition that asks for MFA without the
	// module is told to install it, not to fix a list. The mode is the parsed
	// configuration's — stage 1's schema admits off, optional and required
	// alone — so the reader answers, never throws, here.
	const mode = readMfaMode(config);
	if (mode !== undefined && mode !== "off" && !registered.includes(MFA_REQUIREMENT_NAME)) {
		const cleanupErrors = await runCleanupsReverse(material.cleanups);
		throw new BootError({
			message:
				`mfa.mode = "${mode}" asks for a second factor, but no requirement named "${MFA_REQUIREMENT_NAME}" is registered: ` +
				'install the MFA module, or set mfa.mode = "off".',
			reason: "session-requirement-missing",
			stage: "applyContributions",
			details: {
				reason: "session-requirement-missing",
				configKey: "mfa.mode",
				mode,
				requirement: MFA_REQUIREMENT_NAME,
				...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
			},
		});
	}
	if (consumedBy.length > 0) {
		const declared = (config as { sessionRequirements?: { expected?: unknown } } | undefined)
			?.sessionRequirements?.expected;
		const declaredNames =
			Array.isArray(declared) && declared.every((name) => typeof name === "string")
				? (declared as readonly string[])
				: undefined;
		if (declaredNames === undefined || !sameSet(new Set(declaredNames), new Set(registered))) {
			const cleanupErrors = await runCleanupsReverse(material.cleanups);
			throw new BootError({
				message:
					`sessionRequirements.expected must name exactly the session requirements this composition registers: ` +
					`${declaredNames === undefined ? "nothing is declared" : `[${declaredNames.join(", ")}] is declared`}, ` +
					`[${registered.join(", ")}] registered, and ${consumedBy.length === 1 ? `module "${consumedBy[0]}"` : `modules [${consumedBy.join(", ")}]`} ` +
					"consult session admission. Write the key to state what this composition expects (`[]` for none).",
				reason: "session-requirements-undeclared",
				stage: "applyContributions",
				details: {
					reason: "session-requirements-undeclared",
					configKey: "sessionRequirements.expected",
					declared: declaredNames,
					registered,
					consumedBy,
					...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
				},
			});
		}
	}
	if (consumedBy.length > 0 || registrations.length > 0) {
		const logger = components.logger as Logger | undefined;
		(logger ?? consoleLogger).info(
			{
				requirements: registrations.map(({ name, module, requirement }) => ({
					name,
					module,
					remediations: [...requirement.remediations],
				})),
			},
			"session_requirements_registered",
		);
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
function collectorFor(
	contributionKinds: ContributionCollectorMap,
	kind: string,
): NameKeyedCollector<unknown> | ListCollector<unknown> | RouteCollector | undefined {
	return (contributionKinds as Record<string, unknown>)[kind] as
		| NameKeyedCollector<unknown>
		| ListCollector<unknown>
		| RouteCollector
		| undefined;
}

/**
 * Warn when a deployment runs BOTH token-binding surfaces (#199 I4).
 *
 * `assembleApp` mounts the composed `tokenBindingMw` (synthesized from
 * `tokenBindingMechanisms`) on `/oauth/token` first, and `grantMiddleware`
 * contributions after. `tokenBindingMw` assigns `req.tokenBinding` without
 * guarding an already-populated field, so a `tokenBindingMw` arriving through
 * `grantMiddleware` runs last and **always** wins — the configured
 * `dispatch-policy` on the composed surface never decides anything.
 *
 * That is the shape of an incomplete v0.7 → v0.8 migration: the consumer
 * adopted `tokenBindingMechanisms` but left their old `grantMiddleware`
 * wiring in place. It produces no error and no behavioral signal, which is
 * exactly why it needs a boot-time warning.
 *
 * Deliberately silent when only the legacy surface is present — that is a
 * working pre-migration deployment, not an override — and when the
 * `grantMiddleware` contributions are ordinary middleware (rate limiters,
 * body pre-processing), which the slot is equally intended for.
 * @internal
 */
function warnOnTokenBindingSurfaceOverlap(
	components: Record<string, unknown>,
	contributionKinds: ContributionCollectorMap,
	legacyTokenBindingModules: readonly string[],
): void {
	if (legacyTokenBindingModules.length === 0) return;

	const mechanismCollector = collectorFor(contributionKinds, "tokenBindingMechanisms");
	if (mechanismCollector === undefined || mechanismCollector.kind !== "list") return;
	// Null entries are the disabled-by-config path — a module whose mechanism
	// is switched off contributes nothing to the composed middleware, so it
	// cannot be the surface being overridden.
	let hasMechanism = false;
	for (const m of mechanismCollector.values()) {
		if (m !== null) {
			hasMechanism = true;
			break;
		}
	}
	if (!hasMechanism) return;

	const logger = components.logger as Logger | undefined;
	(logger ?? consoleLogger).warn(
		{
			reason: "token_binding_surface_overlap",
			modules: [...legacyTokenBindingModules],
		},
		"a grantMiddleware-mounted tokenBindingMw runs after the composed one and will override every binding it resolves; " +
			"migrate these modules to the tokenBindingMechanisms contribution kind, or the configured dispatch-policy stays inert",
	);
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
 *      `grants`, `tokenExchangeValidators`, `federations`,
 *      `federationRedirectPolicies`, `mfaFactors` into the working
 *      component map so contribution factories can capture resolver references
 *      that are fully populated at request time.
 *   2. Name-keyed pass (in `BootPlan.initOrder`):
 *        - Pre-scan phase: validate no duplicate/missing-target in collector
 *          state BEFORE running any factory for this module, so a module
 *          whose contribution set fails midway leaves no factory side effect
 *          behind.
 *        - Materialize+register phase: invoke factories, route to
 *          `collector.register` (contributes) or `collector.replace` (overrides).
 *   3. List-shaped pass (in INPUT-ARRAY order):
 *        - auditHooks / grantPolicyHooks: invoke factory, call `collector.append`
 *          (dedup by reference identity is the collector's responsibility).
 *        - routes: invoke factory or take static value; wrap as
 *          `CollectedRouteContribution`; assign `declarationIndex`.
 *
 * On factory throw: wrap as `BootError reason="contribute-factory-failed"`,
 * `cause = thrown`, `stage = "applyContributions"`, its message naming the
 * thrown value by `failureSummary` (never `String(thrown)`). Run stage-3
 * cleanups from `material.cleanups` in REVERSE before propagating.
 *
 * Per A2-β §5.4.
 */
export async function applyContributions(
	material: ComponentWorld,
	contributionKinds: ContributionCollectorMap,
): Promise<RegistryWorld> {
	// ---------------------------------------------------------------------------
	// Mutable working component map (stage 3 handed it as Readonly<Partial<...>>
	// but it is not yet Object.frozen — freezeWorld does that in stage 5).
	// We cast to a plain Record so we can write the synthetic projections.
	// ---------------------------------------------------------------------------
	const components = material.components as Record<string, unknown>;

	// ---------------------------------------------------------------------------
	// Step 0: prepareSyntheticProjections. Per A2-β §5.4 step 0.
	// ---------------------------------------------------------------------------
	prepareSyntheticProjections(components, contributionKinds);
	openSyntheticProjections(components);

	// Modules that mounted a `tokenBindingMw` through the legacy v0.7
	// `grantMiddleware` slot. Collected here because module provenance is only
	// in scope inside the loop below — `ListCollector` keeps values, not the
	// module that contributed them. Evaluated after the loop (#199 I4).
	const legacyTokenBindingModules: string[] = [];

	// ---------------------------------------------------------------------------
	// Step 2: Name-keyed pass in BootPlan.initOrder.
	// Per A2-β §5.4 step 2.
	// ---------------------------------------------------------------------------

	for (const moduleName of material.plan.initOrder) {
		const validatedModule = material.plan.validated.byName.get(moduleName);
		if (!validatedModule) continue;

		const blueprint = material.plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(
			components,
			blueprint?.requires ?? [],
			blueprint?.optional ?? [],
			validatedModule.section,
		);

		// Collect name-keyed contributes + overrides entries for this module.
		// Routing uses collector.kind === "name-keyed" so that consumer-defined
		// kinds (not in any hardcoded set) are handled correctly. Per A2-β §5.4.
		const nameKeyedContributes = validatedModule.normalised.contributesEntries.filter(
			(e) => collectorFor(contributionKinds, e.kind)?.kind === "name-keyed",
		);
		const nameKeyedOverrides = validatedModule.normalised.overridesEntries.filter(
			(e) => collectorFor(contributionKinds, e.kind)?.kind === "name-keyed",
		);

		// ------------------------------------------------------------------
		// Pre-scan phase: validate ALL collector invariants for this module
		// BEFORE invoking any factory. If any check fails, no factory for this
		// module runs, so none leaves a side effect behind.
		// ------------------------------------------------------------------

		for (const entry of nameKeyedContributes) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
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
						modules: [moduleName, moduleName] as [string, string],
					},
				});
			}
		}

		for (const entry of nameKeyedOverrides) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
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
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = checkNameKeyedValue(entry.kind, name, await factory(deps), components.config);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" contribution factory for kind "${entry.kind}" name "${name}" failed: ${failureSummary(thrownValue)}`,
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
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = checkNameKeyedValue(entry.kind, name, await factory(deps), components.config);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" override factory for kind "${entry.kind}" name "${name}" failed: ${failureSummary(thrownValue)}`,
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
	// Step 2b: the session-requirement checks and the boot line, once every
	// name-keyed contribution has registered (the session-admission ADR's D3,
	// D7) and before a list-shaped factory reads a requirement's reach.
	// ---------------------------------------------------------------------------

	await checkSessionRequirements(material, components, contributionKinds.sessionRequirements);

	// ---------------------------------------------------------------------------
	// Step 3: List-shaped pass in INPUT-ARRAY order.
	// Per A2-β §5.4 step 3.
	// ---------------------------------------------------------------------------

	const routes: CollectedRouteContribution[] = [];
	let declarationIndex = 0;

	for (const validatedModule of material.plan.validated.modules) {
		const moduleName = validatedModule.normalised.name;
		const blueprint = material.plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(
			components,
			blueprint?.requires ?? [],
			blueprint?.optional ?? [],
			validatedModule.section,
		);

		// List-shaped and list-routes pass: dispatch on collector.kind.
		// Handles built-in list kinds (auditHooks, grantPolicyHooks) AND any
		// consumer-defined list-shaped kinds — per A2-β §5.4 step 3.
		for (const entry of validatedModule.normalised.contributesEntries) {
			const collector = collectorFor(contributionKinds, entry.kind);
			if (collector === undefined) continue;

			if (collector.kind === "list-routes") {
				// Routes kind: entry.factory is a RouteContributionEntry<Deps> —
				// either a bare RouteContribution value or a factory.
				const entryValue = entry.factory;
				let contribution: unknown;

				if (typeof entryValue === "function") {
					try {
						contribution = await (entryValue as (deps: Record<string, unknown>) => unknown)(deps);
					} catch (thrownValue) {
						const cleanupErrors = await runCleanupsReverse(material.cleanups);
						throw new BootError({
							message: `Module "${moduleName}" route factory failed: ${failureSummary(thrownValue)}`,
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
				} else {
					// Static RouteContribution value — take directly.
					contribution = entryValue;
				}

				const collected: CollectedRouteContribution = {
					contribution:
						contribution as import("../modules/manifest/route-contribution.mjs").RouteContribution,
					contributedBy: moduleName,
					declarationIndex,
				};

				declarationIndex++;
				routes.push(collected);
				collector.append(collected);
			} else if (collector.kind === "list") {
				// Generic list-shaped kind (auditHooks, grantPolicyHooks, or any
				// consumer-defined kind whose collector has kind === "list").
				const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

				let value: unknown;
				try {
					value = await factory(deps);
				} catch (thrownValue) {
					const cleanupErrors = await runCleanupsReverse(material.cleanups);
					throw new BootError({
						message: `Module "${moduleName}" list-kind factory for "${entry.kind}" failed: ${failureSummary(thrownValue)}`,
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

				if (
					entry.kind === "grantMiddleware" &&
					isTokenBindingMw(value) &&
					// A module may register several such factories; the operator
					// acts on the module, so name it once.
					!legacyTokenBindingModules.includes(moduleName)
				) {
					legacyTokenBindingModules.push(moduleName);
				}

				collector.append(value);
			}
			// kind === "name-keyed" entries are handled in step 2; skip here.
		}
	}

	warnOnTokenBindingSurfaceOverlap(components, contributionKinds, legacyTokenBindingModules);

	// ---------------------------------------------------------------------------
	// Build registries map: kind → collector reference. Stage 5 uses this to
	// call freeze() on each collector that exposes it.
	// Per A2-β §5.4 output.
	// ---------------------------------------------------------------------------
	// (see warnOnTokenBindingSurfaceOverlap above)
	const registries = new Map<ContributionKind, unknown>();
	for (const [kind, collector] of Object.entries(contributionKinds)) {
		if (collector !== undefined) {
			registries.set(kind as ContributionKind, collector);
		}
	}

	return {
		material,
		registries: registries as ReadonlyMap<ContributionKind, unknown>,
		routes,
	};
}
