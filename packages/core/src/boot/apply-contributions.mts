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
 * boot/apply-contributions.mts: stage 4 of the boot planner. Runs every
 * module's contribution factories against the `ComponentWorld` from stage 3
 * and fills the `ContributionCollectorMap`; the steps are listed on
 * {@link applyContributions}.
 */

import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
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
import { compositionIssuer } from "./oauth-token-settings.mjs";
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
 * A missing `requires` key means an earlier stage (validate-manifests or
 * planBoot's activation closure) broke an invariant, so it throws a plain
 * Error, not a BootError; this mirrors materialize-components.buildDeps as
 * defence in depth. `optional` keys may be absent and are included as
 * `undefined`. `deps.section`, the module's own configuration section parsed
 * at stage 1, is set only when the module declares one.
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
 * Run cleanup records in REVERSE order (best-effort), the partial rollback
 * after a factory failure. Returns the errors for `details.cleanupErrors`.
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
 * `NameKeyedCollector`. `get` / `entries` read through at call time, so a
 * factory that captures the resolver before the collector is populated sees
 * the full view at request time.
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
 * Instantiate a stable `ReadonlyMap`-shaped view of a federation collector
 * (the `federationProviders` projection), in the collector's own value type.
 * Reads through at call time, each access over a fresh `Map` snapshot so the
 * `ReadonlyMap` return shapes (iterators included) hold.
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
 * Instantiate a stable read-through view of the `federationRedirectPolicies`
 * collector, shaped like `makeFederationProviders`. The reference is stable
 * from step 0; its contents are complete after step 2.
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
 * `rateLimitBudgets` collector. A prefix whose factory answered
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
 * During stage 3 it would be empty (its contributions register in stage 4),
 * and a provider that computed from it would keep an empty answer; the read
 * throws instead and the boot is refused (`provides-factory-failed`). Only
 * the view's own members (`get`, `entries`, a map view's `size` and
 * iterator) are guarded. `then` answers `undefined`, so the view is not
 * thenable, and `Symbol.toStringTag`, `Symbol.toPrimitive` and
 * `Object.prototype` members pass, so a factory may hold, await, return or
 * print it.
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
 * Step 0: for each name-keyed collector present in `contributionKinds` that
 * has a synthetic `ComponentMap` projection, write a stable read-side
 * resolver into the working component map under the synthetic key (never
 * `undefined`).
 *
 * `createApp` runs it before stage 3 (`materializeComponents`), so a
 * `provides` factory that requires a synthetic key is handed the projection
 * that fills as stage 4 registers the contributions; reading it while the
 * provides factories run throws (`readableFromStage4`). A projection already
 * in the map is kept, so stage 4's pass does not replace the object a
 * provider holds; that pass opens them for reading
 * (`openSyntheticProjections`).
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
	// knows it and a home-made object forges nothing (ADR
	// 2026-09-28-session-admission).
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

/**
 * The issuer the pages a requirement declares are registered on: the
 * `oauthTokenSettings` slot's when the composition holds it, otherwise
 * `oauth.jwt.issuer` as the parsed configuration carries it; `undefined` when
 * it is not a non-empty string.
 */
const issuerOf = (components: Readonly<Record<string, unknown>>): string | undefined => {
	const issuer = compositionIssuer(components);
	return typeof issuer === "string" && issuer.length > 0 ? issuer : undefined;
};

/**
 * The value a name-keyed contribution registers, or a `RangeError` (reported
 * as a failed contribution factory) for one its kind's projection could not
 * answer for:
 *
 * - a `grants` value that is not an object with a callable `handle`: the
 *   grant resolver would list the name as registered while `/oauth/token`
 *   could not call it;
 * - an `mfaFactors` factor whose `kind` is not its key: the resolver answers
 *   by key and a record's kind is read back through it, so a misfiled factor
 *   would verify another kind's records;
 * - a `sessionRequirements` value that is `null` (a requirement is switched
 *   off by not installing it) or whose `name` is not the key. What registers
 *   is the copy `registeredRequirement` makes, its page held to the issuer's
 *   origin; its `reach` is read later (`checkSessionRequirements`);
 * - a `rateLimitBudgets` budget no limiter can apply as written
 *   (`isUsableRateLimitSpec`). What registers is the frozen copy that was
 *   validated.
 *
 * `null` (switched off by configuration) passes for `mfaFactors` and
 * `rateLimitBudgets` and keeps the name claimed.
 * @internal
 */
function checkNameKeyedValue(
	kind: string,
	name: string,
	value: unknown,
	issuer: string | undefined,
): unknown {
	if (kind === "grants") {
		// What `/oauth/token` dispatches to, calling `handle`, and what the
		// resolver lists as registered: one answer to both only when the value
		// is a handler.
		const handle =
			typeof value === "object" && value !== null && !Array.isArray(value)
				? (value as { handle?: unknown }).handle
				: undefined;
		if (typeof handle !== "function") {
			throw new RangeError(
				`grants "${name}": the factory must answer a grant handler, an object whose handle is a function`,
			);
		}
		return value;
	}
	if (kind === "mfaFactors") {
		if (value === null) return value;
		if ((value as { kind?: unknown } | undefined)?.kind !== name) {
			throw new RangeError(
				`mfaFactors "${name}": the factor's kind must be the key it is contributed under`,
			);
		}
		// The values the MFA requirement's reach is recomputed from: held
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
		return registeredRequirement(value, issuer);
	}
	return value;
}

/** One registered session requirement, with the module that contributed it. */
interface RequirementRegistration {
	readonly name: string;
	readonly module: string;
	readonly requirement: RegisteredRequirement;
}

/** The three ports an MFA implementation is wired to. */
const MFA_PORTS = ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"] as const;
/** The remediation the MFA requirement's step-up route admits with. */
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

/** Names as a list of JSON strings, so a name with a space or a quote in it reads as written. */
const quotedNames = (names: readonly string[]): string =>
	`[${names.map((name) => JSON.stringify(name)).join(", ")}]`;

const sameSet = (a: ReadonlySet<string>, b: ReadonlySet<string>): boolean =>
	a.size === b.size && [...a].every((value) => b.has(value));

/**
 * Step 2b: once the name-keyed pass is done and before any list-shaped
 * factory reads a reach, check every registered session requirement (see ADR
 * 2026-09-28-session-admission):
 *
 * - seal each `reach` with `sealRegisteredReach`, which holds its rules, so
 *   the `acr` drop and admission read what was checked;
 * - accept the reserved name `mfa` only from a module that requires every one
 *   of `MFA_PORTS`, reaches what core recomputes from the enabled factors,
 *   and declares `mfa.step_up` among its remediations;
 * - once `sessionRequirements.expected` is written, compare it with the
 *   registered names both ways, whether or not anything consults admission:
 *   a name in it that no module registers is `session-requirement-missing`
 *   (the composition would believe a requirement is in force that is not),
 *   checked first so a composition is told to install the module rather than
 *   to fix the list; a registered name it leaves out is
 *   `session-requirements-undeclared`;
 * - when a module requires or reads `sessionRequirementResolver`, require the
 *   key written (`session-requirements-undeclared`). With no such module and
 *   no key, nothing is compared.
 *
 * A refused requirement is `contribute-factory-failed`. Logs
 * `session_requirements_registered` at info when a consumer or a requirement
 * is installed. A failure runs the stage-3 cleanups first.
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
	const expected = (
		components.config as { sessionRequirements?: { expected?: unknown } } | undefined
	)?.sessionRequirements?.expected;
	const declared =
		Array.isArray(expected) && expected.every((name) => typeof name === "string")
			? (expected as readonly string[])
			: undefined;
	const missing = [...new Set(declared)].filter((name) => !registered.includes(name));
	if (declared !== undefined && missing.length > 0) {
		const cleanupErrors = await runCleanupsReverse(material.cleanups);
		throw new BootError({
			message:
				`sessionRequirements.expected names ${quotedNames(missing)}, which no installed module registers ` +
				`(${quotedNames(registered)} registered): install the module that registers each, ` +
				"or remove the name from sessionRequirements.expected.",
			reason: "session-requirement-missing",
			stage: "applyContributions",
			details: {
				reason: "session-requirement-missing",
				configKey: "sessionRequirements.expected",
				missing,
				declared,
				registered,
				...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
			},
		});
	}
	if (
		declared === undefined
			? consumedBy.length > 0
			: registered.some((name) => !declared.includes(name))
	) {
		const cleanupErrors = await runCleanupsReverse(material.cleanups);
		const consulting =
			consumedBy.length === 0
				? ""
				: `, and ${consumedBy.length === 1 ? `module "${consumedBy[0]}"` : `modules [${consumedBy.join(", ")}]`} consult session admission`;
		throw new BootError({
			message:
				`sessionRequirements.expected must name exactly the session requirements this composition registers: ` +
				`${declared === undefined ? "nothing is declared" : `${quotedNames(declared)} is declared`}, ` +
				`${quotedNames(registered)} registered${consulting}. ` +
				"Write the key to state what this composition expects (`[]` for none).",
			reason: "session-requirements-undeclared",
			stage: "applyContributions",
			details: {
				reason: "session-requirements-undeclared",
				configKey: "sessionRequirements.expected",
				declared,
				registered,
				consumedBy,
				...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
			},
		});
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
 * `undefined` when the kind has no entry. Routing MUST narrow on
 * `collector.kind`, never a hardcoded set, so consumer-defined kinds (added
 * via `declare module` augmentation) are handled too.
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
 * Warn when a deployment runs BOTH token-binding surfaces.
 *
 * `assembleApp` mounts the composed `tokenBindingMw` (synthesized from
 * `tokenBindingMechanisms`) on `/oauth/token` before the `grantMiddleware`
 * contributions. `tokenBindingMw` overwrites `req.tokenBinding`, so one
 * arriving through `grantMiddleware` **always** wins and the configured
 * `dispatch-policy` decides nothing, with no error or other signal. This is
 * what a half-finished move to `tokenBindingMechanisms` looks like.
 *
 * Silent when only the `grantMiddleware` surface is present (a working
 * deployment, not an override) and when the `grantMiddleware` contributions
 * are ordinary middleware (rate limiters, body pre-processing).
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
 * Stage 4 of the boot planner: fills the merged `ContributionCollectorMap`
 * (built-in defaults + consumer overrides) from the stage-3 `ComponentWorld`.
 *
 *   0. `prepareSyntheticProjections`: stable read-side resolvers over the
 *      name-keyed collectors, fully populated by request time.
 *   2. Name-keyed pass, in `BootPlan.initOrder`: a pre-scan refuses a
 *      duplicate or a missing override target before any of the module's
 *      factories runs, so a failing module leaves no side effect; factories
 *      then feed `collector.register` (contributes) or `collector.replace`
 *      (overrides).
 *   2b. `checkSessionRequirements`, before a list-shaped factory reads a
 *      requirement's reach.
 *   3. List-shaped pass, in INPUT-ARRAY order: `collector.append` (dedup by
 *      reference is the collector's job); routes are wrapped as
 *      `CollectedRouteContribution` with a `declarationIndex`.
 *
 * A throwing factory becomes `BootError` `contribute-factory-failed` (`cause`
 * the thrown value, message via `failureSummary`, never `String(thrown)`),
 * after the stage-3 cleanups in `material.cleanups` run in reverse.
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
	// Step 0: prepareSyntheticProjections.
	// ---------------------------------------------------------------------------
	prepareSyntheticProjections(components, contributionKinds);
	openSyntheticProjections(components);

	// Modules that mounted a `tokenBindingMw` through the `grantMiddleware`
	// slot. Collected here because module provenance is only in scope inside
	// the loop below (`ListCollector` keeps values, not their module), and
	// evaluated after it.
	const legacyTokenBindingModules: string[] = [];

	// ---------------------------------------------------------------------------
	// Step 2: Name-keyed pass in BootPlan.initOrder.
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
		// kinds (not in any hardcoded set) are handled correctly.
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
				value = checkNameKeyedValue(entry.kind, name, await factory(deps), issuerOf(components));
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
				value = checkNameKeyedValue(entry.kind, name, await factory(deps), issuerOf(components));
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
	// name-keyed contribution has registered and before a list-shaped factory
	// reads a requirement's reach.
	// ---------------------------------------------------------------------------

	await checkSessionRequirements(material, components, contributionKinds.sessionRequirements);

	// ---------------------------------------------------------------------------
	// Step 3: List-shaped pass in INPUT-ARRAY order.
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
		// consumer-defined list-shaped kinds.
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
	// ---------------------------------------------------------------------------
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
