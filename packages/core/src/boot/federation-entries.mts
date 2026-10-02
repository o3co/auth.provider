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
 * boot/federation-entries.mts: the dispatch of `core.federations` by type.
 * What a `federationTypes` declaration registers as, read once; at stage 1,
 * the refusal of an enabled entry no module handles and the parse of each
 * entry dispatched to a registered type; at stage 4, the provider and the
 * redirect policy one dispatched entry builds, and the check that holds a
 * provider — dispatched, or contributed directly by its key — to the name it
 * registers under.
 */

import type { z } from "zod";
import { operatorPath } from "../config/composed.mjs";
import {
	enabledFederationsOf,
	FEDERATION_ENTRY_CORE_KEYS,
	federationNameProblem,
} from "../federations/configured.mjs";
import type { FederationProvider } from "../federations/types.mjs";
import type {
	FederationInstance,
	FederationTypeContribution,
} from "../modules/manifest/contributes-map.mjs";
import { failureSummary } from "./failure-summary.mjs";
import { frozenSection, parseSection } from "./parsed-values.mjs";
import type {
	ContributionKindMap,
	DispatchedFederation,
	NameKeyedCollector,
	NormalisedModule,
	RegisteredFederationType,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// The declaration, read once
// ---------------------------------------------------------------------------

/** A `federationTypes` declaration's members, as normalisation read them. */
export interface FederationTypeSnapshot {
	readonly entrySchema: unknown;
	readonly factory: unknown;
	readonly redirectPolicy: unknown;
}

/**
 * What each `federationTypes` declaration was read as, once, at stage 1,
 * keyed by the registration `federationTypeRegistration` answered for it.
 * The shape check and the parse read these, and the registration closes over
 * the same values, so what is checked is what registers, and a declaration
 * changed afterwards changes none of it.
 */
const snapshots = new WeakMap<object, FederationTypeSnapshot>();

/**
 * The registration a `federationTypes` declaration contributes through: its
 * members read once, here, and a factory of the deps stage 4 hands every
 * contribution that answers a `RegisteredFederationType`, each factory bound
 * to those deps and called as the method it was declared as.
 */
export function federationTypeRegistration(
	declaration: object,
): (deps: Record<string, unknown>) => RegisteredFederationType {
	const { entrySchema, factory, redirectPolicy } = declaration as {
		readonly entrySchema?: unknown;
		readonly factory?: unknown;
		readonly redirectPolicy?: unknown;
	};
	type Declared = FederationTypeContribution<Record<string, unknown>>;
	const register = (deps: Record<string, unknown>): RegisteredFederationType =>
		Object.freeze({
			entrySchema: entrySchema as z.ZodType,
			create: (instance: FederationInstance<unknown>) =>
				(factory as Declared["factory"]).call(declaration, deps, instance),
			redirectPolicy: (instance: FederationInstance<unknown>) =>
				(redirectPolicy as Declared["redirectPolicy"]).call(declaration, deps, instance),
		});
	snapshots.set(register, { entrySchema, factory, redirectPolicy });
	return register;
}

/** What a `federationTypes` entry's registration read its declaration as; `undefined` for anything else. */
export function federationTypeSnapshot(registration: unknown): FederationTypeSnapshot | undefined {
	return typeof registration === "function" ? snapshots.get(registration) : undefined;
}

// ---------------------------------------------------------------------------
// Stage 1
// ---------------------------------------------------------------------------

/** One type, with the module whose declaration of it is in force and that declaration. */
interface DeclaredType {
	readonly module: string;
	readonly snapshot: FederationTypeSnapshot;
}

/**
 * The types the modules register, in module order: each with its overriding
 * module's declaration, or else its contributing module's. Read after the
 * rows that hold the declarations' shapes, duplicates and override targets.
 */
function declaredTypes(modules: readonly NormalisedModule[]): ReadonlyMap<string, DeclaredType> {
	const types = new Map<string, DeclaredType>();
	for (const channel of ["contributesEntries", "overridesEntries"] as const) {
		for (const m of modules) {
			for (const entry of m[channel]) {
				if (entry.kind !== "federationTypes" || typeof entry.key !== "string") continue;
				const snapshot = federationTypeSnapshot(entry.factory);
				if (snapshot !== undefined) types.set(entry.key, { module: m.name, snapshot });
			}
		}
	}
	return types;
}

/** Each name a module contributes or overrides under `federations`, with the first such module. */
function directFederations(modules: readonly NormalisedModule[]): ReadonlyMap<string, string> {
	const names = new Map<string, string>();
	for (const m of modules) {
		for (const entry of [...m.contributesEntries, ...m.overridesEntries]) {
			if (entry.kind !== "federations" || typeof entry.key !== "string") continue;
			if (!names.has(entry.key)) names.set(entry.key, m.name);
		}
	}
	return names;
}

/**
 * The host collector — `federations`, then `federationRedirectPolicies` —
 * that already holds `name`, or `undefined`. A host may pre-load a name-keyed
 * collector (the `override-targets` row takes such an entry as a target): a
 * provider it pre-loaded serves its federation, and either half of a pair it
 * pre-loaded leaves no room for a dispatched entry's pair.
 */
function seededBy(
	contributionKinds: ContributionKindMap | undefined,
	name: string,
): "federations" | "federationRedirectPolicies" | undefined {
	if (contributionKinds?.federations?.get(name) !== undefined) return "federations";
	if (contributionKinds?.federationRedirectPolicies?.get(name) !== undefined) {
		return "federationRedirectPolicies";
	}
	return undefined;
}

/** The `type` an entry names, when it names one. */
const typeOf = (entry: object): string | undefined => {
	const type = (entry as { readonly type?: unknown }).type;
	return typeof type === "string" ? type : undefined;
};

/** A list of names as JSON strings, so a name with a space or a quote in it reads as written. */
const quoted = (names: readonly string[]): string =>
	`[${names.map((name) => JSON.stringify(name)).join(", ")}]`;

/** A key that reads as itself in a path: no `.`, quote, space or control character. */
const BARE_KEY = /^[A-Za-z0-9_-]+$/;

/**
 * `section.<name>`, as the path is written: the name bare when it is a bare
 * key, and otherwise quoted as JSON, so a name with a dot, a quote or a
 * newline in it reads as one key on one line.
 */
const keyAt = (section: string, name: string): string =>
	`${section}.${BARE_KEY.test(name) ? name : JSON.stringify(name)}`;

/** Where an entry is written, as the operator writes the path (`keyAt`). */
const entryAt = (name: string): string => keyAt("core.federations", name);

/**
 * Every enabled `core.federations` entry is handled by an installed module:
 * one that registers its `type` under `federationTypes`, or one that
 * contributes or overrides `federations.<name>` directly — or a host whose
 * `federations` collector already holds the name. An enabled entry neither
 * handles is `federation-type-unhandled`, every such entry listed at once
 * with its type, and the types handled. One dispatched by its type and also
 * contributed by name, or already held by either host collector
 * (`federations`, `federationRedirectPolicies`), is `duplicate-contribute`,
 * refused here rather than when stage 4 registers half of its pair. The message names each entry and its type, and
 * quotes nothing else of it. A disabled entry is not read.
 * @internal
 */
export function checkFederationEntriesHandled(
	modules: readonly NormalisedModule[],
	config: unknown,
	contributionKinds?: ContributionKindMap,
): void {
	const types = declaredTypes(modules);
	const direct = directFederations(modules);
	const unhandled: { readonly federationName: string; readonly type?: string }[] = [];
	const both: {
		readonly name: string;
		readonly kind: "federations" | "federationRedirectPolicies";
		readonly modules: readonly [string, string];
		readonly byHost: boolean;
	}[] = [];
	for (const [name, entry] of enabledFederationsOf(config)) {
		const type = typeOf(entry);
		const declared = type === undefined ? undefined : types.get(type);
		const contributor = direct.get(name);
		const seeded = seededBy(contributionKinds, name);
		if (declared !== undefined && contributor !== undefined) {
			both.push({
				name,
				kind: "federations",
				modules: [declared.module, contributor],
				byHost: false,
			});
		} else if (declared !== undefined && seeded !== undefined) {
			both.push({
				name,
				kind: seeded,
				modules: [declared.module, `contributionKinds.${seeded}`],
				byHost: true,
			});
		} else if (declared === undefined && contributor === undefined && seeded !== "federations") {
			unhandled.push(
				type === undefined ? { federationName: name } : { federationName: name, type },
			);
		}
	}
	if (unhandled.length > 0) {
		const handled = [...types.keys()];
		const fixes = unhandled.map(({ federationName, type }) => {
			const at = entryAt(federationName);
			// The type named like the entry, when one is handled: a hint, never a default.
			const settable = types.has(federationName)
				? `set ${at}.type = ${JSON.stringify(federationName)} (an installed module handles the type of its name), set its type to another one`
				: "set its type to one";
			return type === undefined
				? `${at} names no type: ${settable} an installed module handles, install the module that contributes federations[${JSON.stringify(federationName)}], or set ${at}.enabled = false`
				: `${at} names the type ${JSON.stringify(type)}: install the module that contributes federationTypes[${JSON.stringify(type)}], correct the type to one an installed module handles, or set ${at}.enabled = false`;
		});
		throw new BootError({
			message:
				`${unhandled.length === 1 ? "An enabled federation is" : `${unhandled.length} enabled federations are`} ` +
				`handled by no installed module, and would answer 404: ${fixes.join("; ")}. ` +
				`The installed modules handle the types ${quoted(handled)}.`,
			reason: "federation-type-unhandled",
			stage: "validateManifests",
			details: { reason: "federation-type-unhandled", unhandled, handled },
		});
	}
	const [first] = both;
	if (first !== undefined) {
		throw new BootError({
			message: first.byHost
				? `${entryAt(first.name)} is dispatched by its type to module "${first.modules[0]}" ` +
					`and its name is already held by the host's ${first.modules[1]} collector: one federation has one handler, ` +
					`so remove its type or remove ${JSON.stringify(first.name)} from that collector.`
				: `${entryAt(first.name)} is dispatched by its type to module "${first.modules[0]}" ` +
					`and contributed by name by module "${first.modules[1]}": one federation has one handler, so remove its ` +
					`type or remove the module that contributes federations[${JSON.stringify(first.name)}].`,
			reason: "duplicate-contribute",
			stage: "validateManifests",
			details: {
				reason: "duplicate-contribute",
				kind: first.kind,
				identity: first.name,
				identityKind: "name",
				modules: first.modules,
			},
		});
	}
}

/** An entry without the keys core owns: what its type's schema reads. */
const typeKeysOf = (entry: object): Record<string, unknown> =>
	Object.fromEntries(
		Object.entries(entry).filter(([key]) => !FEDERATION_ENTRY_CORE_KEYS.includes(key)),
	);

/**
 * Whether `entry` holds an object under the key its type is named by: the
 * shape of an entry whose type's keys are nested, where a dispatched entry is
 * flat.
 */
const nestsUnderType = (entry: object, type: string): boolean => {
	if (!Object.hasOwn(entry, type)) return false;
	const nested = (entry as Record<string, unknown>)[type];
	return typeof nested === "object" && nested !== null;
};

/**
 * Parses each enabled `core.federations` entry whose `type` a module
 * registers, in the configuration's key order: its name held to the
 * federation-name rule, its `callbackURL` a non-empty string, and the rest of
 * it — the keys core owns removed — parsed synchronously by the type's
 * `entrySchema` as stage 1 read it, then copied and frozen. Answers what
 * stage 4 dispatches. Any refusal makes one `config-validation-failed`
 * naming every issue at the path the operator wrote
 * (`core.federations.<name>…`), each refused entry listed with the module
 * whose declaration of its type is in force and its path; a schema that
 * throws, or answers a value that throws as it is copied, is an issue at the
 * entry. An entry is flat: a key named after its type is read as one of the
 * type's keys, and the refusal of a missing `callbackURL` says so when that
 * key holds an object. Runs after `checkFederationEntriesHandled`, so an
 * entry it dispatches is contributed by no module directly.
 * @internal
 */
export function parseFederationEntries(
	modules: readonly NormalisedModule[],
	config: unknown,
): readonly DispatchedFederation[] {
	const types = declaredTypes(modules);
	const dispatched: DispatchedFederation[] = [];
	const issues: z.ZodIssue[] = [];
	// Each issue as the message names it, its entry's name written by `entryAt`.
	const named: string[] = [];
	const refused: { readonly module: string; readonly schemaPath: string }[] = [];
	for (const [name, entry] of enabledFederationsOf(config)) {
		const type = typeOf(entry);
		const declared = type === undefined ? undefined : types.get(type);
		if (type === undefined || declared === undefined) continue;
		const at = ["core", "federations", name];
		const found = issues.length;
		const issue = (path: readonly PropertyKey[], message: string, extra: object = {}): void => {
			issues.push({ code: "custom", ...extra, path: [...at, ...path], message } as z.ZodIssue);
			named.push(`${[entryAt(name), ...path.map(String)].join(".")}: ${message}`);
		};
		const nameProblem = federationNameProblem(name);
		if (nameProblem !== undefined) issue([], nameProblem);
		const callbackURL = (entry as { readonly callbackURL?: unknown }).callbackURL;
		if (typeof callbackURL !== "string" || callbackURL.length === 0) {
			issue(
				["callbackURL"],
				"an enabled federation's callbackURL is required: the URL its upstream redirects back to" +
					(nestsUnderType(entry, type)
						? `; a dispatched entry is flat: the keys nested under ${JSON.stringify(type)} are not read, so write them beside its type`
						: ""),
			);
		}
		const result = parseSection(
			declared.snapshot.entrySchema as z.ZodType,
			typeKeysOf(entry),
			`the entry schema of the type ${JSON.stringify(type)}`,
		);
		if ("issues" in result) {
			for (const { path, message, ...extra } of result.issues) issue(path, message, extra);
		}
		let parsed: unknown;
		if ("data" in result) {
			try {
				parsed = frozenSection(result.data);
			} catch (thrown) {
				issue(
					[],
					`the entry the schema of the type ${JSON.stringify(type)} answered threw as it was copied: ${failureSummary(thrown)}`,
				);
			}
		}
		if (issues.length > found || !("data" in result)) {
			refused.push({ module: declared.module, schemaPath: operatorPath(at) });
			continue;
		}
		dispatched.push({
			type,
			module: declared.module,
			instance: Object.freeze({ name, callbackURL: callbackURL as string, entry: parsed }),
		});
	}
	if (issues.length > 0) {
		throw new BootError({
			message: `Config validation failed — ${issues.length} issue(s) found in core.federations: ${named.join("; ")}.`,
			reason: "config-validation-failed",
			stage: "validateManifests",
			details: { reason: "config-validation-failed", issues, modules: refused },
		});
	}
	return dispatched;
}

// ---------------------------------------------------------------------------
// Stage 4
// ---------------------------------------------------------------------------

/** What one dispatched entry builds: its provider and its redirect policy, registered as a pair. */
export interface DispatchedPair {
	readonly provider: FederationProvider;
	readonly redirectPolicy: unknown;
}

/**
 * Builds the provider and the redirect policy of one dispatched entry with
 * its type's registered factories, the provider first. Throws — for the
 * caller to report as the contribution's failure — when a factory throws,
 * when the provider is not an object named after its entry
 * (`namedProvider`), or when the policy is not an object. Registers nothing:
 * the caller registers both, or neither.
 * @internal
 */
export async function buildDispatchedFederation(
	federation: DispatchedFederation,
	types: NameKeyedCollector<RegisteredFederationType> | undefined,
): Promise<DispatchedPair> {
	const { instance } = federation;
	const registered = types?.get(federation.type);
	if (registered === undefined) {
		throw new Error(
			`invariant violated: the type ${JSON.stringify(federation.type)} stage 1 dispatched ${JSON.stringify(instance.name)} to is not registered`,
		);
	}
	const subject = `the type ${JSON.stringify(federation.type)}'s`;
	const provider = namedProvider(
		await registered.create(instance),
		instance.name,
		`${subject} factory`,
		`its entry, ${JSON.stringify(instance.name)}`,
	);
	const redirectPolicy: unknown = await registered.redirectPolicy(instance);
	if (typeof redirectPolicy !== "object" || redirectPolicy === null) {
		throw new RangeError(`${subject} redirectPolicy must answer a redirect policy, an object`);
	}
	return { provider, redirectPolicy };
}

/**
 * The provider a module contributes or overrides directly under
 * `federations.<key>`, held to what a dispatched entry's provider is held to
 * (`namedProvider`): an object named `key`. Throws — for the caller to report
 * as the contribution's failure — otherwise; the message names the key as a
 * path (`keyAt`).
 * @internal
 */
export function checkDirectFederation(key: string, provider: unknown): FederationProvider {
	return namedProvider(provider, key, `${keyAt("federations", key)}: the factory`, "its key");
}

/**
 * `provider` when it is an object whose `name` is `name`, or a `RangeError`:
 * the session finds a federation's redirect policy and callback URL by its
 * provider's name, so a provider registered under another name would be
 * served there with another federation's. `subject` is what answered the
 * provider and `namedAfter` what its name must be, as the message says them.
 * The provider's name is read once and quoted only as JSON, and only when it
 * is a string; nothing else of the provider is quoted.
 */
function namedProvider(
	provider: unknown,
	name: string,
	subject: string,
	namedAfter: string,
): FederationProvider {
	if (typeof provider !== "object" || provider === null) {
		throw new RangeError(`${subject} must answer a provider, an object`);
	}
	const answered = (provider as { readonly name?: unknown }).name;
	if (answered !== name) {
		const named =
			typeof answered === "string"
				? `named ${JSON.stringify(answered)}`
				: answered === undefined
					? "without a name"
					: "whose name is not a string";
		throw new RangeError(
			`${subject} must answer a provider named after ${namedAfter} (it answered one ${named}): its redirect policy and callback URL are found by that name`,
		);
	}
	return provider as FederationProvider;
}
