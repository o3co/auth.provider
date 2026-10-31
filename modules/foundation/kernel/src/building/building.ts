import type { Contract, ExtensionPoint, Handle } from "../handles.ts";
import { periodic } from "../lifecycle/every.ts";
import { isTimerMs, type ReadinessReport } from "../lifecycle/readiness.ts";
import type { StopHook } from "../lifecycle/stop.ts";
import type { BuildContext, Module } from "../module.ts";
import {
	buildRefusalOf,
	type Refusal,
	RefusalSignal,
	readThrown,
	refusalsIn,
} from "../refusal/refusal.ts";
import type { Runtime } from "../runtime/runtime.ts";
import { countRefusal, takenByRefusal } from "../takes/takes.ts";

type Hook = () => Promise<void> | void;
/** One provision or contribution, as assembly builds it. */
export type Buildable = {
	readonly module: Module;
	readonly create: (c: BuildContext<unknown>) => unknown;
};

/** Failure of something this item needed; the original refusal is already recorded. */
class DependencyFailed extends Error {}

/** What a test may watch of the takes as the assembly holds them; nothing an app is given. */
export interface TakesWatch {
	/** The takes a declaring module is held to, once the preflight has asked them. */
	held(module: string, handles: ReadonlySet<Handle>): void;
	/** A handle a declaring module's factory took, by get, late or collect. */
	took(module: string, handle: Handle): void;
}

/**
 * Records why a build failed, unless the refusal behind it is recorded already. A value whose
 * reading throws, or that is no refusal the kernel can read, is a failure, never passed over.
 */
export function recordFailure(error: unknown, where: string, refusals: Refusal[]): void {
	const failed = { where, reason: "failed during assembly" };
	const seen = readThrown(
		() =>
			error instanceof RefusalSignal
				? "signal"
				: error instanceof DependencyFailed
					? "dependency"
					: "other",
		"unreadable",
	);
	if (seen === "signal") {
		// Read as a thrown value is, into the kernel's own list: a signal rethrown altered may hold none.
		const told = refusalsIn(readThrown(() => (error as RefusalSignal).refusals, undefined));
		for (const refusal of told.length > 0 ? told : [failed]) refusals.push(refusal);
	}
	// A library's refusal names its own where and reason; any other error's text is never kept.
	else if (seen !== "dependency") refusals.push(buildRefusalOf(error) ?? failed);
}

/** Freezes each contribution one level and checks the point's rule; a break records and throws. */
export function checkPoint<T>(
	point: ExtensionPoint<T>,
	values: T[],
	refusals: Refusal[],
): readonly T[] {
	// One level only: the values a contribution holds (schemas and the like) keep internal state.
	for (const value of values) if (value !== null && typeof value === "object") Object.freeze(value);
	const rule = point.rule;
	const broken = countRefusal(rule, values.length);
	if (broken) {
		refusals.push({ where: point.label, reason: broken });
		throw new DependencyFailed();
	}
	if (rule.multiplicity === "keyed") {
		const seen = new Set<string>();
		const twice = new Set<string>();
		for (const value of values) {
			const key = rule.keyOf(value);
			if (seen.has(key)) twice.add(key);
			seen.add(key);
		}
		for (const key of twice) {
			refusals.push({
				where: `${point.label}:${key}`,
				reason: "more than one contribution for the same key",
			});
		}
		if (twice.size > 0) throw new DependencyFailed();
	}
	return Object.freeze(values);
}

/** What `buildingWith` builds from: the preflight's outcome, and where its refusals go. */
export interface BuildingParts {
	readonly runtime: Runtime;
	readonly environment: BuildContext<unknown>["environment"];
	readonly sections: ReadonlyMap<Module, unknown>;
	readonly parts: {
		readonly providers: ReadonlyMap<Contract<unknown>, Buildable>;
		readonly contributions: ReadonlyMap<ExtensionPoint<unknown>, readonly Buildable[]>;
	};
	readonly heldTakes: ReadonlyMap<Module, ReadonlySet<Handle>>;
	readonly refusals: Refusal[];
	readonly watch?: TakesWatch | undefined;
}

/**
 * Builds provisions and contributions on request, each once, refusing cycles, gaps and takes beyond
 * the takes; it answers what the builds registered, and is told when assembly has succeeded.
 */
export function buildingWith({
	runtime,
	environment,
	sections,
	parts,
	heldTakes,
	refusals,
	watch,
}: BuildingParts) {
	const { providers, contributions } = parts;
	const built = new Map<Buildable, Promise<unknown>>();
	const builtContracts = new Map<Contract<unknown>, unknown>();
	const startHooks: Hook[] = [];
	const stopHooks: StopHook[] = [];
	const periodics: ReturnType<typeof periodic>[] = [];

	/** Which builds each unfinished build is waiting on, so a cycle across branches is seen. */
	const waits = new Map<Buildable, Set<Buildable>>();
	/** Contracts named by late references, with who named them; checked once everything is built. */
	const lateNamed: { contract: Contract<unknown>; by: string }[] = [];
	/** Set once assembly succeeds; late references and readiness are refused until then. */
	let assembled:
		| { readonly readiness: (deadlineMs: number) => Promise<ReadinessReport> }
		| undefined;
	/** Points some module collected, each with its check's outcome: one check, one refusal, however many collect it. */
	const collected = new Map<ExtensionPoint<unknown>, readonly unknown[] | undefined>();
	const waitsOn = (from: Buildable, to: Buildable, seen = new Set<Buildable>()): boolean => {
		if (from === to) return true;
		if (seen.has(from)) return false;
		seen.add(from);
		return [...(waits.get(from) ?? [])].some((next) => waitsOn(next, to, seen));
	};
	/** A module a contract does not name taking it is refused, recorded even where the taker catches the throw. */
	const mayTake = (contract: Contract<unknown>, item: Buildable) => {
		const taken = takenByRefusal(contract, item.module);
		if (taken === undefined) return;
		refusals.push({ where: item.module.name, reason: taken });
		throw new DependencyFailed();
	};
	/** Each take beyond a declaring module's takes, refused once, even where the taker catches the throw. */
	const beyondTakes = new Map<Module, Set<Handle>>();
	const mayName = (handle: Handle, item: Buildable) => {
		// Every module is held once the preflight passed; one it could not ask holds nothing.
		const held = heldTakes.get(item.module) ?? new Set<Handle>();
		if (held.has(handle)) {
			watch?.took(item.module.name, handle);
			return;
		}
		if (item.module.provides?.some((provision) => provision.contract === handle)) return;
		const refused = beyondTakes.get(item.module) ?? new Set<Handle>();
		if (!refused.has(handle)) {
			refusals.push({
				where: item.module.name,
				reason: `takes ${handle.label}, which its takes do not name`,
			});
		}
		beyondTakes.set(item.module, refused.add(handle));
		throw new DependencyFailed();
	};
	/** What a factory sees while `item` is built; `next` is the stack its requests extend. */
	const contextFor = (item: Buildable, next: readonly Buildable[]): BuildContext<unknown> =>
		withEnvironment({
			...runtime,
			section: sections.get(item.module),
			get: async <T>(contract: Contract<T>) => {
				mayName(contract as Contract<unknown>, item);
				mayTake(contract as Contract<unknown>, item);
				const provider = providers.get(contract as Contract<unknown>);
				if (!provider) {
					refusals.push({
						where: item.module.name,
						reason: `no module provides ${contract.label}`,
					});
					throw new DependencyFailed();
				}
				return (await build(provider, next)) as T;
			},
			collect: async <T>(point: ExtensionPoint<T>) => {
				mayName(point, item);
				const list = contributions.get(point as ExtensionPoint<unknown>) ?? [];
				const values: T[] = [];
				// Each collector builds the contributions itself, so a cycle through it is still seen.
				for (const contributor of list) values.push((await build(contributor, next)) as T);
				const key = point as ExtensionPoint<unknown>;
				if (collected.has(key)) {
					const checked = collected.get(key);
					if (checked === undefined) throw new DependencyFailed();
					return checked as readonly T[];
				}
				try {
					const checked = checkPoint(point, values, refusals);
					collected.set(key, checked);
					return checked;
				} catch (error) {
					collected.set(key, undefined);
					throw error;
				}
			},
			late: <T>(contract: Contract<T>) => {
				mayName(contract as Contract<unknown>, item);
				mayTake(contract as Contract<unknown>, item);
				lateNamed.push({ contract: contract as Contract<unknown>, by: item.module.name });
				return () => {
					if (!assembled) throw new Error(`${contract.label} is used before assembly is done`);
					return builtContracts.get(contract as Contract<unknown>) as T;
				};
			},
			readinessReport: (deadlineMs) => {
				if (!assembled) {
					return Promise.reject(new Error("readiness is asked before assembly is done"));
				}
				return assembled.readiness(deadlineMs);
			},
			onStart: (hook) => startHooks.push(hook),
			onStop: (hook) => stopHooks.push({ module: item.module.name, run: hook }),
			every: (intervalMs, task) => {
				if (!isTimerMs(intervalMs)) {
					throw new RefusalSignal([
						{
							where: item.module.name,
							reason: "the every interval must be a whole number of ms, 1 to 2^31-1",
						},
					]);
				}
				periodics.push(periodic(intervalMs, task, runtime.log, item.module.name));
			},
			refuse: (where, reason) => {
				throw new RefusalSignal([{ where, reason }]);
			},
			refuseAll: (list) => {
				throw new RefusalSignal(
					list.length > 0 ? list : [{ where: item.module.name, reason: "refused" }],
				);
			},
		});
	/** The context with the deployment's environment, which no factory can write or redefine. */
	const withEnvironment = (context: Omit<BuildContext<unknown>, "environment">) =>
		Object.defineProperty(context, "environment", {
			value: environment,
			enumerable: true,
			writable: false,
			configurable: false,
		}) as BuildContext<unknown>;
	const build = (item: Buildable, stack: readonly Buildable[]): Promise<unknown> => {
		const requester = stack.at(-1);
		// Before the cache: joining an unfinished build that waits on the requester would never settle.
		if (stack.includes(item) || (requester && waitsOn(item, requester))) {
			refusals.push({ where: item.module.name, reason: "dependency cycle" });
			return Promise.reject(new DependencyFailed());
		}
		if (requester) waits.set(requester, (waits.get(requester) ?? new Set()).add(item));
		const existing = built.get(item);
		if (existing) return existing;
		const context = contextFor(item, [...stack, item]);
		const promise = (async () => {
			try {
				return await item.create(context);
			} catch (error) {
				recordFailure(error, item.module.name, refusals);
				throw new DependencyFailed();
			}
		})();
		// Cached for every later request; a failure nobody awaits must not surface as unhandled.
		promise.catch(() => {});
		built.set(item, promise);
		return promise;
	};

	return {
		build,
		collected,
		lateNamed,
		builtContracts,
		hooks: { start: startHooks, stop: stopHooks, periodics },
		/** Late references and readiness answer from here on, readiness by `readiness`. */
		assembledWith: (readiness: (deadlineMs: number) => Promise<ReadinessReport>) => {
			assembled = { readiness };
		},
	};
}
