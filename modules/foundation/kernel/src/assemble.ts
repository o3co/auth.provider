import { readSections } from "./config/sections.ts";
import { checkProduction, checkReplicas } from "./deployment/deployment.ts";
import type { Contract, ExtensionPoint, Handle } from "./handles.ts";
import { periodic } from "./lifecycle/every.ts";
import {
	isTimerMs,
	type Probe,
	probes,
	type ReadinessReport,
	readinessOf,
} from "./lifecycle/readiness.ts";
import { type StopHook, stopWithin } from "./lifecycle/stop.ts";
import type { BuildContext, Module } from "./module.ts";
import {
	BootRefused,
	buildRefusalOf,
	type Refusal,
	RefusalSignal,
	readThrown,
} from "./refusal/refusal.ts";
import { guardedLog, logSinks, routedLog } from "./runtime/log.ts";
import { type LogSink, type Runtime, systemClock, systemRandom } from "./runtime/runtime.ts";
import { checkTakes, countRefusal, takenByRefusal } from "./takes/takes.ts";

export interface Assembly {
	get<T>(contract: Contract<T>): T;
	start(): Promise<void>;
	/** Without a deadline, the kernel section's `stop-deadline`. */
	stop(deadlineMs?: number): Promise<void>;
}

export interface AssemblyInput {
	readonly modules: readonly Module[];
	readonly config: unknown;
	readonly runtime?: Runtime;
}

type Hook = () => Promise<void> | void;
/** One provision or contribution, as assembly builds it. */
type Item = { readonly module: Module; readonly create: (c: BuildContext<unknown>) => unknown };
/** A top-level build as a value; a failure's refusal is recorded already. */
type Built = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

/** Failure of something this item needed; the original refusal is already recorded. */
class DependencyFailed extends Error {}

/** Who provides each contract and who contributes to each point; a contract provided twice is refused. */
function indexParts(modules: readonly Module[], refusals: Refusal[]) {
	const providers = new Map<Contract<unknown>, Item>();
	const contributions = new Map<ExtensionPoint<unknown>, Item[]>();
	for (const module of modules) {
		for (const provision of module.provides ?? []) {
			if (providers.has(provision.contract)) {
				refusals.push({
					where: provision.contract.label,
					reason: "provided by more than one module",
				});
			}
			providers.set(provision.contract, { module, create: provision.create });
		}
		for (const contribution of module.contributes ?? []) {
			const list = contributions.get(contribution.point) ?? [];
			list.push({ module, create: contribution.create });
			contributions.set(contribution.point, list);
		}
	}
	return { providers, contributions };
}

function refuseIfAny(refusals: readonly Refusal[]): void {
	if (refusals.length > 0) throw new BootRefused(refusals);
}

/**
 * Records why a build failed, unless the refusal behind it is recorded already. A value whose
 * reading throws, or that is no refusal the kernel can read, is a failure, never passed over.
 */
function recordFailure(error: unknown, where: string, refusals: Refusal[]): void {
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
	if (seen === "signal") refusals.push(...(error as RefusalSignal).refusals);
	// A library's refusal names its own where and reason; any other error's text is never kept.
	else if (seen !== "dependency") refusals.push(buildRefusalOf(error) ?? failed);
}

/** What a test may watch of the takes as the assembly holds them; nothing an app is given. */
export interface TakesWatch {
	/** The takes a declaring module is held to, once the preflight has asked them. */
	held(module: string, handles: ReadonlySet<Handle>): void;
	/** A handle a declaring module's factory took, by get, late or collect. */
	took(module: string, handle: Handle): void;
}

export function assemble(input: AssemblyInput): Promise<Assembly> {
	return assembleWatching(input);
}

/** `assemble`, with the takes it holds and the takes taken told to a test's watch (`./testing`). */
export async function assembleWatching(
	input: AssemblyInput,
	watch?: TakesWatch,
): Promise<Assembly> {
	const modules = input.modules;
	const refusals: Refusal[] = [];
	const { kernel, sections } = readSections(modules, input.config, refusals);
	let sinkList: readonly LogSink[] | undefined;
	// A runtime a test passes keeps its log, without threshold or sinks; its calls still never throw.
	const runtime: Runtime = input.runtime
		? { ...input.runtime, log: guardedLog(input.runtime.log) }
		: {
				clock: systemClock,
				random: systemRandom,
				log: routedLog(kernel.logging.level, systemClock, () => sinkList),
			};
	checkReplicas(modules, sections, kernel.deployment, refusals);
	checkProduction(modules, sections, kernel.environment, refusals);
	// One preflight before any factory runs: every structural gap is named in one refusal, and a
	// refused boot has built nothing, so no stop hook is left to run.
	const parts = indexParts(modules, refusals);
	const { providers, contributions } = parts;
	const heldTakes = checkTakes(modules, sections, parts, refusals);
	for (const [module, handles] of heldTakes) watch?.held(module.name, handles);
	refuseIfAny(refusals);

	const built = new Map<Item, Promise<unknown>>();
	const builtContracts = new Map<Contract<unknown>, unknown>();
	const startHooks: Hook[] = [];
	const stopHooks: StopHook[] = [];
	const periodics: ReturnType<typeof periodic>[] = [];

	/** Which builds each unfinished build is waiting on, so a cycle across branches is seen. */
	const waits = new Map<Item, Set<Item>>();
	/** Contracts named by late references, with who named them; checked once everything is built. */
	const lateNamed: { contract: Contract<unknown>; by: string }[] = [];
	let stopping = false;
	/** Set once assembly succeeds; late references and readiness are refused until then. */
	let assembled:
		| { readonly readiness: (deadlineMs: number) => Promise<ReadinessReport> }
		| undefined;
	/** Points some module collected, each with its check's outcome: one check, one refusal, however many collect it. */
	const collected = new Map<ExtensionPoint<unknown>, readonly unknown[] | undefined>();
	const waitsOn = (from: Item, to: Item, seen = new Set<Item>()): boolean => {
		if (from === to) return true;
		if (seen.has(from)) return false;
		seen.add(from);
		return [...(waits.get(from) ?? [])].some((next) => waitsOn(next, to, seen));
	};
	/** A module a contract does not name taking it is refused, recorded even where the taker catches the throw. */
	const mayTake = (contract: Contract<unknown>, item: Item) => {
		const taken = takenByRefusal(contract, item.module);
		if (taken === undefined) return;
		refusals.push({ where: item.module.name, reason: taken });
		throw new DependencyFailed();
	};
	/** Each take beyond a declaring module's takes, refused once, even where the taker catches the throw. */
	const beyondTakes = new Map<Module, Set<Handle>>();
	const mayName = (handle: Handle, item: Item) => {
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
	const contextFor = (item: Item, next: readonly Item[]): BuildContext<unknown> => ({
		...runtime,
		section: sections.get(item.module),
		environment: kernel.environment,
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
	const build = (item: Item, stack: readonly Item[]): Promise<unknown> => {
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
	const outcomeOf = (item: Item): Promise<Built> =>
		build(item, []).then(
			(value) => ({ ok: true, value }),
			() => ({ ok: false }),
		);

	// Sinks come first, so the other parts' lines reach them; lines logged while they build are dropped.
	const sinks: LogSink[] = [];
	for (const item of contributions.get(logSinks as ExtensionPoint<unknown>) ?? []) {
		const outcome = await outcomeOf(item);
		if (outcome.ok) sinks.push(outcome.value as LogSink);
	}
	sinkList = sinks;
	for (const [contract, item] of providers) {
		const outcome = await outcomeOf(item);
		if (outcome.ok) builtContracts.set(contract, outcome.value);
	}
	let probeList: readonly Probe[] = [];
	for (const [point, list] of contributions) {
		const outcomes: Built[] = [];
		for (const item of list) outcomes.push(await outcomeOf(item));
		const values = outcomes.flatMap((outcome) => (outcome.ok ? [outcome.value] : []));
		if (point === probes) probeList = values as Probe[];
		// A point no module collects still keeps its promises; a failed contribution is refused already.
		if (outcomes.every((outcome) => outcome.ok) && !collected.has(point)) {
			try {
				checkPoint(point, values, refusals);
			} catch (error) {
				recordFailure(error, point.label, refusals);
			}
		}
	}
	for (const { contract, by } of lateNamed) {
		if (!providers.has(contract)) {
			refusals.push({ where: by, reason: `no module provides ${contract.label}` });
		}
	}
	if (refusals.length > 0) {
		// Taken first: a context a build kept may still add refusals, from a stop hook too.
		const refused = new BootRefused(refusals);
		// What the builds started, ended before refusing: the hooks registered so far, in reverse.
		await stopWithin(kernel["stop-deadline"] * 1000, [], stopHooks, runtime.log, {
			during: "refusal",
		});
		throw refused;
	}
	assembled = { readiness: readinessOf(probeList, runtime, () => stopping) };

	return {
		get: <T>(contract: Contract<T>) => {
			if (!builtContracts.has(contract as Contract<unknown>)) {
				throw new Error(`${contract.label} is not provided`);
			}
			return builtContracts.get(contract as Contract<unknown>) as T;
		},
		start: async () => {
			for (const hook of startHooks) await hook();
			for (const task of periodics) task.start();
		},
		stop: async (deadlineMs = kernel["stop-deadline"] * 1000) => {
			if (!isTimerMs(deadlineMs)) {
				throw new TypeError("the stop deadline must be a whole number of ms, 1 to 2^31-1");
			}
			stopping = true;
			await stopWithin(deadlineMs, periodics, stopHooks, runtime.log);
		},
	};
}

/** Freezes each contribution one level and checks the point's rule; a break records and throws. */
function checkPoint<T>(point: ExtensionPoint<T>, values: T[], refusals: Refusal[]): readonly T[] {
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
