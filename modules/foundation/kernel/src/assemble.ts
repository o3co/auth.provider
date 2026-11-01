import {
	type Buildable,
	buildingWith,
	checkPoint,
	recordFailure,
	type TakesWatch,
} from "./building/building.ts";
import { readSections } from "./config/sections.ts";
import { checkProduction, checkReplicas } from "./deployment/deployment.ts";
import type { Contract, ExtensionPoint } from "./handles.ts";
import { isTimerMs, type Probe, probes, readinessOf } from "./lifecycle/readiness.ts";
import { stopWithin } from "./lifecycle/stop.ts";
import type { Module } from "./module.ts";
import { BootRefused, type Refusal } from "./refusal/refusal.ts";
import { guardedLog, logSinks, routedLog } from "./runtime/log.ts";
import {
	hearStandardStreams,
	type LogSink,
	type Runtime,
	systemClock,
	systemRandom,
} from "./runtime/runtime.ts";
import { checkTakes } from "./takes/takes.ts";

export interface Assembly {
	/** The contract's interface; one no module provides throws an Error at once. */
	get<T>(contract: Contract<T>): T;
	/**
	 * Runs the start hooks in the order registered, one at a time; the first that rejects stops the
	 * rest and the periodic tasks from starting, and `start` rejects with it. It has no deadline and
	 * is called once: a second call runs the hooks and starts the periodic tasks again.
	 */
	start(): Promise<void>;
	/**
	 * Without a deadline, the kernel section's `stop-deadline`. It is called once: each call runs the
	 * stop hooks again, and calls made side by side are not joined, so the caller stops once.
	 */
	stop(deadlineMs?: number): Promise<void>;
}

export interface AssemblyInput {
	readonly modules: readonly Module[];
	readonly config: unknown;
	readonly runtime?: Runtime;
}

/** A top-level build as a value; a failure's refusal is recorded already. */
type Built = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

/** Who provides each contract and who contributes to each point; a contract provided twice is refused. */
function indexParts(modules: readonly Module[], refusals: Refusal[]) {
	const providers = new Map<Contract<unknown>, Buildable>();
	const contributions = new Map<ExtensionPoint<unknown>, Buildable[]>();
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

/** Builds the modules; it waits on each factory without a deadline (`stop-deadline` bounds stopping alone). */
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
	const { kernel, unsure, sections } = readSections(modules, input.config, refusals);
	hearStandardStreams();
	let sinkList: readonly LogSink[] | undefined;
	// A runtime a test passes keeps its log, without threshold or sinks; its calls still never throw.
	const runtime: Runtime = input.runtime
		? { ...input.runtime, log: guardedLog(input.runtime.log) }
		: {
				clock: systemClock,
				random: systemRandom,
				log: routedLog(kernel.logging.level, systemClock, () => sinkList),
			};
	// A deployment or environment its refused section does not hold validly is no ground to refuse on.
	if (!unsure.has("deployment")) checkReplicas(modules, sections, kernel.deployment, refusals);
	const allowed = unsure.has("environment")
		? []
		: checkProduction(modules, sections, kernel.environment, refusals);
	// One preflight before any factory runs: every structural gap is named in one refusal, and a
	// refused boot has built nothing, so no stop hook is left to run.
	const parts = indexParts(modules, refusals);
	const { providers, contributions } = parts;
	const heldTakes = checkTakes(modules, sections, parts, refusals);
	for (const [module, handles] of heldTakes) watch?.held(module.name, handles);
	refuseIfAny(refusals);

	const { build, collected, lateNamed, provided, hooks, assembledWith } = buildingWith({
		runtime,
		environment: kernel.environment,
		sections,
		parts,
		heldTakes,
		refusals,
		watch,
	});
	let stopping = false;
	const outcomeOf = (item: Buildable): Promise<Built> =>
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
	// Once the sinks are built, so the lines reach them: what production would refuse, at each start.
	for (const { where, reason } of allowed) {
		runtime.log.warn("kernel.allowed_in_development", { key: where, reason });
	}
	// Each provision records its interface as it is built.
	for (const item of providers.values()) await outcomeOf(item);
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
		await stopWithin(kernel["stop-deadline"] * 1000, [], hooks.stop, runtime.log, {
			during: "refusal",
		});
		throw refused;
	}
	assembledWith(readinessOf(probeList, runtime, () => stopping));

	return {
		get: <T>(contract: Contract<T>) => {
			const found = provided(contract as Contract<unknown>);
			if (!found) throw new Error(`${contract.label} is not provided`);
			return found.value as T;
		},
		start: async () => {
			for (const hook of hooks.start) await hook();
			for (const task of hooks.periodics) task.start();
		},
		stop: async (deadlineMs = kernel["stop-deadline"] * 1000) => {
			if (!isTimerMs(deadlineMs)) {
				throw new TypeError("the stop deadline must be a whole number of ms, 1 to 2^31-1");
			}
			stopping = true;
			await stopWithin(deadlineMs, hooks.periodics, hooks.stop, runtime.log);
		},
	};
}
