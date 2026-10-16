import { ConfigError, fromMap } from "@o3co/ts.hocon";
import { getValidated } from "@o3co/ts.hocon/zod";
import { type ZodType, z } from "zod";
import { periodic } from "./every.ts";
import { deepFreeze } from "./freeze.ts";
import type { Contract, ExtensionPoint } from "./handles.ts";
import { guardedLog, logSinks, routedLog } from "./log.ts";
import type { BuildContext, Module } from "./module.ts";
import { isTimerMs, type Probe, probes, type ReadinessReport, readinessOf } from "./readiness.ts";
import { BootRefused, type Refusal, RefusalSignal } from "./refusal.ts";
import { type LogSink, type Runtime, systemClock, systemRandom } from "./runtime.ts";
import { type KernelSettings, kernelSection } from "./settings.ts";

export interface Assembly {
	get<T>(contract: Contract<T>): T;
	start(): Promise<void>;
	/** Without a deadline, the kernel section's `stop-seconds`. */
	stop(deadlineMs?: number): Promise<void>;
}

export interface AssemblyInput {
	readonly modules: readonly Module[];
	readonly config: unknown;
	readonly runtime?: Runtime;
}

type Hook = () => Promise<void> | void;
type StopHook = {
	readonly module: string;
	readonly run: (signal: AbortSignal) => Promise<void> | void;
};
/** One provision or contribution, as assembly builds it. */
type Item = { readonly module: Module; readonly create: (c: BuildContext<unknown>) => unknown };
/** A top-level build as a value; a failure's refusal is recorded already. */
type Built = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

/** Failure of something this item needed; the original refusal is already recorded. */
class DependencyFailed extends Error {}

export const KERNEL_SECTION = "kernel";

/** The kernel's own section, a single deployment unless `settings` say otherwise; with none, all a new project needs. */
export function kernelConfig(settings: Partial<KernelSettings> = {}) {
	return { [KERNEL_SECTION]: { deployment: "single", ...settings } };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
	const proto = Object.getPrototypeOf(value);
	return proto === null || proto === Object.prototype;
}

type Issue = { readonly message: string; readonly path?: readonly PropertyKey[] };

/** Checks a section with the HOCON library's typed reading: a string converts as the schema asks. */
function readSection<T>(
	schema: ZodType<T>,
	raw: unknown,
): { readonly value: T } | { readonly issues: readonly Issue[] } {
	try {
		const tree = fromMap({ raw: plainTree(raw, "raw") });
		return { value: getValidated(tree, "raw", schema) };
	} catch (error) {
		if (error instanceof ConfigError) {
			return {
				issues: [{ message: "holds a value configuration cannot hold", path: keysOf(error.path) }],
			};
		}
		if (error instanceof z.core.$ZodError) return { issues: error.issues };
		throw error;
	}
}

/** The value as HOCON holds it (undefined fields absent, only plain objects nested), `at` its path as `raw.a[0].b`. */
function plainTree(value: unknown, at: string): unknown {
	if (Array.isArray(value)) return value.map((item, i) => plainTree(item, `${at}[${i}]`));
	if (value === null || typeof value !== "object") return value;
	if (!isPlainObject(value)) throw new ConfigError("not a plain object", at);
	const fields = Object.entries(value).filter((entry) => entry[1] !== undefined);
	return Object.fromEntries(fields.map(([key, field]) => [key, plainTree(field, `${at}.${key}`)]));
}

/** A path as the HOCON library writes one under the section's `raw`, as the keys a refusal names. */
const keysOf = (path: string): string[] =>
	path
		.replace(/\[(\d+)\]/g, ".$1")
		.split(".")
		.slice(1);

function readSections(
	modules: readonly Module[],
	config: unknown,
	refusals: Refusal[],
): { kernel: KernelSettings; sections: Map<Module, unknown> } {
	const sections = new Map<Module, unknown>();
	if (!isPlainObject(config)) {
		refusals.push({ where: "config", reason: "the configuration root is not an object" });
		return { kernel: refusedKernel(), sections };
	}
	const names = new Set<string>();
	for (const module of modules) {
		// "kernel" is taken by the kernel's own section.
		if (names.has(module.name) || module.name === KERNEL_SECTION) {
			refusals.push({ where: module.name, reason: "duplicate module name" });
		}
		names.add(module.name);
	}
	for (const key of Object.keys(config)) {
		if (key !== KERNEL_SECTION && !names.has(key)) {
			refusals.push({ where: key, reason: "section for a module that is not loaded" });
		}
	}
	const kernel = readKernel(config[KERNEL_SECTION], refusals);
	for (const module of modules) {
		const raw = Object.hasOwn(config, module.name) ? config[module.name] : undefined;
		if (module.section === undefined) {
			if (raw !== undefined)
				refusals.push({ where: module.name, reason: "module without a section" });
			continue;
		}
		const result = readSection(module.section, raw ?? {});
		if ("issues" in result) refuseIssues(module.name, result.issues, refusals);
		else sections.set(module, deepFreeze(result.value));
	}
	return { kernel, sections };
}

function refuseIssues(name: string, issues: readonly Issue[], refusals: Refusal[]): void {
	for (const issue of issues) {
		const path = (issue.path ?? []).map(String).join(".");
		refusals.push({ where: path ? `${name}.${path}` : name, reason: issue.message });
	}
}

function readKernel(raw: unknown, refusals: Refusal[]): KernelSettings {
	const result = readSection(kernelSection, raw ?? null);
	if (!("issues" in result)) return result.value;
	refuseIssues(KERNEL_SECTION, result.issues, refusals);
	return refusedKernel();
}

/** Stands in for a refused kernel section: boot is refused before any of it is used. */
function refusedKernel(): KernelSettings {
	return kernelSection.parse({ deployment: "single" });
}

function checkReplicas(
	modules: readonly Module[],
	sections: Map<Module, unknown>,
	deployment: KernelSettings["deployment"],
	refusals: Refusal[],
): void {
	if (deployment !== "multi") return;
	for (const module of modules) {
		// A section that failed its schema is refused already; the declaration expects a checked one.
		if (module.section !== undefined && !sections.has(module)) continue;
		const safe =
			typeof module.replicaSafe === "function"
				? module.replicaSafe(sections.get(module))
				: (module.replicaSafe ?? true);
		if (!safe)
			refusals.push({
				where: module.name,
				reason: "declares itself unsafe for multiple instances",
			});
	}
}

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

/** Records why a build failed, unless the refusal behind it is recorded already. */
function recordFailure(error: unknown, where: string, refusals: Refusal[]): void {
	if (error instanceof RefusalSignal) refusals.push(...error.refusals);
	else if (!(error instanceof DependencyFailed)) {
		refusals.push({ where, reason: "failed during assembly" });
	}
}

export async function assemble(input: AssemblyInput): Promise<Assembly> {
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
	refuseIfAny(refusals);
	const { providers, contributions } = indexParts(modules, refusals);
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
	/** What a factory sees while `item` is built; `next` is the stack its requests extend. */
	const contextFor = (item: Item, next: readonly Item[]): BuildContext<unknown> => ({
		...runtime,
		section: sections.get(item.module),
		get: async <T>(contract: Contract<T>) => {
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
	refuseIfAny(refusals);
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
		stop: async (deadlineMs = kernel["stop-seconds"] * 1000) => {
			if (!isTimerMs(deadlineMs)) {
				throw new TypeError("the stop deadline must be a whole number of ms, 1 to 2^31-1");
			}
			stopping = true;
			const controller = new AbortController();
			const late = new Promise<"late">((resolve) =>
				controller.signal.addEventListener("abort", () => resolve("late")),
			);
			const timer = setTimeout(() => controller.abort(), deadlineMs);
			timer.unref();
			await Promise.race([Promise.all(periodics.map((task) => task.stop())), late]);
			for (const hook of [...stopHooks].reverse()) {
				// Started inside a promise, so a hook that throws at once is logged like one that rejects.
				const done = Promise.resolve()
					.then(() => hook.run(controller.signal))
					.catch((error: unknown) => {
						runtime.log.warn("kernel.stop_failed", {
							module: hook.module,
							outcome: "failed",
							kind: error instanceof Error ? error.name : typeof error,
						});
					});
				// Past the deadline, each hook left is called with the aborted signal and not awaited.
				if (controller.signal.aborted) continue;
				if ((await Promise.race([done, late])) === "late") {
					runtime.log.warn("kernel.stop_failed", { module: hook.module, outcome: "late" });
				}
			}
			clearTimeout(timer);
		},
	};
}

/** Freezes each contribution one level and checks the point's rule; a break records and throws. */
function checkPoint<T>(point: ExtensionPoint<T>, values: T[], refusals: Refusal[]): readonly T[] {
	// One level only: the values a contribution holds (schemas and the like) keep internal state.
	for (const value of values) if (value !== null && typeof value === "object") Object.freeze(value);
	const rule = point.rule;
	switch (rule.multiplicity) {
		case "one":
			if (values.length !== 1) {
				refusals.push({
					where: point.label,
					reason: `needs exactly one contribution (${values.length})`,
				});
				throw new DependencyFailed();
			}
			break;
		case "some":
			if (values.length === 0) {
				refusals.push({ where: point.label, reason: "needs at least one contribution" });
				throw new DependencyFailed();
			}
			break;
		case "keyed": {
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
			break;
		}
		case "many":
			break;
	}
	return Object.freeze(values);
}
