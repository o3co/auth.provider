import type { ZodType } from "zod";
import type { Contract, ExtensionPoint, Handle } from "./handles.ts";
import type { ReadinessReport } from "./lifecycle/readiness.ts";
import type { Refusal } from "./refusal/refusal.ts";
import type { Runtime } from "./runtime/runtime.ts";

export interface BuildContext<S> extends Runtime {
	readonly section: S;
	/**
	 * The deployment's environment (`kernel.environment`), for a check only a build can make, such
	 * as of settings an owner opens while it builds. What a section alone shows is a module's
	 * `refusedInProduction`, refused with the preflight at once; a refusal here comes as it builds.
	 * No factory can write or redefine it.
	 */
	readonly environment: "production" | "development";
	get<T>(contract: Contract<T>): Promise<T>;
	collect<T>(point: ExtensionPoint<T>): Promise<readonly T[]>;
	/**
	 * The interface a contract names, for use once assembly is done; it builds nothing now, so a
	 * contributor may hold its owner's. Called during assembly, or after a refused one, it throws.
	 */
	late<T>(contract: Contract<T>): () => T;
	/**
	 * Whether every contribution to `probes` passes within `deadlineMs` (1 to 2^31-1, else it
	 * rejects with a TypeError), with each probe's result by name; unready and all down once stop
	 * begins. It rejects until assembly is done.
	 */
	readinessReport(deadlineMs: number): Promise<ReadinessReport>;
	onStart(hook: () => Promise<void> | void): void;
	/**
	 * Hooks run in reverse order, each awaited; one that fails is logged and the next runs. At the
	 * stop deadline the signal aborts, and the hooks left are called without waiting.
	 */
	onStop(hook: (signal: AbortSignal) => Promise<void> | void): void;
	/**
	 * Runs `task` every `intervalMs` from the start, never two runs at once. Stopping aborts the
	 * running run's signal and waits for it, before the stop hooks. A failed run is logged, and the
	 * next one comes as usual.
	 */
	every(intervalMs: number, task: (signal: AbortSignal) => Promise<void>): void;
	refuse(where: string, reason: string): never;
	/**
	 * Refuses with every problem found at once, so the operator sees them together. The list, and
	 * the signal thrown, are left as given: one emptied or rethrown altered may leave no refusal read.
	 */
	refuseAll(refusals: readonly Refusal[]): never;
}

export type Factory<S, T> = (context: BuildContext<S>) => T | Promise<T>;

export interface Provision<S> {
	readonly contract: Contract<unknown>;
	readonly create: Factory<S, unknown>;
}

export interface Contribution<S> {
	readonly point: ExtensionPoint<unknown>;
	readonly create: Factory<S, unknown>;
}

export interface ModuleHead<S> {
	readonly name: string;
	readonly section?: ZodType<S>;
	/** A function is asked only with a section that passed its schema. */
	readonly replicaSafe?: boolean | ((section: S) => boolean);
	/**
	 * What a production deployment must not hold in this section: each a key path below the section
	 * and a reason, never a value, which boot is refused with. Asked only where `kernel.environment`
	 * is production, and only with a section that passed its schema.
	 */
	readonly refusedInProduction?: (
		section: S,
	) => readonly { readonly key: string; readonly reason: string }[];
	/**
	 * What its factories take from other modules: each contract they `get` or hold `late`, and each
	 * point they `collect`; a contract it provides itself is not named. A function is asked only
	 * with a section that passed its schema. Required: a module taking nothing names none (`[]`).
	 */
	readonly takes: readonly Handle[] | ((section: S) => readonly Handle[]);
}

export interface ModuleDefinition<S = unknown> extends ModuleHead<S> {
	readonly provides?: readonly Provision<S>[];
	readonly contributes?: readonly Contribution<S>[];
}

/** A module with its section type erased, as assembly sees it. */
export type Module = ModuleDefinition<unknown>;

/** Two steps, so the value type is fixed by the handle before the factory is checked. */
export interface Parts<S> {
	provide<T>(contract: Contract<T>): { by(create: Factory<S, T>): Provision<S> };
	contribute<T>(point: ExtensionPoint<T>): { by(create: Factory<S, T>): Contribution<S> };
}

const parts: Parts<never> = {
	provide: (contract) => ({
		by: (create) => ({ contract: contract as Contract<unknown>, create }) as Provision<never>,
	}),
	contribute: (point) => ({
		// keyOf takes T, so a point is not assignable to the unknown one directly.
		by: (create) =>
			({ point: point as unknown as ExtensionPoint<unknown>, create }) as Contribution<never>,
	}),
};

export function defineModule<S = undefined>(
	head: ModuleHead<S>,
	body: (parts: Parts<S>) => readonly (Provision<S> | Contribution<S>)[] = () => [],
): Module {
	const all = body(parts as unknown as Parts<S>);
	const definition: ModuleDefinition<S> = {
		...head,
		provides: all.filter((part): part is Provision<S> => "contract" in part),
		contributes: all.filter((part): part is Contribution<S> => "point" in part),
	};
	return Object.freeze(definition) as unknown as Module;
}
