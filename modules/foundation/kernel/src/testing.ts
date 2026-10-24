import { type AssemblyInput, assembleWatching } from "./assemble.ts";
import type { Contract, Handle } from "./handles.ts";
import type { Module } from "./module.ts";
import { Unavailable } from "./refusal/refusal.ts";
import {
	type Log,
	type LogFields,
	type LogLevel,
	type LogLine,
	type Runtime,
	systemClock,
	systemRandom,
} from "./runtime/runtime.ts";

/** A log that writes nothing. */
export const quietLog: Log = Object.freeze({
	trace: () => {},
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
	fatal: () => {},
});

/** A runtime for tests: the system clock and randomness and a quiet log, unless the test sets one. */
export function quietRuntime(parts: Partial<Runtime> = {}): Runtime {
	return Object.freeze({ clock: systemClock, random: systemRandom, log: quietLog, ...parts });
}

export interface RecordingLog {
	readonly log: Log;
	/** The lines so far, in order, with their level; fields are empty when the call gave none. */
	lines(): readonly Omit<LogLine, "at">[];
}

export function recordingLog(): RecordingLog {
	const kept: Omit<LogLine, "at">[] = [];
	const writer = (level: LogLevel) => (event: string, fields?: LogFields) => {
		kept.push(Object.freeze({ level, event, fields: Object.freeze({ ...fields }) }));
	};
	return Object.freeze({
		log: Object.freeze({
			trace: writer("trace"),
			debug: writer("debug"),
			info: writer("info"),
			warn: writer("warn"),
			error: writer("error"),
			fatal: writer("fatal"),
		}),
		lines: () => [...kept],
	});
}

/** Names of T's members that are functions answering a promise. Sync methods and values are not switchable. */
export type AsyncMethodOf<T> = {
	[K in keyof T]-?: T[K] extends (...args: never[]) => Promise<unknown> ? K : never;
}[keyof T] &
	string;

export interface UnavailableSwitch<T extends object> {
	/** T with each async method going through this switch; other members read through to `implementation`. */
	wrap(implementation: T): T;
	/** The next call of `method` rejects with Unavailable and does not reach the implementation. Called n times, the next n calls do. */
	failNext(method: AsyncMethodOf<T>): void;
	/** From now on, every call of these methods rejects with Unavailable and does not reach the implementation. */
	unavailable(method: AsyncMethodOf<T>, ...more: AsyncMethodOf<T>[]): void;
	/** Calls reach the implementation again; pending failNext calls are dropped. */
	restore(): void;
}

function memberKeys(implementation: object): (string | symbol)[] {
	const keys = new Set<string | symbol>();
	for (
		let at: object | null = implementation;
		at !== null && at !== Object.prototype;
		at = Object.getPrototypeOf(at)
	) {
		for (const key of Reflect.ownKeys(at)) if (key !== "constructor") keys.add(key);
	}
	return [...keys];
}

/** `what` goes into each Unavailable it throws. */
export function unavailableSwitch<T extends object>(what = "test"): UnavailableSwitch<T> {
	const pending = new Map<PropertyKey, number>();
	const down = new Set<PropertyKey>();
	const fails = (method: PropertyKey): boolean => {
		if (down.has(method)) return true;
		const left = pending.get(method) ?? 0;
		if (left === 0) return false;
		pending.set(method, left - 1);
		return true;
	};
	return Object.freeze({
		wrap(implementation: T): T {
			const source = implementation as Record<PropertyKey, unknown>;
			const wrapped: Record<PropertyKey, unknown> = {};
			for (const key of memberKeys(implementation)) {
				if (typeof source[key] === "function") {
					wrapped[key] = (...args: unknown[]) =>
						fails(key)
							? Promise.reject(new Unavailable(what))
							: Reflect.apply(source[key] as (...a: unknown[]) => unknown, implementation, args);
				} else {
					Object.defineProperty(wrapped, key, { enumerable: true, get: () => source[key] });
				}
			}
			return Object.freeze(wrapped) as T;
		},
		failNext(method: AsyncMethodOf<T>) {
			pending.set(method, (pending.get(method) ?? 0) + 1);
		},
		unavailable(method: AsyncMethodOf<T>, ...more: AsyncMethodOf<T>[]) {
			for (const name of [method, ...more]) down.add(name);
		},
		restore() {
			pending.clear();
			down.clear();
		},
	});
}

/** The same module, its provision of `provided` built and then wrapped by `by`; every other part unchanged. Throws TypeError at once if the module does not provide `provided`. */
export function switchedModule<T extends object>(
	module: Module,
	provided: Contract<T>,
	by: UnavailableSwitch<T>,
): Module {
	const provides = module.provides ?? [];
	if (!provides.some((part) => part.contract === provided)) {
		throw new TypeError(`${module.name} does not provide ${provided.label}`);
	}
	return Object.freeze({
		...module,
		provides: provides.map((part) =>
			part.contract !== provided
				? part
				: {
						contract: part.contract,
						create: async (context: Parameters<typeof part.create>[0]) =>
							by.wrap((await part.create(context)) as T),
					},
		),
	});
}

/**
 * Each handle a module's takes name that no factory took in this assembly, by module (a module
 * without takes left out, and one that took all it names): a stale take shows in a test, for each
 * section the test gives. It stops the assembly before it answers, and refuses as the boot does.
 */
export async function takesUnused(
	input: AssemblyInput,
): Promise<Readonly<Record<string, readonly string[]>>> {
	const held = new Map<string, ReadonlySet<Handle>>();
	const taken = new Map<string, Set<Handle>>();
	const assembly = await assembleWatching(input, {
		held: (module, handles) => held.set(module, handles),
		took: (module, handle) => taken.set(module, (taken.get(module) ?? new Set()).add(handle)),
	});
	// Read as the assembly left it: a take a stop hook makes is no take of the assembly.
	const unused = Object.fromEntries(
		[...held].flatMap(([module, handles]) => {
			const left = [...handles].filter((handle) => !taken.get(module)?.has(handle));
			return left.length > 0 ? [[module, left.map((handle) => handle.label)]] : [];
		}),
	);
	// What the factories opened is closed before the answer: each package's tests ask this.
	await assembly.stop();
	return unused;
}
