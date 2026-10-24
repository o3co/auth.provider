import { deepFreeze } from "../freeze.ts";
import { extensionPoint } from "../handles.ts";
import type { Runtime } from "../runtime/runtime.ts";
import { kindOf } from "./kind.ts";

export interface Probe {
	/** The resource's name, as the log shows it; the key at `probes`. */
	readonly name: string;
	/** Resolves when the resource answers, rejects when it does not. Aborted at the deadline. */
	check(signal: AbortSignal): Promise<void>;
}

export type Readiness = "ready" | "unready";

/** One run's answer with each probe's result, in contribution order. */
export interface ReadinessReport {
	readonly answer: Readiness;
	readonly probes: readonly { readonly name: string; readonly up: boolean }[];
}

export const probes = extensionPoint<Probe>("probes", {
	multiplicity: "keyed",
	keyOf: (probe) => probe.name,
});

/** A timer's delay in whole ms, from 1 to the longest a timer takes (2^31-1). */
export function isTimerMs(ms: number): boolean {
	return Number.isInteger(ms) && ms >= 1 && ms <= 2 ** 31 - 1;
}

/** One probe's result for one caller, in the shape its warn line takes. */
type Outcome =
	| { readonly outcome: "passed" }
	| { readonly outcome: "failed"; readonly kind: string }
	| { readonly outcome: "late" };

/** A check in progress, with how many callers wait for it. */
type Running = {
	readonly done: Promise<void>;
	readonly controller: AbortController;
	waiting: number;
};

/**
 * Answers whether every probe passes within the caller's deadline, joining a check still running.
 * A check is aborted once no caller waits for it.
 */
export function readinessOf(
	list: readonly Probe[],
	runtime: Runtime,
	stopping: () => boolean,
): (deadlineMs: number) => Promise<ReadinessReport> {
	const running = new Map<Probe, Running>();
	const begin = (probe: Probe): Running => {
		const existing = running.get(probe);
		if (existing) return existing;
		const controller = new AbortController();
		// Started inside a promise, so a check that throws at once fails like one that rejects.
		const done = Promise.resolve().then(() => probe.check(controller.signal));
		const clear = () => running.delete(probe);
		// This also handles the rejection when nobody waits for the check any more.
		done.then(clear, clear);
		const entry = { done, controller, waiting: 0 };
		running.set(probe, entry);
		return entry;
	};
	const one = async (probe: Probe, deadline: Promise<Outcome>): Promise<boolean> => {
		const started = runtime.clock.now();
		const entry = begin(probe);
		entry.waiting++;
		const result = await Promise.race([
			entry.done.then(
				(): Outcome => ({ outcome: "passed" }),
				(error: unknown): Outcome => ({
					outcome: "failed",
					kind: kindOf(error),
				}),
			),
			deadline,
		]);
		entry.waiting--;
		if (result.outcome === "passed") return true;
		if (result.outcome === "late" && entry.waiting === 0) entry.controller.abort();
		runtime.log.warn("kernel.probe_failed", {
			probe: probe.name,
			...result,
			ms: runtime.clock.now() - started,
		});
		return false;
	};
	return (deadlineMs) => {
		if (!isTimerMs(deadlineMs)) {
			return Promise.reject(
				new TypeError("the readiness deadline must be a whole number of ms, 1 to 2^31-1"),
			);
		}
		const report = (passed: readonly boolean[], answer: Readiness): ReadinessReport =>
			deepFreeze({
				answer,
				probes: list.map((probe, i) => ({ name: probe.name, up: passed[i] === true })),
			});
		// Once stop begins, no probe runs and every one reads down.
		if (stopping()) return Promise.resolve(report([], "unready"));
		const { promise: deadline, resolve } = Promise.withResolvers<Outcome>();
		const timer = setTimeout(() => resolve({ outcome: "late" }), deadlineMs);
		timer.unref();
		return Promise.all(list.map((probe) => one(probe, deadline)))
			.then((passed) => report(passed, passed.every(Boolean) ? "ready" : "unready"))
			.finally(() => clearTimeout(timer));
	};
}
