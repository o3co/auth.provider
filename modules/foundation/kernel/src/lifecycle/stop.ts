import type { Log } from "../runtime/runtime.ts";
import type { periodic } from "./every.ts";

/** A module's stop hook, run with a signal that aborts at the deadline. */
export type StopHook = {
	readonly module: string;
	readonly run: (signal: AbortSignal) => Promise<void> | void;
};

/** Stops the periodic tasks, then runs the stop hooks in reverse order within the deadline. */
export async function stopWithin(
	deadlineMs: number,
	periodics: readonly ReturnType<typeof periodic>[],
	hooks: readonly StopHook[],
	log: Log,
): Promise<void> {
	const controller = new AbortController();
	const late = new Promise<"late">((resolve) =>
		controller.signal.addEventListener("abort", () => resolve("late")),
	);
	const timer = setTimeout(() => controller.abort(), deadlineMs);
	timer.unref();
	await Promise.race([Promise.all(periodics.map((task) => task.stop())), late]);
	for (const hook of [...hooks].reverse()) {
		// Started inside a promise, so a hook that throws at once is logged like one that rejects.
		const done = Promise.resolve()
			.then(() => hook.run(controller.signal))
			.catch((error: unknown) => {
				log.warn("kernel.stop_failed", {
					module: hook.module,
					outcome: "failed",
					kind: error instanceof Error ? error.name : typeof error,
				});
			});
		// Past the deadline, each hook left is called with the aborted signal and not awaited.
		if (controller.signal.aborted) continue;
		if ((await Promise.race([done, late])) === "late") {
			log.warn("kernel.stop_failed", { module: hook.module, outcome: "late" });
		}
	}
	clearTimeout(timer);
}
