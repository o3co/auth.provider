import { thrownKind } from "../refusal/refusal.ts";
import type { Log } from "../runtime/runtime.ts";
import type { periodic } from "./every.ts";

/** A module's stop hook, run with a signal that aborts at the deadline. */
export type StopHook = {
	readonly module: string;
	readonly run: (signal: AbortSignal) => Promise<void> | void;
};

/** A stop's own way: a refused assembly's is marked in its warnings, and keeps its process alive. */
export interface StopKind {
	readonly during?: "refusal";
}

/** Stops the periodic tasks, then runs the stop hooks in reverse order within the deadline. */
export async function stopWithin(
	deadlineMs: number,
	periodics: readonly ReturnType<typeof periodic>[],
	hooks: readonly StopHook[],
	log: Log,
	{ during }: StopKind = {},
): Promise<void> {
	const marked = during === undefined ? {} : { during };
	const controller = new AbortController();
	const late = new Promise<"late">((resolve) =>
		controller.signal.addEventListener("abort", () => resolve("late")),
	);
	const timer = setTimeout(() => controller.abort(), deadlineMs);
	// A refused assembly's hooks may be all its process holds: the refusal must still reach its host.
	if (during === undefined) timer.unref();
	try {
		await Promise.race([Promise.all(periodics.map((task) => task.stop())), late]);
		for (const hook of [...hooks].reverse()) {
			// Started inside a promise, so a hook that throws at once is logged like one that rejects.
			const done = Promise.resolve()
				.then(() => hook.run(controller.signal))
				.catch((error: unknown) => {
					log.warn("kernel.stop_failed", {
						module: hook.module,
						outcome: "failed",
						kind: thrownKind(error),
						...marked,
					});
				});
			// Past the deadline, each hook left is called with the aborted signal and not awaited.
			if (controller.signal.aborted) continue;
			if ((await Promise.race([done, late])) === "late") {
				log.warn("kernel.stop_failed", { module: hook.module, outcome: "late", ...marked });
			}
		}
	} finally {
		clearTimeout(timer);
	}
}
