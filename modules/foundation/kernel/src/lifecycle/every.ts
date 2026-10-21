import type { Log } from "../runtime/runtime.ts";

/** A task run at a fixed interval while the app runs; runs never overlap. */
export function periodic(
	intervalMs: number,
	task: (signal: AbortSignal) => Promise<void>,
	log: Log,
	where: string,
) {
	let timer: ReturnType<typeof setInterval> | undefined;
	let current: { readonly done: Promise<void>; readonly controller: AbortController } | undefined;
	const tick = () => {
		// A run still going takes this tick too.
		if (current) return;
		const controller = new AbortController();
		// Started inside a promise, so a task that throws before returning one is caught all the same.
		const done = Promise.resolve()
			.then(() => task(controller.signal))
			.catch((error: unknown) => {
				log.warn("kernel.every_failed", {
					module: where,
					kind: error instanceof Error ? error.name : typeof error,
				});
			})
			.finally(() => {
				current = undefined;
			});
		current = { done, controller };
	};
	return {
		start: () => {
			timer = setInterval(tick, intervalMs);
			timer.unref();
		},
		/** Stops the ticks, asks a running run to end, and waits for it. */
		stop: async () => {
			clearInterval(timer);
			current?.controller.abort();
			await current?.done;
		},
	};
}
