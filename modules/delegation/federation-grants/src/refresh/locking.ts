import type { RefreshLockStore } from "../store.ts";

const lockMs = 10_000;
const pollMs = 100;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Holds the grant's lock under `mark`, asking again for half its life; false when another holder kept it. */
export const locked = async (locks: RefreshLockStore, id: string, mark: string) => {
	for (let waited = 0; waited <= lockMs / 2; waited += pollMs) {
		if ((await locks.hold(id, mark, lockMs)) === "created") return true;
		if (waited < lockMs / 2) await pause(pollMs);
	}
	return false;
};

/** The lock kept for its life again every half of it, only under `mark`; `ours` keeps it once more, answering whether it is still held. */
export const keeping = (locks: RefreshLockStore, id: string, mark: string) => {
	const keep = async () =>
		(
			await locks.update(id, (holds) =>
				holds === mark ? { value: holds, lifetimeMs: lockMs } : undefined,
			)
		)?.before === mark;
	let lost = false;
	const timer = setInterval(() => {
		keep().then(
			(ours) => {
				if (!ours) {
					lost = true;
					clearInterval(timer);
				}
			},
			() => clearInterval(timer),
		);
	}, lockMs / 2);
	timer.unref?.();
	return { ours: async () => !lost && (await keep()), stop: () => clearInterval(timer) };
};
