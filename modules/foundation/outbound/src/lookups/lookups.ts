/** Lookups shared among those asking a name at once, each waiting until its own deadline. */
import type { Job } from "../resolver-process/contract.ts";

/** Why a lookup gives a caller no addresses: no place, its deadline, or the lookup's own failure. */
export type LookupFailure = "unavailable" | "timeout" | "unreachable";

export class LookupRefused extends Error {
	readonly failure: LookupFailure;
	constructor(failure: LookupFailure) {
		super(`the lookup was refused: ${failure}`);
		this.failure = failure;
	}
}

/** What lookups are run in: a lookup where a place is free, none otherwise. */
export interface Pool {
	run(name: string, family?: 4): Job | undefined;
}

export interface Lookups {
	/** The addresses `name` resolves to, waiting no longer than `signal`. */
	resolve(name: string, family: 4 | undefined, signal: AbortSignal): Promise<readonly string[]>;
}

/**
 * Lookups over one pool: a name already resolving, for the same family, is answered by that lookup,
 * each caller waiting on it until its own deadline, the lookup told when one stops waiting.
 */
/** One asker waiting on a lookup: how it is answered, and its deadline's hold on it. */
interface Waiter {
	readonly answered: (addresses: readonly string[]) => void;
	readonly failed: (error: LookupRefused) => void;
	readonly signal: AbortSignal;
	readonly left: () => void;
}

export function lookupsOver(pool: Pool): Lookups {
	const resolving = new Map<string, { readonly job: Job; readonly waiters: Set<Waiter> }>();
	return {
		resolve: (name, family, signal) => {
			if (signal.aborted) return Promise.reject(new LookupRefused("timeout"));
			const key = `${family ?? "any"} ${name}`;
			let entry = resolving.get(key);
			if (entry !== undefined && !entry.job.want()) {
				// No longer to be waited on: put aside, the key's next lookup begun.
				if (resolving.get(key) === entry) resolving.delete(key);
				entry = undefined;
			}
			if (entry === undefined) {
				const job = pool.run(name, family);
				if (job === undefined) return Promise.reject(new LookupRefused("unavailable"));
				const begun = { job, waiters: new Set<Waiter>() };
				entry = begun;
				resolving.set(key, begun);
				// Its answer is heard once, for whoever still waits: an asker gone holds nothing of it.
				const settle = (answer: (waiter: Waiter) => void) => {
					// Taken off only where it is still this lookup's: a later one of the key is left.
					if (resolving.get(key) === begun) resolving.delete(key);
					for (const waiter of begun.waiters) {
						waiter.signal.removeEventListener("abort", waiter.left);
						answer(waiter);
					}
					begun.waiters.clear();
				};
				job.answer.then(
					(addresses) => settle((waiter) => waiter.answered(addresses)),
					() =>
						settle((waiter) =>
							waiter.failed(new LookupRefused(waiter.signal.aborted ? "timeout" : "unreachable")),
						),
				);
			}
			const { job, waiters } = entry;
			return new Promise<readonly string[]>((answered, failed) => {
				const waiter: Waiter = {
					answered,
					failed,
					signal,
					left: () => {
						waiters.delete(waiter);
						job.unwant();
						failed(new LookupRefused("timeout"));
					},
				};
				waiters.add(waiter);
				signal.addEventListener("abort", waiter.left, { once: true });
			});
		},
	};
}
