/** Lookups in this process, by the system's resolver: as many at once as given, none stopped. */
import type { Job } from "../resolver-process/contract.ts";

/**
 * A pool running at most `size` lookups at once in this process with `resolve`. One left by all
 * waiting on it runs on until it ends, holding its place, and may be waited on again meanwhile.
 */
export function inProcessPool(
	size: number,
	resolve: (name: string, family?: 4) => Promise<readonly string[]>,
): { run(name: string, family?: 4): Job | undefined } {
	let running = 0;
	return {
		run: (name, family) => {
			if (running >= size) return undefined;
			running += 1;
			let ended = false;
			// Started inside the chain, so a resolver that throws at once is caught as well.
			const answer = Promise.resolve()
				.then(() => resolve(name, family))
				.finally(() => {
					ended = true;
					running -= 1;
				});
			answer.catch(() => {});
			return { answer, want: () => !ended, unwant: () => {} };
		},
	};
}
