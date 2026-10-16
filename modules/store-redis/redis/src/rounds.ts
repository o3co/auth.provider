/**
 * Shares confirmation rounds: a call made while a round is running waits for the next round,
 * never the running one, whose start may predate the caller's own work.
 */
export function sharedRounds<T>(round: () => Promise<T>): () => Promise<T> {
	let running: Promise<T> | undefined;
	let next: Promise<T> | undefined;
	const start = () => {
		running = round().finally(() => {
			running = undefined;
		});
		return running;
	};
	return () => {
		if (!running) return start();
		next ??= running
			.catch(() => {})
			.then(() => {
				next = undefined;
				return start();
			});
		return next;
	};
}
