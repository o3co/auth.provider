/** What of standard output the sink waits on at stop. */
export interface Outgoing {
	readonly writableLength: number;
	write(chunk: string, done?: (error?: Error | null) => void): boolean;
}

/**
 * Answers once the lines queued on `out` are handed to the OS, or once `signal` aborts, whichever is
 * first; it never throws. An empty write's callback comes after every write queued before it.
 */
export function drained(out: Outgoing, signal: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		if (signal.aborted || out.writableLength === 0) return resolve();
		const done = () => {
			signal.removeEventListener("abort", done);
			resolve();
		};
		signal.addEventListener("abort", done, { once: true });
		try {
			out.write("", done);
		} catch {
			done();
		}
	});
}
