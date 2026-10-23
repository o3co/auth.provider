/** What a scene reads of a container and of Docker's answers about it. */

/** Where the container's cgroup counts its processes: cgroup v2, then v1's pids controller. */
const pidsCounts = ["/sys/fs/cgroup/pids.current", "/sys/fs/cgroup/pids/pids.current"] as const;

/** The processes the container's cgroup counts, read by `read` at whichever place the host keeps them. */
export function pidsCurrent(read: (path: string) => string): number {
	let last: unknown;
	for (const path of pidsCounts) {
		try {
			return Number(read(path).trim());
		} catch (error) {
			last = error;
		}
	}
	throw new Error(`the processes are counted at neither ${pidsCounts.join(" nor ")}`, {
		cause: last,
	});
}

/** Whether a failed `docker` command failed only as the container is no longer there. */
export const noSuchContainer = (error: unknown): boolean =>
	error instanceof Error &&
	/no such (container|object)/i.test(
		String((error as { stderr?: unknown }).stderr ?? error.message),
	);

/** Whether `inspect` finds the container gone; any other failure of it is thrown. */
export function gone(inspect: () => unknown): boolean {
	try {
		inspect();
		return false;
	} catch (error) {
		if (noSuchContainer(error)) return true;
		throw error;
	}
}

/** `waiting`, or a failure told `late` once `ms` pass first. */
export async function within<T>(waiting: Promise<T>, ms: number, late: string): Promise<T> {
	let timer: NodeJS.Timeout | undefined;
	const deadline = new Promise<never>((_, fail) => {
		timer = setTimeout(() => fail(new Error(late)), ms);
	});
	try {
		return await Promise.race([waiting, deadline]);
	} finally {
		clearTimeout(timer);
	}
}
