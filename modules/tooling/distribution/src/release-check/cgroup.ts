/** The processes a container takes, read from its cgroup where the host keeps the count. */
import { DockerFailed } from "./containers/docker.ts";

const counts = ["/sys/fs/cgroup/pids.current", "/sys/fs/cgroup/pids/pids.current"] as const;

const notThere = (error: unknown) =>
	error instanceof DockerFailed && error.kind === "failed" && /no such file/i.test(error.told);

/** The count, read by `read` (`cat` in the container) at the first place that has it. */
export async function pidsCurrent(read: (path: string) => Promise<string>): Promise<number> {
	for (const path of counts) {
		try {
			return Number((await read(path)).trim());
		} catch (error) {
			if (!notThere(error)) throw error;
		}
	}
	throw new Error(`the processes are counted at neither ${counts.join(" nor ")}`);
}
