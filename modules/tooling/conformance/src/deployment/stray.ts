import { mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Where a run marks the instances it starts, each by the run's process id and the instance's group. */
export const instancesDir = () => join(tmpdir(), "conformance-instances");

const running = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
};

/** Marks an instance's process group as this run's, so a later run ends it where this one could not. */
export async function markInstance(pid: number, dir = instancesDir()): Promise<void> {
	await mkdir(dir, { recursive: true });
	await writeFile(join(dir, `${process.pid}-${pid}`), "");
}

/** Unmarks an instance this run ended. */
export const unmarkInstance = (pid: number, dir = instancesDir()) =>
	unlink(join(dir, `${process.pid}-${pid}`)).catch(() => undefined);

/** Ends every marked instance group whose run no longer runs, and forgets its mark. */
export async function sweepStrayInstances(dir = instancesDir()): Promise<void> {
	const marks = await readdir(dir).catch(() => [] as string[]);
	for (const mark of marks) {
		const [owner, group] = mark.split("-").map(Number);
		if (!owner || !group || running(owner)) continue;
		try {
			process.kill(-group, "SIGKILL");
		} catch {}
		await unlink(join(dir, mark)).catch(() => undefined);
	}
}
