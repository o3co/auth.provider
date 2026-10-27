import { mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { groupLive, running, startOf } from "../processes.ts";

/** Where a run marks the instances it starts, each by the run's process id and the instance's group. */
export const instancesDir = () => join(tmpdir(), "conformance-instances");

type Started = { readonly owner: string | null; readonly group: string | null };

/** Marks an instance's process group as this run's, so a later run ends it where this one could not. */
export async function markInstance(pid: number, dir = instancesDir()): Promise<void> {
	await mkdir(dir, { recursive: true });
	const started: Started = { owner: startOf(process.pid) ?? null, group: startOf(pid) ?? null };
	await writeFile(join(dir, `${process.pid}-${pid}`), JSON.stringify(started));
}

/** Unmarks an instance this run ended. */
export const unmarkInstance = (pid: number, dir = instancesDir()) =>
	unlink(join(dir, `${process.pid}-${pid}`)).catch(() => undefined);

const startedOf = async (file: string): Promise<Started> => {
	const read = await readFile(file, "utf8")
		.then((text) => JSON.parse(text) as Partial<Started>)
		.catch(() => ({}) as Partial<Started>);
	return { owner: read.owner ?? null, group: read.group ?? null };
};

/** Ends every marked instance group whose run no longer runs, and forgets its mark; what it leaves running, named. */
export async function sweepStrayInstances(dir = instancesDir()): Promise<string[]> {
	const named: string[] = [];
	const marks = await readdir(dir).catch(() => [] as string[]);
	for (const mark of marks) {
		const [owner, group] = mark.split("-").map(Number);
		if (!owner || !group) continue;
		const started = await startedOf(join(dir, mark));
		const ownerNow = startOf(owner);
		if (running(owner) && (ownerNow === undefined || ownerNow === started.owner)) continue;
		const leaderNow = startOf(group);
		if (leaderNow !== undefined && leaderNow === started.group) {
			try {
				process.kill(-group, "SIGKILL");
			} catch {}
		} else if (running(-group) && (groupLive(group) ?? true))
			named.push(
				`group ${group}, marked by run ${owner}: its leader is not the process marked, left running`,
			);
		await unlink(join(dir, mark)).catch(() => undefined);
	}
	return named;
}
