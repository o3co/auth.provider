import { execFileSync } from "node:child_process";

/** Whether a process of the pid (a group, for a negative one) is there; signal 0 reaches a zombie too. */
export const running = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
};

/** What `ps` prints with `args`, read the same on every run; undefined where it fails. */
const ps = (...args: string[]) => {
	try {
		return execFileSync("ps", args, {
			encoding: "utf8",
			env: { PATH: process.env.PATH ?? "", LC_ALL: "C", TZ: "UTC" },
			stdio: ["ignore", "pipe", "ignore"],
		});
	} catch {
		return undefined;
	}
};

/** When the process started, which tells it from a later one given its pid; undefined where none runs or `ps` cannot tell. */
export const startOf = (pid: number): string | undefined =>
	ps("-o", "lstart=", "-p", String(pid))?.trim() || undefined;

/** Whether a process of the group is there and is no zombie; undefined where `ps` cannot tell. */
export function groupLive(group: number): boolean | undefined {
	const listed = ps("-A", "-o", "pgid=,stat=");
	if (listed === undefined) return undefined;
	return listed.split("\n").some((line) => {
		const [id, state = ""] = line.trim().split(/\s+/);
		return Number(id) === group && !state.startsWith("Z");
	});
}
