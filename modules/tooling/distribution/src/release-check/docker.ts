/** The one way the release check runs the docker client: each command within a deadline, its client killed past it. */
import { type ChildProcessWithoutNullStreams, execFileSync, spawn } from "node:child_process";

export const buildWithin = 15 * 60_000;

/** Runs `docker <args>`, answering what it wrote, trimmed; past `within` ms its client is killed and it fails. */
export function docker(args: readonly string[], within = 60_000): string {
	try {
		return execFileSync("docker", args, {
			encoding: "utf8",
			stdio: "pipe",
			timeout: within,
			killSignal: "SIGKILL",
		}).trim();
	} catch (error) {
		if ((error as { code?: unknown }).code !== "ETIMEDOUT") throw error;
		throw new Error(`docker ${args[0]} did not answer within ${within / 1000} seconds`, {
			cause: error,
		});
	}
}

export const dockerStarted = (args: readonly string[]): ChildProcessWithoutNullStreams =>
	spawn("docker", args);
