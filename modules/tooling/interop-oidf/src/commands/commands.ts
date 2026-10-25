import { execFile } from "node:child_process";
import { promisify } from "node:util";

/** A command run for a plan: held to its own time, and to the plan's deadline where it is given one. */
export type Command = (
	cmd: string,
	args: readonly string[],
	options: {
		readonly timeoutMs: number;
		readonly signal?: AbortSignal;
		readonly env?: NodeJS.ProcessEnv;
		readonly cwd?: string;
	},
) => Promise<{ readonly stdout: string }>;

/** The system's commands, killed past their time or at the deadline. */
export const systemCommand: Command = async (cmd, args, options) => {
	const { stdout } = await promisify(execFile)(cmd, [...args], {
		timeout: options.timeoutMs,
		killSignal: "SIGKILL",
		maxBuffer: 64 * 1024 * 1024,
		...(options.signal ? { signal: options.signal } : {}),
		...(options.env ? { env: options.env } : {}),
		...(options.cwd ? { cwd: options.cwd } : {}),
	});
	return { stdout: String(stdout) };
};
