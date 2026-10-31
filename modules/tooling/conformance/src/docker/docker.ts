import { type ExecFileSyncOptions, execFile, execFileSync } from "node:child_process";

/**
 * How long each kind of docker call may take before its client is killed. In CI a control call
 * answers within a second, a fault scene's kills, starts and catching up within 25 seconds, and
 * building an image and running it once within 10: each deadline leaves the slowest of those many
 * times over, and still ends a scene well inside its test's own time.
 */
export const dockerWithin = {
	/** `ps`, `inspect`, `port`, `exec`, `kill`, `start`, `pause`, `rm`, `network`. */
	control: 60_000,
	/** `run`, which may pull its image first. */
	run: 180_000,
	/** `build`. */
	build: 600_000,
} as const;

export type DockerCall = keyof typeof dockerWithin;

/** The subcommand a call names, its object's kind with it: `rm`, `image inspect`, `network create`. */
const subcommandOf = (args: readonly string[]) =>
	args
		.slice(0, ["image", "network", "container", "volume"].includes(args[0] ?? "") ? 2 : 1)
		.join(" ");

/** A call past its deadline as an error naming both, the client's own error its cause. */
const pastDeadline = (args: readonly string[], within: number, cause: unknown) =>
	new Error(`docker ${subcommandOf(args)} gave no answer within ${within / 1000} seconds`, {
		cause,
	});

/** How a call is run: the client's input and streams, and, for a test of the deadline itself, a shorter one. */
export interface DockerOptions extends Pick<ExecFileSyncOptions, "input" | "stdio"> {
	readonly within?: number;
}

const timedOut = (error: unknown) => (error as { code?: unknown } | null)?.code === "ETIMEDOUT";

/**
 * Runs `docker` with `args`, holding the process until it answers, within its kind's deadline: past
 * it the client is killed and this throws, so no stalled daemon holds a scene past its test's time.
 * Answers what it wrote, as text; nothing where its output is not kept.
 */
export function dockerSync(
	kind: DockerCall,
	args: readonly string[],
	{ within = dockerWithin[kind], ...options }: DockerOptions = {},
): string {
	try {
		const out = execFileSync("docker", args, {
			encoding: "utf8",
			...options,
			timeout: within,
			killSignal: "SIGKILL",
		});
		return typeof out === "string" ? out : "";
	} catch (error) {
		throw timedOut(error) ? pastDeadline(args, within, error) : error;
	}
}

/** As `dockerSync`, without holding the process while it works, so several calls run at once. */
export const dockerAsync = (
	kind: DockerCall,
	args: readonly string[],
	within: number = dockerWithin[kind],
) =>
	new Promise<string>((resolve, reject) =>
		execFile(
			"docker",
			args,
			{ encoding: "utf8", timeout: within, killSignal: "SIGKILL" },
			(error, out) => {
				if (!error) resolve(out);
				// An async client killed at its time has no code, only the signal it was sent.
				else if (error.killed && error.signal === "SIGKILL")
					reject(pastDeadline(args, within, error));
				else reject(error);
			},
		),
	);
