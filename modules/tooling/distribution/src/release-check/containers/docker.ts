/** The docker client, run as a child within the time given; each failure sorted once, here. */
import { spawn } from "node:child_process";

/**
 * How a docker command failed: `absent` (Docker answers no such container or object), `timeout`
 * (no answer in its time, the client killed), `unstarted` (no client could start), `failed` (any other).
 */
export type DockerFailure = "absent" | "timeout" | "unstarted" | "failed";

export class DockerFailed extends Error {
	readonly kind: DockerFailure;
	readonly command: string;
	/** What the client wrote to its errors' stream. */
	readonly told: string;
	readonly code: number | null;
	/** What the client wrote to its output, kept for a failure's diagnosis. */
	readonly wrote: string;

	constructor(
		kind: DockerFailure,
		command: string,
		message: string,
		told = "",
		code: number | null = null,
		options?: ErrorOptions & { readonly wrote?: string },
	) {
		super(message, options);
		this.name = "DockerFailed";
		this.kind = kind;
		this.command = command;
		this.told = told;
		this.code = code;
		this.wrote = options?.wrote ?? "";
	}
}

/** How a command is run: `merged`, answering its errors' stream too; `signal`, ending it when its work ends. */
export interface Told {
	readonly merged?: boolean;
	readonly signal?: AbortSignal;
}

/** Runs a docker command within `within` ms, answering what it wrote, trimmed. */
export type Docker = (args: readonly string[], within: number, told?: Told) => Promise<string>;

export const docker: Docker = (args, within, { merged = false, signal } = {}) =>
	new Promise((answer, fail) => {
		const command = args[0] ?? "";
		if (within <= 0 || signal?.aborted) {
			fail(new DockerFailed("timeout", command, `docker ${command} had no time left`));
			return;
		}
		// Its own process group, so ending it ends what it started too.
		const child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"], detached: true });
		// Decoded as streams, so a character split between chunks is read whole.
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		let out = "";
		let told = "";
		child.stdout.on("data", (chunk) => {
			out += chunk;
		});
		child.stderr.on("data", (chunk) => {
			told += chunk;
			if (merged) out += chunk;
		});
		// Its end ends the wait itself: something it started may hold its output open.
		const end = (why: string) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", stopped);
			try {
				if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
			} catch {
				child.kill("SIGKILL");
			}
			child.stdout.destroy();
			child.stderr.destroy();
			fail(new DockerFailed("timeout", command, `docker ${command} ${why}`, told));
		};
		const stopped = () => end("was stopped: its work's time ended");
		const timer = setTimeout(() => end(`did not answer within ${within / 1000} seconds`), within);
		signal?.addEventListener("abort", stopped, { once: true });
		child.once("error", (error) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", stopped);
			fail(
				new DockerFailed("unstarted", command, `docker ${command} could not start`, "", null, {
					cause: error,
				}),
			);
		});
		child.once("close", (code) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", stopped);
			if (code === 0) {
				answer(out.trim());
			} else {
				const kind = /no such (container|object)/i.test(told) ? "absent" : "failed";
				// What it wrote goes with the failure too: a command may tell why on its output alone.
				const both = merged ? out.trim() : [told.trim(), out.trim()].filter(Boolean).join("\n");
				fail(
					new DockerFailed(
						kind,
						command,
						`docker ${command} failed (${code}): ${both}`,
						told,
						code,
						{
							wrote: out,
						},
					),
				);
			}
		});
	});
