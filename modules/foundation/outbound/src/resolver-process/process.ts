/** The one place outbound starts a process: a resolver's helper, in the launch form guard holds it to. */
import { fork } from "node:child_process";
import { join } from "node:path";

/** A started helper, as a pool drives it. */
export interface HelperProcess {
	/** None where the process was never started. */
	readonly pid: number | undefined;
	send(message: object): void;
	kill(): void;
	/** Whether the parent is kept alive by it: while someone waits on one of its lookups. */
	hold(held: boolean): void;
	on(event: "message", listener: (message: unknown) => void): void;
	on(event: "exit" | "disconnect", listener: () => void): void;
	on(event: "error", listener: (error: Error) => void): void;
}

/** Starts a helper of this generation with this many threads; the default, `fork`. */
export type StartHelper = (gen: number, threads: number) => HelperProcess;

/**
 * The helper of `helper.mjs`, on this node, with a small heap, none of the parent's environment but
 * the resolver's own variables and its thread count, and no standard input or output.
 */
export const startHelper: StartHelper = (gen, threads) => {
	const child = fork(join(import.meta.dirname, "helper.mjs"), [String(gen)], {
		execPath: process.execPath,
		execArgv: ["--max-old-space-size=16"],
		env: {
			UV_THREADPOOL_SIZE: String(threads),
			LOCALDOMAIN: process.env.LOCALDOMAIN,
			RES_OPTIONS: process.env.RES_OPTIONS,
			HOSTALIASES: process.env.HOSTALIASES,
		},
		stdio: ["ignore", "ignore", "inherit", "ipc"],
		serialization: "json",
	});
	return {
		get pid() {
			return child.pid;
		},
		send: (message) => {
			// A message is queued when the channel is busy; it is never sent again.
			if (child.connected) child.send(message);
		},
		kill: () => {
			child.kill("SIGKILL");
		},
		hold: (held) => {
			if (held) {
				child.ref();
				child.channel?.ref();
			} else {
				child.unref();
				child.channel?.unref();
			}
		},
		on: (event: string, listener: (...args: never[]) => void) => {
			(child as NodeJS.EventEmitter).on(event, listener as (...args: unknown[]) => void);
		},
	} as HelperProcess;
};
