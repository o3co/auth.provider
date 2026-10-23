/** The registry of `registry.ts` run as a process of its own, as the scene and its tests start it. */
import { spawn } from "node:child_process";
import { join } from "node:path";

/** How long the registry may take to listen. */
const startLimitMs = 30_000;

/**
 * Starts the registry over the directories, before the upstream's: its origin once it listens, and
 * a stop that ends when it has exited. Refuses one that exits, cannot be spawned, or is not
 * listening in time, stopping it first.
 */
export async function served(
	upstream: string,
	dirs: readonly string[],
): Promise<{ origin: string; stop: () => Promise<void> }> {
	const child = spawn("node", [join(import.meta.dirname, "registry.ts"), upstream, ...dirs], {
		stdio: ["ignore", "pipe", "inherit"],
	});
	const exited = new Promise<void>((resolve) => child.once("close", () => resolve()));
	const stop = async () => {
		if (child.exitCode === null && child.signalCode === null) child.kill();
		await exited;
	};
	let timer: NodeJS.Timeout | undefined;
	try {
		const origin = await new Promise<string>((resolve, reject) => {
			let said = "";
			child.stdout.on("data", (chunk: Buffer) => {
				said += chunk.toString();
				if (said.includes("\n")) resolve(said.trim());
			});
			child.once("error", (error) =>
				reject(new Error(`the registry was not started: ${error.message}`)),
			);
			child.once("exit", (code) => reject(new Error(`the registry exited ${code}`)));
			timer = setTimeout(
				() => reject(new Error("the registry was not listening in time")),
				startLimitMs,
			);
		});
		return { origin, stop };
	} catch (error) {
		await stop();
		throw error;
	} finally {
		clearTimeout(timer);
	}
}
