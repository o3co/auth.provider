/** The registry of `registry.ts` run as a process of its own, as its callers and its tests start it. */
import { spawn } from "node:child_process";
import { join } from "node:path";

/** How long the registry may take to listen. */
const startLimitMs = 30_000;

/**
 * Serves the packed release, as just published, and the packages outside it, as published before,
 * ahead of the upstream registry: its origin once it listens, and a stop that ends when it has
 * exited. Refuses one that exits, cannot be spawned, or is not listening in time, stopping it first.
 */
export async function packedRegistry(options: {
	/** The directory holding the release's tarballs. */
	readonly release: string;
	/** The directories holding the tarballs of packages outside the release. */
	readonly outside: readonly string[];
	/** The registry answering every other name. */
	readonly upstream: string;
	readonly limits?: { readonly upstreamMs?: number };
}): Promise<{ origin: string; stop: () => Promise<void> }> {
	const upstream = options.upstream.endsWith("/") ? options.upstream : `${options.upstream}/`;
	const upstreamMs = options.limits?.upstreamMs;
	const child = spawn(
		"node",
		[join(import.meta.dirname, "registry.ts"), upstream, options.release, ...options.outside],
		{
			stdio: ["ignore", "pipe", "inherit"],
			env: {
				...process.env,
				...(upstreamMs === undefined ? {} : { REGISTRY_UPSTREAM_LIMIT_MS: String(upstreamMs) }),
				REGISTRY_JUST_PUBLISHED: options.release,
			},
		},
	);
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
