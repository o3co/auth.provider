import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import type { AuditTrail } from "./audit/audit.ts";
import type { Mailbox } from "./smtp.ts";

export type Started =
	| {
			readonly kind: "running";
			readonly baseUrl: string;
			stop(): Promise<void>;
			/** Makes the store unreachable, or reachable again; only where the scene asked for store faults. */
			fault?(down: boolean): Promise<void>;
			/** The audit events it sends, on a target that can meet the need. */
			readonly audit?: AuditTrail;
			/** The mail it sent, where the driver runs the relay it sends to. */
			readonly mail?: Mailbox;
	  }
	| { readonly kind: "refused"; readonly output: string };

export interface Launch {
	readonly command: string;
	readonly args: readonly string[];
	readonly cwd: string;
	readonly env: Readonly<Record<string, string>>;
	/** The port the target was told to listen on; readiness is the first HTTP answer there. */
	readonly port: number;
}

export function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = createServer();
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => resolve(typeof address === "object" && address ? address.port : 0));
		});
	});
}

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Starts a target at a free port, choosing again (up to `attempts`) where another took it first (EADDRINUSE). */
export async function untilPortHeld(
	start: (port: number) => Promise<Started>,
	attempts: number,
): Promise<Started> {
	for (let attempt = 1; ; attempt++) {
		const started = await start(await freePort());
		const taken = started.kind === "refused" && started.output.includes("EADDRINUSE");
		if (!taken || attempt >= attempts) return started;
	}
}

export async function launch(spec: Launch, timeoutMs = 30_000): Promise<Started> {
	const child = spawn(spec.command, [...spec.args], { cwd: spec.cwd, env: { ...spec.env } });
	let output = "";
	child.stdout.on("data", (chunk: Buffer) => {
		output += chunk;
	});
	child.stderr.on("data", (chunk: Buffer) => {
		output += chunk;
	});
	const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
	const stop = async () => {
		if (child.exitCode === null && child.signalCode === null) {
			child.kill("SIGTERM");
			await exited;
		}
	};
	const baseUrl = `http://127.0.0.1:${spec.port}`;
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (child.exitCode !== null || child.signalCode !== null) return { kind: "refused", output };
		try {
			await fetch(baseUrl, { signal: AbortSignal.timeout(500) });
			return { kind: "running", baseUrl, stop };
		} catch {
			await Promise.race([pause(100), exited]);
		}
	}
	child.kill("SIGKILL");
	throw new Error(`target did not answer in ${timeoutMs}ms:\n${output}`);
}

export function baseEnv(): Record<string, string> {
	return { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" };
}

const owner = "conformance.owner";

/** Whether a process of the pid runs here. */
const running = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
};

/** Removes the throwaway Redis that a process no longer running left behind, such as a run killed mid-scene. */
function sweepLeftBehind(): void {
	const listed = execFileSync(
		"docker",
		["ps", "-a", "--filter", `label=${owner}`, "--format", `{{.ID}} {{.Label "${owner}"}}`],
		{ encoding: "utf8" },
	);
	for (const line of listed.split("\n").filter(Boolean)) {
		const [id, pid] = line.split(" ");
		if (!id || running(Number(pid))) continue;
		// Its run may be removing it as this lists it (its stop, or `--rm`): gone or going is what this wants.
		try {
			execFileSync("docker", ["rm", "-f", "-v", id], { stdio: "ignore" });
		} catch {}
	}
}

/** A throwaway Redis in a container, for the length of one scene. */
export async function startRedis(
	settings: readonly string[] = [],
): Promise<{ url: string; stop(): Promise<void>; pause(paused: boolean): Promise<void> }> {
	sweepLeftBehind();
	const name = `conformance-redis-${process.pid}-${randomBytes(4).toString("hex")}`;
	// Docker picks the host port as it binds, so no other process can take it in between.
	execFileSync("docker", [
		"run",
		"-d",
		"--rm",
		"--name",
		name,
		"--label",
		`${owner}=${process.pid}`,
		"-p",
		"127.0.0.1::6379",
		"redis:7-alpine",
		"redis-server",
		...settings,
	]);
	const stop = async () => {
		execFileSync("docker", ["rm", "-f", "-v", name], { stdio: "ignore" });
	};
	const bound = execFileSync("docker", ["port", name, "6379/tcp"], { encoding: "utf8" });
	const port = /:(\d+)\s*$/m.exec(bound)?.[1];
	/** Whether the server answers, asked again for up to ten seconds. */
	const answers = async () => {
		for (let i = 0; port !== undefined && i < 100; i++) {
			try {
				const pong = execFileSync("docker", ["exec", name, "redis-cli", "ping"], {
					encoding: "utf8",
				});
				if (pong.trim() === "PONG") return true;
			} catch {}
			await new Promise((resolve) => setTimeout(resolve, 100));
		}
		return false;
	};
	if (!(await answers())) {
		await stop();
		throw new Error(`the throwaway Redis ${name} did not answer`);
	}
	return {
		url: `redis://127.0.0.1:${port}`,
		stop,
		/**
		 * A paused server keeps its connections open and answers nothing, as a hung store does. One
		 * resumed is back once it answers again, so the scene's next step meets a store, not one waking.
		 */
		pause: async (paused) => {
			execFileSync("docker", [paused ? "pause" : "unpause", name], { stdio: "ignore" });
			if (!paused && !(await answers()))
				throw new Error(`the throwaway Redis ${name} did not come back`);
		},
	};
}
