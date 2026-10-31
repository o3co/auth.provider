import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import type { AuditTrail } from "./audit/audit.ts";
import { dockerSync } from "./docker/docker.ts";
import { groupLive, running } from "./processes.ts";
import type { Mailbox } from "./smtp.ts";

export type Started =
	| {
			readonly kind: "running";
			readonly baseUrl: string;
			stop(): Promise<void>;
			/**
			 * Ends it at once with SIGKILL, its process group with it, answering how it ended and when, on
			 * this process's monotonic clock (`performance.now()`); only where launched as a group.
			 */
			kill?(): Promise<{ readonly signal: string | null; readonly endedAt: number }>;
			/** Its process group's id, where launched as a group. */
			readonly pid?: number;
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
	/** How long a stop waits after SIGTERM before SIGKILL: past the kernel's stop deadline (30 s) unless given. */
	readonly stopGraceMs?: number;
	/** How long a stop waits after SIGKILL before it fails. */
	readonly killWithinMs?: number;
	/** In a process group of its own, so a stop or a kill ends what it started too. */
	readonly group?: boolean;
}

/** A target draining within the kernel's stop deadline (30 s) is never cut short. */
const stopGraceMs = 40_000;
const killWithinMs = 5_000;

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
	const child = spawn(spec.command, [...spec.args], {
		cwd: spec.cwd,
		env: { ...spec.env },
		...(spec.group ? { detached: true } : {}),
	});
	let output = "";
	child.stdout.on("data", (chunk: Buffer) => {
		output += chunk;
	});
	child.stderr.on("data", (chunk: Buffer) => {
		output += chunk;
	});
	const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
	// No pid is taken again while a group holds it as its id: a process holding the reaped target's pid means its group has ended.
	const groupGone = (pid: number) =>
		(child.exitCode !== null || child.signalCode !== null) && running(pid);
	/** Signals the target, its whole process group where launched as one and still its own. */
	const signal = (name: NodeJS.Signals) => {
		if (!spec.group || child.pid === undefined) return child.kill(name);
		if (groupGone(child.pid)) return;
		try {
			process.kill(-child.pid, name);
		} catch {}
	};
	/** Whether a process of the target's group is still there and no zombie: launched as a group, its end is the group's, not the target's alone. */
	const groupAlive = () =>
		child.pid !== undefined &&
		!groupGone(child.pid) &&
		running(-child.pid) &&
		(groupLive(child.pid) ?? true);
	const ended = () =>
		spec.group ? !groupAlive() : child.exitCode !== null || child.signalCode !== null;
	/** Whether the target (its whole group, where launched as one) ended within `ms`; the timer is cleared either way. */
	const endedWithin = async (ms: number) => {
		let timer: NodeJS.Timeout | undefined;
		const late = new Promise<false>((resolve) => {
			timer = setTimeout(() => resolve(false), ms);
		});
		let waiting = true;
		const gone = spec.group
			? (async () => {
					while (waiting && groupAlive()) await pause(20);
					return true as const;
				})()
			: exited.then(() => true as const);
		const done = await Promise.race([gone, late]);
		waiting = false;
		clearTimeout(timer);
		return done && !(spec.group && groupAlive());
	};
	// SIGTERM, then SIGKILL past its grace; one still there after that fails the stop.
	const stop = async () => {
		if (ended()) return;
		signal("SIGTERM");
		if (await endedWithin(spec.stopGraceMs ?? stopGraceMs)) return;
		signal("SIGKILL");
		if (await endedWithin(spec.killWithinMs ?? killWithinMs)) return;
		throw new Error(`target ${child.pid} did not end after SIGTERM and SIGKILL:\n${output}`);
	};
	// The group is signalled even where the target has ended, and answered only once all of it has.
	const kill = async () => {
		signal("SIGKILL");
		await exited;
		if (!(await endedWithin(spec.killWithinMs ?? killWithinMs)))
			throw new Error(`group ${child.pid} did not end after SIGKILL:\n${output}`);
		return { signal: child.signalCode, endedAt: performance.now() };
	};
	const baseUrl = `http://127.0.0.1:${spec.port}`;
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (child.exitCode !== null || child.signalCode !== null) {
			// What the target started may outlive it: the group is stopped before the refusal is told.
			await stop();
			return { kind: "refused", output };
		}
		try {
			await fetch(baseUrl, { signal: AbortSignal.timeout(500) });
			return {
				kind: "running",
				baseUrl,
				stop,
				...(spec.group ? { kill, ...(child.pid ? { pid: child.pid } : {}) } : {}),
			};
		} catch {
			await Promise.race([pause(100), exited]);
		}
	}
	signal("SIGKILL");
	const gone = await endedWithin(spec.killWithinMs ?? killWithinMs);
	throw new Error(
		`target did not answer in ${timeoutMs}ms${gone ? "" : ", nor end after SIGKILL"}:\n${output}`,
	);
}

export function baseEnv(): Record<string, string> {
	return { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" };
}

const owner = "conformance.owner";

/** Removes the throwaway Redis that a process no longer running left behind, such as a run killed mid-scene. */
function sweepLeftBehind(): void {
	const listed = dockerSync("control", [
		"ps",
		"-a",
		"--filter",
		`label=${owner}`,
		"--format",
		`{{.ID}} {{.Label "${owner}"}}`,
	]);
	for (const line of listed.split("\n").filter(Boolean)) {
		const [id, pid] = line.split(" ");
		if (!id || running(Number(pid))) continue;
		// Its run may be removing it as this lists it (its stop, or `--rm`): gone or going is what this wants.
		try {
			dockerSync("control", ["rm", "-f", "-v", id], { stdio: "ignore" });
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
	dockerSync("run", [
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
		dockerSync("control", ["rm", "-f", "-v", name], { stdio: "ignore" });
	};
	const bound = dockerSync("control", ["port", name, "6379/tcp"]);
	const port = /:(\d+)\s*$/m.exec(bound)?.[1];
	/** Whether the server answers, asked again for up to ten seconds. */
	const answers = async () => {
		for (let i = 0; port !== undefined && i < 100; i++) {
			try {
				const pong = dockerSync("control", ["exec", name, "redis-cli", "ping"]);
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
			dockerSync("control", [paused ? "pause" : "unpause", name], { stdio: "ignore" });
			if (!paused && !(await answers()))
				throw new Error(`the throwaway Redis ${name} did not come back`);
		},
	};
}
