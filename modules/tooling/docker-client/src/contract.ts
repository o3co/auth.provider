/** The docker client, run as a child within the time given; each failure sorted once, here. */
import { spawn, spawnSync } from "node:child_process";

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

/**
 * How long each kind of docker command may take before its client is ended. In CI a control command
 * answers within a second, and building an app's image and booting it within minutes: each leaves the
 * slowest seen many times over.
 */
export const dockerWithin = {
	/** Asking, starting, stopping, pausing or removing a container, a network or an image. */
	control: 60_000,
	/** `run`, which may pull its image first. */
	run: 3 * 60_000,
	/** Building, writing out or reading a whole image. */
	build: 15 * 60_000,
} as const;

/** The objects whose command is its second word: `image inspect`, `network create`. */
const objects = new Set(["image", "network", "volume", "container", "builder", "buildx"]);
/** A command as its failure names it: its first word, and an object's command with it. */
const commandOf = ([first = "", second]: readonly string[]) =>
	objects.has(first) && second !== undefined ? `${first} ${second}` : first;

/**
 * How a command is run: `merged`, answering its errors' stream too; `signal`, ending it when its work
 * ends; `input`, written to it, as a build's Dockerfile on its standard input.
 */
export interface Told {
	readonly merged?: boolean;
	readonly signal?: AbortSignal;
	readonly input?: string;
}

/** Runs a docker command within `within` ms, answering what it wrote, trimmed. */
export type Docker = (args: readonly string[], within: number, told?: Told) => Promise<string>;

export const docker: Docker = (args, within, { merged = false, signal, input } = {}) =>
	new Promise((answer, fail) => {
		const command = commandOf(args);
		if (within <= 0 || signal?.aborted) {
			fail(new DockerFailed("timeout", command, `docker ${command} had no time left`));
			return;
		}
		// Its own process group, so ending it ends what it started too.
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], detached: true });
		// Its input, or none, the stream ended at once; a client that ends before reading all of it is
		// told by its own answer, not by the pipe.
		child.stdin.on("error", () => {});
		child.stdin.end(input);
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

/**
 * The commands `dockerSync` takes: each answered by the client itself, starting no process of its own
 * that ending the client would leave running. A build (buildx) and a run are `docker`'s alone.
 */
const heldCommands = new Set([
	"ps",
	"inspect",
	"port",
	"exec",
	"kill",
	"start",
	"stop",
	"restart",
	"pause",
	"unpause",
	"rm",
	"version",
	"logs",
]);
/** The same, under an object's command: `image inspect`, `network create`. */
const heldUnder: Readonly<Record<string, ReadonlySet<string>>> = {
	image: new Set(["inspect", "ls", "rm"]),
	network: new Set(["create", "inspect", "ls", "rm", "connect", "disconnect"]),
	volume: new Set(["inspect", "ls", "rm"]),
	container: new Set(["inspect", "ls", "rm"]),
};
const held = ([first = "", second = ""]: readonly string[]) =>
	heldCommands.has(first) || (heldUnder[first]?.has(second) ?? false);

/**
 * Runs a control command within `within` ms, holding the process until it answers, as `docker` sorts
 * its failures. Past its time only the client is ended, so it takes no command that starts a process of
 * its own: one it does not take throws a TypeError, before anything runs.
 */
export function dockerSync(
	args: readonly string[],
	within: number,
	{ input, stdio }: { readonly input?: string; readonly stdio?: "ignore" } = {},
): string {
	const command = commandOf(args);
	if (!held(args)) {
		throw new TypeError(
			`docker ${command} is for docker alone: it starts a process of its own, which ending a held client would leave running`,
		);
	}
	if (within <= 0) throw new DockerFailed("timeout", command, `docker ${command} had no time left`);
	const ran = spawnSync("docker", args, {
		encoding: "utf8",
		input,
		stdio: ["pipe", stdio ?? "pipe", stdio ?? "pipe"],
		timeout: within,
		killSignal: "SIGKILL",
		maxBuffer: 1 << 28,
	});
	const out = ran.stdout ?? "";
	const told = ran.stderr ?? "";
	const code = (ran.error as NodeJS.ErrnoException | undefined)?.code;
	if (code === "ETIMEDOUT") {
		throw new DockerFailed(
			"timeout",
			command,
			`docker ${command} did not answer within ${within / 1000} seconds`,
			told,
		);
	}
	if (ran.error) {
		throw new DockerFailed("unstarted", command, `docker ${command} could not start`, "", null, {
			cause: ran.error,
		});
	}
	if (ran.status !== 0) {
		const kind = /no such (container|object)/i.test(told) ? "absent" : "failed";
		const both = [told.trim(), out.trim()].filter(Boolean).join("\n");
		throw new DockerFailed(
			kind,
			command,
			`docker ${command} failed (${ran.status}): ${both}`,
			told,
			ran.status,
			{ wrote: out },
		);
	}
	return out.trim();
}
