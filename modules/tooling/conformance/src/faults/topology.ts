import { execFile, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { ask, askAll, microsOf, ok, textOf } from "../ask/ask.ts";
import { clockImage, faketimeEnv } from "../clock/clock.ts";
import { type PromoteOptions, promote } from "../promotion/promotion.ts";
import type { Reply, Upstream } from "../relay/relay.ts";

/** The Redis every fault scene runs, by version and digest. */
export const redisImage =
	"redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499";
const owner = "conformance.owner";
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const docker = (...args: string[]) => execFileSync("docker", args, { encoding: "utf8" }).trim();
/** Docker, without holding the process while it works, so several containers start at once. */
const dockerAsync = (...args: string[]) =>
	new Promise<string>((resolve, reject) =>
		execFile("docker", args, { encoding: "utf8" }, (error, out) =>
			error ? reject(error) : resolve(out.trim()),
		),
	);
const field = (info: string, name: string) =>
	new RegExp(`^${name}:(.*)$`, "m").exec(info)?.[1]?.trim();

/** Removes the topologies a process no longer running left behind. */
function sweepLeftBehind() {
	const alive = (pid: number) => {
		try {
			process.kill(pid, 0);
			return true;
		} catch (error) {
			return (error as NodeJS.ErrnoException).code === "EPERM";
		}
	};
	const kinds = [
		["container", ["ps", "-a"]],
		["network", ["network", "ls"]],
	] as const;
	for (const [what, list] of kinds) {
		const format = `{{.ID}} {{.Label "${owner}"}}`;
		const listed = docker(...list, "--filter", `label=${owner}`, "--format", format);
		for (const line of listed.split("\n").filter(Boolean)) {
			const [id, pid] = line.split(" ");
			if (!id || alive(Number(pid))) continue;
			try {
				// A container's anonymous volume (its /data) goes with it.
				docker(what, "rm", "-f", ...(what === "container" ? ["-v"] : []), id);
			} catch {}
		}
	}
}

export interface Node {
	readonly name: string;
	/** Where it answers on this host now; a restart may move it. */
	upstream(): Upstream;
	ask(...args: string[]): Promise<Reply>;
	runId(): Promise<string>;
	state(): { readonly running: boolean; readonly exitCode: number };
}

export interface TopologySpec {
	readonly replicas: number;
	/** Settings every node starts with, after the topology's own. */
	readonly settings?: readonly string[];
	/** A libfaketime offset every node's clock runs at, such as `+2h`. */
	readonly clock?: string;
}

/**
 * A primary and its replicas in containers on a network of their own, each answering on a port of
 * this host, for a scene's faults: promotion, crash, a slow server, a moved clock.
 */
export async function startTopology(spec: TopologySpec) {
	sweepLeftBehind();
	const id = `${process.pid}-${randomBytes(4).toString("hex")}`;
	const network = `conformance-net-${id}`;
	// The image comes first: a build that fails leaves no network behind.
	const image = spec.clock ? clockImage(redisImage) : redisImage;
	const clockEnv = spec.clock ? faketimeEnv(spec.clock) : [];
	const ports = new Map<string, Upstream>();
	const portOf = (name: string): Upstream => {
		const bound = docker("port", name, "6379/tcp");
		const port = Number(/:(\d+)\s*$/m.exec(bound)?.[1]);
		return { host: "127.0.0.1", port };
	};
	const node = (name: string): Node => ({
		name,
		upstream: () => ports.get(name) ?? portOf(name),
		ask: (...args) => ask(ports.get(name) ?? portOf(name), args),
		runId: async () => {
			const info = textOf(await ask(ports.get(name) ?? portOf(name), ["INFO", "server"]), ["INFO"]);
			const id = field(info, "run_id");
			if (!id) throw new Error(`INFO server named no run id for ${name}`);
			return id;
		},
		state: () => {
			const [running, exitCode] = docker(
				"inspect",
				"-f",
				"{{.State.Running}} {{.State.ExitCode}}",
				name,
			).split(" ");
			return { running: running === "true", exitCode: Number(exitCode) };
		},
	});
	/** Until the node answers PING, within ten seconds. */
	const answering = async (n: Node) => {
		for (let i = 0; i < 100; i++) {
			try {
				const pong = await ask(n.upstream(), ["PING"], 1_000);
				if (pong.kind === "simple" && pong.text === "PONG") return;
			} catch {}
			await pause(100);
		}
		throw new Error(`the Redis ${n.name} did not answer`);
	};
	const until = async (what: string, ok: () => Promise<boolean>, ms = 10_000) => {
		const end = performance.now() + ms;
		while (!(await ok())) {
			if (performance.now() > end) throw new Error(what);
			await pause(100);
		}
	};
	const info = async (n: Node) => {
		return textOf(await n.ask("INFO", "replication"), ["INFO"]);
	};
	const start = async (name: string) => {
		await dockerAsync(
			"run",
			"-d",
			"--name",
			name,
			"--network",
			network,
			"--network-alias",
			name,
			"--label",
			`${owner}=${process.pid}`,
			"-p",
			"127.0.0.1::6379",
			// Redis runs as its own user from the start, so a preloaded libfaketime is never first
			// loaded by a root entrypoint whose semaphore that user could not open.
			"--user",
			"redis",
			"--entrypoint",
			"redis-server",
			...clockEnv,
			image,
			"--appendonly",
			"yes",
			"--appendfsync",
			"always",
			"--enable-debug-command",
			"yes",
			...(spec.settings ?? []),
		);
		ports.set(name, portOf(name));
		return node(name);
	};
	const names = Array.from({ length: spec.replicas + 1 }, (_, i) => `conformance-redis-${id}-${i}`);
	const removeAll = () => {
		try {
			docker("rm", "-f", "-v", ...names);
		} catch {}
		try {
			docker("network", "rm", network);
		} catch {}
	};
	const nodes: Node[] = [];
	/** Each node's primary by name, none for a primary: what a restart puts back. */
	const follows = new Map<string, string | undefined>();
	const killed = new Set<string>();
	const onlineAt = async (p: Node, count: number) =>
		(await info(p)).split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length >= count;
	const following = async (n: Node, upstream: string) => {
		const i = await info(n);
		return field(i, "master_host") === upstream && field(i, "master_link_status") === "up";
	};
	try {
		docker("network", "create", "--label", `${owner}=${process.pid}`, network);
		// Every node starts on its own: a replica is pointed at its primary by command, never by a
		// start argument a restart would reuse.
		const started = await Promise.allSettled(names.map((name) => start(name)));
		for (const s of started) {
			if (s.status === "rejected") throw s.reason;
			nodes.push(s.value);
		}
		for (const n of nodes) await answering(n);
		const first = names[0] ?? "";
		for (const [i, n] of nodes.entries()) follows.set(n.name, i === 0 ? undefined : first);
		for (const n of nodes.slice(1)) ok(await n.ask("REPLICAOF", first, "6379"), ["REPLICAOF"]);
		await until("the replicas did not come online", () =>
			onlineAt(nodes[0] as Node, nodes.length - 1),
		);
	} catch (error) {
		removeAll();
		throw error;
	}
	let primary = nodes[0] as Node;

	return {
		network,
		nodes,
		primary: () => primary,
		/** The nodes following the current primary, none killed. */
		replicas: () =>
			nodes.filter((n) => follows.get(n.name) === primary.name && !killed.has(n.name)),
		/** Promotes a replica, as `promotion` does, in this topology. */
		promote: (o: PromoteOptions<Node>) =>
			promote(
				{
					nodes,
					follows,
					killed,
					primary: () => primary,
					setPrimary: (n) => {
						primary = n;
					},
					kill: (n) => docker("kill", "-s", "KILL", n.name),
				},
				o,
			),
		/**
		 * Ends the node with SIGKILL, as a crash does, and starts it again in the role it had,
		 * following the primary it followed; answers how it ended.
		 */
		async crash(n: Node) {
			docker("kill", "-s", "KILL", n.name);
			const { exitCode } = n.state();
			docker("start", n.name);
			ports.set(n.name, portOf(n.name));
			await answering(n);
			const upstream = follows.get(n.name);
			if (upstream === undefined) {
				const r = await n.ask("ROLE");
				const head = r.kind === "array" ? r.items?.[0] : undefined;
				if (!(head?.kind === "bulk" && head.data?.toString() === "master"))
					throw new Error(`${n.name} did not start again as a primary`);
			} else {
				ok(await n.ask("REPLICAOF", upstream, "6379"), ["REPLICAOF"]);
				await until(`${n.name} did not follow ${upstream} again`, () => following(n, upstream));
			}
			return { exitCode };
		},
		/**
		 * Holds the server itself for `seconds` (`DEBUG SLEEP`), not the network. `awake` gives, on
		 * Redis's clock (µs), when the sleep began and ended: a `TIME` just before and just after it,
		 * in the same write, so they bracket it whatever the load. `asleep` is only a hint (a PING
		 * unanswered); a scene proves a request was held by the times Redis served it.
		 */
		sleep(n: Node, seconds: number) {
			const awake = askAll(
				n.upstream(),
				[["TIME"], ["DEBUG", "SLEEP", String(seconds)], ["TIME"]],
				(seconds + 30) * 1_000,
			).then(([before, slept, after]) => {
				if (slept) ok(slept, ["DEBUG", "SLEEP"]);
				const span = { from: microsOf(before), to: microsOf(after) };
				if (!Number.isFinite(span.from) || !Number.isFinite(span.to))
					throw new Error("TIME refused around the sleep");
				return span;
			});
			awake.catch(() => {});
			const asleep = (async () => {
				await pause(50);
				for (let i = 0; i < 50; i++) {
					const answered = await ask(n.upstream(), ["PING"], 300).then(
						() => true,
						() => false,
					);
					if (!answered) return;
				}
				throw new Error(`the Redis ${n.name} did not fall asleep`);
			})();
			return { asleep, awake };
		},
		/** Pauses a node's container, or resumes it. */
		pause: (n: Node, paused: boolean) => {
			docker(paused ? "pause" : "unpause", n.name);
		},
		async stop() {
			removeAll();
		},
	};
}

export type Topology = Awaited<ReturnType<typeof startTopology>>;
