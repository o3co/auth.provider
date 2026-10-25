import { execFile, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createConnection } from "node:net";
import type { Reply, Upstream } from "../relay/relay.ts";
import { frames } from "../relay/resp.ts";

/** The Redis every fault scene runs, by version and digest. */
export const redisImage =
	"redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499";
/** The libfaketime a node with a moved clock preloads, by its Alpine package version. */
export const libfaketime = "libfaketime=0.9.10-r3";

const owner = "conformance.owner";
const command = (args: readonly string[]) =>
	Buffer.from(
		`*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join("")}`,
	);
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

/** One command on a connection of its own, and its reply. */
export function ask(to: Upstream, args: readonly string[], timeoutMs = 30_000): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const socket = createConnection(to, () => socket.write(command(args)));
		const reader = frames();
		const timer = setTimeout(() => socket.destroy(new Error(`no reply to ${args[0]}`)), timeoutMs);
		socket.on("data", (chunk: Buffer) => {
			const [frame] = reader.push(chunk);
			if (!frame) return;
			clearTimeout(timer);
			socket.end();
			resolve(frame.value);
		});
		socket.on("error", (error) => {
			clearTimeout(timer);
			reject(error);
		});
	});
}

/** Several commands in one write on a connection of its own, and their replies in order. */
export function askAll(
	to: Upstream,
	commands: readonly (readonly string[])[],
	timeoutMs = 30_000,
): Promise<Reply[]> {
	return new Promise((resolve, reject) => {
		const socket = createConnection(to, () => socket.write(Buffer.concat(commands.map(command))));
		const reader = frames();
		const replies: Reply[] = [];
		const timer = setTimeout(() => socket.destroy(new Error("no reply")), timeoutMs);
		socket.on("data", (chunk: Buffer) => {
			replies.push(...reader.push(chunk).map((f) => f.value));
			if (replies.length < commands.length) return;
			clearTimeout(timer);
			socket.end();
			resolve(replies);
		});
		socket.on("error", (error) => {
			clearTimeout(timer);
			reject(error);
		});
	});
}

/** A `TIME` reply as microseconds on Redis's clock. */
export const microsOf = (reply: Reply | undefined): number => {
	const items = reply?.kind === "array" ? (reply.items ?? []) : [];
	const [s, us] = items.map((i) => (i.kind === "bulk" ? Number(i.data?.toString()) : Number.NaN));
	return (s ?? Number.NaN) * 1_000_000 + (us ?? Number.NaN);
};

/** The image a node with a moved clock runs: the Redis image with libfaketime, built once. */
function clockImage(): string {
	const recipe = `FROM ${redisImage}\nRUN apk add --no-cache ${libfaketime}\n`;
	const tag = `conformance-redis-clock:${createHash("sha256").update(recipe).digest("hex").slice(0, 16)}`;
	try {
		docker("image", "inspect", tag);
	} catch {
		execFileSync("docker", ["build", "-q", "-t", tag, "-"], {
			input: recipe,
			stdio: ["pipe", "ignore", "inherit"],
		});
	}
	return tag;
}

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
				docker(what, "rm", "-f", id);
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
	docker("network", "create", "--label", `${owner}=${process.pid}`, network);
	const image = spec.clock ? clockImage() : redisImage;
	const clockEnv = spec.clock
		? [
				"-e",
				"LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1",
				"-e",
				`FAKETIME=${spec.clock}`,
				"-e",
				"FAKETIME_DONT_FAKE_MONOTONIC=1",
			]
		: [];
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
			const info = await ask(ports.get(name) ?? portOf(name), ["INFO", "server"]);
			return field(info.kind === "bulk" ? (info.data?.toString() ?? "") : "", "run_id") ?? "";
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
		const r = await n.ask("INFO", "replication");
		return r.kind === "bulk" ? (r.data?.toString() ?? "") : "";
	};
	const start = async (name: string, extra: readonly string[]) => {
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
			...extra,
			...(spec.settings ?? []),
		);
		ports.set(name, portOf(name));
		return node(name);
	};
	const names = Array.from({ length: spec.replicas + 1 }, (_, i) => `conformance-redis-${id}-${i}`);
	const removeAll = () => {
		try {
			docker("rm", "-f", ...names);
		} catch {}
		try {
			docker("network", "rm", network);
		} catch {}
	};
	const nodes: Node[] = [];
	try {
		const started = await Promise.allSettled(
			names.map((name, i) => start(name, i === 0 ? [] : ["--replicaof", names[0] ?? "", "6379"])),
		);
		for (const s of started) {
			if (s.status === "rejected") throw s.reason;
			nodes.push(s.value);
		}
	} catch (error) {
		removeAll();
		throw error;
	}
	let primary = nodes[0] as Node;
	const replicasOf = async (p: Node) => Number(field(await info(p), "connected_slaves") ?? 0);
	const onlineAt = async (p: Node, count: number) =>
		(await info(p)).split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length >= count;
	try {
		for (const n of nodes) await answering(n);
		await until("the replicas did not come online", () => onlineAt(primary, spec.replicas));
	} catch (error) {
		removeAll();
		throw error;
	}

	return {
		network,
		nodes,
		primary: () => primary,
		replicas: () => nodes.filter((n) => n !== primary),
		/**
		 * Promotes a replica: refused unless it has caught up with the primary within `catchUpMs`;
		 * the old primary is killed (SIGKILL) unless kept on; the replicas named follow the new one.
		 */
		async promote(o: {
			replica: Node;
			reattach?: readonly Node[];
			keepOld?: boolean;
			catchUpMs?: number;
		}) {
			const old = primary;
			const offset = Number(field(await info(old), "master_repl_offset"));
			const caughtUp = async () =>
				Number(field(await info(o.replica), "slave_repl_offset") ?? -1) >= offset;
			await until(
				`not eligible: ${o.replica.name} lags behind ${old.name}`,
				caughtUp,
				o.catchUpMs ?? 5_000,
			);
			if (!o.keepOld) docker("kill", "-s", "KILL", old.name);
			await o.replica.ask("REPLICAOF", "NO", "ONE");
			for (const r of o.reattach ?? []) await r.ask("REPLICAOF", o.replica.name, "6379");
			primary = o.replica;
			const count = o.reattach?.length ?? 0;
			await until("the replicas named did not follow", () => onlineAt(o.replica, count));
			if (o.keepOld)
				await until("the old primary lost every replica", async () => (await replicasOf(old)) > 0);
			return { primary: o.replica, old };
		},
		/** Ends the node with SIGKILL, as a crash does, and starts it again; answers how it ended. */
		async crash(n: Node) {
			docker("kill", "-s", "KILL", n.name);
			const { exitCode } = n.state();
			docker("start", n.name);
			ports.set(n.name, portOf(n.name));
			await answering(n);
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
			).then(([before, , after]) => ({ from: microsOf(before), to: microsOf(after) }));
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
