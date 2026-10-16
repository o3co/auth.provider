import { execFileSync } from "node:child_process";
import { createConnection, createServer, type Socket } from "node:net";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { spaces, store } from "@mod/store";
import { contractSpaces, storeContract } from "@mod/store/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";

const image = "redis:7.4-alpine";
let container = "";
let url = "";

async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const server = createServer().listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => resolve(typeof address === "object" && address ? address.port : 0));
		});
	});
}

async function waitFor(check: () => boolean, ms = 20_000) {
	const end = Date.now() + ms;
	while (Date.now() < end) {
		if (check()) return;
		await new Promise((r) => setTimeout(r, 200));
	}
	throw new Error("redis did not start");
}

let replica = "";
let secondReplica = "";
let network = "";

const docker = (...args: string[]) => execFileSync("docker", args, { encoding: "utf8" }).trim();
const cli = (target: string, ...args: string[]) => docker("exec", target, "redis-cli", ...args);
/** Whether the target answers PING; a container still starting answers nothing yet. */
const pings = (target: string) => {
	try {
		return cli(target, "ping").includes("PONG");
	} catch {
		return false;
	}
};
/** Online is not enough: after a pause the primary refuses writes until the replica catches up. */
const writable = () => {
	try {
		return cli(container, "set", "writable-probe", "1") === "OK";
	} catch {
		return false;
	}
};
const connectedReplicas = () => {
	try {
		return (cli(container, "info", "replication").match(/state=online/g) ?? []).length;
	} catch {
		return 0;
	}
};

let proxyUrl = "";
let dropNext = false;
let proxyTarget = 0;
let replicaPort = 0;
let replicaPaused = false;
let primaryName = "";
const sockets = new Set<Socket>();

/** A TCP relay to the primary that can drop the next reply and cut the connection carrying it. */
async function startProxy(target: number): Promise<number> {
	proxyTarget = target;
	const port = await freePort();
	const server = createServer((client) => {
		const upstream = createConnection(proxyTarget, "127.0.0.1");
		sockets.add(client);
		sockets.add(upstream);
		client.on("data", (chunk) => upstream.write(chunk));
		upstream.on("data", (chunk) => {
			if (dropNext) {
				dropNext = false;
				client.destroy();
				upstream.destroy();
				return;
			}
			client.write(chunk);
		});
		const close = () => {
			client.destroy();
			upstream.destroy();
		};
		client.on("error", close);
		upstream.on("error", close);
		client.on("close", close);
		upstream.on("close", close);
	});
	await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", () => resolve()));
	stops.push(async () => {
		for (const socket of sockets) socket.destroy();
		server.close();
	});
	return port;
}

beforeAll(async () => {
	const port = await freePort();
	const tag = `store-test-${process.pid}-${Date.now()}`;
	network = docker("network", "create", tag);
	primaryName = `${tag}-primary`;
	replicaPort = await freePort();
	container = docker(
		"run",
		"-d",
		"--rm",
		"--network",
		tag,
		"--name",
		`${tag}-primary`,
		"-p",
		`127.0.0.1:${port}:6379`,
		image,
		"redis-server",
		"--appendonly",
		"yes",
		"--appendfsync",
		"always",
		"--min-replicas-to-write",
		"1",
	);
	replica = docker(
		"run",
		"-d",
		"--rm",
		"--network",
		tag,
		"--name",
		`${tag}-replica`,
		"-p",
		`127.0.0.1:${replicaPort}:6379`,
		image,
		"redis-server",
		"--replicaof",
		`${tag}-primary`,
		"6379",
	);
	secondReplica = docker(
		"run",
		"-d",
		"--rm",
		"--network",
		tag,
		"--name",
		`${tag}-replica2`,
		image,
		"redis-server",
		"--replicaof",
		`${tag}-primary`,
		"6379",
	);
	url = `redis://127.0.0.1:${port}`;
	proxyUrl = `redis://127.0.0.1:${await startProxy(port)}`;
	await waitFor(() => connectedReplicas() === 2);
}, 60_000);

afterAll(() => {
	for (const id of [replica, secondReplica, container]) if (id) docker("rm", "-f", id);
	if (network) docker("network", "rm", network);
});

const durable = defineModule({ name: "durable-owner" }, (m) => [
	m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["durable", "no-eviction"] })),
	...contractSpaces.map((space) => m.contribute(spaces).by(() => space)),
]);

const prefixes = new WeakMap<object, string>();
let opened = 0;

async function open(
	extra = [durable],
	prefix = `t${Date.now()}x${++opened}`,
	through = url,
	replication: string | null = "replicas",
) {
	const app = await assemble({
		modules: [redisModule, ...extra],
		config: {
			...kernelConfig({ deployment: "multi" }),
			redis: { url: through, prefix, ...(replication ? { replication } : {}) },
		},
	});
	prefixes.set(app.get(store), prefix);
	return app;
}

const stops: (() => Promise<void>)[] = [];
afterAll(async () => {
	for (const stop of stops) await stop();
});

storeContract("redis", {
	open: async () => {
		const app = await open([durable], undefined, proxyUrl);
		stops.push(() => app.stop(1000));
		return app.get(store);
	},
	stopReplicas: async () => {
		docker("pause", replica);
		replicaPaused = true;
		return async () => {
			docker("unpause", replica);
			replicaPaused = false;
			await waitFor(() => connectedReplicas() === 2 && writable(), 60_000);
		};
	},
	failover: async () => {
		const primaryPort = proxyTarget;
		docker("pause", container);
		if (replicaPaused) docker("unpause", replica);
		replicaPaused = false;
		cli(replica, "replicaof", "no", "one");
		proxyTarget = replicaPort;
		for (const socket of sockets) socket.destroy();
		return async () => {
			docker("unpause", container);
			cli(replica, "replicaof", primaryName, "6379");
			proxyTarget = primaryPort;
			for (const socket of sockets) socket.destroy();
			await waitFor(() => connectedReplicas() === 2 && writable(), 60_000);
		};
	},
	loseNextReply: async () => {
		dropNext = true;
	},
	restart: async () => {
		docker("restart", container);
		await waitFor(() => pings(container));
		await waitFor(() => connectedReplicas() === 2, 60_000);
	},
	peer: async (s) => {
		const prefix = prefixes.get(s);
		const app = await open([durable], prefix, proxyUrl);
		stops.push(() => app.stop(1000));
		return app.get(store);
	},
});

describe("redis", () => {
	it("refuses replicated spaces unless the operator states the replication, and checks the statement", async () => {
		await expect(open([durable], undefined, url, null)).rejects.toBeInstanceOf(BootRefused);
		await expect(open([durable], undefined, url, "none")).rejects.toBeInstanceOf(BootRefused);
		cli(container, "config", "set", "min-replicas-to-write", "0");
		try {
			await expect(open([durable], undefined, url, "replicas")).rejects.toBeInstanceOf(BootRefused);
		} finally {
			cli(container, "config", "set", "min-replicas-to-write", "1");
		}
	});

	it("refuses a replica, a cluster node and a primary that would not refuse writes without replicas", async () => {
		await expect(
			open([durable], undefined, `redis://127.0.0.1:${replicaPort}`),
		).rejects.toBeInstanceOf(BootRefused);
		cli(container, "config", "set", "min-replicas-max-lag", "0");
		try {
			await expect(open()).rejects.toBeInstanceOf(BootRefused);
		} finally {
			cli(container, "config", "set", "min-replicas-max-lag", "10");
		}
		const port = await freePort();
		const node = docker(
			"run",
			"-d",
			"--rm",
			"-p",
			`127.0.0.1:${port}:6379`,
			image,
			"redis-server",
			"--cluster-enabled",
			"yes",
		);
		try {
			await waitFor(() => pings(node));
			await expect(
				open([durable], undefined, `redis://127.0.0.1:${port}`, "none"),
			).rejects.toBeInstanceOf(BootRefused);
		} finally {
			docker("rm", "-f", node);
		}
	}, 60_000);

	it("answers unavailable when a replica appears where none was declared", async () => {
		const tag = `none-${Date.now()}`;
		const net = docker("network", "create", tag);
		const port = await freePort();
		const lone = docker(
			"run",
			"-d",
			"--rm",
			"--network",
			tag,
			"--name",
			`${tag}-p`,
			"-p",
			`127.0.0.1:${port}:6379`,
			image,
		);
		let follower = "";
		try {
			await waitFor(() => pings(lone));
			const replicatedOnly = defineModule({ name: "replicated-owner" }, (m) =>
				contractSpaces.map((space) => m.contribute(spaces).by(() => space)),
			);
			const app = await open(
				[replicatedOnly],
				`none${Date.now()}`,
				`redis://127.0.0.1:${port}`,
				"none",
			);
			stops.push(() => app.stop(1000));
			const s = app.get(store);
			const k = {
				space: contractSpaces[1] as (typeof contractSpaces)[number],
				partition: "p",
				name: "a",
			};
			expect((await s.put(k, 1, { expiry: { kind: "never" } })).kind).toBe("written");
			follower = docker(
				"run",
				"-d",
				"--rm",
				"--network",
				tag,
				image,
				"redis-server",
				"--replicaof",
				`${tag}-p`,
				"6379",
			);
			await waitFor(() => /state=online/.test(cli(lone, "info", "replication")), 30_000);
			await expect(s.put(k, 2, { expiry: { kind: "never" } })).rejects.toMatchObject({
				name: "Unavailable",
			});
		} finally {
			for (const id of [follower, lone]) if (id) docker("rm", "-f", id);
			docker("network", "rm", net);
		}
	}, 90_000);

	it("answers unavailable for a replicated write when no replica is online", async () => {
		const app = await open();
		stops.push(() => app.stop(1000));
		const s = app.get(store);
		const k = {
			space: contractSpaces[1] as (typeof contractSpaces)[number],
			partition: "p",
			name: "lonely",
		};
		docker("pause", replica);
		docker("pause", secondReplica);
		try {
			cli(container, "client", "kill", "type", "replica");
			await waitFor(() => connectedReplicas() === 0, 20_000);
			await expect(s.put(k, 1, { expiry: { kind: "never" } })).rejects.toMatchObject({
				name: "Unavailable",
			});
		} finally {
			docker("unpause", replica);
			docker("unpause", secondReplica);
			await waitFor(() => connectedReplicas() === 2 && writable(), 60_000);
		}
	}, 90_000);

	it("answers unavailable when the confirming connection reaches another server", async () => {
		const port = await freePort();
		const lone = docker("run", "-d", "--rm", "-p", `127.0.0.1:${port}:6379`, image);
		try {
			await waitFor(() => pings(lone));
			const { Redis } = await import("ioredis");
			const { redisStore } = await import("../src/redis-store.ts");
			const main = new Redis(url, { maxRetriesPerRequest: 0 });
			const other = new Redis(`redis://127.0.0.1:${port}`, { maxRetriesPerRequest: 0 });
			const same = new Redis(url, { maxRetriesPerRequest: 0 });
			const options = {
				prefix: "mismatch",
				replicationTimeoutMs: 1000,
				replication: "replicas" as const,
			};
			const k = {
				space: contractSpaces[1] as (typeof contractSpaces)[number],
				partition: "p",
				name: "a",
			};
			try {
				const wrong = redisStore(main, other, options, contractSpaces);
				await expect(wrong.put(k, 1, { expiry: { kind: "never" } })).rejects.toMatchObject({
					name: "Unavailable",
				});
				const right = redisStore(main, same, options, contractSpaces);
				expect((await right.put(k, 2, { expiry: { kind: "never" } })).kind).toBe("written");
			} finally {
				main.disconnect();
				other.disconnect();
				same.disconnect();
			}
		} finally {
			docker("rm", "-f", lone);
		}
	}, 60_000);

	it("refuses spaces whose guarantees the server settings do not give", async () => {
		cli(container, "config", "set", "maxmemory-policy", "allkeys-lru");
		try {
			await expect(open()).rejects.toBeInstanceOf(BootRefused);
		} finally {
			cli(container, "config", "set", "maxmemory-policy", "noeviction");
		}
	});

	it("refuses durable spaces when the server does not persist", async () => {
		cli(container, "config", "set", "appendonly", "no");
		try {
			await expect(open()).rejects.toBeInstanceOf(BootRefused);
		} finally {
			cli(container, "config", "set", "appendonly", "yes");
		}
	});

	it("hands out a new version after a restart even when the counter rolls back", async () => {
		const prefix = `rollback${Date.now()}`;
		const app = await open([durable], prefix);
		stops.push(() => app.stop(1000));
		const s = app.get(store);
		const key = {
			space: contractSpaces[0] as (typeof contractSpaces)[number],
			partition: "p",
			name: "a",
		};
		const seen: string[] = [];
		for (let i = 0; i < 3; i++) {
			const w = await s.put(key, i, { expiry: { kind: "never" } });
			if (w.kind === "written") seen.push(w.version);
		}
		const counter = `${prefix}:{contract:p}:#version`;
		docker("restart", container);
		await waitFor(() => pings(container));
		cli(container, "hset", counter, "n", "1");
		let after: string | undefined;
		for (let i = 0; i < 100 && !after; i++) {
			after = await s.put(key, 9, { expiry: { kind: "never" } }).then(
				(w) => (w.kind === "written" ? w.version : undefined),
				async () => {
					await new Promise((r) => setTimeout(r, 100));
					return undefined;
				},
			);
		}
		expect(after).toBeDefined();
		expect(seen).not.toContain(after);
		await waitFor(() => connectedReplicas() === 2, 60_000);
	}, 90_000);

	it("refuses a server older than 7.0", async () => {
		const port = await freePort();
		const old = docker("run", "-d", "--rm", "-p", `127.0.0.1:${port}:6379`, "redis:6.2-alpine");
		try {
			await waitFor(() => pings(old));
			const app = assemble({
				modules: [redisModule],
				config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
			});
			await expect(app).rejects.toBeInstanceOf(BootRefused);
		} finally {
			docker("rm", "-f", old);
		}
	}, 60_000);

	it("refuses to start when the server cannot be reached", async () => {
		const app = assemble({
			modules: [redisModule],
			config: {
				...kernelConfig(),
				redis: { url: `redis://127.0.0.1:${await freePort()}` },
			},
		});
		await expect(app).rejects.toBeInstanceOf(BootRefused);
	});
});
