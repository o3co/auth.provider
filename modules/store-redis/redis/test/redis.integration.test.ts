import { execFileSync } from "node:child_process";
import { createConnection, createServer, type Socket } from "node:net";
import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { spaces, store } from "@mod/store";
import { contractSpaces, overwrite, storeContract } from "@mod/store/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";

/** The server the suite runs on; `STORE_REDIS_IMAGE` runs it on another, such as Valkey, by hand. */
const image = process.env.STORE_REDIS_IMAGE ?? "redis:7.4-alpine";
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

/**
 * A docker call killed past a minute, as long as its hook may take, so a stalled daemon fails the test.
 * Its own, not `docker-client`'s: an adapter's tests take no assembly package (G10).
 */
const docker = (...args: string[]) =>
	execFileSync("docker", args, { encoding: "utf8", timeout: 60_000, killSignal: "SIGKILL" }).trim();
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
	for (const id of [replica, secondReplica, container]) if (id) docker("rm", "-f", "-v", id);
	if (network) docker("network", "rm", network);
});

const durable = defineModule({ name: "durable-owner", replicaSafe: true, takes: [] }, (m) => [
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
		modules: [redisModule, tlsOptionsForTests, ...extra],
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

it("answers an empty batch in time as committed with no versions, as the contract's answer is shaped", async () => {
	const app = await open([durable], undefined, proxyUrl);
	stops.push(() => app.stop(1000));
	const s = app.get(store);
	const now = await s.now();
	expect(await s.batch([], [], { deadline: now + 60_000 })).toEqual({
		kind: "committed",
		versions: [],
	});
	expect(await s.batch([], [])).toEqual({ kind: "committed", versions: [] });
});

it("offers a batch across partitions and spaces of one guarantee, so the contract's batches across run on it", async () => {
	const app = await open([durable], undefined, proxyUrl);
	stops.push(() => app.stop(1000));
	expect(typeof app.get(store).batchAcross).toBe("function");
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

	/** Boots as a user the server's ACL holds to `rules`: why boot was refused, or `booted`. */
	const asUser = async (
		rules: readonly string[],
		extra = [durable],
		replication: string | null = "replicas",
		prefix?: string,
	) => {
		const user = `u${++opened}`;
		cli(container, "acl", "setuser", user, "on", ">pw", ...rules);
		try {
			const through = url.replace("redis://", `redis://${user}:pw@`);
			const booted = await open(extra, prefix, through, replication).catch((error) => error);
			if (booted instanceof BootRefused) {
				const reasons = booted.refusals.map((r) => r.reason).join("; ");
				expect(reasons).not.toContain("pw@");
				return reasons;
			}
			if (booted instanceof Error) throw booted;
			await booted.stop(1000);
			return "booted";
		} finally {
			cli(container, "acl", "deluser", user);
		}
	};
	const every = ["~*", "&*", "+@all"];

	it("refuses boot where the server refuses a command the store sends, naming it, in a script or not", async () => {
		expect(await asUser([...every, "-wait"])).toContain("the server refuses WAIT");
		expect(await asUser([...every, "-hset"])).toContain("the server refuses HSET");
		expect(await asUser([...every, "-time"])).toContain("the server refuses TIME");
		expect(await asUser([...every, "-scan"])).toContain("the server refuses SCAN");
	});

	it("names the store's keys where a script is refused one, though the command is allowed elsewhere", async () => {
		expect(await asUser([...every, "-hset", "(+hset ~other:*)"], [], null)).toContain(
			"the server refuses this user the store's keys",
		);
	});

	it("boots and answers ready as a user refused EVALSHA and SCRIPT, which the store never sends", async () => {
		const user = `u${++opened}`;
		cli(container, "acl", "setuser", user, "on", ">pw", ...every, "-evalsha", "-script");
		try {
			let context: BuildContext<unknown> | undefined;
			// Safe: it keeps the build context for the test once, at build; no request writes it.
			const asker = defineModule({ name: "asker", replicaSafe: true, takes: [] }, (m) => [
				m.provide(contract<object>("asker")).by((c) => {
					context = c;
					return {};
				}),
			]);
			const app = await open(
				[durable, asker],
				undefined,
				url.replace("redis://", `redis://${user}:pw@`),
			);
			try {
				expect((await context?.readinessReport(1000))?.answer).toBe("ready");
			} finally {
				await app.stop(1000);
			}
		} finally {
			cli(container, "acl", "deluser", user);
		}
	});

	it("boots a user held to the store's own keys, needing the confirmation key only where it confirms", async () => {
		expect(await asUser(["~acl:{*", "&*", "+@all"], [], null, "acl")).toBe("booted");
		const refused = await asUser(["~acl:{*", "&*", "+@all"], [durable], "replicas", "acl");
		// Named by the setting that sets it, never by the prefix's value.
		expect(refused).toContain("<redis.prefix>:#confirm");
		expect(refused).not.toContain("acl:");
	});

	it("boots while no replica takes writes: that leaves the commands undetermined, never refused", async () => {
		docker("pause", replica);
		docker("pause", secondReplica);
		try {
			cli(container, "client", "kill", "type", "replica");
			await waitFor(() => connectedReplicas() === 0 && !writable(), 20_000);
			const app = await open();
			await app.stop(1000);
		} finally {
			docker("unpause", replica);
			docker("unpause", secondReplica);
			await waitFor(() => connectedReplicas() === 2 && writable(), 60_000);
		}
	}, 90_000);

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
			docker("rm", "-f", "-v", node);
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
			const replicatedOnly = defineModule(
				{ name: "replicated-owner", replicaSafe: true, takes: [] },
				(m) => contractSpaces.map((space) => m.contribute(spaces).by(() => space)),
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
			expect((await overwrite(s, k, 1, { expiry: { kind: "never" } })).kind).toBe("written");
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
			await expect(overwrite(s, k, 2, { expiry: { kind: "never" } })).rejects.toMatchObject({
				name: "Unavailable",
			});
		} finally {
			for (const id of [follower, lone]) if (id) docker("rm", "-f", "-v", id);
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
			await expect(overwrite(s, k, 1, { expiry: { kind: "never" } })).rejects.toMatchObject({
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
				await expect(overwrite(wrong, k, 1, { expiry: { kind: "never" } })).rejects.toMatchObject({
					name: "Unavailable",
				});
				const right = redisStore(main, same, options, contractSpaces);
				expect((await overwrite(right, k, 2, { expiry: { kind: "never" } })).kind).toBe("written");
			} finally {
				main.disconnect();
				other.disconnect();
				same.disconnect();
			}
		} finally {
			docker("rm", "-f", "-v", lone);
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

	it("refuses durable spaces when the server does not persist, saying first what to set", async () => {
		cli(container, "config", "set", "appendonly", "no");
		try {
			const refused = await open().catch((error: BootRefused) => error.refusals);
			expect(refused).toEqual([
				{
					where: "redis",
					reason: expect.stringMatching(
						/^set appendonly yes and appendfsync always on the server \(docs\/runbook\.md, Redis\), which the durable guarantee of these spaces needs: /,
					),
				},
			]);
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
			const w = await overwrite(s, key, i, { expiry: { kind: "never" } });
			if (w.kind === "written") seen.push(w.version);
		}
		const counter = `${prefix}:{contract:p}:#version`;
		docker("restart", container);
		await waitFor(() => pings(container));
		cli(container, "hset", counter, "n", "1");
		let after: string | undefined;
		for (let i = 0; i < 100 && !after; i++) {
			after = await overwrite(s, key, 9, { expiry: { kind: "never" } }).then(
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
				modules: [redisModule, tlsOptionsForTests],
				config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
			});
			await expect(app).rejects.toBeInstanceOf(BootRefused);
		} finally {
			docker("rm", "-f", "-v", old);
		}
	}, 60_000);

	it("cuts its connections at the stop's deadline, rather than waiting on a server that does not answer", async () => {
		// A relay of its own, so only this app's connections are watched.
		const target = Number(new URL(url).port);
		const relayed: Socket[] = [];
		const relay = createServer((client) => {
			const upstream = createConnection(target, "127.0.0.1");
			relayed.push(client);
			client.pipe(upstream).pipe(client);
			const close = () => {
				client.destroy();
				upstream.destroy();
			};
			client.on("error", close);
			upstream.on("error", close);
			client.on("close", close);
			upstream.on("close", close);
		});
		const port = await freePort();
		await new Promise<void>((resolve) => relay.listen(port, "127.0.0.1", () => resolve()));
		try {
			const app = await open([durable], undefined, `redis://127.0.0.1:${port}`);
			expect(relayed.length).toBeGreaterThan(0);
			docker("pause", container);
			try {
				await app.stop(300);
				await waitFor(() => relayed.every((socket) => socket.destroyed), 2000);
			} finally {
				docker("unpause", container);
				await waitFor(writable, 60_000);
			}
		} finally {
			relay.close();
		}
	}, 90_000);

	it("refuses to start when the server cannot be reached", async () => {
		const app = assemble({
			modules: [redisModule, tlsOptionsForTests],
			config: {
				...kernelConfig(),
				redis: { url: `redis://127.0.0.1:${await freePort()}` },
			},
		});
		await expect(app).rejects.toBeInstanceOf(BootRefused);
	});
});

describe("one server alone, as configured with replication none", () => {
	const lone: string[] = [];
	afterAll(() => {
		for (const id of lone) docker("rm", "-f", "-v", id);
	});
	const replicatedOnly = defineModule(
		{ name: "replicated-owner", replicaSafe: true, takes: [] },
		(m) => [m.contribute(spaces).by(() => ({ name: "replicated", guarantees: ["replicated"] }))],
	);

	it("boots on Redis 7.4 and 7.0 alike: one server, its run id the same to both connections, and the store's scripts run, warning at each boot of the spaces it leaves unreplicated", async () => {
		for (const version of ["redis:7.4-alpine", "redis:7.0-alpine"]) {
			const port = await freePort();
			const id = docker("run", "-d", "--rm", "-p", `127.0.0.1:${port}:6379`, version);
			lone.push(id);
			await waitFor(() => pings(id));
			const recorded = recordingLog();
			const app = await assemble({
				modules: [redisModule, tlsOptionsForTests, replicatedOnly],
				config: {
					...kernelConfig(),
					redis: { url: `redis://127.0.0.1:${port}`, prefix: "alone", replication: "none" },
				},
				runtime: quietRuntime({ log: recorded.log }),
			});
			await app.stop(1000);
			const warned = recorded.lines().filter((line) => line.event === "redis.replication_none");
			expect(
				warned.map((line) => line.fields.spaces),
				version,
			).toEqual(["replicated"]);
		}
	}, 90_000);
});

describe("a Redis 7.0 server", () => {
	let old = "";
	let oldUrl = "";
	beforeAll(async () => {
		const port = await freePort();
		old = docker("run", "-d", "--rm", "-p", `127.0.0.1:${port}:6379`, "redis:7.0-alpine");
		oldUrl = `redis://u:pw@127.0.0.1:${port}`;
		await waitFor(() => pings(old));
	}, 60_000);
	afterAll(() => {
		if (old) docker("rm", "-f", "-v", old);
	});

	it("names the store's keys where a script is refused one, in 7.0's words", async () => {
		docker("exec", old, "redis-cli", "acl", "setuser", "u", "on", ">pw", "~*", "&*", "+@all");
		docker("exec", old, "redis-cli", "acl", "setuser", "u", "-hset", "(+hset ~other:*)");
		const refused = await assemble({
			modules: [redisModule, tlsOptionsForTests],
			config: { ...kernelConfig(), redis: { url: oldUrl, prefix: "old" } },
		}).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		const reasons = (refused as BootRefused).refusals.map((r) => r.reason).join("; ");
		expect(reasons).toContain("the server refuses this user the store's keys");
	});
});

describe("settings the server will not show", () => {
	let blocked = "";
	let blockedUrl = "";
	beforeAll(async () => {
		const port = await freePort();
		const args = ["redis-server", "--rename-command", "CONFIG", ""];
		blocked = docker("run", "-d", "--rm", "-p", `127.0.0.1:${port}:6379`, image, ...args);
		blockedUrl = `redis://127.0.0.1:${port}`;
		await waitFor(() => pings(blocked));
	}, 60_000);
	afterAll(() => {
		if (blocked) docker("rm", "-f", "-v", blocked);
	});
	const kept = defineModule({ name: "kept-owner", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["durable", "no-eviction"] })),
	]);
	const boot = (redis: object, through = blockedUrl, recorded = recordingLog()) =>
		assemble({
			modules: [redisModule, tlsOptionsForTests, kept],
			config: { ...kernelConfig(), redis: { url: through, prefix: `d${++opened}`, ...redis } },
			runtime: quietRuntime({ log: recorded.log }),
		});
	const refusedFor = async (redis: object, through?: string) => {
		const refused = await boot(redis, through).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		return (refused as BootRefused).refusals.map((r) => r.reason).join("; ");
	};

	it("names each setting it needs that the operator has not declared", async () => {
		const reasons = await refusedFor({});
		for (const name of ["maxmemory-policy", "appendonly", "appendfsync"]) {
			expect(reasons, name).toContain(`declare ${name} in redis.server-settings`);
		}
	});

	it("judges declared settings as it judges those it reads", async () => {
		const declared = {
			"maxmemory-policy": "allkeys-lru",
			appendonly: "yes",
			appendfsync: "always",
		};
		expect(await refusedFor({ "server-settings": declared })).toContain("noeviction");
	});

	it("boots on declared settings, warning on each boot that they hold as declared, unchecked", async () => {
		const recorded = recordingLog();
		const declared = { "maxmemory-policy": "noeviction", appendonly: "yes", appendfsync: "always" };
		const app = await boot({ "server-settings": declared }, blockedUrl, recorded);
		stops.push(() => app.stop(1000));
		const warned = recorded.lines().filter((line) => line.event === "redis.settings_declared");
		expect(warned.map((line) => line.fields.settings)).toEqual([
			"maxmemory-policy, appendonly, appendfsync",
		]);
	});

	it("takes durability none in place of append-only settings, warning on each boot of the spaces it leaves undurable", async () => {
		const recorded = recordingLog();
		const app = await boot(
			{ durability: "none", "server-settings": { "maxmemory-policy": "noeviction" } },
			blockedUrl,
			recorded,
		);
		stops.push(() => app.stop(1000));
		const warned = recorded.lines().filter((line) => line.event === "redis.durability_none");
		expect(warned.map((line) => line.fields.spaces)).toEqual(["kept"]);
	});

	/** A relay to the primary that answers every CONFIG command with `error`, relaying the rest. */
	const refusingConfig = async (error: string) => {
		const port = await freePort();
		const server = createServer((client) => {
			const upstream = createConnection(Number(new URL(url).port), "127.0.0.1");
			client.on("data", (chunk) => {
				if (/\$6\r\nconfig\r\n/i.test(chunk.toString())) client.write(`-${error}\r\n`);
				else upstream.write(chunk);
			});
			upstream.on("data", (chunk) => client.write(chunk));
			const close = () => {
				client.destroy();
				upstream.destroy();
			};
			for (const end of [client, upstream]) end.on("error", close).on("close", close);
		});
		await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", () => resolve()));
		stops.push(async () => {
			server.close();
		});
		return `redis://127.0.0.1:${port}`;
	};
	const declaredAll = {
		"server-settings": {
			"maxmemory-policy": "noeviction",
			appendonly: "yes",
			appendfsync: "always",
		},
	};

	it("takes the declaration only where the server refuses CONFIG for want of permission or the command", async () => {
		for (const error of [
			"NOPERM User default has no permissions to run the 'config|get' command",
			"ERR unknown subcommand 'GET'. Try CONFIG HELP.",
		]) {
			const app = await boot(declaredAll, await refusingConfig(error));
			stops.push(() => app.stop(1000));
		}
	});

	it("refuses boot, never taking the declaration, where CONFIG fails for a passing reason", async () => {
		const busy =
			"BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSCRIPT.";
		expect(await refusedFor(declaredAll, await refusingConfig(busy))).toContain(
			"cannot check its configuration",
		);
	});

	it("refuses a declared setting that differs from what a server answering CONFIG GET holds", async () => {
		const differs = { "server-settings": { "maxmemory-policy": "allkeys-lru" } };
		expect(await refusedFor(differs, url)).toContain(
			"redis.server-settings.maxmemory-policy differs",
		);
		const recorded = recordingLog();
		const app = await boot(
			{ "server-settings": { "maxmemory-policy": "noeviction" } },
			url,
			recorded,
		);
		stops.push(() => app.stop(1000));
		expect(recorded.lines().map((line) => line.event)).not.toContain("redis.settings_declared");
	});
});
