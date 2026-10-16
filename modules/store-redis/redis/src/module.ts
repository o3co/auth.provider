import { contract, defineModule, probes } from "@mod/kernel";
import { type Space, spaces, store } from "@mod/store";
import { Redis } from "ioredis";
import { z } from "zod";
import { redisProbe } from "./probe.ts";
import { redisStore } from "./redis-store.ts";

const section = z.strictObject({
	url: z.url({ protocol: /^rediss?$/ }).describe("The Redis server to connect to."),
	prefix: z
		.string()
		.regex(/^[a-z0-9-]+$/)
		.default("store")
		.describe("What every key the store writes begins with."),
	"connect-timeout-ms": z
		.number()
		.int()
		.min(100)
		.default(2000)
		.describe("How long connecting to Redis may take, in milliseconds."),
	"replication-timeout-ms": z
		.number()
		.int()
		.min(1)
		.max(60_000)
		.default(1000)
		.describe("How long a confirmation waits for every replica to have a write, in milliseconds."),
	"command-timeout-ms": z
		.number()
		.int()
		.min(10)
		.max(60_000)
		.default(1000)
		.describe("How long one Redis command may take, in milliseconds."),
	replication: z
		.enum(["none", "replicas"])
		.optional()
		.describe(
			'Required when a space asks for replication or confirmed reads. "replicas": every write must reach the replicas, and Redis itself must refuse writes without them. "none": the operator states there is no failover at all, accepting that a failover would lose writes.',
		),
});

const minimumVersion = [7, 0];

async function configValue(client: Redis, name: string): Promise<string | undefined> {
	const pair = (await client.config("GET", name)) as string[];
	return pair[1];
}

type Role = [string, number, unknown[]];
const roleOf = async (client: Redis) => (await client.call("ROLE")) as Role;
const replicasOf = (role: Role) => (Array.isArray(role[2]) ? role[2].length : 0);

async function serverProblems(client: Redis, role: Role): Promise<string[]> {
	const problems: string[] = [];
	if (role[0] !== "master") problems.push("connect to a primary (role master)");
	if (/cluster_enabled:1/.test(await client.info("cluster"))) {
		problems.push("Redis cluster, and proxies that split keys across nodes, are not supported");
	}
	const version = /redis_version:(\d+)\.(\d+)/.exec(await client.info("server"));
	const [major, minor] = [Number(version?.[1] ?? 0), Number(version?.[2] ?? 0)];
	if (
		major < (minimumVersion[0] ?? 0) ||
		(major === minimumVersion[0] && minor < (minimumVersion[1] ?? 0))
	) {
		problems.push(`needs Redis ${minimumVersion.join(".")} or later`);
	}
	return problems;
}

async function evictionProblems(client: Redis, declared: readonly Space[]): Promise<string[]> {
	const kept = declared.filter((s) => s.guarantees.includes("no-eviction"));
	if (kept.length === 0 || (await configValue(client, "maxmemory-policy")) === "noeviction")
		return [];
	const names = kept.map((s) => s.name).join(", ");
	return [`the no eviction guarantee needs maxmemory-policy noeviction: ${names}`];
}

async function replicationProblems(
	client: Redis,
	role: Role,
	declared: readonly Space[],
	replication: "none" | "replicas" | undefined,
): Promise<string[]> {
	const replicated = declared.filter(
		(s) => s.guarantees.includes("replicated") || s.guarantees.includes("confirmed-reads"),
	);
	if (replicated.length === 0) return [];
	if (replication === undefined) {
		const names = replicated.map((s) => s.name).join(", ");
		return [
			`spaces need replicated or confirmed reads, so redis.replication (none or replicas) is required: ${names}`,
		];
	}
	if (
		replication === "replicas" &&
		(Number(await configValue(client, "min-replicas-to-write")) < 1 ||
			Number(await configValue(client, "min-replicas-max-lag")) < 1)
	) {
		return [
			"with replication replicas, set min-replicas-to-write and min-replicas-max-lag to 1 or more",
		];
	}
	if (replication === "none" && replicasOf(role) > 0) {
		return ["replication is none but a replica is connected"];
	}
	return [];
}

async function durabilityProblems(client: Redis, declared: readonly Space[]): Promise<string[]> {
	const durable = declared.filter((s) => s.guarantees.includes("durable"));
	if (durable.length === 0) return [];
	const persisted =
		(await configValue(client, "appendonly")) === "yes" &&
		(await configValue(client, "appendfsync")) === "always";
	if (persisted) return [];
	const names = durable.map((s) => s.name).join(", ");
	return [`the durable guarantee needs appendonly yes and appendfsync always: ${names}`];
}

/** What the server's settings fail to give the declared spaces; empty when everything holds. */
async function unmet(
	client: Redis,
	declared: readonly Space[],
	replication: "none" | "replicas" | undefined,
): Promise<string[]> {
	const role = await roleOf(client);
	return [
		...(await serverProblems(client, role)),
		...(await evictionProblems(client, declared)),
		...(await replicationProblems(client, role, declared, replication)),
		...(await durabilityProblems(client, declared)),
	];
}

/** The two connections, open and checked, for the store and its probe alike. */
const connections = contract<{
	readonly client: Redis;
	readonly confirmer: Redis;
	readonly declared: readonly Space[];
}>("redis.connections");

export default defineModule({ name: "redis", section }, (m) => [
	m.provide(connections).by(async (c) => {
		const client = new Redis(c.section.url, {
			lazyConnect: true,
			connectTimeout: c.section["connect-timeout-ms"],
			maxRetriesPerRequest: 0,
			enableOfflineQueue: false,
			// A command whose reply was lost must not be sent again on a new connection: a resent
			// WAIT would confirm nothing, and a resent script would run twice.
			autoResendUnfulfilledCommands: false,
			commandTimeout: c.section["command-timeout-ms"],
		});
		client.on("error", () => c.log.warn("redis.error"));
		const confirmer = client.duplicate({
			commandTimeout: c.section["replication-timeout-ms"] + c.section["command-timeout-ms"],
		});
		confirmer.on("error", () => c.log.warn("redis.error"));
		let problems: string[];
		const declared = await c.collect(spaces);
		try {
			await client.connect();
			await confirmer.connect();
			problems = await unmet(client, declared, c.section.replication);
		} catch {
			client.disconnect();
			confirmer.disconnect();
			return c.refuse("redis.url", "cannot connect to Redis, or cannot check its configuration");
		}
		if (problems.length > 0) {
			client.disconnect();
			confirmer.disconnect();
			return c.refuse("redis", problems.join("; "));
		}
		c.onStop(async () => {
			await client.quit().catch(() => client.disconnect());
			await confirmer.quit().catch(() => confirmer.disconnect());
		});
		return { client, confirmer, declared };
	}),
	m.provide(store).by(async (c) => {
		const { client, confirmer, declared } = await c.get(connections);
		return redisStore(
			client,
			confirmer,
			{
				prefix: c.section.prefix,
				replicationTimeoutMs: c.section["replication-timeout-ms"],
				replication: c.section.replication,
			},
			declared,
		);
	}),
	m.contribute(probes).by(async (c) => {
		const { client, confirmer } = await c.get(connections);
		return redisProbe([client, confirmer]);
	}),
]);
