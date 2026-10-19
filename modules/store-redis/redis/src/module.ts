import { contract, defineModule, probes, setting } from "@mod/kernel";
import { type Space, spaces, store } from "@mod/store";
import { Redis, ReplyError } from "ioredis";
import { z } from "zod";
import { redisProbe } from "./probe.ts";
import { redisStore } from "./redis-store.ts";

const section = z.strictObject({
	url: z.url({ protocol: /^rediss?$/ }).describe("The Redis server to connect to."),
	prefix: z
		.string()
		.regex(/^[a-z0-9-]+$/)
		.prefault("store")
		.describe("What every key the store writes begins with."),
	"connect-timeout": setting
		.duration("ms")
		.pipe(z.number().int().min(100))
		.prefault("2s")
		.describe("How long connecting to Redis may take, at least 100ms."),
	"replication-timeout": setting
		.duration("ms")
		.pipe(z.number().int().min(1).max(60_000))
		.prefault("1s")
		.describe("How long a confirmation waits for every replica to have a write, from 1ms to 1m."),
	"command-timeout": setting
		.duration("ms")
		.pipe(z.number().int().min(10).max(60_000))
		.prefault("1s")
		.describe("How long one Redis command may take, from 10ms to 1m."),
	replication: z
		.enum(["none", "replicas"])
		.optional()
		.describe(
			'Required when a space asks for replication or confirmed reads. "replicas": every write must reach the replicas, and Redis itself must refuse writes without them. "none": the operator states there is no failover at all, accepting that a failover would lose writes.',
		),
	durability: z
		.literal("none")
		.optional()
		.describe(
			'"none": the operator states the server does not fsync every write, accepting that a crash loses the latest writes, among them spent assertion and proof ids and lockout records. Without it, a durable space needs appendonly yes and appendfsync always.',
		),
	"server-settings": z
		.strictObject({
			"maxmemory-policy": z
				.string()
				.min(1)
				.optional()
				.describe("The server's maxmemory-policy, as it is set there."),
			appendonly: z
				.enum(["yes", "no"])
				.optional()
				.describe("Whether the server keeps an append-only file."),
			appendfsync: z
				.enum(["always", "everysec", "no"])
				.optional()
				.describe("How often the server fsyncs its append-only file."),
			"min-replicas-to-write": z
				.number()
				.int()
				.min(0)
				.optional()
				.describe("The replicas the server needs before it takes a write."),
			"min-replicas-max-lag": z
				.number()
				.int()
				.min(0)
				.optional()
				.describe("How many seconds behind a replica may be and still count for writes."),
		})
		.optional()
		.describe(
			"The server's settings as the operator declares them, read only where the server refuses CONFIG GET; declare only what the server really has. Where CONFIG GET answers, a declared value that differs refuses boot.",
		),
});

type Declared = NonNullable<z.output<typeof section>["server-settings"]>;
type SettingName = keyof Declared;

const minimumVersion = [7, 0];

/** Whether CONFIG is refused for good, for want of permission or of the command; any other error is no answer. */
const refusesConfig = (error: unknown) =>
	error instanceof ReplyError &&
	/^(NOPERM|ERR unknown (sub)?command)\b/i.test((error as Error).message);

/** Reads a server setting by CONFIG GET; where the server refuses it, the operator's declaration. */
type Settings = (name: SettingName) => Promise<string | undefined>;

/**
 * The server's settings: CONFIG GET where it answers, a declared value that differs then refused;
 * the declaration where the server refuses CONFIG, a setting left undeclared then refused.
 */
function serverSettings(client: Redis, declared: Declared) {
	const problems: string[] = [];
	const used = new Set<SettingName>();
	const declaredOf = (name: SettingName) =>
		declared[name] === undefined ? undefined : String(declared[name]);
	const read: Settings = async (name) => {
		let answered: string | undefined;
		try {
			answered = ((await client.config("GET", name)) as string[])[1];
		} catch (error) {
			if (!refusesConfig(error)) throw error;
			used.add(name);
			const value = declaredOf(name);
			if (value === undefined) {
				problems.push(`the server refuses CONFIG GET: declare ${name} in redis.server-settings`);
			}
			return value;
		}
		const value = declaredOf(name);
		if (value !== undefined && value !== answered) {
			problems.push(`redis.server-settings.${name} differs from what the server answers`);
		}
		return answered;
	};
	/** Compares every declared setting the checks did not read, so none is left unchecked where it can be. */
	const rest = async () => {
		for (const name of Object.keys(declared) as SettingName[]) await read(name);
	};
	return { read, rest, problems, used };
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

async function evictionProblems(settings: Settings, declared: readonly Space[]): Promise<string[]> {
	const kept = declared.filter((s) => s.guarantees.includes("no-eviction"));
	if (kept.length === 0 || (await settings("maxmemory-policy")) === "noeviction") return [];
	const names = kept.map((s) => s.name).join(", ");
	return [`the no eviction guarantee needs maxmemory-policy noeviction: ${names}`];
}

async function replicationProblems(
	settings: Settings,
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
		(Number(await settings("min-replicas-to-write")) < 1 ||
			Number(await settings("min-replicas-max-lag")) < 1)
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

async function durabilityProblems(
	settings: Settings,
	declared: readonly Space[],
	durability: "none" | undefined,
): Promise<string[]> {
	const durable = declared.filter((s) => s.guarantees.includes("durable"));
	if (durable.length === 0 || durability === "none") return [];
	// Both are read, so a refusal names every setting left undeclared at once.
	const [appendonly, appendfsync] = [await settings("appendonly"), await settings("appendfsync")];
	const persisted = appendonly === "yes" && appendfsync === "always";
	if (persisted) return [];
	const names = durable.map((s) => s.name).join(", ");
	return [`the durable guarantee needs appendonly yes and appendfsync always: ${names}`];
}

/** What the server's settings fail to give the declared spaces, empty when everything holds; and the settings taken as declared. */
async function unmet(
	client: Redis,
	declared: readonly Space[],
	s: z.output<typeof section>,
): Promise<{
	readonly problems: string[];
	readonly declaredOnly: readonly SettingName[];
	readonly undurable: readonly string[];
}> {
	const role = await roleOf(client);
	const settings = serverSettings(client, s["server-settings"] ?? {});
	const problems = [
		...(await serverProblems(client, role)),
		...(await evictionProblems(settings.read, declared)),
		...(await replicationProblems(settings.read, role, declared, s.replication)),
		...(await durabilityProblems(settings.read, declared, s.durability)),
	];
	await settings.rest();
	const undurable =
		s.durability === "none"
			? declared.filter((d) => d.guarantees.includes("durable")).map((d) => d.name)
			: [];
	return {
		problems: [...problems, ...settings.problems],
		declaredOnly: [...settings.used],
		undurable,
	};
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
			connectTimeout: c.section["connect-timeout"],
			maxRetriesPerRequest: 0,
			enableOfflineQueue: false,
			// A command whose reply was lost must not be sent again on a new connection: a resent
			// WAIT would confirm nothing, and a resent script would run twice.
			autoResendUnfulfilledCommands: false,
			commandTimeout: c.section["command-timeout"],
		});
		client.on("error", () => c.log.warn("redis.error"));
		const confirmer = client.duplicate({
			commandTimeout: c.section["replication-timeout"] + c.section["command-timeout"],
		});
		confirmer.on("error", () => c.log.warn("redis.error"));
		let checked: Awaited<ReturnType<typeof unmet>>;
		const declared = await c.collect(spaces);
		try {
			await client.connect();
			await confirmer.connect();
			checked = await unmet(client, declared, c.section);
		} catch {
			client.disconnect();
			confirmer.disconnect();
			return c.refuse("redis.url", "cannot connect to Redis, or cannot check its configuration");
		}
		if (checked.problems.length > 0) {
			client.disconnect();
			confirmer.disconnect();
			return c.refuse("redis", checked.problems.join("; "));
		}
		if (checked.declaredOnly.length > 0) {
			// On every boot: these the server would not show, so they hold as declared, unchecked.
			c.log.warn("redis.settings_declared", { settings: checked.declaredOnly.join(", ") });
		}
		if (checked.undurable.length > 0) {
			// On every boot: a crash loses these spaces' latest writes, as the operator stated.
			c.log.warn("redis.durability_none", { spaces: checked.undurable.join(", ") });
		}
		c.onStop(async (signal) => {
			// Past the stop's deadline the connections are cut, not left waiting on QUIT.
			const cut = () => {
				client.disconnect();
				confirmer.disconnect();
			};
			if (signal.aborted) return cut();
			signal.addEventListener("abort", cut, { once: true });
			try {
				await client.quit().catch(() => client.disconnect());
				await confirmer.quit().catch(() => confirmer.disconnect());
			} finally {
				signal.removeEventListener("abort", cut);
			}
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
				replicationTimeoutMs: c.section["replication-timeout"],
				replication: c.section.replication,
			},
			declared,
		);
	}),
	m.contribute(probes).by(async (c) => {
		const { client, confirmer, declared } = await c.get(connections);
		const recheck = async () => (await unmet(client, declared, c.section)).problems;
		return redisProbe([client, confirmer], recheck, c.log);
	}),
]);
