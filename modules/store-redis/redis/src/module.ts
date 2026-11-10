import { contract, defineModule, probes, setting } from "@mod/kernel";
import { type Space, spaces, store, storeControl, storeUpkeep } from "@mod/store";
import { isFloor, tlsOptions } from "@mod/tls-options";
import { Redis } from "ioredis";
import { z } from "zod";
import { clientDebugs, clientOptions, plaintextWarning, queryRefusal } from "./client/client.ts";
import { keysUnder } from "./keys.ts";
import { goodReplicaProblems, redisProbe } from "./probe/probe.ts";
import {
	clusterRefused,
	redisStore,
	refusedCommands,
	roundProblems,
	scriptsOn,
	serverOf,
	type Taken,
} from "./redis-store.ts";
import { confirmationRounds } from "./round/round.ts";
import {
	durabilityProblems,
	evictionProblems,
	honoursOf,
	type Role,
	replicationProblems,
	roleOf,
	type SettingName,
	serverSettings,
} from "./settings/settings.ts";
import { redisUpkeepWith } from "./upkeep/upkeep.ts";

const section = z.strictObject({
	url: z
		.url({ protocol: /^rediss?$/ })
		.superRefine((url, ctx) => {
			const refused = queryRefusal(url);
			if (refused !== undefined) ctx.addIssue({ code: "custom", message: refused });
		})
		.describe("The Redis server to connect to, with no query: each option is its own setting."),
	"accept-plaintext": z
		.boolean()
		.prefault(false)
		.describe(
			"Accepts `redis://` at a host not loopback by its name, the store's traffic and the URL's password readable and changeable on the way, in production too; every start warns `redis.plaintext`. Without it, production warns at every start too: deprecated, a later release refuses boot for it.",
		),
	"address-family": z
		.enum(["ipv4", "ipv6"])
		.optional()
		.describe("The address family the host's name resolves to: ipv4 or ipv6; either when unset."),
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
			'"none": the operator states the server does not fsync every write, accepting that a crash loses the latest writes, among them spent assertion and proof ids and lockout records. Without it, a durable space needs appendonly yes, appendfsync always and no-appendfsync-on-rewrite no.',
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
			"no-appendfsync-on-rewrite": z
				.enum(["yes", "no"])
				.optional()
				.describe("Whether the server skips its fsyncs while it rewrites its append-only file."),
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
			"The server's settings as the operator declares them, read only where the server refuses CONFIG GET or does not show the setting; declare only what the server really has. Where CONFIG GET answers, a declared value that differs refuses boot.",
		),
});

const minimumVersion = [7, 0];

async function serverProblems(client: Redis, role: Role): Promise<string[]> {
	const problems: string[] = [];
	if (role[0] !== "master") problems.push("connect to a primary (role master)");
	if (/cluster_enabled:1/.test(await client.info("cluster"))) {
		problems.push(clusterRefused);
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

/** What the server's settings fail to give the declared spaces, empty when everything holds; and the settings taken as declared. */
async function unmet(
	client: Redis,
	confirmer: Redis,
	declared: readonly Space[],
	s: z.output<typeof section>,
): Promise<{
	readonly problems: string[];
	readonly declaredOnly: readonly SettingName[];
	readonly undurable: readonly string[];
	readonly unreplicated: readonly string[];
}> {
	// First, as the checks below send some of the same commands: a refused one is named, not lost.
	const refused = await refusedCommands(client, confirmer, {
		prefix: s.prefix,
		replication: s.replication,
	});
	if (refused.length > 0) {
		return { problems: refused, declaredOnly: [], undurable: [], unreplicated: [] };
	}
	const round = await roundProblems(client, confirmer, {
		prefix: s.prefix,
		replication: s.replication,
	});
	if (round.length > 0)
		return { problems: round, declaredOnly: [], undurable: [], unreplicated: [] };
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
	const unreplicated =
		s.replication === "none"
			? declared
					.filter(
						(d) => d.guarantees.includes("replicated") || d.guarantees.includes("confirmed-reads"),
					)
					.map((d) => d.name)
			: [];
	return {
		problems: [...problems, ...settings.problems],
		declaredOnly: [...settings.used],
		undurable,
		unreplicated,
	};
}

/**
 * What a failure is, by its code alone (`ECONNREFUSED`, `ENOTFOUND`, `NOAUTH`): a system error's
 * code, the first word of a server's reply where it is one, or the error's class (`ParserError`);
 * never the message, which may name a host or a key.
 */
function codeOf(error: unknown): string {
	const word = /^[A-Z][A-Z0-9_]{1,31}$/;
	const { code, message, name } = (error ?? {}) as {
		code?: unknown;
		message?: unknown;
		name?: unknown;
	};
	if (typeof code === "string" && word.test(code)) return code;
	const first = typeof message === "string" ? message.split(" ")[0] : undefined;
	if (first !== undefined && word.test(first)) return first;
	return typeof name === "string" && /^[A-Z][A-Za-z]{1,31}Error$/.test(name) && name !== "Error"
		? name
		: "unknown";
}

/** The two connections, open and checked, for the store and its probe alike. */
const connections = contract<{
	readonly client: Redis;
	readonly confirmer: Redis;
	readonly declared: readonly Space[];
}>("redis.connections");

/** The one process over the store's data, whose epoch the store and its upkeep share. */
const opened = contract<{
	readonly store: ReturnType<typeof redisStore>;
	readonly upkeep: ReturnType<typeof redisUpkeepWith>;
}>("redis.opened");

const takes = [spaces, tlsOptions] as const;

// Safe on many instances: it is the shared store, given the same `url` and `prefix` on each
// (deployment-guarantees, Several instances).
export default defineModule(
	{
		name: "redis",
		replicaSafe: true,
		section,
		// The client's own debug log writes AUTH's password and every command's arguments, what the
		// store keeps among them; production refuses it by the key whose secret it leaks, never a value.
		refusedInProduction: () =>
			clientDebugs(process.env.DEBUG)
				? [
						{
							key: "url",
							reason:
								"DEBUG turns on ioredis' own debug log, which writes this URL's password and every command's arguments; leave ioredis out of DEBUG",
						},
					]
				: [],
		takes,
	},
	(m) => [
		m.provide(connections).by(async (c) => {
			// On every boot: what the store keeps, and the URL's password, go in the clear; no host is told.
			const clear = plaintextWarning(c.section.url, c.section["accept-plaintext"], c.environment);
			if (clear !== undefined) c.log.warn("redis.plaintext", { reason: clear });
			const floor = await c.get(tlsOptions);
			if (!isFloor(floor)) {
				return c.refuse(
					"redis",
					"the TLS floor is not one tls-options made: provide it from @mod/tls-options",
				);
			}
			const client = new Redis(c.section.url, clientOptions(c.section, floor));
			// The last failure's code, which a refused connect tells only through its error events.
			let lastCode = "unknown";
			const failed = (error: unknown) => {
				lastCode = codeOf(error);
				c.log.warn("redis.error", { code: lastCode });
			};
			client.on("error", failed);
			const confirmer = client.duplicate({
				commandTimeout: c.section["replication-timeout"] + c.section["command-timeout"],
			});
			confirmer.on("error", failed);
			const disconnectBoth = () => {
				client.disconnect();
				confirmer.disconnect();
			};
			let checked: Awaited<ReturnType<typeof unmet>>;
			const declared = await c.collect(spaces);
			try {
				await client.connect();
				await confirmer.connect();
				checked = await unmet(client, confirmer, declared, c.section);
			} catch (error) {
				disconnectBoth();
				return c.refuse(
					"redis.url",
					`cannot connect to Redis, or cannot check its configuration (${codeOf(error) === "unknown" ? lastCode : codeOf(error)})`,
				);
			}
			if (checked.problems.length > 0) {
				disconnectBoth();
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
			if (checked.unreplicated.length > 0) {
				// On every boot: a failover loses these spaces' writes, confirmed ones too, as the operator stated.
				c.log.warn("redis.replication_none", { spaces: checked.unreplicated.join(", ") });
			}
			c.onStop(async (signal) => {
				// Past the stop's deadline the connections are cut, not left waiting on QUIT.
				if (signal.aborted) return disconnectBoth();
				signal.addEventListener("abort", disconnectBoth, { once: true });
				try {
					await client.quit().catch(() => client.disconnect());
					await confirmer.quit().catch(() => confirmer.disconnect());
				} finally {
					signal.removeEventListener("abort", disconnectBoth);
				}
			});
			return { client, confirmer, declared };
		}),
		m.provide(opened).by(async (c) => {
			const { client, confirmer, declared } = await c.get(connections);
			const options = {
				prefix: c.section.prefix,
				replicationTimeoutMs: c.section["replication-timeout"],
				replication: c.section.replication,
			};
			const taken: Taken = { epoch: "" };
			const upkeep = redisUpkeepWith({
				run: scriptsOn(client),
				serverOf,
				confirmed:
					options.replication === undefined ? undefined : confirmationRounds(confirmer, options),
				keys: keysUnder(options.prefix),
				declared,
				taken,
				random: c.random,
				honours: (wanted) => honoursOf(client, c.section, wanted),
			});
			try {
				await upkeep.start();
			} catch {
				return c.refuse(
					"redis",
					"cannot take the control record's epoch, or add the declared spaces to the ledger, before the first write",
				);
			}
			return { store: redisStore(client, confirmer, options, declared, taken), upkeep };
		}),
		m.provide(store).by(async (c) => (await c.get(opened)).store),
		m.provide(storeControl).by(async (c) => (await c.get(opened)).upkeep.control),
		m.provide(storeUpkeep).by(async (c) => (await c.get(opened)).upkeep.upkeep),
		m.contribute(probes).by(async (c) => {
			const { client, confirmer, declared } = await c.get(connections);
			// Too few good replicas only the probe asks: boot waits unready rather than failing on a passing state.
			const goodReplicas = async () => {
				if (c.section.replication !== "replicas") return [];
				const settings = serverSettings(client, c.section["server-settings"] ?? {});
				const needed = await settings.read("min-replicas-to-write");
				const info = await client.info("replication");
				return goodReplicaProblems(info, needed === undefined ? undefined : Number(needed));
			};
			const { upkeep } = await c.get(opened);
			const recheck = async () => {
				const { problems } = await unmet(client, confirmer, declared, c.section);
				if (problems.length > 0) return problems;
				// A process under an old epoch changes nothing: it leaves traffic until it starts again.
				const started = await upkeep.recheck();
				return started.length > 0 ? started : goodReplicas();
			};
			return redisProbe([client, confirmer], recheck, c.log, c.clock);
		}),
	],
);
