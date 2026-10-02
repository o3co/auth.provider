/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The two MFA store modules (the MFA ADR's D7, D8, D10, D12, D19) and the one
 * durability check both run at boot. Why the records must survive: the MFA
 * ADR's D12, as amended.
 *
 * Before providing its store, each module reads the server's
 * `maxmemory-policy` and persistence: an `allkeys-*` policy refuses the boot;
 * RDB snapshots without AOF, and no persistence at all, are each one warning;
 * a server that refuses `CONFIG` is one warning that the check could not run.
 * Each store also warns on a `volatile-*` policy, naming the key families
 * that carry a TTL and fail open when evicted: the factor store's emptied
 * sets' tombstones, which an eviction ends before the write lifetime has
 * passed, and its writes' replay keys; the transaction store's lock and week keys, which carry one once
 * no run is counted, and an evicted one lifts a hold early.
 *
 * The policy is read from `INFO memory`, and from `CONFIG GET
 * maxmemory-policy` only where INFO does not say, so a server that blocks
 * `CONFIG` is still held to the refusal; AOF from `INFO persistence`;
 * `CONFIG GET save` only to tell RDB snapshots from no persistence. A part
 * that could not be read is named in the could-not-run warning. Only a reply
 * that refuses the question (an unknown or renamed command, `NOPERM`, a
 * disabled command) is read so; any other reply error, and any failure to
 * reach the server, fails the boot.
 *
 * Every real-server case that reads or sets the eviction policy is in this
 * file alone, so no other file sees the policy this one sets for a moment.
 */

import {
	type AppConfig,
	consoleLogger,
	createApp,
	defineModule,
	type Logger,
	loggableError,
	type Module,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	replicaUnsafeReason,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { Redis } from "ioredis";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { RedisDurability } from "#/clients.mjs";
import {
	makeIoredisClients,
	makeIoredisMfaFactorStoreClient,
	makeIoredisMfaTransactionStoreClient,
} from "#/ioredis.mjs";
import { redisMfaFactorStoreModule } from "#/mfa-factor-store.mjs";
import { redisMfaTransactionStoreModule } from "#/mfa-transaction-store.mjs";
import { testRedis } from "./support/redis.mjs";
import { withSection } from "./support/section.mjs";

let at: Awaited<ReturnType<typeof testRedis>>;
let raw: Redis;

beforeAll(async () => {
	at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	await raw?.quit();
});

afterEach(() => {
	vi.restoreAllMocks();
});

/** A logger that records what each level is handed. */
function recordingLogger(): { logger: Logger; calls: Array<{ level: string; args: unknown[] }> } {
	const calls: Array<{ level: string; args: unknown[] }> = [];
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
		};
	const logger: Logger = {
		trace: record("trace"),
		debug: record("debug"),
		info: record("info"),
		warn: record("warn"),
		error: record("error"),
		fatal: record("fatal"),
		child: () => logger,
	};
	return { logger, calls };
}

interface Case {
	readonly module: Module;
	readonly slot: "mfaFactorStore" | "mfaTransactionStore";
	readonly clientSlot: "mfaFactorStoreClient" | "mfaTransactionStoreClient";
	readonly configKey: "redis-mfa-factor-store" | "redis-mfa-transaction-store";
	readonly defaultPrefix: string;
	readonly evictable: string;
	readonly lossy: string;
	readonly volatile: string;
	readonly unchecked: string;
	/** The notice a `volatile-*` policy is given: some of the store's keys carry a TTL. */
	readonly volatileEvictable: string;
	/** The key families that notice names: each one's loss fails open. */
	readonly evictableFamilies: readonly string[];
	readonly memoryModule: Module;
	readonly client: (io: Redis) => { durability(): Promise<RedisDurability> };
}

const CASES: readonly Case[] = [
	{
		module: redisMfaFactorStoreModule,
		slot: "mfaFactorStore",
		clientSlot: "mfaFactorStoreClient",
		configKey: "redis-mfa-factor-store",
		defaultPrefix: "mfaf:",
		evictable: "mfa-factor-store-evictable",
		lossy: "mfa_factor_store_lossy",
		volatile: "mfa_factor_store_volatile",
		unchecked: "mfa_factor_store_durability_unchecked",
		volatileEvictable: "mfa_factor_store_tombstone_evictable",
		evictableFamilies: ["tombstone", "replay"],
		memoryModule: memoryMfaFactorStoreModule,
		client: makeIoredisMfaFactorStoreClient,
	},
	{
		module: redisMfaTransactionStoreModule,
		slot: "mfaTransactionStore",
		clientSlot: "mfaTransactionStoreClient",
		configKey: "redis-mfa-transaction-store",
		defaultPrefix: "mfat:",
		evictable: "mfa-transaction-store-evictable",
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
		volatileEvictable: "mfa_transaction_store_lock_evictable",
		evictableFamilies: ["lock", "week", "first-binding", "lease"],
		memoryModule: memoryMfaTransactionStoreModule,
		client: makeIoredisMfaTransactionStoreClient,
	},
];

const DURABLE: RedisDurability = {
	maxmemoryPolicy: "noeviction",
	appendOnly: true,
	snapshots: undefined,
	refusal: undefined,
};

/** A reply error as ioredis raises one. */
const replyError = (message: string): Error =>
	Object.assign(new Error(message), { name: "ReplyError" });

/** A client whose server answers `report`; nothing else is asked of it at boot. */
const stubClient = (report: RedisDurability | (() => Promise<RedisDurability>)) => ({
	durability: typeof report === "function" ? report : async () => report,
});

/** The factory a case's module provides its slot with. */
const providerOf = (c: Case): ((deps: unknown) => Promise<{ kind: string }>) => {
	const provider = c.module.provides?.[c.slot];
	if (provider === undefined) throw new Error(`${c.module.name} provides no ${c.slot}`);
	return provider as (deps: unknown) => Promise<{ kind: string }>;
};

describe.each(CASES)("$module.name", (c) => {
	const provide = (deps: Record<string, unknown>) => providerOf(c)(withSection(c.module, deps));

	const boot = (report: RedisDurability | (() => Promise<RedisDurability>), logger?: Logger) =>
		provide({
			[c.clientSlot]: stubClient(report),
			config: {},
			...(logger === undefined ? {} : { logger }),
		});

	it("needs its client, reads the logger if there is one, and fills one slot", () => {
		expect(c.module.requires).toStrictEqual([c.clientSlot]);
		expect(c.module.optional).toStrictEqual(["logger"]);
		expect(Object.keys(c.module.provides ?? {})).toStrictEqual([c.slot]);
	});

	it(`reads ${c.configKey}.keyPrefix, its own section's, "${c.defaultPrefix}" when it is not set`, () => {
		expect(c.module.configSchema).toBeUndefined();
		expect(c.module.section?.schema.parse(undefined)).toStrictEqual({ keyPrefix: c.defaultPrefix });
		expect(c.module.section?.schema.parse({ keyPrefix: "tenant-a:" })).toStrictEqual({
			keyPrefix: "tenant-a:",
		});
	});

	it("declares nothing the replica-safety guard refuses, where the memory module does", () => {
		expect(replicaUnsafeReason(c.module)).toBeUndefined();
		expect(replicaUnsafeReason(c.memoryModule)).toBeDefined();
	});

	it("refuses a keyPrefix that carries a brace before it asks the server anything", async () => {
		const durability = vi.fn(async () => DURABLE);
		await expect(
			provide({
				[c.clientSlot]: { durability },
				config: { [c.configKey]: { keyPrefix: "mfa{x}:" } },
			}),
		).rejects.toThrow(RangeError);
		expect(durability).not.toHaveBeenCalled();
	});

	it.each(["allkeys-lru", "allkeys-lfu", "allkeys-random"])(
		"refuses %s at boot: a policy that may evict any key, naming the policy",
		async (policy) => {
			const { logger, calls } = recordingLogger();
			const refused = boot({ ...DURABLE, maxmemoryPolicy: policy }, logger);
			await expect(refused).rejects.toMatchObject({
				reason: c.evictable,
				maxmemoryPolicy: policy,
			});
			await expect(refused).rejects.toThrow(new RegExp(`${policy}.*noeviction`));
			expect(calls).toEqual([]);
		},
	);

	it("boots on noeviction with AOF, and says nothing", async () => {
		const { logger, calls } = recordingLogger();
		expect((await boot(DURABLE, logger)).kind).toBe("redis");
		expect(calls).toEqual([]);
	});

	it.each(["volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl"])(
		"boots on %s with AOF, and warns once, naming the key families an eviction fails open on",
		async (policy) => {
			// The factor store's tombstones carry a TTL: evicted, an emptied set
			// reads as never written before the write lifetime has passed. The
			// transaction store's lock and week keys carry one once no run is
			// counted: evicted, a weekly hold ends early.
			const { logger, calls } = recordingLogger();
			expect((await boot({ ...DURABLE, maxmemoryPolicy: policy }, logger)).kind).toBe("redis");
			expect(calls).toEqual([
				{
					level: "warn",
					args: [
						{
							store: c.slot,
							adapter: "redis",
							maxmemoryPolicy: policy,
							evictableFamilies: c.evictableFamilies,
						},
						c.volatileEvictable,
					],
				},
			]);
		},
	);

	it("says each thing once when a volatile-* policy and RDB-only persistence come together", async () => {
		const { logger, calls } = recordingLogger();
		await boot(
			{ ...DURABLE, maxmemoryPolicy: "volatile-lru", appendOnly: false, snapshots: true },
			logger,
		);
		expect(calls.map((call) => call.args[1])).toEqual([c.volatileEvictable, c.lossy]);
	});

	it("warns once when RDB snapshots are the only persistence: the last interval is lost on a crash", async () => {
		const { logger, calls } = recordingLogger();
		expect((await boot({ ...DURABLE, appendOnly: false, snapshots: true }, logger)).kind).toBe(
			"redis",
		);
		expect(calls).toEqual([
			{ level: "warn", args: [{ store: c.slot, adapter: "redis" }, c.lossy] },
		]);
	});

	it("warns once when there is no persistence at all: a restart empties the store", async () => {
		const { logger, calls } = recordingLogger();
		expect((await boot({ ...DURABLE, appendOnly: false, snapshots: false }, logger)).kind).toBe(
			"redis",
		);
		expect(calls).toEqual([
			{ level: "warn", args: [{ store: c.slot, adapter: "redis" }, c.volatile] },
		]);
	});

	it("warns once that the check could not run when nothing could be read, naming the parts, and boots", async () => {
		const refusal = replyError("ERR unknown command 'CONFIG'");
		const { logger, calls } = recordingLogger();
		const unread: RedisDurability = {
			maxmemoryPolicy: undefined,
			appendOnly: undefined,
			snapshots: undefined,
			refusal,
		};
		expect((await boot(unread, logger)).kind).toBe("redis");
		expect(calls).toEqual([
			{
				level: "warn",
				args: [
					{
						store: c.slot,
						adapter: "redis",
						unread: ["maxmemory-policy", "appendonly"],
						err: loggableError(refusal),
					},
					c.unchecked,
				],
			},
		]);
	});

	it("refuses an allkeys-* policy it could read, whatever else it could not", async () => {
		const { logger, calls } = recordingLogger();
		const refused = boot(
			{
				maxmemoryPolicy: "allkeys-lru",
				appendOnly: undefined,
				snapshots: undefined,
				refusal: replyError("NOPERM this user has no permissions to run the 'config|get' command"),
			},
			logger,
		);
		await expect(refused).rejects.toMatchObject({ reason: c.evictable });
		expect(calls).toEqual([]);
	});

	it.each(["", "lru", "noeviction-strict", "allkeys-coldest", "volatile-oldest", "NOEVICTION"])(
		"warns that it could not check a policy it does not know (%j), naming it — neither refused nor passed",
		async (policy) => {
			// An allow-list: a future server's policy, or a value no server sends,
			// is judged by no prefix.
			const { logger, calls } = recordingLogger();
			expect((await boot({ ...DURABLE, maxmemoryPolicy: policy }, logger)).kind).toBe("redis");
			expect(calls).toEqual([
				{
					level: "warn",
					args: [{ store: c.slot, adapter: "redis", maxmemoryPolicy: policy }, c.unchecked],
				},
			]);
		},
	);

	it("judges the policy on its own when a server answers CONFIG GET save with nothing", async () => {
		// AOF off and no answer for save: persistence alone falls back to the
		// warning; a known allkeys-* policy is still refused.
		const noSave = { appendOnly: false, snapshots: undefined, refusal: undefined } as const;
		await expect(boot({ ...noSave, maxmemoryPolicy: "allkeys-lru" })).rejects.toMatchObject({
			reason: c.evictable,
		});
		const { logger, calls } = recordingLogger();
		await boot({ ...noSave, maxmemoryPolicy: "noeviction" }, logger);
		expect(calls).toEqual([
			{ level: "warn", args: [{ store: c.slot, adapter: "redis", unread: ["save"] }, c.unchecked] },
		]);
	});

	it("warns that the check could not run for the part it could not read alone", async () => {
		// AOF is off, and the server would not say whether it takes snapshots:
		// neither the lossy nor the volatile notice can be told, so it names
		// `save` as unread — and says nothing of the policy it did read.
		const refusal = replyError(
			"NOPERM this user has no permissions to run the 'config|get' command",
		);
		const { logger, calls } = recordingLogger();
		await boot({ ...DURABLE, appendOnly: false, snapshots: undefined, refusal }, logger);
		expect(calls).toEqual([
			{
				level: "warn",
				args: [
					{ store: c.slot, adapter: "redis", unread: ["save"], err: loggableError(refusal) },
					c.unchecked,
				],
			},
		]);
	});

	it("fails the boot when the server cannot be asked at all: an outage is not a refusal", async () => {
		const outage = new Error("Connection is closed.");
		await expect(boot(() => Promise.reject(outage))).rejects.toBe(outage);
	});

	it("writes its line on consoleLogger when no logger slot is filled", async () => {
		const warn = vi.spyOn(consoleLogger, "warn").mockImplementation(() => undefined);
		await boot({ ...DURABLE, appendOnly: false, snapshots: true });
		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn).toHaveBeenCalledWith({ store: c.slot, adapter: "redis" }, c.lossy);
	});
});

// ---------------------------------------------------------------------------
// Booted through createApp
// ---------------------------------------------------------------------------

/** Reads both MFA slots, as the MFA package will, and contributes a route so it is a closure root. */
const mfaStandIn = defineModule({
	name: "test:mfa-stand-in",
	optional: ["mfaFactorStore", "mfaTransactionStore"] as const,
	contributes: {
		routes: [
			{
				mountPath: "/__test_noop__",
				id: "test-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

const multiReplicaConfig = (extra: Record<string, unknown> = {}): AppConfig =>
	({
		...makeValidCoreConfig(),
		core: { deployment: { mode: "multi" } },
		...extra,
	}) as never;

describe("the MFA store modules booted through createApp", () => {
	it('boot under core.deployment.mode = "multi" off the shared clients and fill both slots with the Redis adapters', async () => {
		const { logger } = recordingLogger();
		const handle = await createApp({
			modules: [redisMfaFactorStoreModule, redisMfaTransactionStoreModule, mfaStandIn],
			bootstrapComponents: {
				config: multiReplicaConfig({
					"redis-mfa-factor-store": { keyPrefix: "boot:mfaf:" },
					"redis-mfa-transaction-store": { keyPrefix: "boot:mfat:" },
				}),
				pathResolver: (p: string) => p,
				logger,
				...makeIoredisClients(raw),
			} as never,
		});
		try {
			const components = handle.components as Record<string, { kind: string } | undefined>;
			expect(components.mfaFactorStore?.kind).toBe("redis");
			expect(components.mfaTransactionStore?.kind).toBe("redis");
		} finally {
			await handle.dispose();
		}
	});

	it('are what the memory modules cannot be: the same composition in memory is refused under "multi"', async () => {
		await expect(
			createApp({
				modules: [memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule, mfaStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
				} as never,
			}),
		).rejects.toMatchObject({ name: "BootError", reason: "replica-unsafe-adapter" });
	});

	it.each(CASES)(
		"$module.name on an allkeys-* server is a refused boot naming the module",
		async (c) => {
			const refused = createApp({
				modules: [c.module, mfaStandIn],
				bootstrapComponents: {
					config: multiReplicaConfig(),
					pathResolver: (p: string) => p,
					[c.clientSlot]: stubClient({ ...DURABLE, maxmemoryPolicy: "allkeys-lru" }),
				} as never,
			});
			await expect(refused).rejects.toMatchObject({
				name: "BootError",
				reason: "provides-factory-failed",
				details: { module: c.module.name, componentKey: c.slot },
				cause: { reason: c.evictable, maxmemoryPolicy: "allkeys-lru" },
			});
			await expect(refused).rejects.toThrow(/allkeys-lru/);
		},
	);
});

// ---------------------------------------------------------------------------
// The clients against a real server
// ---------------------------------------------------------------------------

describe.each(CASES)("$clientSlot's durability() against a real server", (c) => {
	it("reads the policy, whether AOF is on and whether snapshots are taken: the test server's defaults", async () => {
		// redis:7.2-alpine with no configuration file: noeviction, no AOF, the
		// default save points.
		expect(await c.client(raw).durability()).toStrictEqual({
			maxmemoryPolicy: "noeviction",
			appendOnly: false,
			snapshots: true,
			refusal: undefined,
		});
	});

	it("reads the policy and AOF from INFO for a user the server refuses CONFIG, and names the refusal", async () => {
		await asUser(["-config"], async (restricted) => {
			const report = await c.client(restricted).durability();
			expect(report).toMatchObject({
				maxmemoryPolicy: "noeviction",
				appendOnly: false,
				snapshots: undefined,
			});
			expect(loggableError(report.refusal)).toMatchObject({ name: "ReplyError" });
		});
	});

	it("falls back to CONFIG GET maxmemory-policy for a user the server refuses INFO", async () => {
		await asUser(["-info"], async (restricted) => {
			const report = await c.client(restricted).durability();
			expect(report).toMatchObject({
				maxmemoryPolicy: "noeviction",
				appendOnly: undefined,
				snapshots: undefined,
			});
			expect(loggableError(report.refusal)).toMatchObject({ name: "ReplyError" });
		});
	});
});

describe.each(CASES)("$clientSlot's durability() against fakes", (c) => {
	/** A connection whose INFO sections and CONFIG values are what `answers` says; each a text, or an error to throw. */
	const fake = (answers: {
		readonly memory?: string | Error;
		readonly persistence?: string | Error;
		readonly policy?: unknown;
		readonly save?: unknown;
	}) => {
		const asked: string[] = [];
		const answer = (value: unknown) =>
			value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
		const io = {
			info: async (section: string) => {
				asked.push(`INFO ${section}`);
				return answer(section === "memory" ? answers.memory : answers.persistence);
			},
			config: async (_get: string, name: string) => {
				asked.push(`CONFIG GET ${name}`);
				return answer(name === "save" ? answers.save : answers.policy);
			},
		} as unknown as Redis;
		return { io, asked };
	};

	it("reads the policy from INFO memory, asking CONFIG nothing about it, and CONFIG GET save only when AOF is off", async () => {
		const withAof = fake({
			memory: "# Memory\r\nmaxmemory_policy:allkeys-lru\r\n",
			persistence: "# Persistence\r\naof_enabled:1\r\n",
		});
		expect(await c.client(withAof.io).durability()).toStrictEqual({
			maxmemoryPolicy: "allkeys-lru",
			appendOnly: true,
			snapshots: undefined,
			refusal: undefined,
		});
		expect(withAof.asked).toEqual(["INFO memory", "INFO persistence"]);
		const withoutAof = fake({
			memory: "# Memory\r\nmaxmemory_policy:noeviction\r\n",
			persistence: "# Persistence\r\naof_enabled:0\r\n",
			save: ["save", ""],
		});
		expect(await c.client(withoutAof.io).durability()).toMatchObject({
			appendOnly: false,
			snapshots: false,
		});
		expect(withoutAof.asked).toEqual(["INFO memory", "INFO persistence", "CONFIG GET save"]);
	});

	it("asks CONFIG GET maxmemory-policy where INFO memory does not say", async () => {
		const { io, asked } = fake({
			memory: "# Memory\r\nused_memory:1\r\n",
			persistence: "# Persistence\r\naof_enabled:1\r\n",
			policy: ["maxmemory-policy", "volatile-lru"],
		});
		expect((await c.client(io).durability()).maxmemoryPolicy).toBe("volatile-lru");
		expect(asked).toContain("CONFIG GET maxmemory-policy");
	});

	it("leaves unread what answers without a value, with no refusal to name", async () => {
		const { io } = fake({
			memory: "# Memory\r\n",
			persistence: "# Persistence\r\naof_enabled:0\r\n",
			policy: [],
			save: [],
		});
		expect(await c.client(io).durability()).toStrictEqual({
			maxmemoryPolicy: undefined,
			appendOnly: false,
			snapshots: undefined,
			refusal: undefined,
		});
	});

	it.each([
		"NOPERM this user has no permissions to run the 'config|get' command",
		"ERR unknown command 'CONFIG', with args beginning with: 'GET' 'maxmemory-policy' ",
		"ERR unknown subcommand 'GET'. Try CONFIG HELP.",
		"ERR CONFIG is disabled",
	])("reads a reply that refuses the question as a part it could not read: %s", async (message) => {
		const refusal = replyError(message);
		const { io } = fake({ memory: refusal, persistence: refusal, policy: refusal });
		const report = await c.client(io).durability();
		expect(report).toMatchObject({ maxmemoryPolicy: undefined, appendOnly: undefined });
		expect(report.refusal).toBe(refusal);
	});

	it.each([
		"BUSY Redis is busy running a script. You can only call SCRIPT KILL or FUNCTION KILL.",
		"NOAUTH Authentication required.",
		"LOADING Redis is loading the dataset in memory",
		"READONLY You can't write against a read only replica.",
		"ERR something else went wrong",
	])(
		"fails on any other reply error, which says the server cannot answer, not that it will not: %s",
		async (message) => {
			const failure = replyError(message);
			const { io } = fake({ memory: failure });
			await expect(c.client(io).durability()).rejects.toBe(failure);
		},
	);
});

/** Runs `use` over a connection as a fresh ACL user with every command but `denied`, and removes the user. */
async function asUser(denied: readonly string[], use: (io: Redis) => Promise<void>): Promise<void> {
	const user = `mfa-durability-${denied.join("").replace(/\W/g, "")}-${Date.now()}-${Math.random()}`;
	await raw.call("ACL", "SETUSER", user, "on", ">secret", "~*", "+@all", ...denied);
	const restricted = new Redis({ ...at, username: user, password: "secret" });
	try {
		await use(restricted);
	} finally {
		restricted.disconnect();
		await raw.call("ACL", "DELUSER", user);
	}
}

describe("allkeys-lru set on the real server", () => {
	/** Runs `use` with the server's policy at allkeys-lru, and puts the policy back. */
	async function underAllkeysLru(use: () => Promise<void>): Promise<void> {
		const [, original] = (await raw.config("GET", "maxmemory-policy")) as [string, string];
		await raw.config("SET", "maxmemory-policy", "allkeys-lru");
		try {
			await use();
		} finally {
			await raw.config("SET", "maxmemory-policy", original);
		}
		expect(await raw.config("GET", "maxmemory-policy")).toEqual(["maxmemory-policy", original]);
	}

	const refusesBoth = async (io: Redis): Promise<void> => {
		for (const c of CASES) {
			await expect(
				providerOf(c)(withSection(c.module, { [c.clientSlot]: c.client(io), config: {} })),
				c.module.name,
			).rejects.toMatchObject({ reason: c.evictable, maxmemoryPolicy: "allkeys-lru" });
		}
	};

	it("refuses both modules at boot, and the policy is put back", async () => {
		await underAllkeysLru(() => refusesBoth(raw));
	});

	it("refuses both modules for a user the server refuses CONFIG: INFO memory says the policy", async () => {
		await underAllkeysLru(() => asUser(["-config"], refusesBoth));
	});

	it("refuses both modules for a user the server refuses INFO: CONFIG GET says the policy", async () => {
		await underAllkeysLru(() => asUser(["-info"], refusesBoth));
	});

	it("boots both modules with the warning that the check could not run for a user refused INFO and CONFIG", async () => {
		await underAllkeysLru(() =>
			asUser(["-info", "-config"], async (restricted) => {
				for (const c of CASES) {
					const { logger, calls } = recordingLogger();
					const store = await providerOf(c)(
						withSection(c.module, { [c.clientSlot]: c.client(restricted), config: {}, logger }),
					);
					expect(store.kind, c.module.name).toBe("redis");
					expect(
						calls.map((call) => call.args[1]),
						c.module.name,
					).toEqual([c.unchecked]);
					expect(calls[0]?.args[0], c.module.name).toMatchObject({
						unread: ["maxmemory-policy", "appendonly"],
					});
				}
			}),
		);
	});
});
