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
 * durability check both run at boot.
 *
 * "Only zero records open a first binding" (F3) is only as strong as the
 * store that holds the records, and the email-proof requirement an operator
 * reset records is only as strong as the transaction store (D12's step-3
 * amendment). So each module reads the server's `maxmemory-policy` and
 * persistence before it provides its store: an `allkeys-*` policy, which may
 * evict any key, refuses the boot; RDB snapshots without AOF, and no
 * persistence at all, are each one warning; a server that refuses `CONFIG`
 * is one warning that the check could not run.
 *
 * The check's verdicts are pinned against a stub client; the client's reading
 * of a real server, a user the server refuses `CONFIG`, and `allkeys-lru` set
 * on the server, against the shared container. Every real-server case that
 * reads or sets the eviction policy is in this file alone, so no other file
 * sees the policy this one sets for a moment.
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
	readonly configKey: "redisMfaFactorStore" | "redisMfaTransactionStore";
	readonly defaultPrefix: string;
	readonly evictable: string;
	readonly lossy: string;
	readonly volatile: string;
	readonly unchecked: string;
	readonly memoryModule: Module;
	readonly client: (io: Redis) => { durability(): Promise<RedisDurability> };
}

const CASES: readonly Case[] = [
	{
		module: redisMfaFactorStoreModule,
		slot: "mfaFactorStore",
		clientSlot: "mfaFactorStoreClient",
		configKey: "redisMfaFactorStore",
		defaultPrefix: "mfaf:",
		evictable: "mfa-factor-store-evictable",
		lossy: "mfa_factor_store_lossy",
		volatile: "mfa_factor_store_volatile",
		unchecked: "mfa_factor_store_durability_unchecked",
		memoryModule: memoryMfaFactorStoreModule,
		client: makeIoredisMfaFactorStoreClient,
	},
	{
		module: redisMfaTransactionStoreModule,
		slot: "mfaTransactionStore",
		clientSlot: "mfaTransactionStoreClient",
		configKey: "redisMfaTransactionStore",
		defaultPrefix: "mfat:",
		evictable: "mfa-transaction-store-evictable",
		lossy: "mfa_transaction_store_lossy",
		volatile: "mfa_transaction_store_volatile",
		unchecked: "mfa_transaction_store_durability_unchecked",
		memoryModule: memoryMfaTransactionStoreModule,
		client: makeIoredisMfaTransactionStoreClient,
	},
];

const DURABLE: RedisDurability = {
	checked: true,
	maxmemoryPolicy: "noeviction",
	appendOnly: true,
	snapshots: true,
};

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
	const provide = (deps: Record<string, unknown>) => providerOf(c)(deps);

	const boot = (report: RedisDurability | (() => Promise<RedisDurability>), logger?: Logger) =>
		provide({
			[c.clientSlot]: stubClient(report),
			config: {},
			...(logger === undefined ? {} : { logger }),
		});

	it("needs its client and the configuration, reads the logger if there is one, and fills one slot", () => {
		expect(c.module.requires).toStrictEqual([c.clientSlot, "config"]);
		expect(c.module.optional).toStrictEqual(["logger"]);
		expect(Object.keys(c.module.provides ?? {})).toStrictEqual([c.slot]);
	});

	it(`reads ${c.configKey}.keyPrefix, "${c.defaultPrefix}" when it is not set`, () => {
		expect(c.module.configSchema?.parse({})).toStrictEqual({
			[c.configKey]: { keyPrefix: c.defaultPrefix },
		});
		expect(
			c.module.configSchema?.parse({ [c.configKey]: { keyPrefix: "tenant-a:" } }),
		).toStrictEqual({ [c.configKey]: { keyPrefix: "tenant-a:" } });
	});

	it("declares nothing the replica-safety guard refuses (D10), where the memory module does", () => {
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
		"refuses %s at boot: a policy that may evict any key, naming the policy (D12)",
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

	it.each(["noeviction", "volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl"])(
		"boots on %s with AOF, and says nothing",
		async (policy) => {
			const { logger, calls } = recordingLogger();
			expect((await boot({ ...DURABLE, maxmemoryPolicy: policy }, logger)).kind).toBe("redis");
			expect(calls).toEqual([]);
		},
	);

	it("warns once when RDB snapshots are the only persistence: the last interval is lost on a crash", async () => {
		const { logger, calls } = recordingLogger();
		expect((await boot({ ...DURABLE, appendOnly: false }, logger)).kind).toBe("redis");
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

	it("warns once that the check could not run when the server refuses CONFIG, and boots", async () => {
		const refusal = Object.assign(new Error("ERR unknown command 'CONFIG'"), {
			name: "ReplyError",
		});
		const { logger, calls } = recordingLogger();
		expect((await boot({ checked: false, refusal }, logger)).kind).toBe("redis");
		expect(calls).toEqual([
			{
				level: "warn",
				args: [{ store: c.slot, adapter: "redis", err: loggableError(refusal) }, c.unchecked],
			},
		]);
	});

	it("fails the boot when the server cannot be asked at all: an outage is not a refusal", async () => {
		const outage = new Error("Connection is closed.");
		await expect(boot(() => Promise.reject(outage))).rejects.toBe(outage);
	});

	it("writes its line on consoleLogger when no logger slot is filled", async () => {
		const warn = vi.spyOn(consoleLogger, "warn").mockImplementation(() => undefined);
		await boot({ ...DURABLE, appendOnly: false });
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
		deployment: { mode: "multi" },
		...extra,
	}) as never;

describe("the MFA store modules booted through createApp", () => {
	it('boot under deployment.mode = "multi" off the shared clients and fill both slots with the Redis adapters', async () => {
		const { logger } = recordingLogger();
		const handle = await createApp({
			modules: [redisMfaFactorStoreModule, redisMfaTransactionStoreModule, mfaStandIn],
			bootstrapComponents: {
				config: multiReplicaConfig({
					redisMfaFactorStore: { keyPrefix: "boot:mfaf:" },
					redisMfaTransactionStore: { keyPrefix: "boot:mfat:" },
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
			checked: true,
			maxmemoryPolicy: "noeviction",
			appendOnly: false,
			snapshots: true,
		});
	});

	it("answers a check that could not run for a user the server refuses CONFIG, with the refusal", async () => {
		const user = `mfa-durability-${c.slot}-${Date.now()}`;
		await raw.call("ACL", "SETUSER", user, "on", ">secret", "~*", "+@all", "-config");
		const restricted = new Redis({ ...at, username: user, password: "secret" });
		try {
			const report = await c.client(restricted).durability();
			expect(report.checked).toBe(false);
			if (report.checked) return;
			expect(loggableError(report.refusal)).toMatchObject({ name: "ReplyError" });
		} finally {
			restricted.disconnect();
			await raw.call("ACL", "DELUSER", user);
		}
	});

	it("answers a check that could not run when CONFIG GET answers no value", async () => {
		const silent = {
			config: async () => [],
			info: async () => "# Persistence\r\naof_enabled:0\r\n",
		} as unknown as Redis;
		expect((await c.client(silent).durability()).checked).toBe(false);
	});
});

describe("allkeys-lru set on the real server", () => {
	it("refuses both modules at boot, and the policy is put back", async () => {
		const [, original] = (await raw.config("GET", "maxmemory-policy")) as [string, string];
		await raw.config("SET", "maxmemory-policy", "allkeys-lru");
		try {
			for (const c of CASES) {
				await expect(
					providerOf(c)({ [c.clientSlot]: c.client(raw), config: {} }),
					c.module.name,
				).rejects.toMatchObject({ reason: c.evictable, maxmemoryPolicy: "allkeys-lru" });
			}
		} finally {
			await raw.config("SET", "maxmemory-policy", original);
		}
		expect(await raw.config("GET", "maxmemory-policy")).toEqual(["maxmemory-policy", original]);
	});
});
