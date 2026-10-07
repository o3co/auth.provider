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
 * The all-modules composition of `all-modules-composition.test.mts` on more
 * than one replica: every shared store on Redis, `deployment.mode = "multi"`,
 * every module the template can turn on switched on together.
 *
 * What it holds: the replica-safety declarations hold with every module on —
 * the all-Redis composition boots with nothing declaring replica-unsafe state,
 * and each store switched back to memory is refused at boot, naming the
 * module — and the Redis adapters change nothing a client can see: the same
 * routes, the same discovery document as on one replica.
 *
 * ioredis, node-redis and connect-redis are stand-ins, as in
 * `replica-safety.test.mts`: what is under test is the composition and the
 * boot's verdict, and nothing here issues a command. The template has no
 * Redis server to run against — `packages/redis` runs its adapters against
 * one.
 */

import { type Module, replicaUnsafeReason } from "@o3co/auth-provider-core";
import * as redisPackage from "@o3co/auth-provider-redis";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { standaloneRedisClientsModule } from "#/modules.mjs";
import {
	type Composition,
	compose,
	composedModules,
	MULTI_ENV,
	resolveConfig,
} from "./all-modules-composition.fixture.mjs";

vi.mock("redis", () => ({
	createClient: vi.fn(() => ({
		connect: vi.fn().mockResolvedValue(undefined),
		quit: vi.fn().mockResolvedValue(undefined),
		ping: vi.fn().mockResolvedValue("PONG"),
		on: vi.fn(),
	})),
}));

vi.mock("connect-redis", async () => {
	const { EventEmitter } = await import("node:events");
	// express-session subscribes to store events, so the stand-in is an emitter.
	return {
		RedisStore: class MockRedisStore extends EventEmitter {
			constructor(_opts: { client: unknown }) {
				super();
			}
			get(): unknown {
				return undefined;
			}
			set(): void {}
			destroy(): void {}
		},
	};
});

vi.mock("ioredis", () => {
	// Constructible, quits cleanly, answers the readiness probe's `ping`;
	// every other command resolves to nothing.
	const explicit: Record<string, unknown> = {
		on: () => undefined,
		quit: async () => "OK",
		disconnect: () => undefined,
		ping: async () => "PONG",
	};
	const makeMockRedis = (): object =>
		new Proxy(
			{},
			{
				get(_target, prop) {
					// A function-valued `then` would make the instance a thenable.
					if (typeof prop !== "string" || prop === "then") return undefined;
					if (prop === "duplicate") return makeMockRedis;
					if (prop in explicit) return explicit[prop];
					return async () => null;
				},
			},
		);
	function MockRedis(): object {
		return makeMockRedis();
	}
	return { Redis: MockRedis, default: MockRedis };
});

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

const MULTI = { env: MULTI_ENV, shippedRefreshTokenFamilyStore: true } as const;

/** What `buildModules` lists with every switch on and every shared store on Redis. */
const ALL_ON_REDIS_MODULES = [
	"sessionStoreModule",
	"federation-grant-background",
	"federation-grants",
	"oauth",
	"oauth-session",
	"oauth-authorization",
	"jwks",
	"session",
	"federation:google",
	"standalone:google-federation-config",
	"standalone:oidc-federation-config",
	"federation:oidc:oidc",
	"standalone:key-store",
	"test:repositories",
	"standalone:audit-sink",
	"standalone:redis-clients",
	"redis-federation-token-store",
	"redis-federation-grant-store",
	"redis-federation-grant-intent-store",
	"redisSessionStores",
	"redis-rate-limiter",
	"redis-code-repository",
	"redis-access-token-denylist",
	"redis-replay-seen-set",
	"redis-consent-store",
	"redis-refresh-token-family-store",
	"core-default-refresh-token-family-rotation",
	"core-default-refresh-token-family-revocation",
	"subject-revocation-service",
];

describe('every module on, every shared store on Redis, deployment.mode = "multi"', () => {
	it("lists every module, none declaring replica-unsafe state, and boots", async () => {
		const modules = composedModules(resolveConfig(MULTI_ENV), MULTI);
		expect(modules.map((m) => m.name)).toEqual(ALL_ON_REDIS_MODULES);
		for (const module of modules) expect(replicaUnsafeReason(module), module.name).toBeUndefined();
		current = await compose(MULTI);
		expect(current.handle.readinessProbes.map((p) => p.name)).toContain("redis");
	});

	it("mounts the same routes and serves the same discovery document as one replica on memory", async () => {
		current = await compose();
		const single = {
			routes: current.handle.routes.map((r) => r.contribution.id),
			discovery: (await request(current.app).get("/.well-known/openid-configuration")).body,
		};
		await current.handle.dispose();
		current = undefined;

		current = await compose(MULTI);
		expect(current.handle.routes.map((r) => r.contribution.id)).toEqual(single.routes);
		const discovery = await request(current.app).get("/.well-known/openid-configuration");
		expect(discovery.status).toBe(200);
		expect(discovery.body).toEqual(single.discovery);
	});

	/**
	 * Each store's switch back to memory, alone, with every module on. The
	 * boot names the module that declared the state it would fork.
	 */
	const MEMORY_SWITCHES: ReadonlyArray<readonly [variable: string, module: string]> = [
		["SESSION_STORAGE_TYPE", "sessionStoreModule"],
		["USER_SESSION_STORES_ADAPTER", "standalone:in-memory-session-stores"],
		["OAUTH_CODE_ADAPTER", "standalone:in-memory-code-repository"],
		["FEDERATION_TOKEN_STORE_TYPE", "standalone:in-memory-federation-token-store"],
		["RATE_LIMITER_ADAPTER", "core-rate-limiter-memory"],
		["ACCESS_TOKEN_DENYLIST_ADAPTER", "core-access-token-denylist-memory"],
		["REPLAY_SEEN_SET_ADAPTER", "core-replay-seen-set-memory"],
		["CONSENT_STORE_ADAPTER", "core-consent-store-memory"],
		["FEDERATION_GRANT_STORE_ADAPTER", "core-federation-grant-store-memory"],
		["FEDERATION_GRANT_INTENT_STORE_ADAPTER", "core-federation-grant-intent-store-memory"],
	];

	it.each(MEMORY_SWITCHES)("%s=memory is refused at boot, naming %s", async (variable, module) => {
		await expect(
			compose({ ...MULTI, env: { ...MULTI_ENV, [variable]: "memory" } }),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "replica-unsafe-adapter",
			details: { modules: [module] },
		});
	});

	it("names every memory store together when every switch is memory", async () => {
		const env = { ...MULTI_ENV };
		for (const [variable] of MEMORY_SWITCHES) env[variable] = "memory";
		await expect(compose({ ...MULTI, env })).rejects.toMatchObject({
			reason: "replica-unsafe-adapter",
			details: {
				modules: expect.arrayContaining(MEMORY_SWITCHES.map(([, module]) => module)),
			},
		});
	});
});

describe("the shared Redis socket can back every store the Redis package ships", () => {
	/**
	 * Every store module `@o3co/auth-provider-redis` exports, the two built per
	 * composition root included. This template composes some; a deployment adds
	 * the others to the manifest with the modules that read them (the device
	 * grant's code store, WebAuthn's challenge store), and each requires its
	 * client from this module. One it does not provide is a boot refused with
	 * `missing-required-component` — the #439 shape, which `modules.mts`
	 * guards against for the device-code store by name.
	 */
	const storeModules: Module[] = Object.entries(redisPackage).flatMap(([name, value]) => {
		if (name.endsWith("ModuleFor") && typeof value === "function") {
			return [(value as (options: object) => Module)({})];
		}
		if (name.endsWith("Module") && typeof value === "object" && value !== null) {
			return [value as Module];
		}
		return [];
	});

	it.each(storeModules.map((m) => [m.name, m] as const))(
		"%s: its client slot is provided by standalone:redis-clients",
		(_name, module) => {
			const provided = Object.keys(standaloneRedisClientsModule.provides ?? {});
			const clients = (module.requires ?? []).filter((slot) => String(slot).endsWith("Client"));
			expect(clients.length).toBeGreaterThan(0);
			for (const slot of clients) expect(provided, slot).toContain(slot);
		},
	);

	it("finds the store modules to check", () => {
		expect(storeModules.length).toBeGreaterThanOrEqual(12);
	});
});
