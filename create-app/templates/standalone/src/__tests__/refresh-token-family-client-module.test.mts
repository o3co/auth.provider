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
import type { LifecycleRegistrar } from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// D-2 v2: ioredis Redis constructor capture. The module under test imports
// `Redis` from "ioredis"; vi.mock replaces that import so the test never
// opens a real socket. Captured arguments verify that the validated config
// reaches the constructor (BLOCKER 1: schema strip closure).
const redisCtorCalls: Array<{ url: string; options: Record<string, unknown> | undefined }> = [];
const quitSpies: Array<ReturnType<typeof vi.fn>> = [];
const onSpies: Array<ReturnType<typeof vi.fn>> = [];

vi.mock("ioredis", () => {
	class MockRedis {
		duplicate(): MockRedis {
			return new MockRedis("redis://duplicate.local");
		}
		on = vi.fn();
		quit = vi.fn(async () => "OK" as const);
		// Minimal command surface — `makeIoredisClients` only invokes these
		// during construction in some paths; tests never exercise the wrapped
		// client itself, so most stubs are unused.
		set = vi.fn();
		get = vi.fn();
		pttl = vi.fn();
		watch = vi.fn();
		unwatch = vi.fn();
		multi = vi.fn(() => ({
			set: vi.fn().mockReturnThis(),
			exec: vi.fn(async () => []),
		}));

		constructor(url: string, options?: Record<string, unknown>) {
			redisCtorCalls.push({ url, options });
			onSpies.push(this.on);
			quitSpies.push(this.quit);
		}
	}
	return { Redis: MockRedis, default: MockRedis };
});

// Imported AFTER vi.mock so the mocked ioredis is in scope.
const importModule = async () =>
	(await import("../modules.mjs")) as typeof import("../modules.mjs") & {
		standaloneRedisClientsModule: import("@o3co/auth-provider-core").Module;
	};

// D-1 / D-5 are already merged on develop, so importing `standaloneRedisClientsModule`
// from `../modules.mjs` is the natural integration point. Pre-fix the export does not
// exist — TS error → RED.

const baseConfig = {
	refreshTokenFamilyStore: {
		redis: { url: "redis://example.com:6379", password: "test-pw" },
	},
};

describe("D-2 / standaloneRedisClientsModule", () => {
	beforeEach(() => {
		redisCtorCalls.length = 0;
		quitSpies.length = 0;
		onSpies.length = 0;
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("passes operator-supplied Redis URL + password from config to the ioredis constructor (BLOCKER 1 closure)", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;
		await provides.refreshTokenFamilyClient({ config: { ...baseConfig } });

		expect(redisCtorCalls).toHaveLength(1);
		expect(redisCtorCalls[0]?.url).toBe("redis://example.com:6379");
		expect(redisCtorCalls[0]?.options?.password).toBe("test-pw");
	});

	it("registers io.quit() with lifecycleRegistrar when provided; drain calls quit exactly once", async () => {
		const registered: Array<() => Promise<void>> = [];
		const lifecycleRegistrar: LifecycleRegistrar = {
			register: (cleanup) => {
				registered.push(cleanup);
			},
		};

		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;
		await provides.refreshTokenFamilyClient({ config: { ...baseConfig }, lifecycleRegistrar });

		expect(registered).toHaveLength(1);
		// Pre-drain: quit not yet called.
		expect(quitSpies[0]).not.toHaveBeenCalled();

		// Drain (simulate handle.dispose()).
		await registered[0]?.();
		expect(quitSpies[0]).toHaveBeenCalledTimes(1);
	});

	it("does not crash when lifecycleRegistrar is absent (graceful no-op, no quit registered)", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;

		// No lifecycleRegistrar key in deps — must not throw and must NOT
		// register a cleanup (verified by the absence of any quit invocation
		// after the factory resolves; the registrar branch is the only place
		// `quit()` would be wired up in the no-real-shutdown unit-test path).
		await expect(
			provides.refreshTokenFamilyClient({ config: { ...baseConfig } }),
		).resolves.toBeDefined();
		expect(quitSpies[0]).not.toHaveBeenCalled();
	});

	it("fails fast when refreshTokenFamilyStore.redis.url is missing (no silent localhost fallback)", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;

		// Operator deliberately removed the section — must throw instead of
		// silently falling back to redis://localhost:6379 (which would re-
		// introduce the OR-1 multi-replica failure mode in production).
		await expect(provides.refreshTokenFamilyClient({ config: {} })).rejects.toThrow(
			/refreshTokenFamilyStore\.redis\.url/,
		);
		// And no ioredis instance was constructed because we threw before
		// `new Redis(...)`.
		expect(redisCtorCalls).toHaveLength(0);
	});

	it("attaches an error event handler to the ioredis client (prevents unhandled-error crash)", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const provides = (
			standaloneRedisClientsModule as unknown as {
				provides: Record<string, (deps: Record<string, unknown>) => Promise<unknown>>;
			}
		).provides;
		await provides.refreshTokenFamilyClient({ config: { ...baseConfig } });

		expect(onSpies[0]).toHaveBeenCalledWith("error", expect.any(Function));
	});

	it("declares 'config' as required and 'lifecycleRegistrar' as optional", async () => {
		const { standaloneRedisClientsModule } = await importModule();
		const m = standaloneRedisClientsModule as {
			requires?: readonly string[];
			optional?: readonly string[];
		};
		expect(m.requires).toContain("config");
		expect(m.optional).toContain("lifecycleRegistrar");
	});
});
