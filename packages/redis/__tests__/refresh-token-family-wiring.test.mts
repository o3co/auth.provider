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
import {
	type BootstrapMap,
	createBootApp,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenRotationModule,
	defineModule,
} from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisRefreshTokenFamilyStoreModule } from "../src/index.mjs";
import type { DisposableRedisClient, RedisClient, RedisMulti } from "../src/types.mjs";

let container: StartedTestContainer;
let client: Redis;

/**
 * Adapt a raw ioredis Redis instance to the structural RedisClient + provide
 * `duplicate()` returning a DisposableRedisClient (Symbol.asyncDispose calls
 * the duplicated ioredis instance's quit()). The base client itself is NOT
 * disposable — only duplicates owned by `updateFamily` need lifetime
 * management.
 *
 * Inlined from refresh-token-family.test.mts (acceptable test-code
 * duplication; sharing via a shared test helper is a follow-up).
 */
const adapt = (raw: Redis): RedisClient => ({
	set: (key, value, mode, ttlMs, condition) => raw.set(key, value, mode, ttlMs, condition),
	del: (key) => raw.del(key),
	pttl: (key) => raw.pttl(key),
	exists: (key) => raw.exists(key),
	get: (key) => raw.get(key),
	watch: (...keys) => raw.watch(...keys),
	unwatch: () => raw.unwatch(),
	multi: () => {
		const m = raw.multi();
		const facade: RedisMulti = {
			set: (key, value, mode, ttlMs) => {
				m.set(key, value, mode, ttlMs);
				return facade;
			},
			exec: async () => {
				const result = await m.exec();
				return result;
			},
		};
		return facade;
	},
	duplicate: (): DisposableRedisClient => {
		const dup = raw.duplicate();
		const wrapped = adapt(dup);
		return Object.assign(wrapped, {
			[Symbol.asyncDispose]: async () => {
				await dup.quit();
			},
		});
	},
});

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 30_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

describe("A3 wiring — full Redis composition (createBootApp + redis modules)", () => {
	it("composes redisClient + redis store + default rotation + default revocation against real Redis", async () => {
		const myRedisClientModule = defineModule({
			name: "test-redis-client",
			provides: {
				redisClient: () => adapt(client),
			},
		});

		// Activator (same pattern as Phase 5 + Task 10): force materialisation of
		// the wrapper slots via a closure root that requires them.
		const activatorModule = defineModule({
			name: "test-activator",
			requires: [
				"refreshTokenFamilyStore",
				"refreshTokenRotation",
				"refreshTokenFamilyRevocation",
			] as const,
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

		const config = {
			http: {},
			oauth: { jwt: {}, accessToken: {}, refreshToken: {}, grants: {} },
			redisRefreshTokenFamilyStore: {
				keyPrefix: `rtfam:wiring-${Date.now()}:`,
				casRetryLimit: 3,
			},
		};
		const boot = {
			config: config as never,
			pathResolver: (s: string) => s,
		} satisfies Record<string, unknown> as BootstrapMap;

		const handle = await createBootApp({
			modules: [
				myRedisClientModule,
				redisRefreshTokenFamilyStoreModule,
				defaultRefreshTokenRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				activatorModule,
			],
			bootstrapComponents: boot,
		});

		try {
			const rotation = (handle.components as { refreshTokenRotation?: unknown })
				.refreshTokenRotation as unknown as {
				register(j: string, f: string, e: Date): Promise<void>;
				rotate(p: string, n: string, f: string, e: Date): Promise<{ outcome: string }>;
			};
			const revocation = (handle.components as { refreshTokenFamilyRevocation?: unknown })
				.refreshTokenFamilyRevocation as unknown as {
				revokeFamily(f: string): Promise<void>;
				isFamilyRevoked(f: string): Promise<boolean>;
			};

			const familyId = `fam-wiring-${Date.now()}`;
			const exp = new Date(Date.now() + 60_000);

			// 1. unknown_family probe before register
			const unknown = await rotation.rotate("any", "any", familyId, exp);
			expect(unknown.outcome).toBe("unknown_family");

			// 2. register + first rotate
			await rotation.register("jti-1", familyId, exp);
			const rotated = await rotation.rotate("jti-1", "jti-2", familyId, exp);
			expect(rotated.outcome).toBe("rotated");

			// 3. replay attempt with stale previousJti
			const replayed = await rotation.rotate("jti-1", "jti-3", familyId, exp);
			expect(replayed.outcome).toBe("replayed");

			// 4. revoke + try to rotate
			await revocation.revokeFamily(familyId);
			expect(await revocation.isFamilyRevoked(familyId)).toBe(true);
			const revoked = await rotation.rotate("jti-2", "jti-4", familyId, exp);
			expect(revoked.outcome).toBe("revoked");
		} finally {
			await handle.dispose();
		}
	});
});
