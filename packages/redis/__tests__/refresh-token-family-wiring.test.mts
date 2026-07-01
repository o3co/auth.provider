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
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redisRefreshTokenFamilyStoreModule } from "../src/index.mjs";
import { makeIoredisClients } from "../src/ioredis.mjs";

let container: StartedTestContainer;
let client: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(120_000)
		.start();
	client = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 30_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

describe("A3 wiring — full Redis composition (createApp + redis modules)", () => {
	it("composes per-purpose clients + redis store + default rotation + default revocation against real Redis", async () => {
		// Activator (same pattern as Phase 5 + Task 10): force materialisation of
		// the wrapper slots via a closure root that requires them.
		const activatorModule = defineModule({
			name: "test-activator",
			requires: [
				"refreshTokenFamilyStore",
				"refreshTokenFamilyRotation",
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
			...makeValidCoreConfig(),
			redisRefreshTokenFamilyStore: {
				keyPrefix: `rtfam:wiring-${Date.now()}:`,
				casRetryLimit: 3,
			},
		};
		const boot = {
			config: config as never,
			pathResolver: (s: string) => s,
			// Per-purpose client slots — refreshTokenFamilyClient is consumed by
			// redisRefreshTokenFamilyStoreModule (requires: ["refreshTokenFamilyClient", "config"]).
			...makeIoredisClients(client),
		} satisfies Record<string, unknown> as BootstrapMap;

		const handle = await createApp({
			modules: [
				redisRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				activatorModule,
			],
			bootstrapComponents: boot,
		});

		try {
			const rotation = (handle.components as { refreshTokenFamilyRotation?: unknown })
				.refreshTokenFamilyRotation as unknown as {
				register(j: string, f: string, e: number): Promise<void>;
				rotate(p: string, n: string, f: string, e: number): Promise<{ outcome: string }>;
			};
			const revocation = (handle.components as { refreshTokenFamilyRevocation?: unknown })
				.refreshTokenFamilyRevocation as unknown as {
				revokeFamily(f: string): Promise<void>;
				isFamilyRevoked(f: string): Promise<boolean>;
			};

			const familyId = `fam-wiring-${Date.now()}`;
			const expMs = Date.now() + 60_000;

			// 1. unknown_family probe before register
			const unknown = await rotation.rotate("any", "any", familyId, expMs);
			expect(unknown.outcome).toBe("unknown_family");

			// 2. register + first rotate
			await rotation.register("jti-1", familyId, expMs);
			const rotated = await rotation.rotate("jti-1", "jti-2", familyId, expMs);
			expect(rotated.outcome).toBe("rotated");

			// 3. replay attempt with stale previousJti
			const replayed = await rotation.rotate("jti-1", "jti-3", familyId, expMs);
			expect(replayed.outcome).toBe("replayed");

			// 4. revoke + try to rotate
			await revocation.revokeFamily(familyId);
			expect(await revocation.isFamilyRevoked(familyId)).toBe(true);
			const revoked = await rotation.rotate("jti-2", "jti-4", familyId, expMs);
			expect(revoked.outcome).toBe("revoked");
		} finally {
			await handle.dispose();
		}
	});
});
