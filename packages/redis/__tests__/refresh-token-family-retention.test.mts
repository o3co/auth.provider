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
 * A revoked family's Redis key lives until the last access token the family
 * could have minted stops being accepted — not until the family's own expiry.
 *
 * The key's TTL is `PX` = the family's `expiresAtMs` − now, and revocation
 * used to keep `expiresAtMs`: Redis dropped a revoked family when its refresh
 * tokens expired, and an access token minted late in the family's life passed
 * the family check again for the rest of its life. A family whose key had
 * already expired recorded no revocation at all. Composed the way the
 * standalone does — the Redis store module under core's default rotation and
 * revocation, whose horizon comes from `oauth.accessToken.maxExpiresIn` —
 * against a real Redis.
 */

import {
	type BootstrapMap,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
	type RefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRotation,
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
		.withStartupTimeout(60_000)
		.start();
	client = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	await client?.quit();
	await container?.stop();
});

/** Two hours: the longest access token this composition can mint. */
const MAX_ACCESS_TOKEN_SECONDS = 7200;
/** The verifier's five-minute tolerance, the replica allowance and a second of rounding. */
const ALLOWANCE_MS = 300_000 + 1_000 + 1_000;

async function boot(keyPrefix: string) {
	const base = makeValidCoreConfig();
	const config = {
		...base,
		oauth: {
			...base.oauth,
			accessToken: { defaultExpiresIn: 3600, maxExpiresIn: MAX_ACCESS_TOKEN_SECONDS },
		},
		redisRefreshTokenFamilyStore: { keyPrefix, casRetryLimit: 3 },
	};
	const handle = await createApp({
		modules: [
			redisRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRotationModule,
			defaultRefreshTokenFamilyRevocationModule,
			defineModule({
				name: "test-activator",
				requires: ["refreshTokenFamilyRotation", "refreshTokenFamilyRevocation"] as const,
				contributes: {
					routes: [
						{
							mountPath: "/__test_noop__",
							id: "test-noop",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						},
					],
				},
			}),
		],
		bootstrapComponents: {
			config: config as never,
			pathResolver: (s: string) => s,
			...makeIoredisClients(client),
		} satisfies Record<string, unknown> as BootstrapMap,
	});
	return {
		handle,
		rotation: handle.components.refreshTokenFamilyRotation as RefreshTokenFamilyRotation,
		revocation: handle.components.refreshTokenFamilyRevocation as RefreshTokenFamilyRevocation,
	};
}

/** Within a few seconds of `expectedMs` — the round trips between write and read. */
const expectTtlNear = (pttl: number, expectedMs: number): void => {
	expect(pttl).toBeGreaterThan(expectedMs - 5_000);
	expect(pttl).toBeLessThanOrEqual(expectedMs);
};

describe("a revoked family on Redis is kept for the access-token horizon", () => {
	it("extends a family ten seconds from its end to the horizon when it is revoked", async () => {
		const keyPrefix = `rtfam:retention-${Date.now()}:`;
		const { handle, rotation, revocation } = await boot(keyPrefix);
		try {
			await rotation.register("jti-1", "fam-late", Date.now() + 10_000);
			await revocation.revokeFamily("fam-late");
			expect(await revocation.isFamilyRevoked("fam-late")).toBe(true);
			expectTtlNear(
				await client.pttl(`${keyPrefix}fam-late`),
				MAX_ACCESS_TOKEN_SECONDS * 1000 + ALLOWANCE_MS,
			);
		} finally {
			await handle.dispose();
		}
	});

	it("keeps the family's own expiry when that is the later one", async () => {
		const keyPrefix = `rtfam:retention-long-${Date.now()}:`;
		const { handle, rotation, revocation } = await boot(keyPrefix);
		try {
			await rotation.register("jti-1", "fam-young", Date.now() + 86_400_000);
			await revocation.revokeFamily("fam-young");
			expectTtlNear(await client.pttl(`${keyPrefix}fam-young`), 86_400_000 + ALLOWANCE_MS);
		} finally {
			await handle.dispose();
		}
	});

	it("records a family revoked after its key expired", async () => {
		const keyPrefix = `rtfam:retention-gone-${Date.now()}:`;
		const { handle, revocation } = await boot(keyPrefix);
		try {
			await revocation.revokeFamily("fam-gone");
			expect(await revocation.isFamilyRevoked("fam-gone")).toBe(true);
			expect(JSON.parse((await client.get(`${keyPrefix}fam-gone`)) ?? "null")).toMatchObject({
				familyId: "fam-gone",
				revoked: true,
			});
			expectTtlNear(
				await client.pttl(`${keyPrefix}fam-gone`),
				MAX_ACCESS_TOKEN_SECONDS * 1000 + ALLOWANCE_MS,
			);
		} finally {
			await handle.dispose();
		}
	});

	it("keeps a family revoked on replay for the horizon too", async () => {
		const keyPrefix = `rtfam:retention-replay-${Date.now()}:`;
		const { handle, rotation, revocation } = await boot(keyPrefix);
		try {
			const ends = Date.now() + 10_000;
			await rotation.register("jti-1", "fam-replayed", ends);
			await rotation.rotate("jti-1", "jti-2", "fam-replayed", ends);
			expect(await rotation.rotate("jti-1", "jti-evil", "fam-replayed", ends)).toMatchObject({
				outcome: "replayed",
				familyRevoked: true,
			});
			expect(await revocation.isFamilyRevoked("fam-replayed")).toBe(true);
			expectTtlNear(
				await client.pttl(`${keyPrefix}fam-replayed`),
				MAX_ACCESS_TOKEN_SECONDS * 1000 + ALLOWANCE_MS,
			);
		} finally {
			await handle.dispose();
		}
	});
});
