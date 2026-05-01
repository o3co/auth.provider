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

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/index.mjs";
import { createRedisSessionRPRegistry } from "../src/sessionRPRegistry.mjs";
import { runSessionRPRegistryContract } from "./sessionRPRegistry.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

let suiteCounter = 0;
runSessionRPRegistryContract(async () => {
	suiteCounter += 1;
	const { sessionRPRegistryClient } = makeIoredisClients(raw);
	return createRedisSessionRPRegistry({
		client: sessionRPRegistryClient,
		keyPrefix: `t15:${suiteCounter}:`,
	});
});

// ---------------------------------------------------------------------------
// Concurrency cases
// ---------------------------------------------------------------------------

describe("SessionRPRegistry concurrency", () => {
	it("100 parallel registerRP for the same clientId → 1 entry (HSET dedup)", async () => {
		const { sessionRPRegistryClient } = makeIoredisClients(raw);
		const reg = createRedisSessionRPRegistry({
			client: sessionRPRegistryClient,
			keyPrefix: "t15:conc1:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, (_, i) =>
				reg.registerRP(
					"sid-conc",
					{
						clientId: "client-dedup",
						backchannelLogoutUri: `https://rp.example/logout?i=${i}`,
						backchannelLogoutSessionRequired: false,
						frontchannelLogoutUri: undefined,
						frontchannelLogoutSessionRequired: undefined,
						registeredAt: new Date(),
					},
					expiresAt,
				),
			),
		);
		const list = await reg.listRPs("sid-conc");
		expect(list).toHaveLength(1);
		expect(list[0]?.clientId).toBe("client-dedup");
		// registeredAt must be a valid Date
		expect(list[0]?.registeredAt).toBeInstanceOf(Date);
		expect(Number.isFinite(list[0]?.registeredAt.getTime())).toBe(true);
	});

	it("100 parallel registerRP for distinct clientIds → all 100 land", async () => {
		const { sessionRPRegistryClient } = makeIoredisClients(raw);
		const reg = createRedisSessionRPRegistry({
			client: sessionRPRegistryClient,
			keyPrefix: "t15:conc2:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, (_, i) =>
				reg.registerRP(
					"sid-all",
					{
						clientId: `client-${i}`,
						backchannelLogoutUri: `https://rp-${i}.example/logout`,
						backchannelLogoutSessionRequired: false,
						frontchannelLogoutUri: undefined,
						frontchannelLogoutSessionRequired: undefined,
						registeredAt: new Date(),
					},
					expiresAt,
				),
			),
		);
		const list = await reg.listRPs("sid-all");
		expect(list).toHaveLength(100);
		const ids = new Set(list.map((r) => r.clientId));
		expect(ids.size).toBe(100);
		for (let i = 0; i < 100; i++) {
			expect(ids.has(`client-${i}`)).toBe(true);
		}
	});
});
