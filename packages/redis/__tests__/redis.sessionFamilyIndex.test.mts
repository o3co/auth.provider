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
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisSessionFamilyIndex } from "../src/sessionFamilyIndex.mjs";
import { runSessionFamilyIndexContract } from "./sessionFamilyIndex.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

let suiteCounter = 0;
runSessionFamilyIndexContract(async () => {
	suiteCounter += 1;
	const { sessionFamilyIndexClient } = makeIoredisClients(raw);
	return createRedisSessionFamilyIndex({
		client: sessionFamilyIndexClient,
		keyPrefix: `t16:${suiteCounter}:`,
	});
});

// ---------------------------------------------------------------------------
// Concurrency cases
// ---------------------------------------------------------------------------

describe("SessionFamilyIndex concurrency", () => {
	it("100 parallel distinct familyIds → all 100 land", async () => {
		const { sessionFamilyIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFamilyIndex({
			client: sessionFamilyIndexClient,
			keyPrefix: "t16:conc1:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, (_, i) => idx.addFamilyId("sid-conc", `fam-${i}`, expiresAt)),
		);
		const list = await idx.listFamilyIds("sid-conc");
		expect(list).toHaveLength(100);
		const ids = new Set(list);
		expect(ids.size).toBe(100);
		for (let i = 0; i < 100; i++) {
			expect(ids.has(`fam-${i}`)).toBe(true);
		}
	});

	it("100 parallel same familyId → 1 entry (ZADD NX dedup)", async () => {
		const { sessionFamilyIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFamilyIndex({
			client: sessionFamilyIndexClient,
			keyPrefix: "t16:conc2:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, () => idx.addFamilyId("sid-dedup", "fam-dedup", expiresAt)),
		);
		const list = await idx.listFamilyIds("sid-dedup");
		expect(list).toHaveLength(1);
		expect(list[0]).toBe("fam-dedup");
	});
});
