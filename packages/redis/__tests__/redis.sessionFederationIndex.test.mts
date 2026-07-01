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
import { createRedisSessionFederationIndex } from "../src/sessionFederationIndex.mjs";
import { runSessionFederationIndexContract } from "./sessionFederationIndex.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(120_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

let suiteCounter = 0;
runSessionFederationIndexContract(async () => {
	suiteCounter += 1;
	const { sessionFederationIndexClient } = makeIoredisClients(raw);
	return createRedisSessionFederationIndex({
		client: sessionFederationIndexClient,
		keyPrefix: `t17:${suiteCounter}:`,
	});
});

// ---------------------------------------------------------------------------
// Concurrency / ordering cases (5 extra)
// ---------------------------------------------------------------------------

describe("SessionFederationIndex concurrency", () => {
	it("100 parallel distinct federations → all 100 land", async () => {
		const { sessionFederationIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFederationIndex({
			client: sessionFederationIndexClient,
			keyPrefix: "t17:conc1:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, (_, i) => idx.addFederation("sid-conc", `fed-${i}`, expiresAt)),
		);
		const list = await idx.listFederations("sid-conc");
		expect(list).toHaveLength(100);
		const names = new Set(list);
		expect(names.size).toBe(100);
		for (let i = 0; i < 100; i++) {
			expect(names.has(`fed-${i}`)).toBe(true);
		}
	});

	it("100 parallel same-federation → 1 entry (ZADD NX dedup)", async () => {
		const { sessionFederationIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFederationIndex({
			client: sessionFederationIndexClient,
			keyPrefix: "t17:conc2:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await Promise.all(
			Array.from({ length: 100 }, () => idx.addFederation("sid-dedup", "fed-dedup", expiresAt)),
		);
		const list = await idx.listFederations("sid-dedup");
		expect(list).toHaveLength(1);
		expect(list[0]).toBe("fed-dedup");
	});

	it("interleaved add/remove → either [fed-x] or [] (never partial)", async () => {
		const { sessionFederationIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFederationIndex({
			client: sessionFederationIndexClient,
			keyPrefix: "t17:conc3:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		// Run 50 add and 50 remove operations concurrently; result is valid if
		// it's either fully present or fully absent — never a corrupted state.
		await Promise.all([
			...Array.from({ length: 50 }, () => idx.addFederation("sid-race", "fed-x", expiresAt)),
			...Array.from({ length: 50 }, () => idx.removeFederation("sid-race", "fed-x")),
		]);
		const list = await idx.listFederations("sid-race");
		expect(list.length === 0 || (list.length === 1 && list[0] === "fed-x")).toBe(true);
	});

	it("insertion-order preserved across serial adds (load-bearing per A4 §5.4)", async () => {
		// The internal helper uses a module-level monotonic counter as score
		// (see redisSidSortedSet.mts), so no inter-add sleep is needed to
		// guarantee strict insertion order even within the same millisecond.
		const { sessionFederationIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFederationIndex({
			client: sessionFederationIndexClient,
			keyPrefix: "t17:order1:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		const names = ["alpha", "beta", "gamma", "delta", "epsilon"];
		for (const name of names) {
			await idx.addFederation("sid-order", name, expiresAt);
		}
		const list = await idx.listFederations("sid-order");
		expect(list).toEqual(names);
	});

	it("re-add of existing member does NOT promote position", async () => {
		const { sessionFederationIndexClient } = makeIoredisClients(raw);
		const idx = createRedisSessionFederationIndex({
			client: sessionFederationIndexClient,
			keyPrefix: "t17:order2:",
		});
		const expiresAt = new Date(Date.now() + 60_000);
		await idx.addFederation("sid-promote", "first", expiresAt);
		await idx.addFederation("sid-promote", "second", expiresAt);
		// Re-add "first" — must NOT move it after "second" (ZADD NX preserves
		// the original counter score).
		await idx.addFederation("sid-promote", "first", expiresAt);
		const list = await idx.listFederations("sid-promote");
		expect(list).toEqual(["first", "second"]);
	});
});
