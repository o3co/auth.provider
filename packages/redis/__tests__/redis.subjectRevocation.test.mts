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
 * Redis {@link SubjectRevocation} (#321).
 *
 * The watermark is monotonic, and on a shared store that has to hold under
 * concurrent writers — which is what makes a plain `SET key value PX ttl` the
 * wrong primitive and an atomic read-compare-write the right one.
 */

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisSubjectRevocation } from "../src/subjectRevocation.mjs";
import { runSubjectRevocationContract } from "./subjectRevocation.contract.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let suiteCounter = 0;
runSubjectRevocationContract(
	async () => {
		suiteCounter += 1;
		const { subjectRevocationClient } = makeIoredisClients(raw);
		return createRedisSubjectRevocation({
			client: subjectRevocationClient,
			keyPrefix: `t321r:${suiteCounter}:`,
		});
	},
	{ waitPastExpiry: sleep },
);

describe("SubjectRevocation — Redis-specific behaviour (#321)", () => {
	const store = (prefix: string) =>
		createRedisSubjectRevocation({
			client: makeIoredisClients(raw).subjectRevocationClient,
			keyPrefix: prefix,
		});

	it("expires the watermark on the server's clock", async () => {
		const s = store("t321r:exp:");
		await s.revokeBefore("u1", new Date(1_000), new Date(Date.now() + 60));
		expect((await s.revokedBefore("u1"))?.getTime()).toBe(1_000);
		await sleep(150);
		expect(await s.revokedBefore("u1")).toBeNull();
	});

	it("starts a fresh watermark after the previous one expired", async () => {
		// The monotonic guard must not resurrect an expired entry's larger value.
		const s = store("t321r:fresh:");
		await s.revokeBefore("u2", new Date(9_000_000), new Date(Date.now() + 60));
		await sleep(150);
		await s.revokeBefore("u2", new Date(1_000), new Date(Date.now() + 600_000));
		expect((await s.revokedBefore("u2"))?.getTime()).toBe(1_000);
	});

	it("holds monotonicity under concurrent writers", async () => {
		// The reason this is a server-side compare rather than GET-then-SET: two
		// replicas resetting the same credential race, and a read-modify-write in
		// the client would let the loser's smaller value win.
		const s = store("t321r:race:");
		const expiresAt = new Date(Date.now() + 600_000);
		await Promise.all(
			Array.from({ length: 50 }, (_, i) =>
				s.revokeBefore("u3", new Date(1_000_000 + i * 1_000), expiresAt),
			),
		);
		expect((await s.revokedBefore("u3"))?.getTime()).toBe(1_000_000 + 49 * 1_000);
	});

	it("never truncates an in-force watermark's TTL under a shorter write", async () => {
		const s = store("t321r:ttl:");
		await s.revokeBefore("u4", new Date(1_000), new Date(Date.now() + 600_000));
		const afterLong = await raw.pttl("t321r:ttl:u4");
		await s.revokeBefore("u4", new Date(2_000), new Date(Date.now() + 5_000));
		const afterShort = await raw.pttl("t321r:ttl:u4");
		expect(afterShort).toBeGreaterThan(5_000);
		expect(Math.abs(afterShort - afterLong)).toBeLessThan(2_000);
	});
});
