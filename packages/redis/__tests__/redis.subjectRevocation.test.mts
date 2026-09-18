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
import {
	runSessionsOnlyRevocationContract,
	runSubjectRevocationContract,
} from "./subjectRevocation.contract.mjs";

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

// #593, D13: the bundled adapter claims the capability, so it owes its
// contract — on a real Redis, where the expiry cases run on the server's clock
// rather than a fake timer's.
runSessionsOnlyRevocationContract(
	async () => {
		suiteCounter += 1;
		return createRedisSubjectRevocation({
			client: makeIoredisClients(raw).subjectRevocationClient,
			keyPrefix: `t593c:${suiteCounter}:`,
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

describe("SubjectRevocation — the two boundaries on one key (#593, D13)", () => {
	const store = (prefix: string) =>
		createRedisSubjectRevocation({
			client: makeIoredisClients(raw).subjectRevocationClient,
			keyPrefix: prefix,
		});

	it("writes a bare decimal while the boundaries are equal, so a rollback is safe", async () => {
		// The whole compatibility argument in one assertion. A previous release
		// reads this form and only this form, and `revokeBefore` — every caller
		// written before #593, and the whole "revoke" path — only ever writes
		// it. A deployment that never makes a sessions-only stamp can roll back.
		const prefix = "t593e:1:";
		const before = new Date();
		await store(prefix).revokeBefore("u", before, new Date(Date.now() + 600_000));
		expect(await raw.get(`${prefix}u`)).toBe(String(before.getTime()));
	});

	it("uses the richer form only once the boundaries actually differ", async () => {
		const prefix = "t593e:2:";
		await store(prefix).revokeSessionsBefore("u", new Date(1_000), new Date(Date.now() + 600_000));
		expect(await raw.get(`${prefix}u`)).toBe("v1:1000:-");
		await store(prefix).revokeBefore("u", new Date(500), new Date(Date.now() + 600_000));
		expect(await raw.get(`${prefix}u`)).toBe("v1:1000:500");
	});

	it("reads a value an older release wrote as both boundaries", async () => {
		// Not as "sessions only": a lone number was written by a release where
		// one watermark ended everything, and reading it as sessions-only would
		// resurrect grants an earlier revocation had ended.
		const prefix = "t593e:3:";
		await raw.set(`${prefix}u`, "1000", "PX", 600_000);
		const adapter = store(prefix);
		expect((await adapter.revokedBefore("u"))?.getTime()).toBe(1_000);
		expect((await adapter.grantsRevokedBefore("u"))?.getTime()).toBe(1_000);
	});

	it("keeps both boundaries on the one key, so there is no half-written state", async () => {
		const prefix = "t593e:4:";
		await store(prefix).revokeSessionsBefore("u", new Date(9_000), new Date(Date.now() + 600_000));
		expect(await raw.keys(`${prefix}*`)).toEqual([`${prefix}u`]);
	});

	it("leaves a key with no expiry without one", async () => {
		// An operator who pinned a boundary for ever meant it. Turning infinite
		// retention into a year would be this adapter deciding otherwise.
		const prefix = "t593e:5:";
		await raw.set(`${prefix}u`, "1000");
		await store(prefix).revokeSessionsBefore("u", new Date(2_000), new Date(Date.now() + 1_000));
		expect(await raw.pttl(`${prefix}u`)).toBe(-1);
		expect((await store(prefix).revokedBefore("u"))?.getTime()).toBe(2_000);
	});

	it("keeps a full revocation for a year, whatever expiry the caller asked for", async () => {
		const prefix = "t593e:6:";
		const before = new Date();
		await store(prefix).revokeBefore("u", before, new Date(Date.now() + 1_000));
		const ttl = await raw.pttl(`${prefix}u`);
		// A year and a minute from the boundary, less whatever the round trip took.
		expect(ttl).toBeGreaterThan(31_000_000_000);
	});

	it("refuses a value it cannot read rather than answering that nothing was revoked", async () => {
		const prefix = "t593e:7:";
		const adapter = store(prefix);
		for (const corrupt of [
			"not-a-watermark",
			"v1:abc:1",
			"v2:1:2",
			"v1:1",
			// Found by review: all digits, and `Number` reads it as Infinity.
			// `new Date(Infinity)` is an Invalid Date, every comparison against
			// it is false, and a boundary that compares false against
			// everything reads as "nothing was revoked for this subject" —
			// revocation silently off, which is the failure this refusal
			// exists for.
			"9".repeat(400),
			`v1:${"9".repeat(400)}:1`,
			`v1:1:${"9".repeat(400)}`,
			// One millisecond past what a Date can hold.
			"8640000000000001",
		]) {
			await raw.set(`${prefix}u`, corrupt, "PX", 600_000);
			await expect(adapter.revokedBefore("u"), corrupt).rejects.toThrow();
			await expect(adapter.grantsRevokedBefore("u"), corrupt).rejects.toThrow();
		}
	});

	it("refuses to write over a record it cannot read", async () => {
		// The script fails the whole call rather than starting a fresh record:
		// a value nobody can decode may be a newer release's, and overwriting
		// it would lose a boundary that is in force.
		const prefix = "t593e:8:";
		await raw.set(`${prefix}u`, "v9:1:2", "PX", 600_000);
		await expect(
			store(prefix).revokeBefore("u", new Date(), new Date(Date.now() + 600_000)),
		).rejects.toThrow();
		expect(await raw.get(`${prefix}u`)).toBe("v9:1:2");
	});

	it("refuses a driver that cannot express a sessions-only stamp", async () => {
		// A driver that kept the old single-boundary primitive would answer
		// every sessions-only stamp by revoking the subject's grants.
		expect(() =>
			createRedisSubjectRevocation({
				client: { get: async () => null } as never,
				keyPrefix: "t593e:9:",
			}),
		).toThrow(/setRevocationBoundaries/);
	});
});
