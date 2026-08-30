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
 * #321's acceptance criterion, end to end: a deployment on Redis-backed
 * session stores calls `revokeAllForSubject` after a credential change and
 * gets `unavailable: []`, with every session cascaded and the watermark in
 * force across replicas.
 *
 * Before this, the two subject slots had in-memory adapters only. A
 * multi-replica deployment filled neither, so the call answered
 * `unavailable: ["subjectRevocation", "subjectSessionIndex"]` and revoked
 * nothing — visible rather than silent, deliberately, but nothing revoked all
 * the same.
 */

import { revokeAllForSubject } from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisSubjectRevocation } from "../src/subjectRevocation.mjs";
import { createRedisSubjectSessionIndex } from "../src/subjectSessionIndex.mjs";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";

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

const FUTURE = () => new Date(Date.now() + 600_000);

const session = (sid: string, sub = "u1") => ({
	sid,
	sub,
	authTime: new Date(),
	expiresAt: FUTURE(),
	claims: {},
});

/** One replica's view of the shared store — separate adapter objects, one Redis. */
const replica = (n: string) => {
	const clients = makeIoredisClients(raw);
	return {
		userSessionStore: createRedisUserSessionStore({
			client: clients.userSessionStoreClient,
			keyPrefix: `t321e:${n}:us:`,
		}),
		subjectSessionIndex: createRedisSubjectSessionIndex({
			client: clients.subjectSessionIndexClient,
			keyPrefix: `t321e:${n}:sub:`,
		}),
		subjectRevocation: createRedisSubjectRevocation({
			client: clients.subjectRevocationClient,
			keyPrefix: `t321e:${n}:rev:`,
		}),
	};
};

describe("revokeAllForSubject on Redis-backed stores (#321)", () => {
	it("reports nothing unavailable and cascades every session", async () => {
		const r = replica("cascade");
		await r.userSessionStore.create(session("s1"));
		await r.userSessionStore.create(session("s2"));
		await r.subjectSessionIndex.addSid("u1", "s1", FUTURE());
		await r.subjectSessionIndex.addSid("u1", "s2", FUTURE());

		// The composition supplies the cascade; what #321 changes is that the
		// two stores it enumerates and stamps are now shared across replicas.
		const cascaded: string[] = [];
		const result = await revokeAllForSubject({
			subject: "u1",
			cascadeSession: async (sid) => {
				cascaded.push(sid);
				await r.userSessionStore.delete(sid);
				return { ok: true };
			},
			subjectSessionIndex: r.subjectSessionIndex,
			subjectRevocation: r.subjectRevocation,
			watermarkTtlMs: 600_000,
		});

		// The acceptance criterion.
		expect(result.unavailable).toEqual([]);
		expect(result.complete).toBe(true);
		expect(result.tokensRevoked).toBe(true);
		expect([...result.sessionsRevoked].sort()).toEqual(["s1", "s2"]);
		expect(result.sessionsFailed).toEqual([]);
		expect(cascaded.sort()).toEqual(["s1", "s2"]);
		expect(await r.subjectSessionIndex.listSids("u1")).toEqual([]);
		expect(await r.userSessionStore.get("s1")).toBeNull();
		expect(await r.userSessionStore.get("s2")).toBeNull();
	});

	it("puts the watermark in force for a replica that never saw the reset", async () => {
		// The point of moving these stores to Redis: the replica that handles the
		// next request is not the one that handled the password change.
		const writer = replica("shared");
		const reader = replica("shared");

		await writer.subjectSessionIndex.addSid("u2", "s1", FUTURE());
		const before = await revokeAllForSubject({
			subject: "u2",
			cascadeSession: async () => ({ ok: true }),
			subjectSessionIndex: writer.subjectSessionIndex,
			subjectRevocation: writer.subjectRevocation,
			watermarkTtlMs: 600_000,
		});
		expect(before.unavailable).toEqual([]);

		const watermark = await reader.subjectRevocation.revokedBefore("u2");
		expect(watermark).not.toBeNull();
		expect(watermark?.getTime()).toBeGreaterThan(Date.now() - 60_000);
	});

	it("still reports what is missing when a slot is left unwired", async () => {
		// The structured result #296 shipped keeps its meaning: a composition that
		// wires only one of the pair is told which one it left out.
		const r = replica("partial");
		const result = await revokeAllForSubject({
			subject: "u3",
			cascadeSession: async () => ({ ok: true }),
			subjectRevocation: r.subjectRevocation,
			watermarkTtlMs: 600_000,
		});
		expect(result.unavailable).toEqual(["subjectSessionIndex"]);
		expect(result.complete).toBe(false);
	});
});
