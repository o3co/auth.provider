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

import { sessionAuthentication, vouchedAmr } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";
import { keysExpire, testRedis } from "./support/redis.mjs";
import { runUserSessionStoreContract } from "./userSessionStore.contract.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

let suiteCounter = 0;
runUserSessionStoreContract(
	async () => {
		suiteCounter += 1;
		const { userSessionStoreClient } = makeIoredisClients(raw);
		return createRedisUserSessionStore({
			client: userSessionStoreClient,
			keyPrefix: `t14:${suiteCounter}:`,
		});
	},
	// A relative PX: the session is gone when its key is.
	{
		expiry: keysExpire(
			() => raw,
			() => `t14:${suiteCounter}:`,
		),
	},
);

describe("a session Redis holds from before the MFA ADR's D9", () => {
	// The envelope a release before `authentication` wrote, byte for byte in
	// shape. A live one survives the upgrade and must read no more trusted
	// than it was: a federated session's upstream values are split out as it
	// is read, never vouched for.
	const envelope = (sid: string) => ({
		sid,
		sub: "user-1",
		authTimeMs: Date.now() - 60_000,
		createdAtMs: Date.now() - 60_000,
		expiresAtMs: Date.now() + 60_000,
		claims: { email: "user@example.com" },
		amr: ["hwk", "fed"],
	});

	it("reads with authentication undefined, and splits as it is read", async () => {
		const { userSessionStoreClient } = makeIoredisClients(raw);
		const store = createRedisUserSessionStore({
			client: userSessionStoreClient,
			keyPrefix: "t14:pre-upgrade:",
		});
		await raw.set("t14:pre-upgrade:sid-old", JSON.stringify(envelope("sid-old")), "PX", 60_000);
		const session = await store.get("sid-old");
		expect(session).not.toBeNull();
		if (session === null) return;
		expect(session).toHaveProperty("authentication", undefined);
		expect(session.amr).toEqual(["hwk", "fed"]);
		expect(sessionAuthentication(session)).toStrictEqual({
			primary: "fed",
			federation: undefined,
			upstreamAmr: ["hwk"],
			mfaAt: undefined,
		});
		expect(vouchedAmr(session)).toEqual(["fed"]);
	});
});
