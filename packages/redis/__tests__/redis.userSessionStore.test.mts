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
import {
	PRE_UPGRADE_FEDERATED_ENVELOPE,
	PRE_UPGRADE_FEDERATED_SID,
	PRE_UPGRADE_PASSWORD_ENVELOPE,
	PRE_UPGRADE_PASSWORD_SID,
} from "./support/preUpgradeEnvelopes.mjs";
import { keysExpire, testRedis } from "./support/redis.mjs";
import {
	runSecondFactorUpdateContract,
	runUserSessionStoreContract,
} from "./userSessionStore.contract.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

let suiteCounter = 0;
/** A store on a key prefix of its own, one per case, as both suites need. */
const freshStore = async () => {
	suiteCounter += 1;
	const { userSessionStoreClient } = makeIoredisClients(raw);
	return createRedisUserSessionStore({
		client: userSessionStoreClient,
		keyPrefix: `t14:${suiteCounter}:`,
	});
};
// A relative PX: the session is gone when its key is.
const expiry = keysExpire(
	() => raw,
	() => `t14:${suiteCounter}:`,
);
runUserSessionStoreContract(freshStore, { expiry });
// The step-up capability, which the Redis store claims (the MFA ADR's D9).
runSecondFactorUpdateContract(freshStore, { expiry });

describe("a session Redis holds from before the MFA ADR's D9", () => {
	// Envelopes as the release before `authentication` wrote them, captured
	// from its writer (`support/preUpgradeEnvelopes.mts`). A live one survives
	// the upgrade and must read no more trusted than it was: a federated
	// session's upstream values are split out as it is read, never vouched for.
	const store = () =>
		createRedisUserSessionStore({
			client: makeIoredisClients(raw).userSessionStoreClient,
			keyPrefix: "t14:pre-upgrade:",
		});

	it("reads a federated one with authentication undefined, and splits it as it is read", async () => {
		await raw.set(
			`t14:pre-upgrade:${PRE_UPGRADE_FEDERATED_SID}`,
			PRE_UPGRADE_FEDERATED_ENVELOPE,
			"PX",
			60_000,
		);
		const session = await store().get(PRE_UPGRADE_FEDERATED_SID);
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

	it("reads a password one as the password login it was", async () => {
		await raw.set(
			`t14:pre-upgrade:${PRE_UPGRADE_PASSWORD_SID}`,
			PRE_UPGRADE_PASSWORD_ENVELOPE,
			"PX",
			60_000,
		);
		const session = await store().get(PRE_UPGRADE_PASSWORD_SID);
		expect(session).not.toBeNull();
		if (session === null) return;
		expect(session).toHaveProperty("authentication", undefined);
		expect(sessionAuthentication(session)?.primary).toBe("pwd");
		expect(vouchedAmr(session)).toEqual(["pwd"]);
	});
});

describe("recordSecondFactor on Redis (the MFA ADR's D9)", () => {
	const store = (prefix: string) =>
		createRedisUserSessionStore({
			client: makeIoredisClients(raw).userSessionStoreClient,
			keyPrefix: prefix,
		});

	it("keeps the key's TTL: the write sets no new lifetime", async () => {
		const sessions = store("t14:sf-ttl:");
		await sessions.create({
			sid: "sid-ttl",
			sub: "user-1",
			authTime: new Date(),
			expiresAt: new Date(Date.now() + 60_000),
			claims: {},
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
		const before = await raw.pttl("t14:sf-ttl:sid-ttl");
		expect(before).toBeGreaterThan(0);
		await sessions.recordSecondFactor("sid-ttl", { amr: ["otp", "mfa"], at: new Date() });
		const after = await raw.pttl("t14:sf-ttl:sid-ttl");
		// A plain SET would have dropped it (-1); a new PX would have raised it.
		expect(after).toBeGreaterThan(0);
		expect(after).toBeLessThanOrEqual(before);
	});

	it("splits a session Redis holds from before the upgrade, keeping its TTL, and an older reader still reads it", async () => {
		const sessions = store("t14:sf-pre:");
		const key = `t14:sf-pre:${PRE_UPGRADE_FEDERATED_SID}`;
		await raw.set(key, PRE_UPGRADE_FEDERATED_ENVELOPE, "PX", 60_000);
		const envelope = JSON.parse(PRE_UPGRADE_FEDERATED_ENVELOPE);
		const verifiedAt = new Date();
		const recorded = await sessions.recordSecondFactor(PRE_UPGRADE_FEDERATED_SID, {
			amr: ["otp", "mfa"],
			at: verifiedAt,
		});
		expect(recorded?.amr).toEqual(["fed", "otp", "mfa"]);
		expect(recorded?.authentication).toStrictEqual({
			primary: "fed",
			federation: undefined,
			upstreamAmr: ["hwk"],
			mfaAt: verifiedAt,
		});
		expect(await raw.pttl(key)).toBeGreaterThan(0);
		// What a release before `authentication` reads: every field it knows,
		// as it wrote them, and the split `amr` — `authentication` beside it is
		// a key it ignores (the MFA ADR's "Rolling back").
		const stored = JSON.parse((await raw.get(key)) as string);
		expect(stored).toMatchObject({ ...envelope, amr: ["fed", "otp", "mfa"] });
		expect(stored.authentication).toEqual({
			primary: "fed",
			upstreamAmr: ["hwk"],
			mfaAtMs: verifiedAt.getTime(),
		});
	});
});
