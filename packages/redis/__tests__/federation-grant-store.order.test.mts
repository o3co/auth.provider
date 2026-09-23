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

// The order the store sends its calls in (#593, D16).
//
// Against a stub, because the rule is about *ordering* and a real Redis shows
// it only in a window a test cannot open reliably: the index member is
// reserved, and the reservation acknowledged, BEFORE the record is written. A
// prune that runs in between then sees a member whose horizon is not yet due
// and leaves it alone; the other way round, a record would exist that no
// listing can reach, with nothing to put the member back.

import type { FederationGrantAuthorization } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type { FederationGrantHashFields, FederationGrantStoreClient } from "../src/clients.mjs";
import { createRedisFederationGrantStore } from "../src/federation-grant-store.mjs";
import { makeIoredisFederationGrantStoreClient } from "../src/ioredis.mjs";

const MIN = 60_000;
const DAY = 86_400_000;
const T0 = new Date("2026-09-18T00:00:00.137Z");
const at = (ms: number): Date => new Date(T0.getTime() + ms);
const SCOPES = ["openid", "offline_access"];

const authorization = (): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	resource: undefined,
	scopes: [...SCOPES],
	consent: { at: at(MIN), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(2 * MIN),
	expiresAt: at(30 * DAY),
});

const PENDING: FederationGrantHashFields = {
	format: "1",
	base: JSON.stringify(["g-1", "u-1", "agent", "okta-calendar", String(T0.getTime())]),
	status: "pending",
	version: "1",
	retentionMs: String(30 * DAY),
	intentHandle: "h-g-1",
	intentExpiresAt: String(at(10 * MIN).getTime()),
};

/**
 * Records the order of the calls, and — the part that matters — resolves
 * `reserve` only when the test lets it. A store that sent the record's write
 * without waiting would show up as a `createPending` recorded before the
 * reservation had settled.
 */
const recording = () => {
	const calls: string[] = [];
	let releaseReserve: (() => void) | undefined;
	const client: FederationGrantStoreClient = {
		async reserve(_index, _member, horizonMs) {
			calls.push(`reserve@${horizonMs}`);
			await new Promise<void>((resolve) => {
				releaseReserve = resolve;
			});
			calls.push("reserved");
		},
		async members() {
			return [];
		},
		async prune() {},
		async createPending() {
			calls.push("createPending");
			return PENDING;
		},
		async snapshot() {
			return { fields: PENDING, credential: null };
		},
		async nameIntent() {
			return null;
		},
		async retireIntent() {
			return null;
		},
		async touch() {},
		async activate() {
			calls.push("activate");
			return PENDING;
		},
		async replaceCredentials() {
			return null;
		},
		async requireReauthorization() {
			return null;
		},
		async revoke() {
			calls.push("revoke");
			return PENDING;
		},
		async noteRefreshFailure() {
			return null;
		},
		async tryLock() {
			return true;
		},
		async unlock() {},
	};
	return { calls, client, letReserveFinish: () => releaseReserve?.() };
};

const storeOver = (client: FederationGrantStoreClient) =>
	createRedisFederationGrantStore({
		client,
		keyPrefix: "fg:",
		encryption: { mode: "required", keys: [{ id: "k-1", key: Buffer.alloc(32, 1) }] },
	});

describe("how many commands a read is (#593, D16)", () => {
	it("reads the record and its credential as ONE command", async () => {
		// The property a race cannot prove: between a `HGETALL` and a `GET`, an
		// activation can replace both, and the caller would evaluate one
		// authorization against the other's credential. A client batches the two
		// closely enough that the window almost never opens, so the test is at
		// the seam — what went over the wire — and not at the outcome (the
		// reviewer found the race version of this test proving nothing, over
		// 2,400 concurrent attempts).
		const sent: string[] = [];
		const connection = {
			async evalsha(_sha: string, numkeys: number, ...args: (string | number)[]) {
				sent.push(`evalsha ${numkeys} ${args.slice(0, numkeys).join(" ")}`);
				return [0];
			},
			async eval(_script: string, numkeys: number, ...args: (string | number)[]) {
				sent.push(`eval ${numkeys} ${args.slice(0, numkeys).join(" ")}`);
				return [0];
			},
			async zrange() {
				sent.push("zrange");
				return [];
			},
			async set() {
				sent.push("set");
				return "OK" as const;
			},
		};
		const client = makeIoredisFederationGrantStoreClient(connection);
		await client.snapshot("fg:{a}:grant", "fg:{a}:cred");
		expect(sent).toHaveLength(1);
		expect(sent[0]).toMatch(/^eval(sha)? 2 fg:\{a\}:grant fg:\{a\}:cred$/);
	});
});

describe("the order a write goes out in (#593, D16)", () => {
	it("reserves the index member, and waits for it, before the record is created", async () => {
		const { calls, client, letReserveFinish } = recording();
		const writing = storeOver(client).createPending({
			id: "g-1",
			subject: "u-1",
			clientId: "agent",
			connection: "okta-calendar",
			intent: { handle: "h-g-1", expiresAt: at(10 * MIN) },
			now: T0,
		});
		// Nothing has been written while the reservation is in flight.
		await Promise.resolve();
		expect(calls).toStrictEqual([`reserve@${at(10 * MIN).getTime()}`]);
		letReserveFinish();
		await writing;
		expect(calls).toStrictEqual([`reserve@${at(10 * MIN).getTime()}`, "reserved", "createPending"]);
	});

	it("reserves at the horizon the record is about to have, and waits, before an activation", async () => {
		const { calls, client, letReserveFinish } = recording();
		const writing = storeOver(client).activate({
			grantId: "g-1",
			intentHandle: "h-g-1",
			authorization: authorization(),
			credentials: { refreshToken: "rt-1", accessToken: undefined },
			now: at(2 * MIN),
		});
		await Promise.resolve();
		// The authorization's expiry plus the retention, which is where the
		// record's own deadline is about to be set.
		const horizon = at(30 * DAY).getTime() + 30 * DAY;
		expect(calls).toStrictEqual([`reserve@${horizon}`]);
		letReserveFinish();
		await writing;
		expect(calls).toStrictEqual([`reserve@${horizon}`, "reserved", "activate"]);
	});

	it("reserves before revoking a grant that was never authorized, whose horizon moves forward", async () => {
		const { calls, client, letReserveFinish } = recording();
		const writing = storeOver(client).revoke("g-1", "subject", at(MIN));
		await Promise.resolve();
		expect(calls).toStrictEqual([`reserve@${at(MIN).getTime() + 30 * DAY}`]);
		letReserveFinish();
		await writing;
		expect(calls).toStrictEqual([`reserve@${at(MIN).getTime() + 30 * DAY}`, "reserved", "revoke"]);
	});
});
