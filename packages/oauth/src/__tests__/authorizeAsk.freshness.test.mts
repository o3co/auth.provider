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
 * Two readings of a session against an ask: `loginSince` (when this provider
 * established it), which a trip's loop control reads, and `freshSince` (its
 * freshness, core's `sessionFreshness`), which a freshness ask reads.
 */

import type { UserSession } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { freshSince, loginSince, readableFreshness } from "#/routes/authorizeAsk.mjs";

const NOW = Date.parse("2026-10-05T12:00:00Z");
const ASK = NOW - 60_000;

const federated = (authTime: number, upstream: Date | null | undefined): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date(authTime),
	createdAt: new Date(authTime),
	expiresAt: new Date(NOW + 3_600_000),
	claims: {},
	amr: ["fed"],
	authentication: {
		primary: "fed",
		federation: "google",
		upstreamAmr: undefined,
		mfaAt: undefined,
		...(upstream === undefined ? {} : { upstreamAuthTime: upstream }),
	},
});

describe("loginSince and freshSince", () => {
	it("tell a callback after the ask from an upstream authentication before it", () => {
		const session = federated(NOW - 1_000, new Date(ASK - 1_000));
		expect(loginSince(session, ASK, NOW)).toBe(true);
		expect(freshSince(session, ASK, NOW)).toBe(false);
	});

	it("agree when the upstream authenticated after the ask, or recorded no time", () => {
		for (const upstream of [new Date(ASK + 1_000), undefined]) {
			const session = federated(NOW - 1_000, upstream);
			expect(loginSince(session, ASK, NOW)).toBe(true);
			expect(freshSince(session, ASK, NOW)).toBe(true);
		}
	});

	it("read a session whose upstream showed no time as unreadable for a freshness ask only", () => {
		const session = federated(NOW - 1_000, null);
		expect(loginSince(session, ASK, NOW)).toBe(true);
		expect(freshSince(session, ASK, NOW)).toBe("unreadable");
		expect(readableFreshness(session, NOW)).toBeUndefined();
	});

	it("read freshness as the earlier of establishment and the upstream's authentication", () => {
		expect(readableFreshness(federated(NOW - 1_000, new Date(NOW - 5_000)), NOW)).toBe(NOW - 5_000);
		expect(readableFreshness(federated(NOW - 5_000, new Date(NOW - 1_000)), NOW)).toBe(NOW - 5_000);
	});

	it("compare an upstream authentication to the ask in whole seconds: one in the ask's second counts, one a second earlier does not", () => {
		const ask = Date.parse("2026-10-05T11:59:00.800Z");
		const inSecond = federated(NOW - 1_000, new Date("2026-10-05T11:59:00.000Z"));
		expect(freshSince(inSecond, ask, NOW)).toBe(true);
		const secondBefore = federated(NOW - 1_000, new Date("2026-10-05T11:58:59.000Z"));
		expect(freshSince(secondBefore, ask, NOW)).toBe(false);
	});

	it("still compare a session's establishment to the ask to the millisecond", () => {
		const ask = Date.parse("2026-10-05T11:59:00.800Z");
		const sameSecondBefore = federated(Date.parse("2026-10-05T11:59:00.200Z"), undefined);
		expect(freshSince(sameSecondBefore, ask, NOW)).toBe(false);
		expect(loginSince(sameSecondBefore, ask, NOW)).toBe(false);
		// The upstream is later than the establishment, so the establishment is the freshness.
		const upstreamLater = federated(
			Date.parse("2026-10-05T11:59:00.200Z"),
			new Date("2026-10-05T11:59:01.000Z"),
		);
		expect(freshSince(upstreamLater, ask, NOW)).toBe(false);
	});

	it("are never looser than loginSince: an establishment before the ask is not made fresh by an upstream in the same second", () => {
		const ask = Date.parse("2026-10-05T11:59:00.800Z");
		const session = federated(
			Date.parse("2026-10-05T11:59:00.200Z"),
			new Date("2026-10-05T11:59:00.000Z"),
		);
		expect(loginSince(session, ask, NOW)).toBe(false);
		expect(freshSince(session, ask, NOW)).toBe(false);
	});

	it("read a session established further ahead than the replicas' skew as unreadable, whatever its upstream time", () => {
		const ahead = NOW + 5_000;
		for (const upstream of [new Date(NOW - 1_000), new Date(ahead + 1_000)]) {
			const session = federated(ahead, upstream);
			expect(loginSince(session, ASK, NOW)).toBe("unreadable");
			expect(freshSince(session, ASK, NOW)).toBe("unreadable");
		}
	});
});
