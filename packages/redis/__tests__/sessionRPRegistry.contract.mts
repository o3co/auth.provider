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

import type { RegisteredRP, SessionRPRegistry } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SessionRPRegistryFactory = () => Promise<SessionRPRegistry>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

const RP = (overrides: Partial<RegisteredRP> = {}): RegisteredRP => ({
	clientId: overrides.clientId ?? "client-1",
	backchannelLogoutUri: overrides.backchannelLogoutUri ?? "https://rp.example/logout",
	backchannelLogoutSessionRequired: overrides.backchannelLogoutSessionRequired ?? false,
	frontchannelLogoutUri: overrides.frontchannelLogoutUri,
	frontchannelLogoutSessionRequired: overrides.frontchannelLogoutSessionRequired,
	registeredAt: overrides.registeredAt ?? new Date(),
});

export function runSessionRPRegistryContract(factory: SessionRPRegistryFactory): void {
	describe("SessionRPRegistry contract", () => {
		it("registerRP then listRPs returns the RP", async () => {
			const reg = await factory();
			await reg.registerRP("sid-1", RP(), FUTURE());
			const list = await reg.listRPs("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]?.clientId).toBe("client-1");
		});

		it("same clientId upserts — replaces earlier registration", async () => {
			const reg = await factory();
			await reg.registerRP("sid-1", RP({ backchannelLogoutUri: "https://v1" }), FUTURE());
			await reg.registerRP("sid-1", RP({ backchannelLogoutUri: "https://v2" }), FUTURE());
			const list = await reg.listRPs("sid-1");
			expect(list).toHaveLength(1);
			expect(list[0]?.backchannelLogoutUri).toBe("https://v2");
		});

		it("distinct clientIds accumulate", async () => {
			const reg = await factory();
			await reg.registerRP("sid-1", RP({ clientId: "c1" }), FUTURE());
			await reg.registerRP("sid-1", RP({ clientId: "c2" }), FUTURE());
			const list = await reg.listRPs("sid-1");
			expect(list).toHaveLength(2);
			const ids = list.map((r) => r.clientId).sort();
			expect(ids).toEqual(["c1", "c2"]);
		});

		it("listRPs returns empty array for unknown sid", async () => {
			const reg = await factory();
			const list = await reg.listRPs("ghost");
			expect(list).toEqual([]);
		});

		it("registerRP after past expiresAt is a no-op", async () => {
			const reg = await factory();
			await reg.registerRP("sid-1", RP(), PAST());
			const list = await reg.listRPs("sid-1");
			expect(list).toEqual([]);
		});

		it("listRPs returns empty after expiresAt elapsed", async () => {
			const reg = await factory();
			const soon = new Date(Date.now() + 50);
			await reg.registerRP("sid-1", RP(), soon);
			expect(await reg.listRPs("sid-1")).toHaveLength(1);
			await new Promise((r) => setTimeout(r, 100));
			expect(await reg.listRPs("sid-1")).toEqual([]);
		});

		it("removeBySid clears all RPs for the sid", async () => {
			const reg = await factory();
			await reg.registerRP("sid-1", RP({ clientId: "c1" }), FUTURE());
			await reg.registerRP("sid-1", RP({ clientId: "c2" }), FUTURE());
			await reg.removeBySid("sid-1");
			const list = await reg.listRPs("sid-1");
			expect(list).toEqual([]);
		});

		it("removeBySid is idempotent on absent sid", async () => {
			const reg = await factory();
			await expect(reg.removeBySid("ghost")).resolves.toBeUndefined();
		});

		it("mutating returned RegisteredRP does not affect storage (defensive copy)", async () => {
			const reg = await factory();
			await reg.registerRP(
				"sid-1",
				RP({ clientId: "c1", backchannelLogoutUri: "https://orig" }),
				FUTURE(),
			);
			const list1 = await reg.listRPs("sid-1");
			const rp1 = list1[0];
			expect(rp1).toBeDefined();
			// Stress: mutate the returned RP's mutable Date and string fields.
			// The store MUST return a fresh clone each call.
			(rp1 as unknown as { backchannelLogoutUri?: string }).backchannelLogoutUri =
				"https://injected";
			rp1?.registeredAt.setTime(0);
			const list2 = await reg.listRPs("sid-1");
			expect(list2[0]?.backchannelLogoutUri).toBe("https://orig");
			expect(list2[0]?.registeredAt.getTime()).not.toBe(0);
		});

		it("optional fields round-trip cleanly (undefined stays undefined; not coerced)", async () => {
			// Redis HGETALL implementations sometimes coerce undefined fields to ""
			// or omit them entirely on parse. Pin the contract so the redis adapter
			// (T15) cannot ship a subtle drift (e.g., undefined → "" or → false).
			const reg = await factory();
			await reg.registerRP(
				"sid-1",
				{
					clientId: "c-opt",
					// All optional fields explicitly undefined.
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutUri: undefined,
					frontchannelLogoutSessionRequired: undefined,
					registeredAt: new Date(),
				},
				FUTURE(),
			);
			const list = await reg.listRPs("sid-1");
			expect(list).toHaveLength(1);
			const rp = list[0];
			expect(rp?.backchannelLogoutUri).toBeUndefined();
			expect(rp?.backchannelLogoutSessionRequired).toBeUndefined();
			expect(rp?.frontchannelLogoutUri).toBeUndefined();
			expect(rp?.frontchannelLogoutSessionRequired).toBeUndefined();
		});

		it("readonly kind field present", async () => {
			const reg = await factory();
			expect(typeof reg.kind).toBe("string");
			expect(reg.kind.length).toBeGreaterThan(0);
		});
	});
}
