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
import { describe, expect, it } from "vitest";
import type { CreateUserSessionInput, UserSessionStore } from "../types.mjs";

export type UserSessionStoreContractFactory = () => Promise<UserSessionStore>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

const INPUT = (overrides: Partial<CreateUserSessionInput> = {}): CreateUserSessionInput => ({
	sid: overrides.sid ?? "sid-1",
	sub: overrides.sub ?? "user-1",
	authTime: overrides.authTime ?? new Date(),
	expiresAt: overrides.expiresAt ?? FUTURE(),
	claims: overrides.claims ?? { email: "user@example.com" },
});

export function runUserSessionStoreContract(factory: UserSessionStoreContractFactory): void {
	describe("UserSessionStore contract", () => {
		it("create then get returns the session with claims", async () => {
			const store = await factory();
			await store.create(INPUT());
			const s = await store.get("sid-1");
			expect(s).not.toBeNull();
			expect(s?.sid).toBe("sid-1");
			expect(s?.sub).toBe("user-1");
			expect(s?.claims.email).toBe("user@example.com");
		});

		it("create rejects duplicate sid", async () => {
			const store = await factory();
			await store.create(INPUT({ sid: "dup" }));
			await expect(store.create(INPUT({ sid: "dup" }))).rejects.toThrow();
		});

		it("create with expiresAt in the past throws", async () => {
			const store = await factory();
			await expect(store.create(INPUT({ expiresAt: PAST() }))).rejects.toThrow();
		});

		it("get returns null for unknown sid", async () => {
			const store = await factory();
			expect(await store.get("ghost")).toBeNull();
		});

		it("get returns null after expiresAt elapsed", async () => {
			const store = await factory();
			// Widen timing margins (per T2/T3 review note about CI flake on loaded runners).
			const soon = new Date(Date.now() + 50);
			await store.create(INPUT({ sid: "soon", expiresAt: soon }));
			expect(await store.get("soon")).not.toBeNull();
			await new Promise((r) => setTimeout(r, 100));
			expect(await store.get("soon")).toBeNull();
		});

		it("delete removes the session — get returns null afterwards", async () => {
			const store = await factory();
			await store.create(INPUT({ sid: "to-del" }));
			await store.delete("to-del");
			expect(await store.get("to-del")).toBeNull();
		});

		it("delete is idempotent on absent sid", async () => {
			const store = await factory();
			await expect(store.delete("ghost")).resolves.toBeUndefined();
		});

		it("returned UserSession has createdAt populated by the store", async () => {
			const store = await factory();
			const before = Date.now();
			await store.create(INPUT({ sid: "ts-test" }));
			const s = await store.get("ts-test");
			expect(s?.createdAt.getTime()).toBeGreaterThanOrEqual(before);
		});

		it("mutating returned UserSession does not affect storage (defensive copy)", async () => {
			const store = await factory();
			await store.create(
				INPUT({ sid: "iso", claims: { email: "u@example.com", groups: ["alpha", "beta"] } }),
			);
			const s1 = await store.get("iso");
			expect(s1).not.toBeNull();
			// Stress all three defensive-copy axes: claims index signature,
			// claims.groups array, and Date fields. The contract suite is the
			// load-bearing artifact that the redis adapter MUST satisfy as well —
			// a redis adapter that forgets to clone Dates on retrieve must fail here.
			(s1?.claims as Record<string, unknown>).injected = "evil";
			(s1?.claims.groups as string[] | undefined)?.push("admin");
			s1?.authTime.setTime(0);
			s1?.expiresAt.setTime(0);
			s1?.createdAt.setTime(0);
			const s2 = await store.get("iso");
			expect((s2?.claims as Record<string, unknown>).injected).toBeUndefined();
			expect(s2?.claims.groups).toEqual(["alpha", "beta"]);
			expect(s2?.authTime.getTime()).not.toBe(0);
			expect(s2?.expiresAt.getTime()).not.toBe(0);
			expect(s2?.createdAt.getTime()).not.toBe(0);
		});

		it("readonly kind field present", async () => {
			const store = await factory();
			expect(typeof store.kind).toBe("string");
			expect(store.kind.length).toBeGreaterThan(0);
		});
	});
}
