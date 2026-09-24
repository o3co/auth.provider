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

/**
 * How a test reaches an entry's expiry on the store's own terms.
 *
 * An in-process store judges expiry on this process's clock. A Redis key
 * expires on the server's, which sits to either side of the host's, and a
 * relative `PX` runs from when the command reached the server; a loaded run
 * also reaches its next line late. A fixed sleep after a short expiry therefore
 * either read an entry the store had already dropped, or checked one it had
 * not dropped yet. The default is this process's clock; a Redis runner passes
 * one that reads the server's `TIME`, or waits for the keys to be gone.
 */
export interface ExpiryClock {
	/** Epoch milliseconds on the clock the store expires entries by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything expiring at `at` go. */
	passed(at: Date): Promise<void>;
}

const hostExpiry: ExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at.getTime()) {
			await new Promise((r) => setTimeout(r, at.getTime() - Date.now() + 1));
		}
	},
};

/**
 * An expiry a second ahead of whichever clock is later — the host's, which a
 * write checks it against, and the store's, which expires it — so a read that
 * follows the write lands well inside it however loaded the run is.
 */
const aheadOf = async (clock: ExpiryClock): Promise<Date> =>
	new Date(Math.max(Date.now(), await clock.now()) + 1_000);

const INPUT = (overrides: Partial<CreateUserSessionInput> = {}): CreateUserSessionInput => ({
	sid: overrides.sid ?? "sid-1",
	sub: overrides.sub ?? "user-1",
	authTime: overrides.authTime ?? new Date(),
	expiresAt: overrides.expiresAt ?? FUTURE(),
	claims: overrides.claims ?? { email: "user@example.com" },
	amr: overrides.amr,
});

export function runUserSessionStoreContract(
	factory: UserSessionStoreContractFactory,
	expiry: ExpiryClock = hostExpiry,
): void {
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

		it("round-trips amr (#481), and names it undefined when none was recorded (#626)", async () => {
			const store = await factory();
			await store.create(INPUT({ sid: "sid-amr", amr: ["pwd", "mfa"] }));
			expect((await store.get("sid-amr"))?.amr).toEqual(["pwd", "mfa"]);
			await store.create(INPUT({ sid: "sid-plain" }));
			// Named, not left out: a store that dropped the key on its way back
			// is the copy #626 makes a compile error; this holds it at runtime.
			expect(await store.get("sid-plain")).toHaveProperty("amr", undefined);
		});

		it("returns the session whole, as plain data: what was written, and when it was created (#626)", async () => {
			// Strictly: a key too many, one left out, or a class instance in place
			// of plain data fails here, where the field-by-field checks above pass.
			const store = await factory();
			const input = INPUT({
				sid: "sid-whole",
				authTime: new Date(Date.now() - 1_000),
				claims: { email: "user@example.com", groups: ["alpha"] },
				amr: ["pwd"],
			});
			await store.create(input);
			expect(await store.get("sid-whole")).toStrictEqual({ ...input, createdAt: expect.any(Date) });
			const plain = INPUT({ sid: "sid-whole-plain" });
			await store.create(plain);
			expect(await store.get("sid-whole-plain")).toStrictEqual({
				...plain,
				createdAt: expect.any(Date),
			});
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

		it("create refuses an expiresAt that is not a valid date, and records nothing", async () => {
			// An Invalid Date's `getTime()` is NaN, which is never `<= now`: the
			// memory store kept such a session for ever, and Redis was sent
			// `PX NaN`. A caller fault, and a RangeError, not a session.
			const store = await factory();
			await expect(
				store.create(INPUT({ sid: "sid-invalid", expiresAt: new Date(Number.NaN) })),
			).rejects.toThrow(RangeError);
			expect(await store.get("sid-invalid")).toBeNull();
			// Nothing was recorded, so this is not a duplicate.
			await store.create(INPUT({ sid: "sid-invalid" }));
			expect(await store.get("sid-invalid")).not.toBeNull();
		});

		it("create refuses an authTime that is not a valid date, or is before 1970, and records nothing", async () => {
			// The memory store kept either and handed it back — an Invalid Date as
			// the id_token's `auth_time`. The Redis store wrote either (NaN as JSON
			// `null`) and then read the session back as corrupt: the user was
			// logged out by their own login. Neither is a login time, so neither
			// is a session.
			const store = await factory();
			for (const authTime of [new Date(Number.NaN), new Date(-1)]) {
				await expect(store.create(INPUT({ sid: "sid-bad-auth", authTime }))).rejects.toThrow(
					RangeError,
				);
				expect(await store.get("sid-bad-auth")).toBeNull();
			}
			// The epoch itself is a valid instant, and round-trips.
			await store.create(INPUT({ sid: "sid-bad-auth", authTime: new Date(0) }));
			expect((await store.get("sid-bad-auth"))?.authTime.getTime()).toBe(0);
		});

		it("get returns null for unknown sid", async () => {
			const store = await factory();
			expect(await store.get("ghost")).toBeNull();
		});

		it("get returns null after expiresAt elapsed", async () => {
			// Dated from, and waited out on, the store's own clock (see
			// `ExpiryClock`), not a 50 ms expiry and a 100 ms sleep: on a loaded
			// run the first read landed after the expiry.
			const store = await factory();
			const expiresAt = await aheadOf(expiry);
			await store.create(INPUT({ sid: "soon", expiresAt }));
			expect(await store.get("soon")).not.toBeNull();
			await expiry.passed(expiresAt);
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
			expect((s2?.claims as Record<string, unknown> | undefined)?.injected).toBeUndefined();
			expect(s2?.claims.groups).toEqual(["alpha", "beta"]);
			expect(s2?.authTime.getTime()).not.toBe(0);
			expect(s2?.expiresAt.getTime()).not.toBe(0);
			expect(s2?.createdAt.getTime()).not.toBe(0);
		});

		it("keeps its own copy of amr: neither the array written nor the one read changes what is stored (#626)", async () => {
			// `amr` is what `/authorize` judges `acr_values` against; a store that
			// kept the caller's array, or handed out its own, would let a later
			// push on either one grant a step-up nobody performed.
			const store = await factory();
			const written = ["pwd"];
			await store.create(INPUT({ sid: "amr-iso", amr: written }));
			written.push("mfa");
			const read = await store.get("amr-iso");
			expect(read?.amr).toEqual(["pwd"]);
			(read?.amr as string[] | undefined)?.push("hwk");
			expect((await store.get("amr-iso"))?.amr).toEqual(["pwd"]);
		});

		it("readonly kind field present", async () => {
			const store = await factory();
			expect(typeof store.kind).toBe("string");
			expect(store.kind.length).toBeGreaterThan(0);
		});
	});
}
