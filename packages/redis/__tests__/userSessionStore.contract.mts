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

import {
	type CreateUserSessionInput,
	DEFAULT_CLOCK_SKEW_MS,
	type SupportsSecondFactorUpdate,
	supportsSecondFactorUpdate,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";

export type UserSessionStoreContractFactory = () => Promise<UserSessionStore>;

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

/**
 * How a test reaches an entry's expiry on the store's own terms. A Redis key
 * expires on the server's clock, which may sit either side of the host's, and
 * a relative `PX` runs from when the command reached the server, so a fixed
 * sleep can find an entry already dropped or one not yet dropped. The default
 * is this process's clock; a Redis runner passes one that reads the server's
 * `TIME`, or waits for the keys to be gone.
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
	authentication: overrides.authentication,
});

/** How a password login records itself, every field named. */
const PASSWORD_LOGIN = {
	primary: "pwd",
	federation: undefined,
	upstreamAmr: undefined,
	mfaAt: undefined,
} as const;

export function runUserSessionStoreContract(
	factory: UserSessionStoreContractFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	describe("UserSessionStore contract", () => {
		const expiry = options.expiry ?? hostExpiry;

		it("create then get returns the session with claims", async () => {
			const store = await factory();
			await store.create(INPUT());
			const s = await store.get("sid-1");
			expect(s).not.toBeNull();
			expect(s?.sid).toBe("sid-1");
			expect(s?.sub).toBe("user-1");
			expect(s?.claims.email).toBe("user@example.com");
		});

		it("round-trips amr, and names it undefined when none was recorded", async () => {
			const store = await factory();
			await store.create(INPUT({ sid: "sid-amr", amr: ["pwd", "mfa"] }));
			expect((await store.get("sid-amr"))?.amr).toEqual(["pwd", "mfa"]);
			await store.create(INPUT({ sid: "sid-plain" }));
			// Named, not left out: the required key makes a store's copy that
			// drops it a compile error; this holds it at runtime.
			expect(await store.get("sid-plain")).toHaveProperty("amr", undefined);
		});

		it("round-trips authentication, and names it undefined when none was recorded", async () => {
			const store = await factory();
			const federated = {
				primary: "fed",
				federation: "google",
				upstreamAmr: ["hwk", "mfa"],
				mfaAt: new Date(Date.now() - 5_000),
			};
			await store.create(INPUT({ sid: "sid-auth", amr: ["fed"], authentication: federated }));
			expect((await store.get("sid-auth"))?.authentication).toStrictEqual(federated);
			await store.create(
				INPUT({ sid: "sid-auth-pwd", amr: ["pwd"], authentication: PASSWORD_LOGIN }),
			);
			// Every field named, those holding `undefined` included: a copy that
			// dropped one is what the required keys make a compile error.
			expect((await store.get("sid-auth-pwd"))?.authentication).toStrictEqual(PASSWORD_LOGIN);
			// A session written before the design: named, holding `undefined`,
			// which is how `sessionAuthentication` knows to read it from its `amr`.
			await store.create(INPUT({ sid: "sid-auth-none", amr: ["hwk", "fed"] }));
			expect(await store.get("sid-auth-none")).toHaveProperty("authentication", undefined);
		});

		it("returns the session whole, as plain data: what was written, and when it was created", async () => {
			// Strictly: a key too many, one left out, or a class instance in place
			// of plain data fails here, where the field-by-field checks above pass.
			const store = await factory();
			const input = INPUT({
				sid: "sid-whole",
				authTime: new Date(Date.now() - 1_000),
				claims: { email: "user@example.com", groups: ["alpha"] },
				amr: ["pwd", "otp", "mfa"],
				authentication: { ...PASSWORD_LOGIN, mfaAt: new Date(Date.now() - 500) },
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
			// An Invalid Date's `getTime()` is NaN, which is never `<= now`: a
			// memory store would keep the session for ever, and Redis would be
			// sent `PX NaN`. A caller fault, and a RangeError, not a session.
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
			// Kept, either would come back from a memory store (an Invalid Date as
			// the id_token's `auth_time`), and a Redis store would write it (NaN
			// as JSON `null`) and read the session back as corrupt, logging the
			// user out by their own login. Neither is a login time.
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

		it("create refuses an authentication.mfaAt that is not a valid date, is before 1970, or is further ahead than hosts' clocks are tolerated to drift, and records nothing", async () => {
			// When a second factor was verified is what the baseline reads; an
			// Invalid Date is no time, and the Redis store could not read one back.
			// One further ahead of the store's clock than the clock skew tolerated
			// between hosts (DEFAULT_CLOCK_SKEW_MS) is no clock's reading.
			const store = await factory();
			for (const mfaAt of [
				new Date(Number.NaN),
				new Date(-1),
				new Date(Date.now() + DEFAULT_CLOCK_SKEW_MS + 60_000),
			]) {
				await expect(
					store.create(INPUT({ sid: "sid-bad-mfa", authentication: { ...PASSWORD_LOGIN, mfaAt } })),
				).rejects.toThrow(RangeError);
				expect(await store.get("sid-bad-mfa")).toBeNull();
			}
		});

		it("create records an mfaAt a minute ahead of the store's clock as the store's now: never a time still to come", async () => {
			// A clock a minute ahead is a clock, not a forgery — but kept as it
			// came, it would count as recent for a minute longer than it is.
			const store = await factory();
			const before = Date.now();
			await store.create(
				INPUT({
					sid: "sid-ahead-mfa",
					authentication: { ...PASSWORD_LOGIN, mfaAt: new Date(before + 60_000) },
				}),
			);
			const after = Date.now();
			const recorded = (await store.get("sid-ahead-mfa"))?.authentication?.mfaAt?.getTime();
			expect(recorded).toBeGreaterThanOrEqual(before);
			expect(recorded).toBeLessThanOrEqual(after);
		});

		it.each([
			["a value that is not an object", "pwd"],
			["null", null],
			["a list", []],
			["no primary", { federation: undefined, upstreamAmr: undefined, mfaAt: undefined }],
			["an empty primary", { ...PASSWORD_LOGIN, primary: "" }],
			["a primary that is not a string", { ...PASSWORD_LOGIN, primary: 1 }],
			["a federation that is not a string", { ...PASSWORD_LOGIN, federation: 1 }],
			["a federation that is null", { ...PASSWORD_LOGIN, federation: null }],
			[
				"an upstreamAmr that is a string",
				{ ...PASSWORD_LOGIN, primary: "fed", upstreamAmr: "hwk" },
			],
			[
				"an upstreamAmr holding a number",
				{ ...PASSWORD_LOGIN, primary: "fed", upstreamAmr: ["hwk", 1] },
			],
			["an upstreamAmr that is null", { ...PASSWORD_LOGIN, primary: "fed", upstreamAmr: null }],
			["an mfaAt that is not a Date", { ...PASSWORD_LOGIN, mfaAt: Date.now() }],
		])(
			"create refuses an authentication with %s — a RangeError, and records nothing",
			async (_label, authentication) => {
				// What SessionAuthentication admits, and nothing else: the two stores
				// would otherwise part ways on it — one copying a string's characters
				// as a list, the other writing an envelope it then reads as corrupt.
				const store = await factory();
				await expect(
					store.create(
						INPUT({
							sid: "sid-bad-auth",
							authentication: authentication as unknown as CreateUserSessionInput["authentication"],
						}),
					),
				).rejects.toThrow(RangeError);
				expect(await store.get("sid-bad-auth")).toBeNull();
				// Nothing was recorded, so this is not a duplicate.
				await store.create(INPUT({ sid: "sid-bad-auth", authentication: PASSWORD_LOGIN }));
				expect((await store.get("sid-bad-auth"))?.authentication).toStrictEqual(PASSWORD_LOGIN);
			},
		);

		it("get returns null for unknown sid", async () => {
			const store = await factory();
			expect(await store.get("ghost")).toBeNull();
		});

		it("get returns null after expiresAt elapsed", async () => {
			// Dated from, and waited out on, the store's own clock (see
			// `ExpiryClock`).
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
			// All three defensive-copy axes: the claims index signature, the
			// claims.groups array, and the Date fields. A Redis adapter that
			// forgets to clone Dates on retrieve must fail here.
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

		it("keeps its own copy of amr: neither the array written nor the one read changes what is stored", async () => {
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

		it("keeps its own copy of authentication: neither what was written nor what was read changes what is stored", async () => {
			// `mfaAt` is what the baseline and recent MFA are judged on, and
			// `upstreamAmr` what an untrusted IdP said; a store that shared either
			// with a caller would let a later write change a verified session.
			const store = await factory();
			const mfaAtMs = Date.now() - 1_000;
			const written = {
				primary: "fed",
				federation: "google",
				upstreamAmr: ["hwk"],
				mfaAt: new Date(mfaAtMs),
			};
			await store.create(INPUT({ sid: "auth-iso", amr: ["fed"], authentication: written }));
			written.upstreamAmr.push("mfa");
			written.mfaAt.setTime(0);
			const read = await store.get("auth-iso");
			expect(read?.authentication?.upstreamAmr).toEqual(["hwk"]);
			expect(read?.authentication?.mfaAt?.getTime()).toBe(mfaAtMs);
			(read?.authentication?.upstreamAmr as string[] | undefined)?.push("phr");
			read?.authentication?.mfaAt?.setTime(0);
			const again = await store.get("auth-iso");
			expect(again?.authentication?.upstreamAmr).toEqual(["hwk"]);
			expect(again?.authentication?.mfaAt?.getTime()).toBe(mfaAtMs);
		});

		it("readonly kind field present", async () => {
			const store = await factory();
			expect(typeof store.kind).toBe("string");
			expect(store.kind.length).toBeGreaterThan(0);
		});
	});
}

/**
 * What a store owes once it claims {@link SupportsSecondFactorUpdate}, the
 * step-up capability. Optional on the port (a custom store without it keeps
 * working, and a step-up asks for a re-authentication instead), so the base
 * suite above does not ask for it, and this one runs only against a store
 * that claims it. Both bundled stores do.
 */
export function runSecondFactorUpdateContract(
	factory: UserSessionStoreContractFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	const expiry = options.expiry ?? hostExpiry;
	const capable = async (): Promise<UserSessionStore & SupportsSecondFactorUpdate> => {
		const store = await factory();
		if (!supportsSecondFactorUpdate(store)) {
			throw new Error("this adapter does not claim SupportsSecondFactorUpdate");
		}
		return store;
	};

	describe("SupportsSecondFactorUpdate contract — recordSecondFactor, a second factor verified in a live session", () => {
		const at = (msAgo: number) => new Date(Date.now() - msAgo);

		it("adds the factor's values to amr, in insertion order, sets mfaAt, and changes nothing else", async () => {
			const store = await capable();
			const input = INPUT({
				sid: "sf-1",
				authTime: at(60_000),
				claims: { email: "user@example.com", groups: ["alpha"] },
				amr: ["pwd"],
				authentication: PASSWORD_LOGIN,
			});
			await store.create(input);
			const before = await store.get("sf-1");
			const verifiedAt = at(1_000);
			const recorded = await store.recordSecondFactor("sf-1", {
				amr: ["otp", "mfa"],
				at: verifiedAt,
			});
			const expected = {
				...before,
				amr: ["pwd", "otp", "mfa"],
				authentication: { ...PASSWORD_LOGIN, mfaAt: verifiedAt },
			};
			// What it answers is what is stored, and the session is otherwise
			// the one that was there: sid, sub, authTime (a step-up never moves
			// it), createdAt, expiresAt and claims.
			expect(recorded).toStrictEqual(expected);
			expect(await store.get("sf-1")).toStrictEqual(expected);
		});

		it("keeps every vouched value, never repeats mfa, and takes the later mfaAt, each no later than the recording store's clock", async () => {
			const store = await capable();
			await store.create(INPUT({ sid: "sf-mono", amr: ["pwd"], authentication: PASSWORD_LOGIN }));
			const first = at(10_000);
			await store.recordSecondFactor("sf-mono", { amr: ["otp", "mfa"], at: first });
			// A step-up appends; an earlier time does not move mfaAt back.
			const stale = await store.recordSecondFactor("sf-mono", {
				amr: ["hwk", "mfa"],
				at: at(20_000),
			});
			expect(stale?.amr).toEqual(["pwd", "otp", "mfa", "hwk"]);
			expect(stale?.authentication?.mfaAt?.getTime()).toBe(first.getTime());
			const later = at(1_000);
			const again = await store.recordSecondFactor("sf-mono", { amr: ["otp"], at: later });
			expect(again?.amr).toEqual(["pwd", "otp", "mfa", "hwk"]);
			expect(again?.authentication?.mfaAt?.getTime()).toBe(later.getTime());
			expect((await store.get("sf-mono"))?.authentication?.mfaAt?.getTime()).toBe(later.getTime());
		});

		it('splits a pre-upgrade session first: ["hwk", "fed"] plus TOTP is amr ["fed", "otp", "mfa"], upstreamAmr ["hwk"]', async () => {
			// Never ["hwk", "fed", "otp", "mfa"], whose `hwk` — an untrusted
			// IdP's word — would meet `phr`.
			const store = await capable();
			await store.create(INPUT({ sid: "sf-split", amr: ["hwk", "fed"] }));
			const verifiedAt = at(1_000);
			const recorded = await store.recordSecondFactor("sf-split", {
				amr: ["otp", "mfa"],
				at: verifiedAt,
			});
			const split = {
				amr: ["fed", "otp", "mfa"],
				authentication: {
					primary: "fed",
					federation: undefined,
					upstreamAmr: ["hwk"],
					mfaAt: verifiedAt,
				},
			};
			expect(recorded).toMatchObject(split);
			expect(await store.get("sf-split")).toMatchObject(split);
			expect((await store.get("sf-split"))?.authentication).toStrictEqual(split.authentication);
		});

		it("splits a pre-upgrade password session as the password login it was", async () => {
			const store = await capable();
			await store.create(INPUT({ sid: "sf-split-pwd", amr: ["pwd"] }));
			const verifiedAt = at(1_000);
			const recorded = await store.recordSecondFactor("sf-split-pwd", {
				amr: ["otp", "mfa"],
				at: verifiedAt,
			});
			expect(recorded?.amr).toEqual(["pwd", "otp", "mfa"]);
			expect(recorded?.authentication).toStrictEqual({ ...PASSWORD_LOGIN, mfaAt: verifiedAt });
		});

		it("answers null for a pre-upgrade session whose primary cannot be told, and changes nothing", async () => {
			// Such a session is re-authenticated; a second factor added to
			// it would be recorded against a primary nobody can name.
			const store = await capable();
			await store.create(INPUT({ sid: "sf-unknown", amr: ["hwk"] }));
			expect(
				await store.recordSecondFactor("sf-unknown", { amr: ["otp", "mfa"], at: at(1_000) }),
			).toBeNull();
			const unchanged = await store.get("sf-unknown");
			expect(unchanged?.amr).toEqual(["hwk"]);
			expect(unchanged).toHaveProperty("authentication", undefined);
		});

		it("answers null for a session that is gone, and writes nothing", async () => {
			const store = await capable();
			expect(
				await store.recordSecondFactor("ghost", { amr: ["otp", "mfa"], at: at(1_000) }),
			).toBeNull();
			expect(await store.get("ghost")).toBeNull();
			await store.create(
				INPUT({ sid: "sf-deleted", amr: ["pwd"], authentication: PASSWORD_LOGIN }),
			);
			await store.delete("sf-deleted");
			expect(
				await store.recordSecondFactor("sf-deleted", { amr: ["otp", "mfa"], at: at(1_000) }),
			).toBeNull();
			expect(await store.get("sf-deleted")).toBeNull();
		});

		it("keeps the session's lifetime: it ends when it would have, and then records nothing", async () => {
			const store = await capable();
			const expiresAt = await aheadOf(expiry);
			await store.create(
				INPUT({ sid: "sf-ttl", expiresAt, amr: ["pwd"], authentication: PASSWORD_LOGIN }),
			);
			const recorded = await store.recordSecondFactor("sf-ttl", {
				amr: ["otp", "mfa"],
				at: at(0),
			});
			expect(recorded?.expiresAt.getTime()).toBe(expiresAt.getTime());
			await expiry.passed(expiresAt);
			expect(await store.get("sf-ttl")).toBeNull();
			expect(
				await store.recordSecondFactor("sf-ttl", { amr: ["hwk", "mfa"], at: at(0) }),
			).toBeNull();
		});

		it.each([
			["no values", { amr: [], at: new Date() }],
			["an empty value", { amr: ["otp", ""], at: new Date() }],
			["a primary's marker, pwd", { amr: ["pwd"], at: new Date() }],
			["a primary's marker, fed", { amr: ["otp", "fed"], at: new Date() }],
			["an invalid date", { amr: ["otp", "mfa"], at: new Date(Number.NaN) }],
			["a time before 1970", { amr: ["otp", "mfa"], at: new Date(-1) }],
			[
				"a time further ahead than hosts' clocks are tolerated to drift",
				{ amr: ["otp", "mfa"], at: new Date(Date.now() + DEFAULT_CLOCK_SKEW_MS + 60_000) },
			],
			// `mfa` comes from a factor that adds it, beside that factor's own
			// values: alone, it names no factor that was verified.
			["mfa alone", { amr: ["mfa"], at: new Date() }],
			["mfa repeated alone", { amr: ["mfa", "mfa"], at: new Date() }],
		])("refuses an event with %s — a RangeError, and nothing recorded", async (_label, event) => {
			// A second factor adds its own values; it never changes the primary
			// the baseline is decided on, and a time that is no instant is not
			// when it was verified.
			const store = await capable();
			await store.create(INPUT({ sid: "sf-bad", amr: ["pwd"], authentication: PASSWORD_LOGIN }));
			await expect(store.recordSecondFactor("sf-bad", event)).rejects.toThrow(RangeError);
			const unchanged = await store.get("sf-bad");
			expect(unchanged?.amr).toEqual(["pwd"]);
			expect(unchanged?.authentication).toStrictEqual(PASSWORD_LOGIN);
		});

		it("records a time a minute ahead of the store's clock as the store's now: never a time still to come", async () => {
			const store = await capable();
			await store.create(INPUT({ sid: "sf-ahead", amr: ["pwd"], authentication: PASSWORD_LOGIN }));
			const before = Date.now();
			const recorded = await store.recordSecondFactor("sf-ahead", {
				amr: ["otp", "mfa"],
				at: new Date(before + 60_000),
			});
			const after = Date.now();
			for (const mfaAt of [
				recorded?.authentication?.mfaAt?.getTime(),
				(await store.get("sf-ahead"))?.authentication?.mfaAt?.getTime(),
			]) {
				expect(mfaAt).toBeGreaterThanOrEqual(before);
				expect(mfaAt).toBeLessThanOrEqual(after);
			}
		});

		it("repairs an mfaAt a replica whose clock ran ahead recorded: the next step-up brings it back to the store's now", async () => {
			// Written by a replica ten minutes ahead, a stored mfaAt is ten minutes
			// in this store's future; kept as the later of the two, it would never
			// come back. Only this process's Date is moved, so a Redis store's
			// socket and timers are untouched.
			const store = await capable();
			const realNow = Date.now();
			vi.useFakeTimers({ toFake: ["Date"] });
			try {
				vi.setSystemTime(realNow + 10 * 60_000);
				await store.create(
					INPUT({
						sid: "sf-repair",
						amr: ["pwd", "otp", "mfa"],
						authentication: { ...PASSWORD_LOGIN, mfaAt: new Date() },
					}),
				);
			} finally {
				vi.useRealTimers();
			}
			expect((await store.get("sf-repair"))?.authentication?.mfaAt?.getTime()).toBeGreaterThan(
				Date.now(),
			);
			const before = Date.now();
			const recorded = await store.recordSecondFactor("sf-repair", {
				amr: ["otp", "mfa"],
				at: new Date(before - 1_000),
			});
			const after = Date.now();
			for (const mfaAt of [
				recorded?.authentication?.mfaAt?.getTime(),
				(await store.get("sf-repair"))?.authentication?.mfaAt?.getTime(),
			]) {
				expect(mfaAt).toBeGreaterThanOrEqual(before);
				expect(mfaAt).toBeLessThanOrEqual(after);
			}
		});

		it("keeps its own copy: neither the event nor what it answers changes what is stored", async () => {
			const store = await capable();
			await store.create(INPUT({ sid: "sf-iso", amr: ["pwd"], authentication: PASSWORD_LOGIN }));
			const verifiedAt = at(1_000);
			const event = { amr: ["otp", "mfa"], at: new Date(verifiedAt.getTime()) };
			const recorded = await store.recordSecondFactor("sf-iso", event);
			event.amr.push("hwk");
			event.at.setTime(0);
			(recorded?.amr as string[] | undefined)?.push("phr");
			recorded?.authentication?.mfaAt?.setTime(0);
			const stored = await store.get("sf-iso");
			expect(stored?.amr).toEqual(["pwd", "otp", "mfa"]);
			expect(stored?.authentication?.mfaAt?.getTime()).toBe(verifiedAt.getTime());
		});

		it("records two second factors verified at once: neither is lost", async () => {
			// Two step-ups in flight on one session: a store that read, merged
			// and wrote without noticing the other write would drop one.
			const store = await capable();
			await store.create(INPUT({ sid: "sf-race", amr: ["pwd"], authentication: PASSWORD_LOGIN }));
			const earlier = at(2_000);
			const later = at(1_000);
			await Promise.all([
				store.recordSecondFactor("sf-race", { amr: ["otp", "mfa"], at: earlier }),
				store.recordSecondFactor("sf-race", { amr: ["hwk", "mfa"], at: later }),
			]);
			const stored = await store.get("sf-race");
			expect(new Set(stored?.amr)).toEqual(new Set(["pwd", "otp", "hwk", "mfa"]));
			expect(stored?.amr?.[0]).toBe("pwd");
			expect(stored?.amr?.filter((value) => value === "mfa")).toHaveLength(1);
			expect(stored?.authentication?.mfaAt?.getTime()).toBe(later.getTime());
		});
		it("adds to a trusted federation's recorded session: its IdP's values stay, and nothing is split out", async () => {
			const store = await capable();
			const federated = {
				primary: "fed",
				federation: "google",
				upstreamAmr: undefined,
				mfaAt: undefined,
			};
			await store.create(
				INPUT({ sid: "sf-fed-trusted", amr: ["hwk", "fed"], authentication: federated }),
			);
			const verifiedAt = at(1_000);
			const recorded = await store.recordSecondFactor("sf-fed-trusted", {
				amr: ["otp", "mfa"],
				at: verifiedAt,
			});
			expect(recorded?.amr).toEqual(["hwk", "fed", "otp", "mfa"]);
			expect(recorded?.authentication).toStrictEqual({ ...federated, mfaAt: verifiedAt });
			expect((await store.get("sf-fed-trusted"))?.authentication).toStrictEqual({
				...federated,
				mfaAt: verifiedAt,
			});
		});

		it("adds to an untrusted federation's recorded session: what its IdP asserted stays apart, never vouched for", async () => {
			const store = await capable();
			const federated = {
				primary: "fed",
				federation: "google",
				upstreamAmr: ["hwk"],
				mfaAt: undefined,
			};
			await store.create(
				INPUT({ sid: "sf-fed-untrusted", amr: ["fed"], authentication: federated }),
			);
			const verifiedAt = at(1_000);
			const recorded = await store.recordSecondFactor("sf-fed-untrusted", {
				amr: ["otp", "mfa"],
				at: verifiedAt,
			});
			expect(recorded?.amr).toEqual(["fed", "otp", "mfa"]);
			expect(recorded?.authentication).toStrictEqual({ ...federated, mfaAt: verifiedAt });
			expect((await store.get("sf-fed-untrusted"))?.authentication?.upstreamAmr).toEqual(["hwk"]);
		});
	});
}
