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
 * Conformance suite for `DeviceCodeStore` (#298) — the copy `@o3co/auth-provider-redis`
 * runs against its adapter (#433).
 *
 * Duplicated from `packages/core/src/device-authorization/__tests__/adapters.contract.mts`,
 * differing only in how it imports the port type: a contract file cannot be
 * imported across a package boundary (see `docs/adapter-surface.md`, "Proving
 * an implementation"). Keep the two in step.
 *
 * Every implementation runs this — the in-memory one in core, the Redis one
 * in `@o3co/auth-provider-redis`, and anything an operator writes. The port's
 * atomicity requirements are the whole reason it exists: a Redis adapter that
 * implements `poll` as `GET` then `DEL` passes a naive unit test and issues
 * two access tokens for one approval under concurrency, so the cases that
 * matter most here are the ones that call the same method twice.
 */

import type { DeviceCodeStore } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export interface DeviceCodeStoreContractFactory {
	/** A fresh, empty store for one test. */
	create(): Promise<DeviceCodeStore> | DeviceCodeStore;
	/** Optional teardown (close client, flush db). */
	destroy?(store: DeviceCodeStore): Promise<void> | void;
}

const NOW = 1_800_000_000_000;
const MINUTE = 60_000;
/** When the approving session authenticated: before the approval, as it always is. */
const AUTH_TIME_MS = NOW - 5 * MINUTE;

const seed = {
	deviceCode: "dc-aaaaaaaaaaaaaaaaaaaa",
	userCode: "BCDFGHJK",
	clientId: "tv-app",
	requestedScope: ["openid", "profile"] as readonly string[],
	expiresAtMs: NOW + 10 * MINUTE,
	intervalSeconds: 5,
};

/**
 * Expiries no store may be handed: not finite (NaN, from an Invalid Date or an
 * unset setting; ±Infinity), or outside ECMAScript's Date range (±8.64e15 ms).
 * NaN is never `<= now`, so it passes every past-expiry check; one past the
 * Date range is a number Redis cannot take as a deadline (`1e21` is sent as
 * `1e+21`) and a Date cannot hold, and a script that writes its record before
 * setting the deadline would leave the record with no TTL at all.
 */
const UNSTORABLE_EXPIRIES = [
	Number.NaN,
	Number.POSITIVE_INFINITY,
	Number.NEGATIVE_INFINITY,
	8_640_000_000_000_001,
	1e21,
	-1e21,
];

/**
 * `amr` values no store may record: not a non-empty list of non-empty strings.
 * A hole in a list reads as `undefined`, which is not a string.
 */
const UNSTORABLE_AMRS = [
	[],
	[""],
	["pwd", ""],
	[1],
	["pwd", undefined],
	// biome-ignore lint/suspicious/noSparseArray: a hole is one of the malformed lists
	["pwd", , "mfa"],
	"pwd",
	null,
	{ 0: "pwd", length: 1 },
] as unknown as ReadonlyArray<readonly string[]>;

/** Authentication instants no store may record: not a valid `Date`, or before the epoch. */
const UNSTORABLE_AUTH_TIMES = [
	new Date(Number.NaN),
	new Date(-1),
	AUTH_TIME_MS,
	String(AUTH_TIME_MS),
	null,
] as unknown as ReadonlyArray<Date>;

export const runDeviceCodeStoreContract = (
	name: string,
	factory: DeviceCodeStoreContractFactory,
): void => {
	describe(`DeviceCodeStore contract — ${name}`, () => {
		const withStore = async (body: (store: DeviceCodeStore) => Promise<void>): Promise<void> => {
			const store = await factory.create();
			try {
				await body(store);
			} finally {
				await factory.destroy?.(store);
			}
		};

		it("finds a freshly created authorization by its user code", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				const found = await store.findPendingByUserCode(seed.userCode, NOW);
				expect(found).toMatchObject({
					userCode: seed.userCode,
					clientId: seed.clientId,
					status: "pending",
					intervalSeconds: 5,
				});
				expect(found?.requestedScope).toEqual(["openid", "profile"]);
			});
		});

		it("refuses to create a second record for the same device code, saying it collided", async () => {
			// A collision is a generator failure. Overwriting would hand the new
			// device the old one's pending approval. It is signalled as one — the
			// endpoint re-draws for that and for nothing else, so a store that
			// cannot be reached is not mistaken for an unlucky draw.
			await withStore(async (store) => {
				await store.create(seed);
				await expect(store.create({ ...seed, userCode: "MNPQRSTV" })).rejects.toMatchObject({
					name: "DeviceCodeStoreError",
					reason: "collision",
				});
			});
		});

		it("refuses to create a second record for the same user code, saying it collided", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await expect(store.create({ ...seed, deviceCode: "dc-bbbb" })).rejects.toMatchObject({
					name: "DeviceCodeStoreError",
					reason: "collision",
				});
			});
		});

		it("refuses an expiry that is not a finite number within the Date range, and records nothing", async () => {
			// A non-finite expiry is a caller fault (see `UNSTORABLE_EXPIRIES`).
			await withStore(async (store) => {
				for (const bad of UNSTORABLE_EXPIRIES) {
					await expect(store.create({ ...seed, expiresAtMs: bad })).rejects.toThrow(RangeError);
					expect(await store.findPendingByUserCode(seed.userCode, NOW)).toBeNull();
					expect(await store.poll(seed.deviceCode, NOW)).toEqual({ status: "not_found" });
				}
				// Nothing was recorded, so neither code collides.
				await store.create(seed);
				expect(await store.poll(seed.deviceCode, NOW)).toEqual({ status: "pending" });
			});
		});

		it("accepts a fractional expiry, and holds the authorization until exactly it", async () => {
			// A code lifetime in fractional seconds makes one. Redis's PEXPIREAT
			// takes whole milliseconds, so the keys' deadline is rounded up; the
			// record's own expiry — what `poll` answers from — is the one asked for.
			await withStore(async (store) => {
				const expiresAtMs = seed.expiresAtMs + 0.5;
				await store.create({ ...seed, expiresAtMs });
				expect(await store.findPendingByUserCode(seed.userCode, NOW)).toMatchObject({
					expiresAtMs,
					status: "pending",
				});
				expect(await store.poll(seed.deviceCode, expiresAtMs - 0.25)).toEqual({
					status: "pending",
				});
				expect(await store.poll(seed.deviceCode, expiresAtMs)).toEqual({ status: "expired" });
			});
		});

		it("does not surface an expired authorization to the verification page", async () => {
			// Displaying a code that can no longer be approved invites the user
			// to approve nothing and wonder why the device never proceeds.
			await withStore(async (store) => {
				await store.create(seed);
				expect(await store.findPendingByUserCode(seed.userCode, seed.expiresAtMs + 1)).toBeNull();
			});
		});

		it("reports pending while nobody has answered", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				expect(await store.poll(seed.deviceCode, NOW)).toEqual({ status: "pending" });
			});
		});

		it("reports not_found for a device code that was never issued", async () => {
			await withStore(async (store) => {
				expect(await store.poll("never-issued", NOW)).toEqual({ status: "not_found" });
			});
		});

		it("hands back every field with its own value, through each read", async () => {
			// The types make a store name every field; they cannot see two of the
			// same type swapped — `requestedScope` and `grantedScope` are both
			// scope lists. Granted is narrowed below requested here, so a swap
			// shows, and the whole record is compared at each step.
			await withStore(async (store) => {
				await store.create(seed);
				const pending = {
					userCode: seed.userCode,
					clientId: seed.clientId,
					requestedScope: ["openid", "profile"],
					expiresAtMs: seed.expiresAtMs,
					intervalSeconds: seed.intervalSeconds,
					status: "pending",
					subject: undefined,
					grantedScope: undefined,
					approvedAtMs: undefined,
					amr: undefined,
					authTimeMs: undefined,
				};
				expect(await store.findPendingByUserCode(seed.userCode, NOW)).toStrictEqual(pending);

				// The authentication instant is earlier than the approval, so the two
				// instants swapped show too.
				const approved = {
					...pending,
					status: "approved",
					subject: "user-1",
					grantedScope: ["profile"],
					approvedAtMs: NOW,
					amr: ["pwd", "otp", "mfa"],
					authTimeMs: AUTH_TIME_MS,
				};
				expect(
					await store.approve({
						userCode: seed.userCode,
						subject: "user-1",
						grantedScope: ["profile"],
						nowMs: NOW,
						amr: ["pwd", "otp", "mfa"],
						authTime: new Date(AUTH_TIME_MS),
					}),
				).toStrictEqual({ status: "ok", authorization: approved });
				expect(await store.poll(seed.deviceCode, NOW + 10 * 1000)).toStrictEqual({
					status: "approved",
					authorization: approved,
				});
			});
		});

		it("names every key of a scopeless request, and of a denial", async () => {
			// The fields that hold `undefined` here are the ones a store might
			// leave out rather than name; `toStrictEqual` fails on a missing key
			// where `toEqual` would pass.
			await withStore(async (store) => {
				await store.create({ ...seed, requestedScope: undefined });
				const pending = {
					userCode: seed.userCode,
					clientId: seed.clientId,
					requestedScope: undefined,
					expiresAtMs: seed.expiresAtMs,
					intervalSeconds: seed.intervalSeconds,
					status: "pending",
					subject: undefined,
					grantedScope: undefined,
					approvedAtMs: undefined,
					amr: undefined,
					authTimeMs: undefined,
				};
				expect(await store.findPendingByUserCode(seed.userCode, NOW)).toStrictEqual(pending);
				expect(await store.deny(seed.userCode, NOW)).toStrictEqual({
					status: "ok",
					authorization: { ...pending, status: "denied" },
				});
			});
		});

		it("names every key of a scopeless approval, which grants the empty set", async () => {
			// `grantedScope` is `undefined` only before approval. A request that
			// asked for no scope, approved without one, grants the empty set —
			// adapters intersect with `requestedScope` — and every other key is
			// still named on both reads.
			await withStore(async (store) => {
				await store.create({ ...seed, requestedScope: undefined });
				const approved = {
					userCode: seed.userCode,
					clientId: seed.clientId,
					requestedScope: undefined,
					expiresAtMs: seed.expiresAtMs,
					intervalSeconds: seed.intervalSeconds,
					status: "approved",
					subject: "user-1",
					grantedScope: [],
					approvedAtMs: NOW,
					amr: undefined,
					authTimeMs: undefined,
				};
				expect(
					await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW }),
				).toStrictEqual({ status: "ok", authorization: approved });
				expect(await store.poll(seed.deviceCode, NOW + 10 * 1000)).toStrictEqual({
					status: "approved",
					authorization: approved,
				});
			});
		});

		it("records when the approval was given — the instant the approve call was handed — and hands it to the poll", async () => {
			// What a poll needs to hold an approval against a subject revocation
			// stamped between the approval and the poll: the token minted at the
			// poll postdates it, so only the approval's own instant can.
			await withStore(async (store) => {
				await store.create(seed);
				const approvedAt = NOW + 1_234;
				const decided = await store.approve({
					userCode: seed.userCode,
					subject: "user-1",
					nowMs: approvedAt,
				});
				expect(decided.status === "ok" && decided.authorization.approvedAtMs).toBe(approvedAt);
				const polled = await store.poll(seed.deviceCode, NOW + 10 * 1000);
				expect(polled.status === "approved" && polled.authorization.approvedAtMs).toBe(approvedAt);
			});
		});

		it("records the approving session's amr and authentication time, and hands them to the poll", async () => {
			// What the device's token says about how its user authenticated. The
			// grant stamps them at the poll, so the store carries them from the
			// approval to the poll unchanged.
			await withStore(async (store) => {
				await store.create(seed);
				const decided = await store.approve({
					userCode: seed.userCode,
					subject: "user-1",
					nowMs: NOW,
					amr: ["pwd", "hwk", "mfa"],
					authTime: new Date(AUTH_TIME_MS),
				});
				expect(decided).toMatchObject({
					status: "ok",
					authorization: { amr: ["pwd", "hwk", "mfa"], authTimeMs: AUTH_TIME_MS },
				});
				const polled = await store.poll(seed.deviceCode, NOW + 10 * 1000);
				expect(polled).toMatchObject({
					status: "approved",
					authorization: { amr: ["pwd", "hwk", "mfa"], authTimeMs: AUTH_TIME_MS },
				});
			});
		});

		it("keeps an approval handed neither as one that records neither: absent stays absent", async () => {
			// Absent reads as "cannot tell" downstream, which fails closed; a store
			// that filled in an amr or an instant of its own would vouch for an
			// authentication nobody reported.
			await withStore(async (store) => {
				await store.create(seed);
				const decided = await store.approve({
					userCode: seed.userCode,
					subject: "user-1",
					nowMs: NOW,
				});
				expect(decided.status === "ok" && decided.authorization).toMatchObject({
					amr: undefined,
					authTimeMs: undefined,
				});
				const polled = await store.poll(seed.deviceCode, NOW + 10 * 1000);
				expect(polled.status).toBe("approved");
				if (polled.status === "approved") {
					expect(polled.authorization).toHaveProperty("amr", undefined);
					expect(polled.authorization).toHaveProperty("authTimeMs", undefined);
				}
			});
		});

		it("keeps an approval's amr as it was handed, whatever the caller does to its array afterwards", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				const amr = ["pwd", "otp"];
				await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW, amr });
				amr.push("mfa");
				amr[0] = "fed";
				const polled = await store.poll(seed.deviceCode, NOW + 10 * 1000);
				expect(polled.status === "approved" && polled.authorization.amr).toEqual(["pwd", "otp"]);
			});
		});

		it("refuses an amr that is not a non-empty list of non-empty strings, and records nothing", async () => {
			// A caller fault. Stored, it would reach a token as an amr no reader
			// accepts, or as one that says less than the session vouched for.
			await withStore(async (store) => {
				await store.create(seed);
				for (const bad of UNSTORABLE_AMRS) {
					await expect(
						store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW, amr: bad }),
						String(bad),
					).rejects.toThrow(RangeError);
					expect(await store.findPendingByUserCode(seed.userCode, NOW)).toMatchObject({
						status: "pending",
					});
				}
				expect(
					(await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW })).status,
				).toBe("ok");
			});
		});

		it("refuses an authentication time that is not a valid Date at or after the epoch, and records nothing", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				for (const bad of UNSTORABLE_AUTH_TIMES) {
					await expect(
						store.approve({
							userCode: seed.userCode,
							subject: "user-1",
							nowMs: NOW,
							authTime: bad,
						}),
						String(bad),
					).rejects.toThrow(RangeError);
					expect(await store.findPendingByUserCode(seed.userCode, NOW)).toMatchObject({
						status: "pending",
					});
				}
				const decided = await store.approve({
					userCode: seed.userCode,
					subject: "user-1",
					nowMs: NOW,
					authTime: new Date(0),
				});
				expect(decided.status === "ok" && decided.authorization.authTimeMs).toBe(0);
			});
		});

		it("records neither on a denial", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				const decided = await store.deny(seed.userCode, NOW);
				expect(decided.status === "ok" && decided.authorization).toMatchObject({
					status: "denied",
					amr: undefined,
					authTimeMs: undefined,
				});
			});
		});

		it("keeps an empty requestedScope as asked for — an array, not no scope", async () => {
			await withStore(async (store) => {
				await store.create({ ...seed, requestedScope: [] });
				expect((await store.findPendingByUserCode(seed.userCode, NOW))?.requestedScope).toEqual([]);
			});
		});

		it("hands the approval to the first poll and nothing to the second", async () => {
			// The single most important property in this file. A `find`-then-
			// `delete` implementation passes every other test here and issues
			// two access tokens from one human approval.
			await withStore(async (store) => {
				await store.create(seed);
				await store.approve({
					userCode: seed.userCode,
					subject: "user-1",
					grantedScope: ["openid"],
					nowMs: NOW,
				});

				const first = await store.poll(seed.deviceCode, NOW + 10 * 1000);
				expect(first.status).toBe("approved");
				if (first.status === "approved") {
					expect(first.authorization.subject).toBe("user-1");
					expect(first.authorization.grantedScope).toEqual(["openid"]);
				}

				const second = await store.poll(seed.deviceCode, NOW + 20 * 1000);
				expect(second.status).toBe("not_found");
			});
		});

		it("survives two polls racing for the same approval", async () => {
			// The same property under concurrency rather than in sequence: an
			// adapter whose atomicity comes from a round trip rather than a
			// script fails here and passes the sequential test above.
			await withStore(async (store) => {
				await store.create(seed);
				await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW });

				const [a, b] = await Promise.all([
					store.poll(seed.deviceCode, NOW + 10 * 1000),
					store.poll(seed.deviceCode, NOW + 10 * 1000),
				]);
				const approvals = [a, b].filter((outcome) => outcome.status === "approved");
				expect(approvals).toHaveLength(1);
			});
		});

		it("reports denial once, then forgets the authorization", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await store.deny(seed.userCode, NOW);
				expect(await store.poll(seed.deviceCode, NOW + 10 * 1000)).toEqual({ status: "denied" });
				expect(await store.poll(seed.deviceCode, NOW + 20 * 1000)).toEqual({
					status: "not_found",
				});
			});
		});

		it("reports expiry rather than pending once the window closes", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				expect(await store.poll(seed.deviceCode, seed.expiresAtMs + 1)).toEqual({
					status: "expired",
				});
			});
		});

		it("answers slow_down when a device polls inside its interval", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await store.poll(seed.deviceCode, NOW);
				const tooSoon = await store.poll(seed.deviceCode, NOW + 1_000);
				expect(tooSoon.status).toBe("slow_down");
			});
		});

		it("increases the interval it enforces, not just the one it reports", async () => {
			// RFC 8628 §3.5 says the interval "MUST be increased by 5 seconds
			// for this and all subsequent requests". A server that says
			// slow_down while still measuring against the original interval
			// tells a compliant client to slow down forever.
			await withStore(async (store) => {
				await store.create(seed);
				await store.poll(seed.deviceCode, NOW);
				const first = await store.poll(seed.deviceCode, NOW + 1_000);
				expect(first).toMatchObject({ status: "slow_down", intervalSeconds: 10 });

				// 6s after the slow_down: inside the *new* 10s interval, so still
				// too soon — and the interval grows again.
				const second = await store.poll(seed.deviceCode, NOW + 7_000);
				expect(second).toMatchObject({ status: "slow_down", intervalSeconds: 15 });

				// Past the widened interval: back to a normal answer.
				const third = await store.poll(seed.deviceCode, NOW + 30_000);
				expect(third.status).toBe("pending");
			});
		});

		it("refuses to approve a code that was already denied", async () => {
			// A second decision must not overwrite the first, or a user who
			// denied a phishing prompt could be talked into "just trying again".
			await withStore(async (store) => {
				await store.create(seed);
				await store.deny(seed.userCode, NOW);
				expect(
					await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW }),
				).toEqual({ status: "already_decided", current: "denied" });
			});
		});

		it("refuses to approve twice", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await store.approve({ userCode: seed.userCode, subject: "user-1", nowMs: NOW });
				expect(
					await store.approve({ userCode: seed.userCode, subject: "attacker", nowMs: NOW }),
				).toEqual({ status: "already_decided", current: "approved" });
			});
		});

		it("refuses to approve an expired code", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				expect(
					await store.approve({
						userCode: seed.userCode,
						subject: "user-1",
						nowMs: seed.expiresAtMs + 1,
					}),
				).toEqual({ status: "expired" });
			});
		});

		it("reports not_found when approving a code that does not exist", async () => {
			await withStore(async (store) => {
				expect(
					await store.approve({ userCode: "ZZZZZZZZ", subject: "user-1", nowMs: NOW }),
				).toEqual({ status: "not_found" });
			});
		});

		it("removes an authorization by device code, and tolerates removing it twice", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await store.remove(seed.deviceCode);
				expect(await store.poll(seed.deviceCode, NOW)).toEqual({ status: "not_found" });
				await expect(store.remove(seed.deviceCode)).resolves.toBeUndefined();
			});
		});

		it("frees the user code once the authorization is removed", async () => {
			// Both indexes must drop together, or the user-code space leaks and
			// a later collision is reported for a record nothing can reach.
			await withStore(async (store) => {
				await store.create(seed);
				await store.remove(seed.deviceCode);
				await expect(store.create(seed)).resolves.toBeUndefined();
			});
		});
	});
};
