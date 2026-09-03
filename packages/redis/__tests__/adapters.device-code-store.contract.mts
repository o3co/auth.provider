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

const seed = {
	deviceCode: "dc-aaaaaaaaaaaaaaaaaaaa",
	userCode: "BCDFGHJK",
	clientId: "tv-app",
	requestedScope: ["openid", "profile"] as readonly string[],
	expiresAtMs: NOW + 10 * MINUTE,
	intervalSeconds: 5,
};

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

		it("refuses to create a second record for the same device code", async () => {
			// A collision is a generator failure. Overwriting would hand the new
			// device the old one's pending approval.
			await withStore(async (store) => {
				await store.create(seed);
				await expect(store.create({ ...seed, userCode: "MNPQRSTV" })).rejects.toThrow();
			});
		});

		it("refuses to create a second record for the same user code", async () => {
			await withStore(async (store) => {
				await store.create(seed);
				await expect(store.create({ ...seed, deviceCode: "dc-bbbb" })).rejects.toThrow();
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
