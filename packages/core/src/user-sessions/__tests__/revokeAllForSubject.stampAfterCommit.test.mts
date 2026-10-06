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
 * A subject revocation's boundary covers every token minted before its write
 * took effect, not only those minted before the stamp time was read: a write
 * that commits late is stamped again once it has, until a write commits
 * within the settling bound, a bounded number of times.
 */

import { describe, expect, it, vi } from "vitest";
import {
	claimCoveredByRevocationBoundary,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
} from "#/jwt/verify.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { revokeAllForSubject } from "#/user-sessions/revokeAllForSubject.mjs";
import { createSubjectRevocationService } from "#/user-sessions/subjectRevocationService.mjs";
import type { SubjectRevocation, SupportsSessionsOnlyRevocation } from "#/user-sessions/types.mjs";

const TTL = 3_600_000;
const T0 = 1_790_000_000_000;

/** A clock the test moves. */
const clockAt = (startMs: number) => {
	let ms = startMs;
	return { now: () => ms, set: (to: number) => (ms = to) };
};

/**
 * The memory store behind writes that take `delaysMs[n]` of the clock to
 * commit (the last delay for every later write): the clock moves on before
 * the write lands, as a slow backend's does.
 */
const slowStore = (clock: ReturnType<typeof clockAt>, delaysMs: readonly number[]) => {
	const inner = createInMemorySubjectRevocation({ now: clock.now });
	const writes: number[] = [];
	const late =
		(write: (subject: string, before: Date, expiresAt: Date) => Promise<void>) =>
		async (subject: string, before: Date, expiresAt: Date) => {
			const delayMs = delaysMs[Math.min(writes.length, delaysMs.length - 1)] ?? 0;
			writes.push(before.getTime());
			clock.set(clock.now() + delayMs);
			await write(subject, before, expiresAt);
		};
	const store: SubjectRevocation & SupportsSessionsOnlyRevocation = {
		kind: "slow",
		revokeBefore: late((s, b, e) => inner.revokeBefore(s, b, e)),
		revokeSessionsBefore: late((s, b, e) => inner.revokeSessionsBefore(s, b, e)),
		revokedBefore: (s) => inner.revokedBefore(s),
		grantsRevokedBefore: (s) => inner.grantsRevokedBefore(s),
	};
	return { store, writes };
};

const covered = async (store: SubjectRevocation, iatSeconds: number): Promise<boolean> =>
	claimCoveredByRevocationBoundary(
		iatSeconds,
		await store.revokedBefore("user-1"),
		DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
	);

describe("revokeAllForSubject stamps its boundary after the write commits", () => {
	it("covers a token minted while the boundary write was still in flight", async () => {
		const clock = clockAt(T0);
		const { store, writes } = slowStore(clock, [5_000, 0]);
		// Minted four seconds into a write that takes five to commit.
		const mintedIat = Math.floor((T0 + 4_000) / 1000);
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: store,
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
		});
		expect(result.tokensRevoked).toBe(true);
		expect(writes).toEqual([T0, T0 + 5_000]);
		expect(await covered(store, mintedIat)).toBe(true);
	});

	it("covers a token minted near the end of a slow second write, stamping again until a write settles", async () => {
		const clock = clockAt(T0);
		const { store, writes } = slowStore(clock, [5_000, 5_000, 0]);
		// Minted just before the second write, which takes five seconds, commits.
		const mintedIat = Math.floor((T0 + 9_900) / 1000);
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: store,
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
		});
		expect(writes).toEqual([T0, T0 + 5_000, T0 + 10_000]);
		expect(result.tokensRevoked).toBe(true);
		expect(result.failures).toEqual([]);
		expect(await covered(store, mintedIat)).toBe(true);
	});

	it("takes a write that commits within 250 ms as settled, and one slower as not", async () => {
		for (const [delay, stamps] of [
			[250, 2],
			[251, 3],
		] as const) {
			const clock = clockAt(T0);
			const { store, writes } = slowStore(clock, [5_000, delay, 0]);
			await revokeAllForSubject({
				subject: "user-1",
				watermarkTtlMs: TTL,
				subjectRevocation: store,
				cascadeSession: async () => ({ ok: true }),
				now: clock.now,
			});
			expect(writes, String(delay)).toHaveLength(stamps);
		}
	});

	it("stops after four stamps when no write settles, and reports the boundary as a failed second stamp", async () => {
		const clock = clockAt(T0);
		const { store, writes } = slowStore(clock, [5_000]);
		const error = vi.fn();
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: store,
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as never,
		});
		expect(writes).toEqual([T0, T0 + 5_000, T0 + 10_000, T0 + 15_000]);
		expect(result.tokensRevoked).toBe(true);
		expect(result.complete).toBe(false);
		expect(result.failures).toEqual([
			{
				capability: "subjectRevocation",
				operation: "revokeBefore",
				stamp: 2,
				error: expect.any(Error),
			},
		]);
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ stamp: 2 }),
			"revoke_all_watermark_failed",
		);
		expect((await store.revokedBefore("user-1"))?.getTime()).toBe(T0 + 15_000);
	});

	it("never moves the boundary back, even when the clock stepped back between the stamps", async () => {
		const clock = clockAt(T0);
		const inner = createInMemorySubjectRevocation({ now: clock.now });
		const store: SubjectRevocation = {
			kind: "stepping",
			async revokeBefore(subject, before, expiresAt) {
				await inner.revokeBefore(subject, before, expiresAt);
				clock.set(T0 - 60_000);
			},
			revokedBefore: (s) => inner.revokedBefore(s),
		};
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: store,
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
		});
		expect((await store.revokedBefore("user-1"))?.getTime()).toBe(T0);
	});

	it("reports a second stamp that fails, with the boundary of the first still in force", async () => {
		const clock = clockAt(T0);
		const inner = createInMemorySubjectRevocation({ now: clock.now });
		let calls = 0;
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: {
				kind: "second-fails",
				async revokeBefore(subject, before, expiresAt) {
					calls += 1;
					if (calls === 2) throw new Error("store is down");
					await inner.revokeBefore(subject, before, expiresAt);
				},
				revokedBefore: (s) => inner.revokedBefore(s),
			},
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
		});
		expect(result.tokensRevoked).toBe(true);
		expect(result.complete).toBe(false);
		expect(result.failures).toEqual([
			expect.objectContaining({
				capability: "subjectRevocation",
				operation: "revokeBefore",
				stamp: 2,
			}),
		]);
		expect((await inner.revokedBefore("user-1"))?.getTime()).toBe(T0);
	});

	it("logs which stamp failed", async () => {
		const error = vi.fn();
		let calls = 0;
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: {
				kind: "second-fails",
				async revokeBefore() {
					calls += 1;
					if (calls === 2) throw new Error("store is down");
				},
				revokedBefore: async () => null,
			},
			cascadeSession: async () => ({ ok: true }),
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as never,
		});
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ stamp: 2 }),
			"revoke_all_watermark_failed",
		);
	});

	it("stamps again when the first write throws, since it may have committed first", async () => {
		const clock = clockAt(T0);
		const inner = createInMemorySubjectRevocation({ now: clock.now });
		let calls = 0;
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: {
				kind: "first-fails",
				async revokeBefore(subject, before, expiresAt) {
					calls += 1;
					if (calls === 1) {
						clock.set(clock.now() + 5_000);
						throw new Error("timed out");
					}
					await inner.revokeBefore(subject, before, expiresAt);
				},
				revokedBefore: (s) => inner.revokedBefore(s),
			},
			cascadeSession: async () => ({ ok: true }),
			now: clock.now,
		});
		expect(calls).toBe(2);
		expect(result.tokensRevoked).toBe(true);
		expect(result.complete).toBe(false);
		expect(result.failures).toEqual([
			expect.objectContaining({ operation: "revokeBefore", stamp: 1 }),
		]);
		expect((await inner.revokedBefore("user-1"))?.getTime()).toBe(T0 + 5_000);
	});

	it("reports the second write's error when both throw, and no boundary written", async () => {
		const second = new Error("still down");
		let calls = 0;
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: {
				kind: "down",
				async revokeBefore() {
					calls += 1;
					throw calls === 1 ? new Error("down") : second;
				},
				revokedBefore: async () => null,
			},
			cascadeSession: async () => ({ ok: true }),
		});
		expect(calls).toBe(2);
		expect(result.tokensRevoked).toBe(false);
		expect(result.failures).toEqual([
			expect.objectContaining({ operation: "revokeBefore", stamp: 2, error: second }),
		]);
	});

	it("refuses a watermark lifetime that is not a positive whole number of milliseconds, before any write", async () => {
		for (const watermarkTtlMs of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			let calls = 0;
			await expect(
				revokeAllForSubject({
					subject: "user-1",
					watermarkTtlMs,
					subjectRevocation: {
						kind: "spy",
						async revokeBefore() {
							calls += 1;
						},
						revokedBefore: async () => null,
					},
					cascadeSession: async () => ({ ok: true }),
				}),
				String(watermarkTtlMs),
			).rejects.toThrow(RangeError);
			expect(calls).toBe(0);
		}
	});
});

describe("the subject revocation service's sessions-only stamp, likewise", () => {
	it("covers a token minted while the sessions-only write was in flight", async () => {
		const clock = clockAt(T0);
		const { store, writes } = slowStore(clock, [5_000, 0]);
		const mintedIat = Math.floor((T0 + 4_000) / 1000);
		const service = createSubjectRevocationService({
			subjectRevocation: store,
			cascadeSession: async () => ({ ok: true }),
			watermarkTtlMs: TTL,
			allowKeep: true,
			now: clock.now,
		} as Parameters<typeof createSubjectRevocationService>[0]);
		const result = await service.revokeAllForSubject({
			subject: "user-1",
			federationGrants: "keep",
		});
		expect(result.tokensRevoked).toBe(true);
		expect(writes).toEqual([T0, T0 + 5_000]);
		expect(await covered(store, mintedIat)).toBe(true);
		// The grants boundary stays where it was: the stamps were sessions-only.
		expect(await store.grantsRevokedBefore("user-1")).toBeNull();
	});

	it("stamps again until a write settles, and stops after four stamps when none does", async () => {
		const settling = clockAt(T0);
		const slowSecond = slowStore(settling, [5_000, 5_000, 0]);
		const mintedIat = Math.floor((T0 + 9_900) / 1000);
		const settled = await createSubjectRevocationService({
			subjectRevocation: slowSecond.store,
			cascadeSession: async () => ({ ok: true }),
			watermarkTtlMs: TTL,
			allowKeep: true,
			now: settling.now,
		} as Parameters<typeof createSubjectRevocationService>[0]).revokeAllForSubject({
			subject: "user-1",
			federationGrants: "keep",
		});
		expect(slowSecond.writes).toEqual([T0, T0 + 5_000, T0 + 10_000]);
		expect(settled.failures).toEqual([]);
		expect(await covered(slowSecond.store, mintedIat)).toBe(true);

		const never = clockAt(T0);
		const slow = slowStore(never, [5_000]);
		const unsettled = await createSubjectRevocationService({
			subjectRevocation: slow.store,
			cascadeSession: async () => ({ ok: true }),
			watermarkTtlMs: TTL,
			allowKeep: true,
			now: never.now,
		} as Parameters<typeof createSubjectRevocationService>[0]).revokeAllForSubject({
			subject: "user-1",
			federationGrants: "keep",
		});
		expect(slow.writes).toHaveLength(4);
		expect(unsettled.tokensRevoked).toBe(true);
		expect(unsettled.complete).toBe(false);
		expect(unsettled.failures).toEqual([
			expect.objectContaining({ operation: "revokeSessionsBefore", stamp: 2 }),
		]);
	});
});
