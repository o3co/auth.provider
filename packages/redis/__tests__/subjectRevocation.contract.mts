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
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SubjectRevocationFactoryForContract = () => Promise<SubjectRevocation>;

const LONG = () => new Date(Date.now() + 600_000);

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

/**
 * Behaviour every {@link SubjectRevocation} adapter owes its callers (#321).
 *
 * The load-bearing property is **monotonicity**. Two credential changes in
 * quick succession, the second computed on a replica whose clock is behind,
 * must not move the line backwards and resurrect every token the first one
 * killed. That is a `max` on write, not a last-writer-wins `SET` — which is
 * why the distributed adapter needs an atomic read-compare-write rather than
 * the plain `SET key value PX ttl` the shape looks like it should be.
 *
 * The same guard applies to the entry's own expiry: shortening an in-force
 * watermark would retire the line while tokens it must refuse are still
 * presentable.
 *
 * Expiry-over-time cases are left to each adapter's own suite — a distributed
 * adapter's clock is the server's, which fake timers cannot move — but the
 * post-expiry *semantics* (a truncated expiry would have lapsed) are pinned
 * here, with an expiry a second out, waited out on the store's own clock
 * (`ExpiryClock`).
 */
export function runSubjectRevocationContract(
	factory: SubjectRevocationFactoryForContract,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	describe("SubjectRevocation contract", () => {
		it("returns null for a subject with no watermark", async () => {
			expect(await (await factory()).revokedBefore("u1")).toBeNull();
		});

		it("returns the watermark it was given", async () => {
			const store = await factory();
			const before = new Date(1_000_000);
			await store.revokeBefore("u1", before, LONG());
			expect((await store.revokedBefore("u1"))?.getTime()).toBe(before.getTime());
		});

		it("keeps subjects apart", async () => {
			const store = await factory();
			await store.revokeBefore("u1", new Date(1_000_000), LONG());
			expect(await store.revokedBefore("u2")).toBeNull();
		});

		it("never moves the watermark backwards", async () => {
			// The whole reason a plain SET is the wrong primitive here.
			const store = await factory();
			await store.revokeBefore("u1", new Date(2_000_000), LONG());
			await store.revokeBefore("u1", new Date(1_000_000), LONG());
			expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000_000);
		});

		it("advances the watermark when the newer value is later", async () => {
			const store = await factory();
			await store.revokeBefore("u1", new Date(1_000_000), LONG());
			await store.revokeBefore("u1", new Date(2_000_000), LONG());
			expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000_000);
		});

		it("keeps the longer of two expiries when merging", async () => {
			// Shortening an in-force watermark would retire the line while tokens
			// it must kill are still presentable. Asserted through the surviving
			// value: a truncated entry would have expired by the time it is read.
			const expiry = options.expiry ?? hostExpiry;
			const store = await factory();
			await store.revokeBefore("u1", new Date(1_000), LONG());
			const short = await aheadOf(expiry);
			await store.revokeBefore("u1", new Date(2_000), short);
			await expiry.passed(short);
			expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000);
		});

		it("reports an adapter kind", async () => {
			expect((await factory()).kind).toBeTruthy();
		});
	});
}

/**
 * What an adapter owes once it claims {@link SupportsSessionsOnlyRevocation}
 * (#593, D13).
 *
 * The capability exists because a password change and "revoke everything" are
 * different events. What makes it safe is that the narrower one can only ever
 * do less: `revokeSessionsBefore` may move the sessions line forward and must
 * leave the grants line exactly where it was, including absent. An adapter
 * that derived one from the other — or that took a single maximum across both
 * — would either revoke the grants a caller asked to keep, or rescue grants an
 * earlier revocation had ended. Both are silent.
 */
export function runSessionsOnlyRevocationContract(
	factory: SubjectRevocationFactoryForContract,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	const capable = async (): Promise<SubjectRevocation & SupportsSessionsOnlyRevocation> => {
		const store = await factory();
		if (!supportsSessionsOnlyRevocation(store)) {
			throw new Error("this adapter does not claim SupportsSessionsOnlyRevocation");
		}
		return store;
	};

	describe("SupportsSessionsOnlyRevocation contract", () => {
		it("answers null for each boundary independently", async () => {
			const store = await capable();
			expect(await store.revokedBefore("c-u0")).toBeNull();
			expect(await store.grantsRevokedBefore("c-u0")).toBeNull();
		});

		it("advances both boundaries when the existing method is called", async () => {
			// The compatibility argument in one test: an unchanged call site
			// still ends the subject's grants.
			const store = await capable();
			await store.revokeBefore("c-u1", new Date(1_000_000), LONG());
			expect((await store.revokedBefore("c-u1"))?.getTime()).toBe(1_000_000);
			expect((await store.grantsRevokedBefore("c-u1"))?.getTime()).toBe(1_000_000);
		});

		it("advances only the sessions boundary when asked to", async () => {
			const store = await capable();
			await store.revokeSessionsBefore("c-u2", new Date(1_000_000), LONG());
			expect((await store.revokedBefore("c-u2"))?.getTime()).toBe(1_000_000);
			expect(await store.grantsRevokedBefore("c-u2")).toBeNull();
		});

		it("keeps each boundary's own maximum, in either order", async () => {
			// Two replicas, two clocks: a sessions-only stamp at the later
			// instant followed by a delayed full revocation at the earlier one.
			// Deriving the grants boundary from the resulting sessions boundary
			// would revoke grants consented in between.
			const store = await capable();
			await store.revokeSessionsBefore("c-u3", new Date(2_000_000), LONG());
			await store.revokeBefore("c-u3", new Date(1_000_000), LONG());
			expect((await store.revokedBefore("c-u3"))?.getTime()).toBe(2_000_000);
			expect((await store.grantsRevokedBefore("c-u3"))?.getTime()).toBe(1_000_000);
		});

		it("never lets a sessions-only stamp rescue an ended grant", async () => {
			const store = await capable();
			await store.revokeBefore("c-u4", new Date(1_000_000), LONG());
			await store.revokeSessionsBefore("c-u4", new Date(9_000_000), LONG());
			expect((await store.grantsRevokedBefore("c-u4"))?.getTime()).toBe(1_000_000);
		});

		it("hands back dates a caller cannot use to edit the record", async () => {
			const store = await capable();
			await store.revokeBefore("c-u5", new Date(1_000_000), LONG());
			(await store.revokedBefore("c-u5"))?.setTime(7);
			(await store.grantsRevokedBefore("c-u5"))?.setTime(7);
			expect((await store.revokedBefore("c-u5"))?.getTime()).toBe(1_000_000);
			expect((await store.grantsRevokedBefore("c-u5"))?.getTime()).toBe(1_000_000);
		});

		it("refuses an instant that is not one, and changes nothing doing it", async () => {
			// Every comparison with NaN is false, so a NaN boundary is one that
			// covers nothing while looking like a boundary.
			const store = await capable();
			await store.revokeBefore("c-u6", new Date(1_000_000), LONG());
			await expect(
				store.revokeSessionsBefore("c-u6", new Date(Number.NaN), LONG()),
			).rejects.toThrow();
			await expect(
				store.revokeBefore("c-u6", new Date(2_000_000), new Date(Number.NaN)),
			).rejects.toThrow();
			expect((await store.revokedBefore("c-u6"))?.getTime()).toBe(1_000_000);
		});

		it("keeps a full revocation past the expiry its caller asked for", async () => {
			// The floor is the adapter's, not the helper's: a direct stamp with
			// a short TTL must be as safe as one made through the service, or a
			// grant consented for a year outlives the boundary that ended it.
			//
			// The boundary is `now`, as a real caller's is, because the floor is
			// anchored to the boundary rather than to a clock reading: what it
			// has to outlive is every grant consented BEFORE that instant, and a
			// boundary dated 1970 plus a year covers grants that do not exist.
			const expiry = options.expiry ?? hostExpiry;
			const store = await capable();
			const before = new Date();
			const asked = await aheadOf(expiry);
			await store.revokeBefore("c-u7", before, asked);
			await expiry.passed(asked);
			expect((await store.revokedBefore("c-u7"))?.getTime()).toBe(before.getTime());
			expect((await store.grantsRevokedBefore("c-u7"))?.getTime()).toBe(before.getTime());
		});

		it("still lets a sessions-only stamp lapse on the expiry it was given", async () => {
			const expiry = options.expiry ?? hostExpiry;
			const store = await capable();
			const asked = await aheadOf(expiry);
			await store.revokeSessionsBefore("c-u8", new Date(1_000_000), asked);
			expect((await store.revokedBefore("c-u8"))?.getTime()).toBe(1_000_000);
			await expiry.passed(asked);
			expect(await store.revokedBefore("c-u8")).toBeNull();
		});
	});
}
