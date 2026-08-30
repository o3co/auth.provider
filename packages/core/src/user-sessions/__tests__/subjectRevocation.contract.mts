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
import type { SubjectRevocation } from "../types.mjs";

export type SubjectRevocationFactoryForContract = () => Promise<SubjectRevocation>;

const LONG = () => new Date(Date.now() + 600_000);

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
 * post-expiry *semantics* (a fresh watermark is not blocked by the expired
 * one's larger value) are pinned here, expressed with a TTL short enough to
 * wait out.
 */
export function runSubjectRevocationContract(
	factory: SubjectRevocationFactoryForContract,
	options: { readonly waitPastExpiry?: (ms: number) => Promise<void> } = {},
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
			const store = await factory();
			await store.revokeBefore("u1", new Date(1_000), LONG());
			await store.revokeBefore("u1", new Date(2_000), new Date(Date.now() + 50));
			if (options.waitPastExpiry) await options.waitPastExpiry(150);
			expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000);
		});

		it("reports an adapter kind", async () => {
			expect((await factory()).kind).toBeTruthy();
		});
	});
}
