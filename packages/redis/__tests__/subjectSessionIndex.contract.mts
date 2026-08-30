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

import type { SubjectSessionIndex } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export type SubjectSessionIndexFactory = () => Promise<SubjectSessionIndex>;

const FUTURE = () => new Date(Date.now() + 600_000);
const SOON = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

/**
 * Behaviour every {@link SubjectSessionIndex} adapter owes its callers (#321).
 *
 * ## Why membership is compared unordered
 *
 * `SessionFamilyIndex`'s contract pins insertion order, and can: every member
 * of a sid-keyed index shares the one session's expiry, so a sorted set keyed
 * by expiry preserves the order things were added in. A subject's sessions
 * expire on their own clocks, so the natural Redis encoding — score = expiry —
 * returns them in expiry order, and the in-process Map returns them in
 * insertion order. Neither is wrong, and nothing depends on either:
 * `revokeAllForSubject` enumerates the list to cascade over it. Requiring one
 * order would force an adapter to carry a second index for nobody.
 *
 * ## Why the expiry cases use past dates rather than fake timers
 *
 * A distributed adapter's clock is the Redis server's, which `vi.useFakeTimers`
 * cannot move. Every expiry case here is therefore expressed as "already
 * expired at write time", which both a Map and a sorted-set score answer the
 * same way. Adapter-specific ageing behaviour — an entry that expires *while*
 * the index holds it — is tested per adapter, where each can reach its own
 * clock.
 */
export function runSubjectSessionIndexContract(factory: SubjectSessionIndexFactory): void {
	/** Membership without ordering — see the module comment. */
	const sids = async (index: SubjectSessionIndex, subject: string): Promise<string[]> =>
		[...(await index.listSids(subject))].sort();

	describe("SubjectSessionIndex contract", () => {
		it("lists the sessions added for a subject", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.addSid("u1", "s2", FUTURE());
			expect(await sids(index, "u1")).toEqual(["s1", "s2"]);
		});

		it("keeps subjects apart", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.addSid("u2", "s2", FUTURE());
			expect(await sids(index, "u1")).toEqual(["s1"]);
			expect(await sids(index, "u2")).toEqual(["s2"]);
		});

		it("is idempotent on a repeated sid", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.addSid("u1", "s1", FUTURE());
			expect(await sids(index, "u1")).toEqual(["s1"]);
		});

		it("removes one session without disturbing the others", async () => {
			// Why this index needs per-member removal at all: unlike the sid-keyed
			// indexes, one session ending does not end the subject.
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.addSid("u1", "s2", FUTURE());
			await index.removeSid("u1", "s1");
			expect(await sids(index, "u1")).toEqual(["s2"]);
		});

		it("drops the whole set on removeBySubject", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.addSid("u1", "s2", FUTURE());
			await index.removeBySubject("u1");
			expect(await sids(index, "u1")).toEqual([]);
		});

		it("returns an empty list for an unknown subject", async () => {
			expect(await sids(await factory(), "nobody")).toEqual([]);
		});

		it("ignores a session that has already expired", async () => {
			const index = await factory();
			await index.addSid("u1", "dead", PAST());
			expect(await sids(index, "u1")).toEqual([]);
		});

		it("expires each session on its own clock, not the subject's last write", async () => {
			// Why this index is not built on the sid-keyed sorted-set primitive:
			// that keeps ONE expiry per key, correct where every member shares a
			// session's expiry. A subject's sessions do not, so a longer-lived
			// session must not keep an already-dead one listed.
			const index = await factory();
			await index.addSid("u1", "dead", PAST());
			await index.addSid("u1", "live", FUTURE());
			expect(await sids(index, "u1")).toEqual(["live"]);
		});

		it("does not shorten a live session when a dead one is added after", async () => {
			// The same mismatch in the other direction: a later, shorter-lived
			// write must not retire a session that is still good.
			const index = await factory();
			await index.addSid("u1", "live", FUTURE());
			await index.addSid("u1", "dead", PAST());
			expect(await sids(index, "u1")).toEqual(["live"]);
		});

		it("keeps a live session listed when a shorter-lived one is added after", async () => {
			const index = await factory();
			await index.addSid("u1", "long", FUTURE());
			await index.addSid("u1", "short", SOON());
			expect(await sids(index, "u1")).toEqual(["long", "short"]);
		});

		it("drops the subject entry when its last session is removed", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await index.removeSid("u1", "s1");
			expect(await sids(index, "u1")).toEqual([]);
			// A later add for the same subject starts from a clean set.
			await index.addSid("u1", "s2", FUTURE());
			expect(await sids(index, "u1")).toEqual(["s2"]);
		});

		it("ignores removeSid for a subject it has never seen", async () => {
			// `revokeAllForSubject` calls this per cascaded session; a subject whose
			// entry expired between enumeration and removal must not throw.
			const index = await factory();
			await expect(index.removeSid("nobody", "s1")).resolves.toBeUndefined();
		});

		it("ignores removeSid for a sid the subject does not hold", async () => {
			const index = await factory();
			await index.addSid("u1", "s1", FUTURE());
			await expect(index.removeSid("u1", "other")).resolves.toBeUndefined();
			expect(await sids(index, "u1")).toEqual(["s1"]);
		});

		it("ignores removeBySubject for a subject it has never seen", async () => {
			const index = await factory();
			await expect(index.removeBySubject("nobody")).resolves.toBeUndefined();
		});

		it("reports an adapter kind", async () => {
			expect((await factory()).kind).toBeTruthy();
		});
	});
}
