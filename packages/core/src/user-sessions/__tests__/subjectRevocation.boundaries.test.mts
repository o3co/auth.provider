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
 * The subject watermark becomes two boundaries in one record (#593, D13).
 *
 * A password change and "revoke everything" are different events, and the
 * industry treats them so — Entra leaves a confidential client's token alive
 * after a password change and revokes every class only on an explicit
 * revocation. Ending every delegation on every password change also puts the
 * price in the wrong place: each agent and each paused job then needs a new
 * login, a new grant, a new consent and a new upstream authorization.
 *
 * So `revokeBefore` — the method every existing caller already calls — keeps
 * meaning "end everything" and advances **both**. Keeping grants is the new,
 * narrower operation and takes a deliberate call. A Store that upgrades
 * without touching its call site therefore still ends the subject's grants,
 * exactly as one watermark would.
 */

import { describe, expect, it } from "vitest";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { SUBJECT_REVOCATION_MIN_RETENTION_MS } from "#/user-sessions/retention.mjs";
import { supportsSessionsOnlyRevocation } from "#/user-sessions/types.mjs";

const at = (ms: number) => new Date(ms);
const YEAR = 31_536_000_000;
const far = () => at(Date.now() + YEAR * 2);

const capable = () => {
	const store = createInMemorySubjectRevocation();
	if (!supportsSessionsOnlyRevocation(store))
		throw new Error("the bundled adapter lost the capability");
	return store;
};

describe("supportsSessionsOnlyRevocation", () => {
	it("is detected by both methods being there, as every other capability is", () => {
		expect(supportsSessionsOnlyRevocation(createInMemorySubjectRevocation())).toBe(true);
		const half = {
			kind: "half",
			revokeBefore: async () => undefined,
			revokedBefore: async () => null,
			// One of the two, which is not the capability.
			grantsRevokedBefore: async () => null,
		};
		expect(supportsSessionsOnlyRevocation(half as never)).toBe(false);
		const old = {
			kind: "old",
			revokeBefore: async () => undefined,
			revokedBefore: async () => null,
		};
		expect(supportsSessionsOnlyRevocation(old as never)).toBe(false);
	});
});

describe("the two boundaries", () => {
	it("answers nothing for a subject that has none", async () => {
		const store = capable();
		expect(await store.revokedBefore("u")).toBeNull();
		expect(await store.grantsRevokedBefore("u")).toBeNull();
	});

	it("advances both when the existing method is called", async () => {
		// The whole compatibility argument: an unchanged call site still ends
		// the subject's grants.
		const store = capable();
		await store.revokeBefore("u", at(1_000), far());
		expect((await store.revokedBefore("u"))?.getTime()).toBe(1_000);
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(1_000);
	});

	it("advances only the sessions boundary when asked to", async () => {
		const store = capable();
		await store.revokeSessionsBefore("u", at(1_000), far());
		expect((await store.revokedBefore("u"))?.getTime()).toBe(1_000);
		// Not zero, and not the sessions value: copying it across would revoke
		// the grants the caller asked to keep.
		expect(await store.grantsRevokedBefore("u")).toBeNull();
	});

	it("keeps each field's own maximum, whichever order the writes arrive in", async () => {
		// Two replicas, two clocks. A sessions-only stamp at 200 followed by a
		// delayed full revocation at 100 must leave {sessions: 200, grants: 100}
		// — the grants boundary is not derived from the sessions one.
		const store = capable();
		await store.revokeSessionsBefore("u", at(200), far());
		await store.revokeBefore("u", at(100), far());
		expect((await store.revokedBefore("u"))?.getTime()).toBe(200);
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(100);
	});

	it("never moves a boundary backwards", async () => {
		const store = capable();
		await store.revokeBefore("u", at(500), far());
		await store.revokeBefore("u", at(100), far());
		expect((await store.revokedBefore("u"))?.getTime()).toBe(500);
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(500);
	});

	it("cannot rescue a grant an earlier revocation already ended", async () => {
		// `"keep"` is a narrower operation, not an undo.
		const store = capable();
		await store.revokeBefore("u", at(500), far());
		await store.revokeSessionsBefore("u", at(900), far());
		expect((await store.grantsRevokedBefore("u"))?.getTime()).toBe(500);
	});

	it("starts fresh once the record has expired", async () => {
		const store = capable();
		await store.revokeBefore("u", at(500), at(Date.now() - 1));
		expect(await store.revokedBefore("u")).toBeNull();
		expect(await store.grantsRevokedBefore("u")).toBeNull();
	});
});

describe("the retention floor the adapter applies", () => {
	it("outlives every grant a full revocation covers, however short the caller's expiry", async () => {
		// A caller that passes a one-minute expiry — or a Store on an old
		// version whose TTL is sized to refresh tokens — must not leave a
		// boundary that lapses under a grant consented for a year.
		const store = capable();
		const before = Date.now();
		await store.revokeBefore("u", at(before), at(before + 60_000));
		// The record is still readable well past the caller's expiry, which is
		// the observable form of "the floor was applied".
		expect((await store.revokedBefore("u"))?.getTime()).toBe(before);
	});

	it("keeps a longer expiry the caller or an earlier write asked for", async () => {
		const store = capable();
		const before = Date.now();
		await store.revokeBefore("u", at(before), at(before + SUBJECT_REVOCATION_MIN_RETENTION_MS * 2));
		await store.revokeSessionsBefore("u", at(before + 1), at(before + 60_000));
		expect((await store.revokedBefore("u"))?.getTime()).toBe(before + 1);
	});

	it("does not manufacture a grants boundary, or its year, for a sessions-only stamp", async () => {
		// The floor is about grants. A deployment that has never revoked a
		// grant should not be made to keep a year of keys because somebody
		// changed a password.
		const store = capable();
		await store.revokeSessionsBefore("u", at(Date.now()), at(Date.now() + 60_000));
		expect(await store.grantsRevokedBefore("u")).toBeNull();
	});

	it("hands back dates that cannot be used to edit the record", async () => {
		const store = capable();
		await store.revokeBefore("u", at(1_000), far());
		const read = await store.revokedBefore("u");
		read?.setTime(999_999);
		expect((await store.revokedBefore("u"))?.getTime()).toBe(1_000);
	});

	it("refuses an instant that is not one, rather than storing NaN", async () => {
		// Every comparison with NaN is false, so a NaN boundary is a boundary
		// that covers nothing while looking like one.
		const store = capable();
		await expect(store.revokeBefore("u", new Date(Number.NaN), far())).rejects.toThrow();
		await expect(store.revokeBefore("u", at(1_000), new Date(Number.NaN))).rejects.toThrow();
		await expect(store.revokeSessionsBefore("u", new Date(Number.NaN), far())).rejects.toThrow();
		expect(await store.revokedBefore("u")).toBeNull();
	});
});
