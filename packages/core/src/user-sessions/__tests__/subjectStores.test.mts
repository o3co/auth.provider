/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "#/user-sessions/memory/subjectSessionIndex.mjs";

const FUTURE = new Date(Date.now() + 3_600_000);

afterEach(() => {
	vi.useRealTimers();
});

describe("createInMemorySubjectSessionIndex (#296)", () => {
	it("lists the sessions added for a subject", async () => {
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", FUTURE);
		await index.addSid("u1", "s2", FUTURE);
		expect(await index.listSids("u1")).toEqual(["s1", "s2"]);
	});

	it("keeps subjects apart", async () => {
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", FUTURE);
		await index.addSid("u2", "s2", FUTURE);
		expect(await index.listSids("u1")).toEqual(["s1"]);
		expect(await index.listSids("u2")).toEqual(["s2"]);
	});

	it("is idempotent on a repeated sid", async () => {
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", FUTURE);
		await index.addSid("u1", "s1", FUTURE);
		expect(await index.listSids("u1")).toEqual(["s1"]);
	});

	it("removes one session without disturbing the others", async () => {
		// The reason this index needs per-member removal at all: unlike the
		// sid-keyed indexes, one session ending does not end the subject.
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", FUTURE);
		await index.addSid("u1", "s2", FUTURE);
		await index.removeSid("u1", "s1");
		expect(await index.listSids("u1")).toEqual(["s2"]);
	});

	it("drops the whole set on removeBySubject", async () => {
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", FUTURE);
		await index.addSid("u1", "s2", FUTURE);
		await index.removeBySubject("u1");
		expect(await index.listSids("u1")).toEqual([]);
	});

	it("returns an empty list for an unknown subject", async () => {
		expect(await createInMemorySubjectSessionIndex().listSids("nobody")).toEqual([]);
	});

	it("expires each session on its own clock, not the subject's last write", async () => {
		// The reason this index does not reuse `createMemorySidSortedSet`: that
		// primitive keeps ONE expiry per key, correct for the sid-keyed indexes
		// where every member shares a session's expiry. A subject's sessions do
		// not. Adding a longer-lived session must not keep a shorter-lived one
		// listed past its end.
		vi.useFakeTimers();
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "short", new Date(Date.now() + 1_000));
		await index.addSid("u1", "long", new Date(Date.now() + 600_000));
		vi.advanceTimersByTime(30_000);
		expect(await index.listSids("u1")).toEqual(["long"]);
	});

	it("does not shorten a live session when a shorter-lived one is added after", async () => {
		// The same mismatch in the other direction.
		vi.useFakeTimers();
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "long", new Date(Date.now() + 600_000));
		await index.addSid("u1", "short", new Date(Date.now() + 1_000));
		vi.advanceTimersByTime(30_000);
		expect(await index.listSids("u1")).toEqual(["long"]);
	});

	it("ignores a session that has already expired", async () => {
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "dead", new Date(Date.now() - 1));
		expect(await index.listSids("u1")).toEqual([]);
	});

	it("ages an expired session out of the index", async () => {
		// A long-lived user must not accumulate every session they ever had.
		vi.useFakeTimers();
		const index = createInMemorySubjectSessionIndex();
		await index.addSid("u1", "s1", new Date(Date.now() + 1_000));
		await index.addSid("u1", "s2", new Date(Date.now() + 60_000));
		vi.advanceTimersByTime(30_000);
		expect(await index.listSids("u1")).toEqual(["s2"]);
	});
});

describe("createMemorySubjectRevocation (#296)", () => {
	it("returns null for a subject with no watermark", async () => {
		expect(await createMemorySubjectRevocation().revokedBefore("u1")).toBeNull();
	});

	it("returns the watermark it was given", async () => {
		const store = createMemorySubjectRevocation();
		const before = new Date(1_000_000);
		await store.revokeBefore("u1", before, new Date(Date.now() + 300_000));
		expect((await store.revokedBefore("u1"))?.getTime()).toBe(before.getTime());
	});

	it("keeps subjects apart", async () => {
		const store = createMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(1_000_000), new Date(Date.now() + 300_000));
		expect(await store.revokedBefore("u2")).toBeNull();
	});

	it("never moves the watermark backwards", async () => {
		// Two resets in quick succession, the second computed on a replica whose
		// clock is behind. Taking the newer call's value would resurrect every
		// token the first reset killed.
		const store = createMemorySubjectRevocation();
		const expiresAt = new Date(Date.now() + 300_000);
		await store.revokeBefore("u1", new Date(2_000_000), expiresAt);
		await store.revokeBefore("u1", new Date(1_000_000), expiresAt);
		expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000_000);
	});

	it("advances the watermark when the newer value is later", async () => {
		const store = createMemorySubjectRevocation();
		const expiresAt = new Date(Date.now() + 300_000);
		await store.revokeBefore("u1", new Date(1_000_000), expiresAt);
		await store.revokeBefore("u1", new Date(2_000_000), expiresAt);
		expect((await store.revokedBefore("u1"))?.getTime()).toBe(2_000_000);
	});

	it("expires the watermark once no token it could kill can still exist", async () => {
		vi.useFakeTimers();
		const store = createMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(Date.now()), new Date(Date.now() + 1_000));
		vi.advanceTimersByTime(2_000);
		expect(await store.revokedBefore("u1")).toBeNull();
	});

	it("starts a fresh watermark after the previous one expired", async () => {
		// The monotonic guard must not resurrect an expired entry's value.
		vi.useFakeTimers();
		const store = createMemorySubjectRevocation();
		await store.revokeBefore("u1", new Date(9_000_000), new Date(Date.now() + 1_000));
		vi.advanceTimersByTime(2_000);
		await store.revokeBefore("u1", new Date(1_000), new Date(Date.now() + 300_000));
		expect((await store.revokedBefore("u1"))?.getTime()).toBe(1_000);
	});
});
