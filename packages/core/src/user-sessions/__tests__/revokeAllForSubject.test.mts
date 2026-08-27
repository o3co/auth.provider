/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Issue #296 — the Store owns the password-reset flow; this library owns
 * killing what it issued against the old credential.
 */

import { describe, expect, it, vi } from "vitest";
import { createMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "#/user-sessions/memory/subjectSessionIndex.mjs";
import { revokeAllForSubject } from "#/user-sessions/revokeAllForSubject.mjs";

const FUTURE = new Date(Date.now() + 3_600_000);
const TTL = 300_000;

const ok = async () => ({ ok: true });

const withSessions = async (...sids: string[]) => {
	const index = createInMemorySubjectSessionIndex();
	for (const sid of sids) await index.addSid("user-1", sid, FUTURE);
	return index;
};

describe("revokeAllForSubject", () => {
	it("cascades every session the subject holds", async () => {
		const cascaded: string[] = [];
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2", "s3"),
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: async (sid) => {
				cascaded.push(sid);
				return { ok: true };
			},
		});
		expect(cascaded).toEqual(["s1", "s2", "s3"]);
		expect(result.sessionsRevoked).toEqual(["s1", "s2", "s3"]);
		expect(result.sessionsFailed).toEqual([]);
	});

	it("writes the watermark BEFORE cascading any session", async () => {
		// The ordering is the fix, not an implementation detail. A refresh
		// rotation during the loop mints a token whose session was never in the
		// enumerated list; only a watermark already in force kills it.
		const order: string[] = [];
		const revocation = createMemorySubjectRevocation();
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1"),
			subjectRevocation: {
				kind: "spy",
				async revokeBefore(...args) {
					order.push("watermark");
					return revocation.revokeBefore(...args);
				},
				revokedBefore: revocation.revokedBefore,
			},
			cascadeSession: async (sid) => {
				order.push(`cascade:${sid}`);
				return { ok: true };
			},
		});
		expect(order).toEqual(["watermark", "cascade:s1"]);
	});

	it("removes a session from the index only once its cascade succeeded", async () => {
		const index = await withSessions("s1", "s2");
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: index,
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: async (sid) => ({ ok: sid === "s1" }),
		});
		// s2 stays: the entry is what a retry enumerates, and dropping it would
		// strand a session that is still live.
		expect(await index.listSids("user-1")).toEqual(["s2"]);
	});

	it("reports a failing cascade rather than throwing", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2"),
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: async (sid) => {
				if (sid === "s1") throw new Error("store down");
				return { ok: true };
			},
		});
		expect(result.sessionsFailed).toEqual(["s1"]);
		expect(result.sessionsRevoked).toEqual(["s2"]);
	});

	it("keeps cascading after one session fails", async () => {
		const cascaded: string[] = [];
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2", "s3"),
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: async (sid) => {
				cascaded.push(sid);
				return { ok: sid !== "s1" };
			},
		});
		expect(cascaded).toEqual(["s1", "s2", "s3"]);
	});
});

describe("revokeAllForSubject — unwired stores must not read as success", () => {
	it("names a missing subjectRevocation and does not claim tokens were revoked", async () => {
		// The caller has just written a new password. A bare success while
		// nothing was revoked is the worst thing this could return.
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1"),
			cascadeSession: ok,
		});
		expect(result.unavailable).toEqual(["subjectRevocation"]);
		expect(result.tokensRevoked).toBe(false);
	});

	it("names a missing subjectSessionIndex", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.unavailable).toEqual(["subjectSessionIndex"]);
		expect(result.sessionsRevoked).toEqual([]);
	});

	it("names both when neither is wired, and logs an error", async () => {
		const error = vi.fn();
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			cascadeSession: ok,
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as never,
		});
		expect(result.unavailable).toEqual(["subjectRevocation", "subjectSessionIndex"]);
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ unavailable: expect.any(Array) }),
			"revoke_all_for_subject_incomplete",
		);
	});

	it("reports nothing unavailable when both are wired", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1"),
			subjectRevocation: createMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.unavailable).toEqual([]);
		expect(result.tokensRevoked).toBe(true);
	});
});
