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
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "#/user-sessions/memory/subjectSessionIndex.mjs";
import { revokeAllForSubject } from "#/user-sessions/revokeAllForSubject.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

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
			subjectRevocation: createInMemorySubjectRevocation(),
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
		const revocation = createInMemorySubjectRevocation();
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
			subjectRevocation: createInMemorySubjectRevocation(),
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
			subjectRevocation: createInMemorySubjectRevocation(),
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
			subjectRevocation: createInMemorySubjectRevocation(),
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
			subjectRevocation: createInMemorySubjectRevocation(),
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
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.unavailable).toEqual([]);
		expect(result.tokensRevoked).toBe(true);
	});
});

describe("revokeAllForSubject — a wired store that throws must not abort the teardown", () => {
	// The caller has already written the new credential; there is no undo. An
	// exception here would replace a partial result the caller could act on with
	// nothing at all, so every store call is reported instead of thrown.

	const throwingRevocation = (): SubjectRevocation => ({
		kind: "broken",
		async revokeBefore() {
			throw new Error("watermark store down");
		},
		async revokedBefore() {
			return null;
		},
	});

	it("reports a failing revokeBefore instead of throwing, and still cascades", async () => {
		const cascaded: string[] = [];
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2"),
			subjectRevocation: throwingRevocation(),
			cascadeSession: async (sid) => {
				cascaded.push(sid);
				return { ok: true };
			},
		});
		// Sessions are still worth killing even when the watermark could not be
		// written — returning early would revoke nothing at all.
		expect(cascaded).toEqual(["s1", "s2"]);
		expect(result.tokensRevoked).toBe(false);
		expect(result.failures).toEqual([
			expect.objectContaining({ capability: "subjectRevocation", operation: "revokeBefore" }),
		]);
		// "wired but failed" is not "not wired" — a deployment must be able to
		// tell an outage from a composition gap.
		expect(result.unavailable).toEqual([]);
		expect(result.complete).toBe(false);
	});

	it("logs a failing revokeBefore under its own event", async () => {
		const error = vi.fn();
		await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: throwingRevocation(),
			cascadeSession: ok,
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as never,
		});
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "user-1" }),
			"revoke_all_watermark_failed",
		);
	});

	it("reports a failing listSids instead of throwing", async () => {
		const index = await withSessions("s1");
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: {
				...index,
				async listSids() {
					throw new Error("index store down");
				},
			},
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.sessionsRevoked).toEqual([]);
		expect(result.failures).toEqual([
			expect.objectContaining({ capability: "subjectSessionIndex", operation: "listSids" }),
		]);
		expect(result.complete).toBe(false);
	});

	it("keeps cascading when removeSid throws, and still counts the session revoked", async () => {
		// The cascade is the security-relevant half; removeSid is bookkeeping. A
		// stale entry only costs a redundant, idempotent cascade on the next call.
		const cascaded: string[] = [];
		const index = await withSessions("s1", "s2");
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: {
				...index,
				async removeSid() {
					throw new Error("index store down");
				},
			},
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async (sid) => {
				cascaded.push(sid);
				return { ok: true };
			},
		});
		expect(cascaded).toEqual(["s1", "s2"]);
		expect(result.sessionsRevoked).toEqual(["s1", "s2"]);
		expect(result.sessionsFailed).toEqual([]);
		expect(result.failures).toHaveLength(2);
		expect(result.failures[0]).toMatchObject({ operation: "removeSid", sid: "s1" });
		expect(result.complete).toBe(false);
	});
});

describe("revokeAllForSubject — `complete` is the single field a caller must check", () => {
	it("is true only when both stores were wired and every session cascaded", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2"),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.complete).toBe(true);
	});

	it("is true for a subject with no live sessions", async () => {
		// Nothing to revoke is a complete revocation, not a failed one.
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: createInMemorySubjectSessionIndex(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.complete).toBe(true);
		expect(result.sessionsRevoked).toEqual([]);
	});

	it("is false when a store was not wired", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: ok,
		});
		expect(result.complete).toBe(false);
	});

	it("is false when one session's cascade failed", async () => {
		const result = await revokeAllForSubject({
			subject: "user-1",
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1", "s2"),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async (sid) => ({ ok: sid !== "s1" }),
		});
		expect(result.complete).toBe(false);
	});
});
