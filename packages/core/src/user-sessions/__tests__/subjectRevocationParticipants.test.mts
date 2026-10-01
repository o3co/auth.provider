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
 * Subject-revocation participants: what another feature runs to clear its own
 * state for a subject once a subject revocation completed, and the one runner
 * `revokeAllForSubject` and the service call them through.
 */

import { describe, expect, it } from "vitest";
import type { Logger } from "#/logging/Logger.mjs";
import { createInMemorySubjectRevocation } from "#/user-sessions/memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "#/user-sessions/memory/subjectSessionIndex.mjs";
import { revokeAllForSubject } from "#/user-sessions/revokeAllForSubject.mjs";
import {
	isSubjectRevocationParticipant,
	runSubjectRevocationParticipants,
	type SubjectRevocationParticipant,
	type SubjectRevocationParticipantResolver,
} from "#/user-sessions/subjectRevocationParticipants.mjs";

const SUBJECT = "alice@example.com";
const TTL = 300_000;
const FUTURE = new Date(Date.now() + 3_600_000);

/** A resolver over `participants`, in the order given. */
const resolverOf = (
	participants: ReadonlyArray<readonly [string, SubjectRevocationParticipant]>,
): SubjectRevocationParticipantResolver => {
	const byName = new Map(participants);
	return {
		get: (name) => byName.get(name),
		entries: () => byName.entries(),
	};
};

/** A participant that records each call into `calls`, under `name`. */
const recording = (
	name: string,
	calls: string[],
): readonly [string, SubjectRevocationParticipant] => [
	name,
	{
		async run({ subject }) {
			calls.push(`${name}:${subject}`);
		},
	},
];

const withSessions = async (...sids: string[]) => {
	const index = createInMemorySubjectSessionIndex();
	for (const sid of sids) await index.addSid(SUBJECT, sid, FUTURE);
	return index;
};

const silentLogger = (): { readonly logger: Logger; readonly lines: string[] } => {
	const lines: string[] = [];
	const at =
		(level: string) =>
		(first: unknown, second?: unknown): void => {
			lines.push(`${level}:${typeof first === "string" ? first : String(second)}`);
		};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
};

describe("isSubjectRevocationParticipant", () => {
	it("admits an object whose run is a function", () => {
		expect(isSubjectRevocationParticipant({ run: async () => {} })).toBe(true);
	});

	it.each([
		["null", null],
		["undefined", undefined],
		["a function", async () => {}],
		["an object without run", {}],
		["an object whose run is not a function", { run: "clear" }],
		["an array", [async () => {}]],
	])("refuses %s", (_label, value) => {
		expect(isSubjectRevocationParticipant(value)).toBe(false);
	});
});

describe("revokeAllForSubject — participants", () => {
	it("runs every participant after the watermark, the sessions and the grants, in the resolver's order", async () => {
		const order: string[] = [];
		const revocation = createInMemorySubjectRevocation();
		const result = await revokeAllForSubject({
			subject: SUBJECT,
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
			subjectRevocationParticipantResolver: resolverOf([
				recording("second-feature", order),
				recording("first-feature", order),
			]),
		});

		expect(order).toEqual([
			"watermark",
			"cascade:s1",
			`second-feature:${SUBJECT}`,
			`first-feature:${SUBJECT}`,
		]);
		expect(result.participantFailures).toEqual([]);
		expect(result.participantsHeldBack).toEqual([]);
		expect(result.complete).toBe(true);
	});

	it("awaits each participant before it starts the next", async () => {
		const events: string[] = [];
		const slow: SubjectRevocationParticipant = {
			async run() {
				events.push("slow:start");
				await new Promise((resolve) => setTimeout(resolve, 5));
				events.push("slow:end");
			},
		};
		const next: SubjectRevocationParticipant = {
			async run() {
				events.push("next");
			},
		};
		await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([
				["slow", slow],
				["next", next],
			]),
		});
		expect(events).toEqual(["slow:start", "slow:end", "next"]);
	});

	it("holds every participant back when the watermark could not be written, and says which", async () => {
		const calls: string[] = [];
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1"),
			subjectRevocation: {
				kind: "down",
				revokeBefore: async () => {
					throw new Error("store down");
				},
				revokedBefore: async () => null,
			},
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([
				recording("a", calls),
				recording("b", calls),
			]),
			logger: silentLogger().logger,
		});

		expect(calls).toEqual([]);
		expect(result.participantsHeldBack).toEqual(["a", "b"]);
		expect(result.participantFailures).toEqual([]);
		expect(result.complete).toBe(false);
	});

	it("holds the participants back when a session's cascade failed", async () => {
		const calls: string[] = [];
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions("s1"),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: false }),
			subjectRevocationParticipantResolver: resolverOf([recording("a", calls)]),
			logger: silentLogger().logger,
		});

		expect(calls).toEqual([]);
		expect(result.participantsHeldBack).toEqual(["a"]);
		expect(result.complete).toBe(false);
	});

	it("holds the participants back when a capability is not wired", async () => {
		const calls: string[] = [];
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([recording("a", calls)]),
			logger: silentLogger().logger,
		});

		expect(result.unavailable).toEqual(["subjectSessionIndex"]);
		expect(calls).toEqual([]);
		expect(result.participantsHeldBack).toEqual(["a"]);
	});

	it("goes on past a participant that throws and one that rejects, and reports both by name", async () => {
		const calls: string[] = [];
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([
				[
					"throws",
					{
						run: () => {
							throw new TypeError("synchronous");
						},
					},
				],
				recording("between", calls),
				[
					"rejects",
					{
						run: () => Promise.reject(new RangeError("asynchronous")),
					},
				],
				recording("after", calls),
			]),
			logger: silentLogger().logger,
		});

		expect(calls).toEqual([`between:${SUBJECT}`, `after:${SUBJECT}`]);
		expect(result.participantFailures).toEqual([
			{ name: "throws", error: { name: "TypeError" } },
			{ name: "rejects", error: { name: "RangeError" } },
		]);
		expect(result.participantsHeldBack).toEqual([]);
		expect(result.complete).toBe(false);
		// The revocation itself is reported as done: a participant's failure
		// costs only its own cleanup.
		expect(result.failures).toEqual([]);
		expect(result.tokensRevoked).toBe(true);
	});

	it("keeps a code reason and nothing else of what a participant threw", async () => {
		const hostile = Object.assign(new Error(`could not clear the lock of ${SUBJECT}`), {
			name: `LockError for ${SUBJECT}`,
			reason: "unreachable",
			subject: SUBJECT,
			cause: new Error(SUBJECT),
		});
		const coded = Object.assign(new Error(SUBJECT), { reason: "unreachable" });
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([
				[
					"hostile",
					{
						run: async () => {
							throw hostile;
						},
					},
				],
				[
					"coded",
					{
						run: async () => {
							throw coded;
						},
					},
				],
				[
					"string",
					{
						run: async () => {
							throw SUBJECT;
						},
					},
				],
			]),
			logger: silentLogger().logger,
		});

		expect(result.participantFailures).toEqual([
			{ name: "hostile", error: { name: "Error", reason: "unreachable" } },
			{ name: "coded", error: { name: "Error", reason: "unreachable" } },
			{ name: "string", error: { name: "NonError" } },
		]);
		expect(JSON.stringify(result.participantFailures)).not.toContain("alice");
	});

	it("reports a resolver that cannot be read as a failure of the slot, and still answers", async () => {
		const throwing: SubjectRevocationParticipantResolver = {
			get: () => undefined,
			entries: () => {
				throw new Error("not readable yet");
			},
		};
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: throwing,
			logger: silentLogger().logger,
		});

		expect(result.failures).toEqual([
			expect.objectContaining({
				capability: "subjectRevocationParticipantResolver",
				operation: "entries",
			}),
		]);
		expect(result.complete).toBe(false);
	});

	it("answers no participants, complete, when no resolver is supplied", async () => {
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
		});

		expect(result.participantFailures).toEqual([]);
		expect(result.participantsHeldBack).toEqual([]);
		expect(result.unavailable).toEqual([]);
		expect(result.complete).toBe(true);
	});
});

describe("runSubjectRevocationParticipants", () => {
	it("logs a failure with the participant's name and a held-back pass with every name", async () => {
		const failing = silentLogger();
		await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([
				[
					"x",
					{
						run: async () => {
							throw new Error("down");
						},
					},
				],
			]),
			revocationComplete: true,
			logger: failing.logger,
		});
		expect(failing.lines).toEqual(["error:revoke_all_participant_failed"]);

		const held = silentLogger();
		await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([recording("x", [])]),
			revocationComplete: false,
			logger: held.logger,
		});
		expect(held.lines).toEqual(["warn:revoke_all_participants_held_back"]);
	});

	it("lists the participants once, before the first runs", async () => {
		const calls: string[] = [];
		let listed = 0;
		const byName = new Map<string, SubjectRevocationParticipant>([recording("b", calls)]);
		byName.set("a", {
			async run({ subject }) {
				calls.push(`a:${subject}`);
				// A participant added while the pass runs is not run by it.
				byName.set("late", { run: async () => void calls.push("late") });
			},
		});
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: {
				get: (name) => byName.get(name),
				entries: () => {
					listed += 1;
					return byName.entries();
				},
			},
			revocationComplete: true,
		});
		expect(listed).toBe(1);
		expect(calls).toEqual([`b:${SUBJECT}`, `a:${SUBJECT}`]);
		expect(outcome).toEqual({ participantsHeldBack: [], participantFailures: [] });
	});
});
