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
import { runInNewContext } from "node:vm";
import type { FederationGrantStore } from "#/federation-grants/store.mjs";
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

interface LoggedLine {
	readonly level: string;
	readonly message: string | undefined;
	readonly fields: Record<string, unknown>;
}

/**
 * A logger that keeps each line, its structured fields included; one that
 * throws on the messages in `throwsOn` once it has kept them.
 */
const silentLogger = (
	throwsOn: readonly string[] = [],
): {
	readonly logger: Logger;
	readonly lines: string[];
	readonly logged: LoggedLine[];
} => {
	const lines: string[] = [];
	const logged: LoggedLine[] = [];
	const at =
		(level: string) =>
		(first: unknown, second?: unknown): void => {
			const message = typeof first === "string" ? first : (second as string | undefined);
			lines.push(`${level}:${String(message)}`);
			logged.push({
				level,
				message,
				fields:
					typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {},
			});
			if (message !== undefined && throwsOn.includes(message)) {
				throw new Error("the logger is down");
			}
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
	return { logger, lines, logged };
};

/** A participant that rejects with `thrown`. */
const rejecting = (name: string, thrown: unknown): readonly [string, SubjectRevocationParticipant] => [
	name,
	{ run: () => Promise.reject(thrown) },
];

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
			federationGrantStore: {
				listBySubject: async () => {
					order.push("grants");
					return [];
				},
			} as unknown as FederationGrantStore,
			subjectRevocationParticipantResolver: resolverOf([
				recording("second-feature", order),
				recording("first-feature", order),
			]),
		});

		expect(order).toEqual([
			"watermark",
			"cascade:s1",
			"grants",
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

	it("records a thrown Proxy whose traps throw, and a revoked Proxy, by name, and runs the next", async () => {
		const calls: string[] = [];
		const trapping = new Proxy(new Error("inner"), {
			get() {
				throw new Error("trap");
			},
			getPrototypeOf() {
				throw new Error("trap");
			},
			getOwnPropertyDescriptor() {
				throw new Error("trap");
			},
			has() {
				throw new Error("trap");
			},
		});
		const revocable = Proxy.revocable(new Error("inner"), {});
		revocable.revoke();
		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: TTL,
			subjectSessionIndex: await withSessions(),
			subjectRevocation: createInMemorySubjectRevocation(),
			cascadeSession: async () => ({ ok: true }),
			subjectRevocationParticipantResolver: resolverOf([
				rejecting("trapping", trapping),
				recording("between", calls),
				rejecting("revoked", revocable.proxy),
				recording("after", calls),
			]),
			logger: silentLogger().logger,
		});

		expect(calls).toEqual([`between:${SUBJECT}`, `after:${SUBJECT}`]);
		expect(result.participantFailures).toEqual([
			{ name: "trapping", error: { name: "NonError" } },
			{ name: "revoked", error: { name: "NonError" } },
		]);
		expect(result.failures).toEqual([]);
		expect(result.complete).toBe(false);
	});

	it("reads an Error from another realm as an Error", async () => {
		const foreign = runInNewContext(
			'Object.assign(new TypeError("elsewhere"), { reason: "unreachable" })',
		) as unknown;
		expect(foreign instanceof Error).toBe(false);
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([rejecting("foreign", foreign)]),
			revocationComplete: true,
			logger: silentLogger().logger,
		});
		expect(outcome.participantFailures).toEqual([
			{ name: "foreign", error: { name: "TypeError", reason: "unreachable" } },
		]);
	});

	it("drops an error name that is, or holds, the subject", async () => {
		const outcome = await runSubjectRevocationParticipants({
			subject: "alice42",
			participants: resolverOf([
				rejecting("named", Object.assign(new Error("x"), { name: "alice42" })),
				rejecting("holding", Object.assign(new Error("x"), { name: "Lockalice42" })),
				rejecting("other", Object.assign(new Error("x"), { name: "LockError" })),
			]),
			revocationComplete: true,
			logger: silentLogger().logger,
		});
		expect(outcome.participantFailures).toEqual([
			{ name: "named", error: { name: "Error" } },
			{ name: "holding", error: { name: "Error" } },
			{ name: "other", error: { name: "LockError" } },
		]);
	});

	it("drops a reason that is, or holds, the subject", async () => {
		const outcome = await runSubjectRevocationParticipants({
			subject: "alice",
			participants: resolverOf([
				rejecting("equal", Object.assign(new Error("x"), { reason: "alice" })),
				rejecting("holding", Object.assign(new Error("x"), { reason: "lock-alice" })),
				rejecting("other", Object.assign(new Error("x"), { reason: "unreachable" })),
			]),
			revocationComplete: true,
			logger: silentLogger().logger,
		});
		expect(outcome.participantFailures).toEqual([
			{ name: "equal", error: { name: "Error" } },
			{ name: "holding", error: { name: "Error" } },
			{ name: "other", error: { name: "Error", reason: "unreachable" } },
		]);
	});

	it("keeps only an own reason, never one an error inherits", async () => {
		class CodedError extends Error {}
		Object.defineProperty(CodedError.prototype, "reason", { value: "unreachable" });
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([rejecting("inherited", new CodedError("x"))]),
			revocationComplete: true,
			logger: silentLogger().logger,
		});
		expect(outcome.participantFailures).toEqual([
			{ name: "inherited", error: { name: "Error" } },
		]);
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
	it("logs a failure with the subject, the participant's name and the error's projection", async () => {
		const failing = silentLogger();
		await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([rejecting("x", new RangeError("down"))]),
			revocationComplete: true,
			logger: failing.logger,
		});
		expect(failing.logged).toEqual([
			{
				level: "error",
				message: "revoke_all_participant_failed",
				fields: {
					subject: SUBJECT,
					participant: "x",
					err: expect.objectContaining({ name: "RangeError", detail: "down" }),
				},
			},
		]);
	});

	it("logs a held-back pass once, with the subject and every name", async () => {
		const held = silentLogger();
		await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([recording("x", []), recording("y", [])]),
			revocationComplete: false,
			logger: held.logger,
		});
		expect(held.logged).toEqual([
			{
				level: "warn",
				message: "revoke_all_participants_held_back",
				fields: { subject: SUBJECT, participants: ["x", "y"] },
			},
		]);
	});

	it("logs a listing that threw with the subject and the error's projection", async () => {
		const unlisted = silentLogger();
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: {
				get: () => undefined,
				entries: () => {
					throw new TypeError("not readable yet");
				},
			},
			revocationComplete: true,
			logger: unlisted.logger,
		});
		expect(outcome.participantFailures).toEqual([]);
		expect(outcome.listingError?.error).toBeInstanceOf(TypeError);
		expect(unlisted.logged).toEqual([
			{
				level: "error",
				message: "revoke_all_list_participants_failed",
				fields: {
					subject: SUBJECT,
					err: expect.objectContaining({ name: "TypeError", detail: "not readable yet" }),
				},
			},
		]);
	});

	it("goes on past a logger that throws on a failure's line", async () => {
		const calls: string[] = [];
		const { logger } = silentLogger(["revoke_all_participant_failed"]);
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([
				rejecting("first", new Error("down")),
				recording("between", calls),
				rejecting("second", new Error("down")),
			]),
			revocationComplete: true,
			logger,
		});
		expect(calls).toEqual([`between:${SUBJECT}`]);
		expect(outcome.participantFailures.map((failure) => failure.name)).toEqual([
			"first",
			"second",
		]);
		expect(outcome.listingError).toBeUndefined();
	});

	it("answers the held-back names when the logger throws on the held-back line", async () => {
		const { logger } = silentLogger(["revoke_all_participants_held_back"]);
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: resolverOf([recording("x", [])]),
			revocationComplete: false,
			logger,
		});
		expect(outcome).toEqual({ participantsHeldBack: ["x"], participantFailures: [] });
	});

	it("answers a listing error when the logger throws on its line too", async () => {
		const { logger } = silentLogger(["revoke_all_list_participants_failed"]);
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: {
				get: () => undefined,
				entries: () => {
					throw new Error("not readable yet");
				},
			},
			revocationComplete: true,
			logger,
		});
		expect(outcome.listingError).toBeDefined();
	});

	it("reads an entry that is not a pair as a listing error, and runs none", async () => {
		const calls: string[] = [];
		const outcome = await runSubjectRevocationParticipants({
			subject: SUBJECT,
			participants: {
				get: () => undefined,
				entries: () =>
					[recording("a", calls), 42][Symbol.iterator]() as unknown as IterableIterator<
						readonly [string, SubjectRevocationParticipant]
					>,
			},
			revocationComplete: true,
			logger: silentLogger().logger,
		});
		expect(calls).toEqual([]);
		expect(outcome.listingError).toBeDefined();
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
