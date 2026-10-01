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
 * The MFA stores' answers, read as their ports promise them, beside the
 * bound read: a reservation, a subject attempt's reservation, a consumed
 * transaction, a factor's compare-and-set, a session's account-email proof
 * and a subject's first-binding mark. An answer outside the promise is `undefined` or `false`, which a
 * caller answers as the store's outage — never as a verdict.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";
import { isMfaFactorUpdateWritten, type MfaFactorRecord } from "#/mfa/factorStore.mjs";
import {
	isConsumedMfaTransaction,
	type MfaTransaction,
	readFirstBindingAt,
	readMfaAttemptReservation,
	readMfaRecoverySetFloorAnswer,
	readMfaSubjectAttemptReservation,
	readMfaSubjectCount,
	readMfaSubjectLeaseAnswer,
	readMfaSubjectRecoveryAnswer,
	readSessionEmailProof,
} from "#/mfa/transactionStore.mjs";

describe("readMfaAttemptReservation", () => {
	it("reads a reservation within the limit, and a refusal with the count the store kept", () => {
		expect(readMfaAttemptReservation({ ok: true, attempts: 1 }, 5)).toEqual({
			ok: true,
			attempts: 1,
		});
		expect(readMfaAttemptReservation({ ok: true, attempts: 5 }, 5)).toEqual({
			ok: true,
			attempts: 5,
		});
		expect(readMfaAttemptReservation({ ok: false, attempts: 0 }, 5)).toEqual({
			ok: false,
			attempts: 0,
		});
		expect(readMfaAttemptReservation({ ok: false, attempts: 7 }, 5)).toEqual({
			ok: false,
			attempts: 7,
		});
	});

	it.each<[string, unknown]>([
		["a reservation counting nothing", { ok: true, attempts: 0 }],
		["a reservation past the limit", { ok: true, attempts: 6 }],
		["a count that is not a number", { ok: true, attempts: Number.NaN }],
		["a count that is not whole", { ok: true, attempts: 1.5 }],
		["a count past the safe integers", { ok: false, attempts: 2 ** 53 }],
		["a negative count", { ok: false, attempts: -1 }],
		["a count as text", { ok: true, attempts: "1" }],
		["an ok that is truthy but not true", { ok: "yes", attempts: 1 }],
		["an ok that is missing", { attempts: 1 }],
		["nothing", undefined],
		["null", null],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaAttemptReservation(answer, 5)).toBeUndefined();
	});

	it("reads each field once: a getter cannot answer the check and the caller differently", () => {
		let reads = 0;
		const answer = {
			get ok() {
				reads++;
				return reads === 1;
			},
			attempts: 1,
		};
		expect(readMfaAttemptReservation(answer, 5)).toEqual({ ok: true, attempts: 1 });
	});

	it("reads an answer whose field throws as no answer", () => {
		const answer = {
			get ok(): boolean {
				throw new Error("boom");
			},
			attempts: 1,
		};
		expect(readMfaAttemptReservation(answer, 5)).toBeUndefined();
	});
});

describe("readMfaSubjectAttemptReservation", () => {
	it("reads a pass as its reservation", () => {
		expect(readMfaSubjectAttemptReservation({ ok: true, reservation: "r-1" })).toStrictEqual({
			ok: true,
			reservation: "r-1",
		});
	});

	it("reads a hold with its time to come back, none for the hard hold, and whether it is first", () => {
		expect(
			readMfaSubjectAttemptReservation({
				ok: false,
				hold: "backoff",
				retryAfterMs: 900_000,
				first: true,
			}),
		).toStrictEqual({ ok: false, hold: "backoff", retryAfterMs: 900_000, first: true });
		expect(
			readMfaSubjectAttemptReservation({
				ok: false,
				hold: "weekly",
				retryAfterMs: 0.5,
				first: false,
			}),
		).toStrictEqual({ ok: false, hold: "weekly", retryAfterMs: 0.5, first: false });
		expect(
			readMfaSubjectAttemptReservation({
				ok: false,
				hold: "hard",
				retryAfterMs: null,
				first: true,
			}),
		).toStrictEqual({ ok: false, hold: "hard", retryAfterMs: null, first: true });
	});

	it("copies only the fields its answer has", () => {
		expect(
			readMfaSubjectAttemptReservation({ ok: true, reservation: "r-1", hold: "hard", extra: 1 }),
		).toStrictEqual({ ok: true, reservation: "r-1" });
		expect(
			readMfaSubjectAttemptReservation({
				ok: false,
				hold: "hard",
				retryAfterMs: null,
				first: false,
				reservation: "r-1",
			}),
		).toStrictEqual({ ok: false, hold: "hard", retryAfterMs: null, first: false });
	});

	it.each<[string, unknown]>([
		["nothing", undefined],
		["null", null],
		["a string", "r-1"],
		["an array carrying a pass's fields", Object.assign([], { ok: true, reservation: "r-1" })],
		["a pass without its reservation", { ok: true }],
		["a pass whose reservation is empty", { ok: true, reservation: "" }],
		["a pass whose reservation is not a string", { ok: true, reservation: 1 }],
		["an ok that is truthy but not true", { ok: "yes", reservation: "r-1" }],
		["an ok that is missing", { reservation: "r-1" }],
		["a hold it does not name", { ok: false, hold: "forever", retryAfterMs: 1, first: true }],
		["a refusal without its hold", { ok: false, retryAfterMs: 1, first: true }],
		[
			"a hard hold with a time to come back",
			{ ok: false, hold: "hard", retryAfterMs: 1, first: true },
		],
		["a hard hold whose time is missing", { ok: false, hold: "hard", first: true }],
		[
			"a backoff with no time to come back",
			{ ok: false, hold: "backoff", retryAfterMs: null, first: true },
		],
		["a weekly hold already over", { ok: false, hold: "weekly", retryAfterMs: 0, first: true }],
		[
			"a backoff that came back before it was asked about",
			{ ok: false, hold: "backoff", retryAfterMs: -1, first: true },
		],
		[
			"a time that is not a number",
			{ ok: false, hold: "weekly", retryAfterMs: Number.NaN, first: true },
		],
		[
			"an infinite time",
			{ ok: false, hold: "backoff", retryAfterMs: Number.POSITIVE_INFINITY, first: true },
		],
		["a time as text", { ok: false, hold: "weekly", retryAfterMs: "1", first: true }],
		[
			"a refusal that does not say whether it is first",
			{ ok: false, hold: "hard", retryAfterMs: null },
		],
		["a first that is text", { ok: false, hold: "hard", retryAfterMs: null, first: "true" }],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaSubjectAttemptReservation(answer)).toBeUndefined();
	});

	it("reads each field once: a getter cannot answer the check and the caller differently", () => {
		let reads = 0;
		const answer = {
			ok: true,
			get reservation() {
				reads++;
				return reads === 1 ? "r-1" : 1;
			},
		};
		expect(readMfaSubjectAttemptReservation(answer)).toStrictEqual({
			ok: true,
			reservation: "r-1",
		});

		let holdReads = 0;
		const hold = {
			ok: false,
			hold: "backoff",
			get retryAfterMs() {
				holdReads++;
				return holdReads === 1 ? 900_000 : -1;
			},
			first: true,
		};
		expect(readMfaSubjectAttemptReservation(hold)).toStrictEqual({
			ok: false,
			hold: "backoff",
			retryAfterMs: 900_000,
			first: true,
		});
		expect(holdReads).toBe(1);
	});

	it("reads an answer whose field throws as no answer", () => {
		const answer = {
			get ok(): boolean {
				throw new Error("boom");
			},
			reservation: "r-1",
		};
		expect(readMfaSubjectAttemptReservation(answer)).toBeUndefined();
	});
});

describe("readSessionEmailProof", () => {
	const NOW = 1_800_000_000_000;

	it("reads no proof as no proof, and a proof as when it was given, up to the time asked about", () => {
		expect(readSessionEmailProof(null, NOW)).toBeNull();
		expect(readSessionEmailProof(NOW - 60_000, NOW)).toBe(NOW - 60_000);
		expect(readSessionEmailProof(NOW, NOW)).toBe(NOW);
		expect(readSessionEmailProof(0, NOW)).toBe(0);
	});

	it.each<[string, unknown]>([
		["a time after the one asked about", NOW + 1],
		["a time before the epoch", -1],
		["a time that is not a number", Number.NaN],
		["an infinite time", Number.NEGATIVE_INFINITY],
		["a time as text", String(NOW)],
		["a date", new Date(NOW)],
		["a record", { provedAtMs: NOW }],
		["a boolean", true],
		["nothing", undefined],
	])("reads %s as no answer", (_label, answer) => {
		expect(readSessionEmailProof(answer, NOW)).toBeUndefined();
	});
});

describe("readFirstBindingAt", () => {
	const NOW = 1_800_000_000_000;

	it("reads no mark as no mark, and a mark as when it was noted", () => {
		expect(readFirstBindingAt(null, NOW)).toBeNull();
		expect(readFirstBindingAt(NOW - 60_000, NOW)).toBe(NOW - 60_000);
		expect(readFirstBindingAt(NOW, NOW)).toBe(NOW);
		expect(readFirstBindingAt(0, NOW)).toBe(0);
	});

	it("reads a mark noted ahead of the time asked about, up to the clock skew allowed, as noted", () => {
		// The mark bounds which sessions are trusted: read earlier, it would
		// trust one it should not.
		expect(readFirstBindingAt(NOW + 60_000, NOW)).toBe(NOW + 60_000);
		expect(readFirstBindingAt(NOW + DEFAULT_CLOCK_SKEW_MS, NOW)).toBe(NOW + DEFAULT_CLOCK_SKEW_MS);
	});

	it.each<[string, unknown]>([
		["a time further ahead than the clock skew allowed", NOW + DEFAULT_CLOCK_SKEW_MS + 1],
		["a time before the epoch", -1],
		["a time that is not whole", NOW - 0.5],
		["a time that is not a number", Number.NaN],
		["an infinite time", Number.POSITIVE_INFINITY],
		["a time as text", String(NOW)],
		["a date", new Date(NOW)],
		["a record", { atMs: NOW }],
		["a boolean", true],
		["nothing", undefined],
	])("reads %s as no answer", (_label, answer) => {
		expect(readFirstBindingAt(answer, NOW)).toBeUndefined();
	});
});

const CONTINUATION = {
	interruptedBy: "mfa",
	primary: {
		subject: "u-alice",
		user: { id: "u-alice", username: "alice" },
		claims: {},
		recorded: {
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		},
		authTimeMs: 1_800_000_000_000,
		redirectTo: undefined,
		request: {},
	},
	done: [],
} as unknown as NonNullable<MfaTransaction["continuation"]>;

const BOUND: MfaTransaction = {
	id: "A".repeat(43),
	purpose: "login",
	binding: { kind: "session", id: "express-session-1" },
	subject: "u-alice",
	sid: undefined,
	continuation: CONTINUATION,
	redirectTo: undefined,
	enrollment: "none",
	emailProof: "not_required",
	acrValues: undefined,
	challenge: undefined,
	pendingEnrollment: undefined,
	attempts: 1,
	createdAtMs: 1_800_000_000_000,
	expiresAtMs: 1_800_000_600_000,
	version: 2,
};

describe("isConsumedMfaTransaction", () => {
	it("holds for the transaction the bound read returned, as the store consumed it", () => {
		expect(isConsumedMfaTransaction({ ...BOUND, attempts: 3 }, BOUND)).toBe(true);
	});

	it.each<[string, unknown]>([
		["another transaction's id", { ...BOUND, id: "B".repeat(43) }],
		["another subject", { ...BOUND, subject: "u-bob" }],
		["another purpose", { ...BOUND, purpose: "step_up" }],
		["another version", { ...BOUND, version: 3 }],
		["another binding", { ...BOUND, binding: { kind: "session", id: "express-session-2" } }],
		[
			"a continuation for another subject",
			{
				...BOUND,
				continuation: {
					...CONTINUATION,
					primary: { ...CONTINUATION.primary, subject: "u-bob" },
				},
			},
		],
		[
			"a continuation to another redirect",
			{
				...BOUND,
				continuation: {
					...CONTINUATION,
					primary: { ...CONTINUATION.primary, redirectTo: "https://app.example/elsewhere" },
				},
			},
		],
		["no continuation where the bound read had one", { ...BOUND, continuation: undefined }],
		["nothing", undefined],
		["a string", "consumed"],
	])("does not hold for %s", (_label, consumed) => {
		expect(isConsumedMfaTransaction(consumed, BOUND)).toBe(false);
	});

	it("does not hold for a record whose reading throws", () => {
		const consumed = {
			...BOUND,
			get subject(): string {
				throw new Error("boom");
			},
		};
		expect(isConsumedMfaTransaction(consumed, BOUND)).toBe(false);
	});
});

const RECORD: MfaFactorRecord = {
	id: "f".repeat(22),
	subject: "u-alice",
	kind: "totp",
	label: undefined,
	binding: "password",
	createdAt: new Date(0),
	lastUsedAt: undefined,
	version: 4,
	data: "sealed-before",
};

const REQUEST = {
	subject: "u-alice",
	id: RECORD.id,
	expectedVersion: 4,
	next: { data: "sealed-after", label: undefined, lastUsedAt: new Date(1000) },
} as const;

describe("isMfaFactorUpdateWritten", () => {
	it("holds for the record as the update wrote it: same identity, the next version, the data written", () => {
		expect(
			isMfaFactorUpdateWritten(
				{ ...RECORD, version: 5, data: "sealed-after", lastUsedAt: new Date(1000) },
				REQUEST,
			),
		).toBe(true);
	});

	it.each<[string, unknown]>([
		["nothing, for a lost compare-and-set", undefined],
		["true", true],
		["the record unchanged", RECORD],
		["the next version with the old data", { ...RECORD, version: 5 }],
		["the data written at the old version", { ...RECORD, data: "sealed-after" }],
		["a version two ahead", { ...RECORD, version: 6, data: "sealed-after" }],
		["another factor", { ...RECORD, id: "g".repeat(22), version: 5, data: "sealed-after" }],
		["another subject's", { ...RECORD, subject: "u-bob", version: 5, data: "sealed-after" }],
	])("does not hold for %s", (_label, written) => {
		expect(isMfaFactorUpdateWritten(written, REQUEST)).toBe(false);
	});

	it("does not hold for a record whose reading throws", () => {
		const written = {
			...RECORD,
			version: 5,
			data: "sealed-after",
			get subject(): string {
				throw new Error("boom");
			},
		};
		expect(isMfaFactorUpdateWritten(written, REQUEST)).toBe(false);
	});
});

describe("readMfaSubjectLeaseAnswer", () => {
	it("reads a lease acquired with its token, busy with the time left, and stale", () => {
		expect(readMfaSubjectLeaseAnswer({ outcome: "acquired", token: "t" })).toEqual({
			outcome: "acquired",
			token: "t",
		});
		expect(readMfaSubjectLeaseAnswer({ outcome: "busy", retryAfterMs: 1 })).toEqual({
			outcome: "busy",
			retryAfterMs: 1,
		});
		expect(readMfaSubjectLeaseAnswer({ outcome: "stale" })).toEqual({ outcome: "stale" });
	});

	it("copies only the fields its outcome has", () => {
		expect(readMfaSubjectLeaseAnswer({ outcome: "stale", token: "t" })).toEqual({
			outcome: "stale",
		});
	});

	it.each<[string, unknown]>([
		["a lease with no token", { outcome: "acquired" }],
		["a lease with an empty token", { outcome: "acquired", token: "" }],
		["a lease whose token is not text", { outcome: "acquired", token: 7 }],
		["busy with no time left", { outcome: "busy", retryAfterMs: 0 }],
		["busy with a time that is not a number", { outcome: "busy", retryAfterMs: Number.NaN }],
		["busy for ever", { outcome: "busy", retryAfterMs: Number.POSITIVE_INFINITY }],
		["busy with a time as text", { outcome: "busy", retryAfterMs: "1" }],
		["an outcome it does not know", { outcome: "granted", token: "t" }],
		["nothing", undefined],
		["null", null],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaSubjectLeaseAnswer(answer)).toBeUndefined();
	});

	it("reads each field once, and a getter that throws as no answer", () => {
		let reads = 0;
		const answer = {
			outcome: "acquired",
			get token() {
				reads++;
				return reads === 1 ? "t" : "";
			},
		};
		expect(readMfaSubjectLeaseAnswer(answer)).toEqual({ outcome: "acquired", token: "t" });
		expect(
			readMfaSubjectLeaseAnswer({
				get outcome(): string {
					throw new Error("boom");
				},
			}),
		).toBeUndefined();
	});
});

describe("readMfaSubjectRecoveryAnswer", () => {
	const applied = (
		cleared: { week: boolean; run: boolean; hard: boolean },
		hard: boolean,
	): Record<string, unknown> => ({
		outcome: "applied",
		recoveryId: "r",
		generation: 1,
		cleared,
		hard,
	});

	it.each<[string, Record<string, unknown>]>([
		["the budget given back", applied({ week: true, run: true, hard: false }, false)],
		["everything given back", applied({ week: true, run: true, hard: true }, false)],
		[
			"the week given back while the hard hold stands",
			applied({ week: true, run: false, hard: false }, true),
		],
		[
			"the hard hold lifted while the week stands",
			applied({ week: false, run: true, hard: true }, false),
		],
	])("reads an apply: %s", (_label, answer) => {
		expect(readMfaSubjectRecoveryAnswer(answer)).toEqual(answer);
	});

	it("reads an apply already made and each refusal, copied to their fields", () => {
		expect(
			readMfaSubjectRecoveryAnswer({
				outcome: "already_applied",
				recoveryId: "r",
				generation: 3,
				hard: true,
				cleared: { week: true, run: true, hard: true },
			}),
		).toEqual({ outcome: "already_applied", recoveryId: "r", generation: 3, hard: true });
		for (const reason of [
			"unauthorized",
			"expired",
			"not_revoked_since",
			"boundary_ahead",
			"lease_not_held",
		]) {
			expect(readMfaSubjectRecoveryAnswer({ outcome: "refused", reason, hard: false })).toEqual({
				outcome: "refused",
				reason,
				hard: false,
			});
		}
	});

	it.each<[string, unknown]>([
		[
			"the hard hold lifted and still standing",
			applied({ week: true, run: true, hard: true }, true),
		],
		[
			"the run kept with no hard hold standing",
			applied({ week: true, run: false, hard: false }, false),
		],
		[
			"the hard hold lifted with the run kept",
			applied({ week: true, run: false, hard: true }, false),
		],
		[
			"the run ended under a hard hold that stands",
			applied({ week: true, run: true, hard: false }, true),
		],
		["nothing given back", applied({ week: false, run: false, hard: false }, false)],
		[
			"the run ended and the week kept, with no hard hold lifted",
			applied({ week: false, run: true, hard: false }, false),
		],
		[
			"an apply at generation 0",
			{ ...applied({ week: true, run: true, hard: false }, false), generation: 0 },
		],
		[
			"a generation that is not whole",
			{ ...applied({ week: true, run: true, hard: false }, false), generation: 1.5 },
		],
		[
			"an empty recoveryId",
			{ ...applied({ week: true, run: true, hard: false }, false), recoveryId: "" },
		],
		[
			"a cleared part that is not a boolean",
			applied({ week: true, run: 1 as never, hard: false }, false),
		],
		["no cleared parts", { outcome: "applied", recoveryId: "r", generation: 1, hard: false }],
		[
			"a hard hold that is not a boolean",
			applied({ week: true, run: true, hard: false }, "no" as never),
		],
		[
			"an apply already made at generation 0",
			{ outcome: "already_applied", recoveryId: "r", generation: 0, hard: false },
		],
		["a refusal it does not know", { outcome: "refused", reason: "busy", hard: false }],
		["a refusal with no hard hold named", { outcome: "refused", reason: "expired" }],
		["an outcome it does not know", { outcome: "released", hard: false }],
		["nothing", undefined],
		["null", null],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaSubjectRecoveryAnswer(answer)).toBeUndefined();
	});

	it("reads each field once, and a getter that throws as no answer", () => {
		let reads = 0;
		const answer = {
			outcome: "refused",
			reason: "expired",
			get hard() {
				reads++;
				return reads === 1 ? true : "no";
			},
		};
		expect(readMfaSubjectRecoveryAnswer(answer)).toEqual({
			outcome: "refused",
			reason: "expired",
			hard: true,
		});
		expect(
			readMfaSubjectRecoveryAnswer({
				get outcome(): string {
					throw new Error("boom");
				},
			}),
		).toBeUndefined();
	});
});

describe("readMfaRecoverySetFloorAnswer", () => {
	it("reads a raise with the floor after it, and the refusal without the lease", () => {
		expect(readMfaRecoverySetFloorAnswer({ outcome: "raised", floor: 3 })).toEqual({
			outcome: "raised",
			floor: 3,
		});
		expect(readMfaRecoverySetFloorAnswer({ outcome: "refused", reason: "lease_not_held" })).toEqual(
			{ outcome: "refused", reason: "lease_not_held" },
		);
	});

	it.each<[string, unknown]>([
		["a floor of 0 after a raise", { outcome: "raised", floor: 0 }],
		["a floor that is not whole", { outcome: "raised", floor: 1.5 }],
		["a floor as text", { outcome: "raised", floor: "3" }],
		["a refusal it does not know", { outcome: "refused", reason: "unauthorized" }],
		["an outcome it does not know", { outcome: "lowered", floor: 1 }],
		["nothing", undefined],
		["null", null],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaRecoverySetFloorAnswer(answer)).toBeUndefined();
	});
});

describe("readMfaSubjectCount", () => {
	it("reads a safe whole number from 0", () => {
		expect(readMfaSubjectCount(0)).toBe(0);
		expect(readMfaSubjectCount(Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
	});

	it.each<[string, unknown]>([
		["a negative number", -1],
		["a number that is not whole", 1.5],
		["a number past the safe integers", 2 ** 53],
		["not a number", Number.NaN],
		["text", "1"],
		["nothing", undefined],
		["null", null],
	])("reads %s as no answer", (_label, answer) => {
		expect(readMfaSubjectCount(answer)).toBeUndefined();
	});
});

describe("on the package's root", () => {
	it("are the readings", () => {
		expect(core.readMfaSubjectLeaseAnswer).toBe(readMfaSubjectLeaseAnswer);
		expect(core.readMfaSubjectCount).toBe(readMfaSubjectCount);
		expect(core.readMfaSubjectRecoveryAnswer).toBe(readMfaSubjectRecoveryAnswer);
		expect(core.readMfaRecoverySetFloorAnswer).toBe(readMfaRecoverySetFloorAnswer);
		expect(core.readMfaAttemptReservation).toBe(readMfaAttemptReservation);
		expect(core.readMfaSubjectAttemptReservation).toBe(readMfaSubjectAttemptReservation);
		expect(core.isConsumedMfaTransaction).toBe(isConsumedMfaTransaction);
		expect(core.isMfaFactorUpdateWritten).toBe(isMfaFactorUpdateWritten);
		expect(core.readSessionEmailProof).toBe(readSessionEmailProof);
		expect(core.readFirstBindingAt).toBe(readFirstBindingAt);
	});
});
