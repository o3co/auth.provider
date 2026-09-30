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
 * bound read: a reservation, a consumed transaction and a factor's
 * compare-and-set. An answer outside the promise is `undefined` or `false`,
 * which a caller answers as the store's outage — never as a verdict.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";
import { isMfaFactorUpdateWritten, type MfaFactorRecord } from "#/mfa/factorStore.mjs";
import {
	isConsumedMfaTransaction,
	type MfaTransaction,
	readMfaAttemptReservation,
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
	sends: 0,
	lastSentAtMs: undefined,
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
});

describe("on the package's root", () => {
	it("are the three readings", () => {
		expect(core.readMfaAttemptReservation).toBe(readMfaAttemptReservation);
		expect(core.isConsumedMfaTransaction).toBe(isConsumedMfaTransaction);
		expect(core.isMfaFactorUpdateWritten).toBe(isMfaFactorUpdateWritten);
	});
});
