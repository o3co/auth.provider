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
 * The rules every `MfaTransactionStore` adapter holds a session's
 * account-email proof to, in one place: what a record may be, judged on the
 * store's clock, and what a question is answered.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";
import {
	checkSessionEmailProof,
	checkSessionEmailProofQuestion,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	sessionEmailProofAnswer,
} from "#/mfa/transactionStore.mjs";

const STORE_NOW = 1_800_000_000_000;
const MINUTE = 60_000;

describe("checkSessionEmailProof — a proof a store can keep, on its clock", () => {
	it("admits a proof given up to the skew allowance ahead of the store's clock, ending after it", () => {
		expect(() =>
			checkSessionEmailProof("user-1", "sid-1", STORE_NOW, STORE_NOW + MINUTE, STORE_NOW),
		).not.toThrow();
		expect(() =>
			checkSessionEmailProof(
				"user-1",
				"sid-1",
				STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS,
				STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + MINUTE,
				STORE_NOW,
			),
		).not.toThrow();
	});

	it.each<[string, number, number]>([
		["an end at the store's clock", STORE_NOW - MINUTE, STORE_NOW],
		["an end before the store's clock", STORE_NOW - 2 * MINUTE, STORE_NOW - MINUTE],
		[
			"a proof time past the skew allowance",
			STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1,
			STORE_NOW + MFA_CLOCK_SKEW_ALLOWANCE_MS + MINUTE,
		],
	])("refuses %s with a RangeError", (_label, provedAtMs, untilMs) => {
		expect(() => checkSessionEmailProof("user-1", "sid-1", provedAtMs, untilMs, STORE_NOW)).toThrow(
			RangeError,
		);
	});
});

describe("checkSessionEmailProofQuestion — a question a store can answer", () => {
	it("refuses a time before the epoch, and admits the epoch", () => {
		expect(() => checkSessionEmailProofQuestion("user-1", "sid-1", -1)).toThrow(RangeError);
		expect(() => checkSessionEmailProofQuestion("user-1", "sid-1", 0)).not.toThrow();
	});
});

describe("sessionEmailProofAnswer — what a store answers of a proof it holds", () => {
	const proof = { provedAtMs: STORE_NOW - MINUTE, untilMs: STORE_NOW + 10 * MINUTE };

	it("answers when it was given while its end is after both the time asked about and the store's clock", () => {
		expect(sessionEmailProofAnswer(proof, STORE_NOW, STORE_NOW)).toBe(STORE_NOW - MINUTE);
	});

	it("answers no later than the time asked about", () => {
		expect(sessionEmailProofAnswer(proof, STORE_NOW - 2 * MINUTE, STORE_NOW)).toBe(
			STORE_NOW - 2 * MINUTE,
		);
	});

	it("answers nothing at or past its end, on either clock", () => {
		expect(sessionEmailProofAnswer(proof, proof.untilMs, STORE_NOW)).toBeNull();
		expect(sessionEmailProofAnswer(proof, STORE_NOW, proof.untilMs)).toBeNull();
		expect(sessionEmailProofAnswer(proof, STORE_NOW, proof.untilMs + MINUTE)).toBeNull();
	});

	it("is on the package's root", () => {
		expect(core.sessionEmailProofAnswer).toBe(sessionEmailProofAnswer);
	});
});
