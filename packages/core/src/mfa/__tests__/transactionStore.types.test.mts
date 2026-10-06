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
 * What `MfaTransactionStore` keeps and takes. A transaction counts no sends:
 * a limit on sending is the mail sender's. The subject lock trusts no
 * browser: an exempt success ends the run and answers nothing, and no
 * attempt is let through the weekly hold. These are type assertions: the
 * file is in core's typecheck list.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import {
	MFA_TRANSACTION_PATCH_KEYS,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptReservation,
	type MfaSubjectHold,
	type MfaSubjectRecoveryAnswer,
	type MfaSubjectRecoveryApplication,
	type MfaTransaction,
	type MfaTransactionPatch,
	type MfaTransactionStore,
} from "#/mfa/transactionStore.mjs";

describe("the MfaTransactionStore port", () => {
	it("keeps no send count and no last send on a transaction, and patches neither", () => {
		expectTypeOf<MfaTransaction>().not.toHaveProperty("sends");
		expectTypeOf<MfaTransaction>().not.toHaveProperty("lastSentAtMs");
		expectTypeOf<keyof MfaTransactionPatch>().toEqualTypeOf<
			"enrollment" | "emailProof" | "challenge" | "pendingEnrollment"
		>();
		expect(MFA_TRANSACTION_PATCH_KEYS).toEqual([
			"enrollment",
			"emailProof",
			"challenge",
			"pendingEnrollment",
		]);
	});

	it("holds a lockout policy to the run, the backoff, the week and the hard limit, and to no browser", () => {
		expectTypeOf<keyof MfaLockoutPolicy>().toEqualTypeOf<
			"threshold" | "baseSeconds" | "maxSeconds" | "memorySeconds" | "weeklyBudget" | "hardLimit"
		>();
		expect(true).toBe(true);
	});

	it("reserves a subject's attempt with no browser, and notes an exempt success with the subject, the time and the lockout policy", () => {
		expectTypeOf<MfaTransactionStore["reserveSubjectAttempt"]>().toEqualTypeOf<
			(
				subject: string,
				nowMs: number,
				policy: MfaLockoutPolicy,
			) => Promise<MfaSubjectAttemptReservation>
		>();
		expectTypeOf<MfaTransactionStore["noteExemptSuccess"]>().toEqualTypeOf<
			(subject: string, nowMs: number, policy: MfaLockoutPolicy) => Promise<void>
		>();
		expect(true).toBe(true);
	});

	it("answers a refused attempt with the hold, when to come back, and whether the refusal begins an episode", () => {
		expectTypeOf<Extract<MfaSubjectAttemptReservation, { ok: false }>>().toEqualTypeOf<{
			readonly ok: false;
			readonly hold: MfaSubjectHold;
			readonly retryAfterMs: number | null;
			readonly first: boolean;
		}>();
		expect(true).toBe(true);
	});

	it("notes a subject's first binding with its time and end, answering the mark that stood, and answers the time or null", () => {
		expectTypeOf<MfaTransactionStore["noteFirstBinding"]>().toEqualTypeOf<
			// biome-ignore lint/suspicious/noConfusingVoidType: the form that answers nothing, until it is removed
			(subject: string, atMs: number, untilMs: number) => Promise<number | null | void>
		>();
		expectTypeOf<MfaTransactionStore["firstBindingAt"]>().toEqualTypeOf<
			(subject: string, nowMs: number) => Promise<number | null>
		>();
		expect(true).toBe(true);
	});

	it("has no clearSubjectState: an applied recovery is the one way the lock state ends early", () => {
		expectTypeOf<MfaTransactionStore>().not.toHaveProperty("clearSubjectState");
		expectTypeOf<MfaTransactionStore["applySubjectRecovery"]>().toEqualTypeOf<
			(
				subject: string,
				application: MfaSubjectRecoveryApplication,
			) => Promise<MfaSubjectRecoveryAnswer>
		>();
		expect(true).toBe(true);
	});

	it("answers, on every outcome, from when a rebind counts exactly while the hard hold stands: hard narrows rebindAfterMs", () => {
		type Outcome = MfaSubjectRecoveryAnswer["outcome"];
		expectTypeOf<MfaSubjectRecoveryAnswer["rebindAfterMs"]>().toEqualTypeOf<number | null>();
		expectTypeOf<
			Extract<MfaSubjectRecoveryAnswer, { readonly hard: true }>["rebindAfterMs"]
		>().toEqualTypeOf<number>();
		expectTypeOf<
			Extract<MfaSubjectRecoveryAnswer, { readonly hard: false }>["rebindAfterMs"]
		>().toEqualTypeOf<null>();
		expectTypeOf<
			Extract<MfaSubjectRecoveryAnswer, { readonly hard: true }>["outcome"]
		>().toEqualTypeOf<Outcome>();
		expectTypeOf<
			Extract<MfaSubjectRecoveryAnswer, { readonly hard: false }>["outcome"]
		>().toEqualTypeOf<Outcome>();
		const after = (answer: MfaSubjectRecoveryAnswer): number | undefined => {
			if (!answer.hard) {
				expectTypeOf(answer.rebindAfterMs).toEqualTypeOf<null>();
				return undefined;
			}
			expectTypeOf(answer.rebindAfterMs).toEqualTypeOf<number>();
			return answer.rebindAfterMs;
		};
		expect(after({ outcome: "refused", reason: "expired", hard: true, rebindAfterMs: 1 })).toBe(1);
	});
});
