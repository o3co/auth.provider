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
 * A login reopened for a binding (the MFA ADR's F3, D12, D24, D25), over the
 * coordinator's kit: under `required`, a proof that does not count, verified
 * for a subject left with no counting factor it can use, completes no login.
 * The verification consumes the transaction and spends the proof; then a new
 * login transaction is opened over the same continuation, bound to the same
 * browser session, for:
 *
 * - `allowed` beside a record that may count (`reopenedEnrollment`): bound by
 *   `mfa`, no proof asked, no codes issued;
 * - `required` otherwise, a first binding: the login's `User` must not say
 *   the subject enrolled, and the one gate (`firstBindingGate`) decides the
 *   proof over the continuation's address fact — core's
 *   `enrollmentFactsOfContinuation`, as read at the sign-in — and D25's flag.
 *
 * What it is opened for is settled before anything is spent (`plan`, called
 * before the transaction's attempt is reserved), so a refusal or an outage
 * there spends neither the transaction, nor an attempt, nor the proof: a
 * first binding's witness; the counting factors the user may enroll — none,
 * or one that cannot say, is an outage; D25's flag and the gate — a proof
 * nobody can give is refused; and `mfa.maxFactorsPerSubject` — for a first
 * binding, its factor and its codes, less a set they replace.
 */

import {
	enrollmentFactsOfContinuation,
	type InterruptionAnswer,
	type MfaFactorRecord,
	type MfaTransaction,
} from "@o3co/auth-provider-core";
import {
	type MfaCeremonyKit,
	type MfaReopenRefusal,
	type MfaStoreOutage,
	OUTSIDE_CONTRACT,
	outage,
} from "./ceremony.mjs";
import {
	countingKinds,
	enrollableKinds,
	firstBindingGate,
	MfaEnrollableError,
	recordsAfterFirstBinding,
	reopenedEnrollment,
} from "./firstBinding.mjs";

/** What a login is reopened for, settled before the proof is spent. */
export interface MfaReopenPlan {
	readonly enrollment: "allowed" | "required";
	readonly enrollable: readonly string[];
	/** Whether the account-email proof comes first: a first binding's, as the gate asked. */
	readonly emailProof: boolean;
}

/** The login's reopening over the coordinator's `kit` (see this file's header). */
export function createLoginReopen(kit: MfaCeremonyKit): {
	/** What `tx`'s login reopens for over the subject's `records`; why not, or the outage. */
	plan(
		tx: MfaTransaction,
		records: readonly MfaFactorRecord[],
	): Promise<MfaReopenPlan | MfaReopenRefusal | MfaStoreOutage>;
	/** The new transaction `plan` settled, over `consumed`'s continuation and binding: the login's `403`, or the outage. */
	open(consumed: MfaTransaction, plan: MfaReopenPlan): Promise<InterruptionAnswer | MfaStoreOutage>;
} {
	return {
		async plan(tx, records) {
			let facts: ReturnType<typeof enrollmentFactsOfContinuation>;
			try {
				if (tx.continuation === undefined) {
					throw new TypeError("the login's transaction carries no continuation");
				}
				facts = enrollmentFactsOfContinuation(tx.continuation);
			} catch (cause) {
				// The store holds a login's continuation to the same check at its create.
				return outage("mfa_transaction", "get", cause);
			}
			const enrollment = reopenedEnrollment(kit.factors, records);
			if (enrollment === "required" && facts.witness !== "not_enrolled") {
				return { outcome: "enrollment_state_inconsistent", witness: facts.witness };
			}
			let enrollable: string[];
			try {
				enrollable = enrollableKinds(kit.factors, tx.continuation.primary.user);
			} catch (cause) {
				if (!(cause instanceof MfaEnrollableError)) throw cause;
				return { outcome: "enrollable_failed", factorKind: cause.kind, cause };
			}
			if (enrollable.length === 0) {
				return { outcome: "nothing_enrollable", countingKinds: countingKinds(kit.factors) };
			}
			if (enrollment === "allowed") {
				return records.length < kit.maxFactorsPerSubject
					? { enrollment, enrollable, emailProof: false }
					: { outcome: "binding_refused", unprovable: undefined };
			}
			const flagged = await kit.emailProofRequired(tx.subject);
			if (typeof flagged !== "boolean") return flagged;
			const gate = firstBindingGate({
				requireEmailProof: kit.requireEmailProof,
				mailWired: kit.mailSender !== undefined,
				mailAddress: facts.mailAddress,
				requiredAtNextBinding: flagged,
			});
			if (gate.outcome === "unprovable") {
				return { outcome: "binding_refused", unprovable: gate.reason };
			}
			const by = gate.outcome === "prove" ? "email_proof" : "password";
			if (recordsAfterFirstBinding(kit.factors, records, by) > kit.maxFactorsPerSubject) {
				return { outcome: "binding_refused", unprovable: undefined };
			}
			return { enrollment, enrollable, emailProof: gate.outcome === "prove" };
		},

		open: async (consumed, plan) =>
			consumed.continuation === undefined
				? outage("mfa_transaction", "consume", OUTSIDE_CONTRACT)
				: kit.openLoginBinding(consumed.binding, consumed.continuation, {
						enrollment: plan.enrollment,
						enrollable: plan.enrollable,
						emailProof: plan.emailProof,
					}),
	};
}
