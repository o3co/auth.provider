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
 * What it is opened for is settled before anything is spent (`plan`), so a
 * refusal or an outage there spends neither the transaction nor the proof.
 */

import {
	enrollmentFactsOfContinuation,
	type InterruptionAnswer,
	type MfaFactorRecord,
	type MfaTransaction,
} from "@o3co/auth-provider-core";
import { type MfaCeremonyKit, type MfaStoreOutage, outage } from "./ceremony.mjs";
import {
	enrollableKinds,
	firstBindingGate,
	reopenedEnrollment,
	type UnprovableReason,
} from "./firstBinding.mjs";

/** What a login is reopened for, settled before the proof is spent. */
export interface MfaReopenPlan {
	readonly enrollment: "allowed" | "required";
	readonly enrollable: readonly string[];
	/** Whether the account-email proof comes first: a first binding's, as the gate asked. */
	readonly emailProof: boolean;
	/** Why the proof the gate asked nobody can give; `undefined` when it can be, or none is asked. */
	readonly unprovable: UnprovableReason | undefined;
}

/** The login's reopening over the coordinator's `kit` (see this file's header). */
export function createLoginReopen(kit: MfaCeremonyKit): {
	/** What `tx`'s login reopens for over the subject's `records`; why not, or the outage. */
	plan(
		tx: MfaTransaction,
		records: readonly MfaFactorRecord[],
	): Promise<
		| MfaReopenPlan
		| MfaStoreOutage
		| {
				readonly outcome: "enrollment_state_inconsistent";
				readonly witness: "enrolled" | "malformed";
		  }
	>;
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
			const enrollable = enrollableKinds(kit.factors, tx.continuation.primary.user);
			if (reopenedEnrollment(kit.factors, records) === "allowed") {
				return { enrollment: "allowed", enrollable, emailProof: false, unprovable: undefined };
			}
			if (facts.witness !== "not_enrolled") {
				return { outcome: "enrollment_state_inconsistent", witness: facts.witness };
			}
			const flagged = await kit.emailProofRequired(tx.subject);
			if (typeof flagged !== "boolean") return flagged;
			const gate = firstBindingGate({
				requireEmailProof: kit.requireEmailProof,
				mailWired: kit.mailSender !== undefined,
				mailAddress: facts.mailAddress,
				requiredAtNextBinding: flagged,
			});
			return {
				enrollment: "required",
				enrollable,
				emailProof: gate.outcome !== "bind",
				unprovable: gate.outcome === "unprovable" ? gate.reason : undefined,
			};
		},

		open: (consumed, plan) =>
			kit.openLoginBinding(consumed.binding.id, consumed.continuation, {
				enrollment: plan.enrollment,
				enrollable: plan.enrollable,
				emailProof: plan.emailProof,
			}),
	};
}
