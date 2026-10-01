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
 * A signed-in session's step-up (the MFA ADR's F2), over the coordinator's
 * kit. For a subject holding no record that may count (`mayCount`), its
 * first-binding branch: the `enroll` transaction the account-email proof is
 * owed on — the one the call names, when it is that session's own
 * first-binding transaction and its proof is not met, raised to owe it; a
 * new one otherwise, a met proof included, since the session's proof it
 * recorded may be lost. A subject holding one is answered
 * `counting_factor_held`: the branch that steps up a second factor goes
 * here beside this one.
 */

import type { MfaTransaction } from "@o3co/auth-provider-core";
import {
	type MfaCeremonyCall,
	type MfaCeremonyKit,
	type MfaStepUpOutcome,
	UNKNOWN_TRANSACTION,
} from "./ceremony.mjs";
import { mayCount } from "./firstBinding.mjs";

/** The step-up over the coordinator's `kit` (see this file's header). */
export function createMfaStepUp(kit: MfaCeremonyKit): {
	open(call: MfaCeremonyCall): Promise<MfaStepUpOutcome>;
} {
	/** `tx` as the page names it next. */
	const opened = (tx: MfaTransaction): MfaStepUpOutcome => ({
		outcome: "opened",
		transaction: {
			id: tx.id,
			expiresIn: Math.max(1, Math.ceil((tx.expiresAtMs - kit.now()) / 1000)),
		},
	});

	return {
		async open(call) {
			const session = call.session;
			if (session === undefined) return UNKNOWN_TRANSACTION;
			const records = await kit.recordsOf(session.subject);
			if ("outcome" in records) return records;
			if (records.some((record) => mayCount(kit.factors, record))) {
				return { outcome: "counting_factor_held" };
			}
			if (call.transactionId !== undefined) {
				const tx = await kit.bound(call);
				// A login's transaction, past the boundary or not, is no step-up's.
				if (tx === null || ("outcome" in tx && tx.outcome === "revoked")) {
					return UNKNOWN_TRANSACTION;
				}
				if ("outcome" in tx) return tx;
				if (tx.purpose !== "enroll" || tx.enrollment !== "required") return UNKNOWN_TRANSACTION;
				if (tx.emailProof === "required") return opened(tx);
				if (tx.emailProof === "not_required") {
					const owed = await kit.write(tx, { emailProof: "required" });
					return "outcome" in owed ? owed : opened(owed.written);
				}
			}
			const created = await kit.openEnrollment(call, session, {
				enrollment: "required",
				emailProof: "required",
			});
			return "outcome" in created ? created : opened(created);
		},
	};
}
