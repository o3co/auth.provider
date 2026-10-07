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
import { UNKNOWN_TRANSACTION, } from "./ceremony.mjs";
import { mayCount } from "./firstBinding.mjs";
/** The step-up over the coordinator's `kit` (see this file's header). */
export function createMfaStepUp(kit) {
    /** `tx` as the page names it next, and whether the proof is owed on it. */
    const opened = (tx) => ({
        outcome: "opened",
        transaction: {
            id: tx.id,
            expiresIn: Math.max(1, Math.ceil((tx.expiresAtMs - kit.now()) / 1000)),
        },
        emailProof: tx.emailProof === "required",
    });
    return {
        async open(call) {
            const session = call.session;
            if (session === undefined)
                return UNKNOWN_TRANSACTION;
            // Read as the offers read it: a retired set is not usable.
            const reading = await kit.readSubject(session.subject);
            if ("outcome" in reading)
                return reading;
            if (reading.records.some((record) => mayCount(kit.factors, record))) {
                if (!session.secondFactorRecordable)
                    return { outcome: "step_up_unrecordable" };
                if (!kit.holdsUsable(reading)) {
                    return { outcome: "no_qualifying_factor" };
                }
                if (call.transactionId !== undefined) {
                    const tx = await kit.boundInSession(call);
                    if (tx === null)
                        return UNKNOWN_TRANSACTION;
                    if ("outcome" in tx)
                        return tx;
                    return tx.purpose === "step_up" ? opened(tx) : UNKNOWN_TRANSACTION;
                }
                const created = await kit.openStepUp(call, session, call.acrValues);
                return "outcome" in created ? created : opened(created);
            }
            if (call.transactionId !== undefined) {
                const tx = await kit.boundInSession(call);
                if (tx === null)
                    return UNKNOWN_TRANSACTION;
                if ("outcome" in tx)
                    return tx;
                if (tx.purpose !== "enroll" || tx.enrollment !== "required")
                    return UNKNOWN_TRANSACTION;
                if (tx.emailProof === "required")
                    return opened(tx);
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
