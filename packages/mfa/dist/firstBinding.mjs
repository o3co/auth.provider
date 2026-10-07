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
import { RECOVERY_CODE_FACTOR_KIND } from "./recovery/factor.mjs";
import { replacesStandingSets } from "./recovery/issue.mjs";
/**
 * Whether `record` may hold a counting factor: unless an installed factor of
 * its kind declares it does not, so a kind no longer installed counts. Right
 * for admitting, for telling a first binding, and for clearing the witness
 * after a removal — it fails closed, a password never standing in for a
 * factor it cannot see; wrong for a last-factor check, which asks for a
 * record of an installed counting kind.
 */
export const mayCount = (factors, record) => factors.get(record.kind)?.counting !== false;
/**
 * The enrollment a login reopens for once a non-counting proof left its
 * subject no counting factor it can use: `allowed`, a binding beside a
 * record that may count (one whose data does not open, a kind no longer
 * installed); else `required`, a first binding.
 */
export const reopenedEnrollment = (factors, records) => records.some((record) => mayCount(factors, record)) ? "allowed" : "required";
/**
 * How many records the subject holds once a recovery-code set issued beside
 * a binding by `binding` — `mfa` for a regeneration — stands beside
 * `records`: those records, less the sets the new one replaces, plus — the
 * recovery-code factor installed — the new set. Held to
 * `mfa.maxFactorsPerSubject`.
 */
export const recordsAfterRecoveryCodes = (factors, records, binding) => {
    const replaced = replacesStandingSets(binding);
    const staying = records.filter((record) => !(replaced && record.kind === RECOVERY_CODE_FACTOR_KIND)).length;
    return staying + (factors.get(RECOVERY_CODE_FACTOR_KIND) === undefined ? 0 : 1);
};
/**
 * How many records the subject holds once a first binding by `binding`
 * stands beside `records` (its own factor not among them): what its
 * recovery codes leave (`recordsAfterRecoveryCodes`), plus its factor. Held
 * to `mfa.maxFactorsPerSubject`.
 */
export const recordsAfterFirstBinding = (factors, records, binding) => recordsAfterRecoveryCodes(factors, records, binding) + 1;
/** A factor's `enrollable` that threw: its `kind`, and the factor's error as `cause`, never quoted. */
export class MfaEnrollableError extends Error {
    kind;
    constructor(kind, cause) {
        super(`the ${kind} factor could not say whether the user may enroll it`, { cause });
        this.kind = kind;
        this.name = "MfaEnrollableError";
    }
}
/** The kinds of the installed counting factors, in registration order. */
export const countingKinds = (factors) => [...factors.entries()].filter(([, factor]) => factor.counting).map(([kind]) => kind);
/**
 * Whether `user` may enroll `factor`, contributed as `kind`. A factor whose
 * `enrollable` throws cannot answer — an outage, never "not offered" — so
 * the throw goes through, as an {@link MfaEnrollableError} naming its kind.
 */
export const mayEnroll = (kind, factor, user) => {
    try {
        return Boolean(factor.enrollable?.(user) ?? true);
    }
    catch (cause) {
        throw new MfaEnrollableError(kind, cause);
    }
};
/**
 * The counting factors `user` may enroll, in registration order: what a
 * first binding offers. A factor whose `enrollable` throws is an outage
 * ({@link mayEnroll}).
 */
export const enrollableKinds = (factors, user) => [...factors.entries()].flatMap(([kind, factor]) => factor.counting && mayEnroll(kind, factor, user) ? [kind] : []);
/** `mfa.enrollment.requireEmailProof`. */
export const REQUIRE_EMAIL_PROOF = ["when-mail", "always", "never"];
const BIND = Object.freeze({ outcome: "bind" });
const PROVE = Object.freeze({ outcome: "prove" });
/** The gate over `input` (see this file's header). */
export function firstBindingGate(input) {
    const { requireEmailProof, mailWired, mailAddress, requiredAtNextBinding } = input;
    /** The proof asked for: given where it can be, else unprovable, with why. */
    const asked = () => {
        if (!mailWired)
            return { outcome: "unprovable", reason: "no_sender" };
        if (mailAddress === "address")
            return PROVE;
        return {
            outcome: "unprovable",
            reason: mailAddress === "unreadable" ? "unreadable_address" : "no_address",
        };
    };
    if (requiredAtNextBinding || requireEmailProof === "always")
        return asked();
    if (requireEmailProof === "never" || !mailWired || mailAddress === "none")
        return BIND;
    return asked();
}
