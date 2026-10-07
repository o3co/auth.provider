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
 * The MFA transactions a ceremony runs on: the one a login opens, with the
 * answer the login is interrupted with, and the `enroll` and `step_up` ones a
 * signed-in session opens. See README, "The login's interruption", and ADR
 * 2026-09-25-multi-factor-authentication, as ADR 2026-09-28-session-admission
 * amends it.
 *
 * A login's is opened after the regeneration and bound to the regenerated
 * session, so the browser holding the new cookie is the one that may
 * continue. The id is not a bearer: every later use compares the whole
 * binding, kind included (`isMfaTransactionBoundTo`). The record carries
 * core's continuation, never a `user` or `primary` field of its own, and the
 * primary's subject and `redirectTo`, which the store holds it to. An
 * `enroll` or `step_up` one is bound to the browser session and records the
 * session's `sid` and subject, which every use compares with the session
 * admitted; a `step_up` one owes no proof, binds nothing, and records the
 * `acr_values` the page hinted.
 * `expiresAtMs` is derived from `mfa.transactionTtlSeconds` and nothing else;
 * the store has no ceiling of its own. A store that cannot create one rejects,
 * answered as an outage.
 *
 * A login reopened for a binding after a non-counting proof is a new login
 * transaction over the same continuation, bound to the same browser session,
 * answered with the login's own `403`: `allowed` asks no proof, `required`
 * the proof the gate asked.
 */
import { randomBytes } from "node:crypto";
/** The bytes of a transaction's id: 256 bits. */
const TRANSACTION_ID_BYTES = 32;
/** The shortest and the longest a transaction may live, in seconds. */
export const MFA_TRANSACTION_TTL_SECONDS = { min: 60, max: 1800 };
/** A new transaction id: 32 bytes from the CSPRNG, base64url. Never in a URL. */
const newTransactionId = () => randomBytes(TRANSACTION_ID_BYTES).toString("base64url");
/**
 * The login's transactions over `store`, each living `ttlSeconds` — refused
 * with a `RangeError` when it is not a whole number from 60 to 1800.
 */
export function createLoginTransactions({ store, ttlSeconds, now = Date.now, }) {
    if (!Number.isSafeInteger(ttlSeconds) ||
        ttlSeconds < MFA_TRANSACTION_TTL_SECONDS.min ||
        ttlSeconds > MFA_TRANSACTION_TTL_SECONDS.max) {
        throw new RangeError(`mfa.transactionTtlSeconds must be a whole number from ${MFA_TRANSACTION_TTL_SECONDS.min} to ${MFA_TRANSACTION_TTL_SECONDS.max} seconds`);
    }
    return {
        async open(sessionId, continuation, interruption) {
            // Held at run time too, before anything is stored: the answer and the
            // transaction say the same.
            if (interruption.error === "mfa_enrollment_required" &&
                typeof interruption.emailProof !== "boolean") {
                throw new RangeError("a first binding's email_proof must be true or false");
            }
            const firstBinding = interruption.error === "mfa_enrollment_required";
            const id = newTransactionId();
            await store.create(loginTransaction({
                id,
                binding: { kind: "session", id: sessionId },
                continuation,
                enrollment: firstBinding ? "required" : "none",
                emailProof: firstBinding && interruption.emailProof,
                nowMs: now(),
                ttlSeconds,
            }));
            return interruptionAnswer(id, ttlSeconds, interruption);
        },
    };
}
/** The new login transaction `id` over `continuation`, bound to `binding`. */
const loginTransaction = (shape) => ({
    id: shape.id,
    purpose: "login",
    binding: shape.binding,
    subject: shape.continuation.primary.subject,
    sid: undefined,
    continuation: shape.continuation,
    redirectTo: shape.continuation.primary.redirectTo,
    enrollment: shape.enrollment,
    emailProof: shape.emailProof ? "required" : "not_required",
    acrValues: undefined,
    challenge: undefined,
    pendingEnrollment: undefined,
    attempts: 0,
    createdAtMs: shape.nowMs,
    expiresAtMs: shape.nowMs + shape.ttlSeconds * 1000,
    version: 0,
});
/** The login's closed `403` naming transaction `id`, living `ttlSeconds`. */
const interruptionAnswer = (id, ttlSeconds, interruption) => ({
    status: 403,
    body: {
        error: interruption.error,
        transaction: id,
        expires_in: ttlSeconds,
        ...(interruption.error === "mfa_enrollment_required"
            ? {
                hints: {
                    enrollable: [...interruption.enrollable],
                    email_proof: interruption.emailProof,
                },
            }
            : {}),
    },
});
/**
 * Creates the login transaction `shape` reopens in `store` and answers the
 * login's `403 mfa_enrollment_required` naming it. A proof owed beside a
 * record that may count is a `RangeError`, before anything is stored; a
 * store that cannot keep it rejects.
 */
export async function openLoginBinding(store, shape) {
    if (typeof shape.emailProof !== "boolean" ||
        (shape.enrollment === "allowed" && shape.emailProof)) {
        throw new RangeError("a binding beside a factor that may count owes no account-email proof");
    }
    const id = newTransactionId();
    await store.create(loginTransaction({
        id,
        binding: shape.binding,
        continuation: shape.continuation,
        enrollment: shape.enrollment,
        emailProof: shape.emailProof,
        nowMs: shape.nowMs,
        ttlSeconds: shape.ttlSeconds,
    }));
    return interruptionAnswer(id, shape.ttlSeconds, {
        error: "mfa_enrollment_required",
        enrollable: shape.enrollable,
        emailProof: shape.emailProof,
    });
}
/** A new transaction of a signed-in session, bound to the browser session `sessionId` names, with no continuation, stored and answered. */
async function openSessionTransaction(store, shape) {
    const transaction = {
        id: newTransactionId(),
        purpose: shape.purpose,
        binding: { kind: "session", id: shape.sessionId },
        subject: shape.subject,
        sid: shape.sid,
        continuation: undefined,
        redirectTo: undefined,
        enrollment: shape.enrollment,
        emailProof: shape.emailProof,
        acrValues: shape.acrValues,
        challenge: undefined,
        pendingEnrollment: undefined,
        attempts: 0,
        createdAtMs: shape.nowMs,
        expiresAtMs: shape.nowMs + shape.ttlSeconds * 1000,
        version: 0,
    };
    await store.create(transaction);
    return transaction;
}
/**
 * Creates a new `enroll` transaction for `shape` in `store` — a fresh id, no
 * continuation, bound to the session `sessionId` names — and answers it.
 * Rejects when the store cannot keep it.
 */
export function openEnrollTransaction(store, shape) {
    return openSessionTransaction(store, { ...shape, purpose: "enroll", acrValues: undefined });
}
/**
 * Creates a new `step_up` transaction for `shape` in `store` — a fresh id, no
 * continuation, bound to the session `sessionId` names, verifying a factor
 * the subject holds and owing no proof — and answers it. Rejects when the
 * store cannot keep it.
 */
export function openStepUpTransaction(store, shape) {
    return openSessionTransaction(store, {
        ...shape,
        purpose: "step_up",
        enrollment: "none",
        emailProof: "not_required",
    });
}
