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
 * The operator reset, `resetMfaForSubject`: for a subject who lost their
 * second factors, an identity the operator verified out of band.
 *
 * - Refused with a `RangeError`, nothing done, for a subject that is not a
 *   non-empty string, a federation-grant disposition other than `revoke` or
 *   `keep`, a `requestedBy` that is not a well-formed string of 1 to 256
 *   characters, or `requireEmailProof` with no mail sender wired — nobody
 *   could give the proof, so nobody could bind. A Store must also not ask it
 *   for an account with no address.
 * - Then, in this order: every session and token of the subject's ended
 *   (`revokeAllForSubject`, the federation grants as asked) — a revocation
 *   that throws or is not complete stops it, nothing more done; then, under
 *   one lease of the subject's, waited for (`factorSet.mts`), each write held
 *   to the lease's time: D25's flag set when asked — under the lease, so no
 *   binding that held it before can clear it — the reset's own one-time
 *   authorization recorded (`lockRecovery.mts`) and applied: the lock state
 *   reset whole — the hard hold, every authorization of the subject's, and
 *   the generation moved on, so a factor-set write begun before stops at its
 *   commit — then every record removed (`removeAllForSubject`: one sealed
 *   under a retired key, of a kind not installed, or a recovery-code set
 *   alike), and the witness cleared last; and, once the lease part is done,
 *   every session and token ended again: a login made with a factor before
 *   its removal ends too.
 * - Answers a report: whether it completed — both revocations complete, the
 *   lease held throughout — where it stopped, both sessions' reports, the
 *   kinds and count of the records removed (once the removal succeeded), the
 *   generation, the witness. It is idempotent: run again, it does it all
 *   again. Emits one `mfa.reset`, and no `mfa.lock.recovered`.
 * - Residual: a write admitted before the revocation that ran past its lease
 *   can land after the removal; the factor-set's lease is logical.
 */
import { emitAuditEvent, loggableError, MFA_RECOVERY_AUTHORIZATION_MAX_MS, } from "@o3co/auth-provider-core";
import { createMfaFactorSetReset } from "./factorSet.mjs";
import { mintSubjectRecovery } from "./lockRecovery.mjs";
import { createMfaEnrollmentWitness } from "./witness.mjs";
/** The longest `requestedBy` a reset records. */
const REQUESTED_BY_MAX = 256;
/** `request` read once, or a `RangeError` naming what is wrong. */
function checkRequest(subject, request) {
    const refuse = (what) => {
        throw new RangeError(`resetMfaForSubject: ${what}`);
    };
    if (typeof subject !== "string" || subject.length === 0)
        refuse("subject must be a non-empty string");
    if (typeof request !== "object" || request === null || Array.isArray(request)) {
        return refuse("the request must be an object");
    }
    const { requireEmailProof, federationGrants, requestedBy } = request;
    if (requireEmailProof !== undefined && typeof requireEmailProof !== "boolean") {
        refuse("requireEmailProof must be a boolean");
    }
    if (federationGrants !== undefined &&
        federationGrants !== "revoke" &&
        federationGrants !== "keep") {
        refuse('federationGrants must be "revoke" or "keep"');
    }
    if (requestedBy !== undefined &&
        (typeof requestedBy !== "string" ||
            requestedBy.length === 0 ||
            requestedBy.length > REQUESTED_BY_MAX ||
            !requestedBy.isWellFormed())) {
        refuse(`requestedBy must be a well-formed string of 1 to ${REQUESTED_BY_MAX} characters`);
    }
    return {
        requireEmailProof: requireEmailProof === true,
        ...(federationGrants === undefined
            ? {}
            : { federationGrants: federationGrants }),
        ...(requestedBy === undefined ? {} : { requestedBy: requestedBy }),
    };
}
/** The kinds `records` name, each once in code-unit order; a record that is none, or whose kind cannot be read as a string, names none. */
function kindsOf(records) {
    const kinds = new Set();
    for (const record of records) {
        try {
            const kind = record?.kind;
            if (typeof kind === "string")
                kinds.add(kind);
        }
        catch {
            // A store's record whose field cannot be read names no kind; it was still removed.
        }
    }
    return [...kinds].sort();
}
/** The operator reset over `options` (see this file's header). */
export function createMfaReset(options) {
    const { factorStore, transactionStore, subjectRevocationService, auditSink, logger } = options;
    if (typeof subjectRevocationService?.revokeAllForSubject !== "function") {
        throw new TypeError("the operator reset's subjectRevocationService is no service: it has no revokeAllForSubject");
    }
    const now = options.now ?? (() => Date.now());
    const witness = createMfaEnrollmentWitness(options.userRepository);
    const underLease = createMfaFactorSetReset({
        factorStore,
        witness,
        leases: options.leases,
    });
    return {
        async resetMfaForSubject(subject, request = {}) {
            const asked = checkRequest(subject, request);
            if (asked.requireEmailProof && !options.mailWired) {
                throw new RangeError("resetMfaForSubject: requireEmailProof needs a mail sender, and none is wired: nobody could give the account-email proof, so nobody could bind a factor");
            }
            /** Whether each revocation ended every session, as read once, inside its guard: the deployment's report is never read again. */
            const ended = { sessions: false };
            /** `report` audited once, said once, and answered. */
            const finish = (report) => {
                emitAuditEvent(auditSink, {
                    timestamp: new Date(now()),
                    type: "mfa.reset",
                    subject,
                    details: {
                        by: "operator",
                        ...(report.removed === undefined
                            ? {}
                            : { kinds: [...report.removed.kinds], count: report.removed.count }),
                        requireEmailProof: asked.requireEmailProof,
                        sessions: ended.sessions,
                        ...(ended.sessionsAgain === undefined ? {} : { sessionsAgain: ended.sessionsAgain }),
                        complete: report.complete,
                        ...(asked.requestedBy === undefined ? {} : { requestedBy: asked.requestedBy }),
                    },
                });
                if (report.complete) {
                    logger?.info({ sub: subject, generation: report.generation }, "mfa_reset");
                }
                else {
                    logger?.warn({
                        sub: subject,
                        ...(report.stoppedAt === undefined ? {} : { stoppedAt: report.stoppedAt }),
                        ...(report.cause === undefined ? {} : { err: loggableError(report.cause) }),
                    }, "mfa_reset_incomplete");
                }
                if (report.overran === true) {
                    logger?.error({ sub: subject }, "mfa_subject_lease_overrun");
                }
                return report;
            };
            const base = { subject, requireEmailProof: asked.requireEmailProof };
            /** Every session and token of the subject's ended: the report and its completeness, read once, or why not. */
            const revoke = async () => {
                let report;
                let complete;
                try {
                    report = await subjectRevocationService.revokeAllForSubject({
                        subject,
                        ...(asked.federationGrants === undefined
                            ? {}
                            : { federationGrants: asked.federationGrants }),
                    });
                    // The service is the deployment's: a report that is none, or whose read throws, ends nothing.
                    complete = report?.complete;
                }
                catch (cause) {
                    return { cause, complete: false };
                }
                if (typeof report !== "object" || report === null) {
                    return {
                        cause: new TypeError("the subject revocation service answered no report"),
                        complete: false,
                    };
                }
                return complete === true
                    ? { report, complete: true }
                    : {
                        report,
                        cause: new Error("the subject's sessions could not all be ended, or a boundary is in force without covering in-flight issuance; re-run"),
                        complete: false,
                    };
            };
            const first = await revoke();
            ended.sessions = first.complete;
            if ("cause" in first) {
                return finish({
                    ...base,
                    complete: false,
                    stoppedAt: "sessions",
                    cause: first.cause,
                    ...(first.report === undefined ? {} : { sessions: first.report }),
                });
            }
            // Taken after the revocation, which has no deadline: an authorization minted at an earlier time could have ended already.
            const nowMs = now();
            const done = await underLease.reset(subject, {
                nowMs,
                ...(asked.requireEmailProof
                    ? { requireEmailProof: () => transactionStore.requireEmailProofAtNextBinding(subject) }
                    : {}),
                authorize: () => mintSubjectRecovery(transactionStore, subject, {
                    operation: "reset",
                    sid: undefined,
                    nowMs,
                    lifetimeMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS,
                }),
            });
            // A login made with a factor before its removal ends too.
            const again = await revoke();
            ended.sessionsAgain = again.complete;
            const removed = done.removed === undefined
                ? undefined
                : { kinds: kindsOf(done.removed), count: done.removed.length };
            const after = {
                sessions: first.report,
                ...(again.report === undefined ? {} : { sessionsAgain: again.report }),
                ...(removed === undefined ? {} : { removed }),
                ...(done.generation === undefined ? {} : { generation: done.generation }),
                ...(done.overran === true ? { overran: true } : {}),
            };
            if (done.outcome === "stopped") {
                return finish({
                    ...base,
                    complete: false,
                    stoppedAt: done.at,
                    cause: done.cause,
                    ...after,
                });
            }
            if (done.witness.outcome !== "marked" && done.witness.outcome !== "unwritable") {
                return finish({
                    ...base,
                    complete: false,
                    stoppedAt: "witness",
                    cause: done.witness.outcome === "unwritten" ? done.witness.cause : undefined,
                    ...after,
                });
            }
            const witness = done.witness.outcome === "marked" ? "cleared" : "unwritable";
            if ("cause" in again) {
                return finish({
                    ...base,
                    complete: false,
                    stoppedAt: "sessions",
                    cause: again.cause,
                    ...after,
                    witness,
                });
            }
            return finish({ ...base, complete: done.overran !== true, ...after, witness });
        },
    };
}
