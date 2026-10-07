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
 * The account page's management of the signed-in subject's second factors,
 * under `/session/mfa/factors`, mounted from `routes.mts` behind its
 * `no-store`, body parsing, CSRF and flood guards, each route admitting the
 * session through `routes.mts` first.
 *
 * - `GET /factors`, admitted as `mfa.view`: every record of the subject, oldest
 *   first, with its state as `factorState.mts` reads it for the session's login
 *   address, the records read as every judgment over them reads them
 *   (`readSubjectRecords`: a recovery set below the subject's recovery-set
 *   floor `retired`) — and a usable or exhausted recovery set's codes left and
 *   whether they were ever answered (`recovery_codes_shown`); never a
 *   record's data. A record
 *   whose data or digest needs a key the ring no longer holds is said at error
 *   with that key's id.
 * - `POST /factors/rename {factor_id, label}`, admitted as `mfa.manage`: the
 *   label written by compare-and-set at the version read, the data and last use
 *   as read; a lost race is `409`, nothing retried; an answer without that label
 *   or that last use is outside the port, `503`.
 * - `POST /factors/remove {factor_id}`, admitted as `mfa.manage`, run whole by
 *   `factorSet.mts` (the read, this file's refusal, the removal, the witness),
 *   held to the start the admission carries — the subject's generation read
 *   before it — one write of the subject's at a time: another in the way past
 *   its wait is `409 mfa_factors_busy` with `Retry-After`; a recovery or a
 *   reset since it began, or another write of the subject's factors landing
 *   after the removal read them (a writer past its own lease), `409
 *   mfa_factors_changed`, nothing removed; one that
 *   ran past its hold said at error whatever it came to, a removal it made
 *   audited and answered `409 mfa_factors_changed`. Under `required`, removing
 *   an installed counting factor is refused `409` when no other usable counting
 *   record stands — one unreadable or `address_changed` does not. Audited
 *   `mfa.factor.removed`; a re-read that failed, and a witness clear that
 *   failed, are said at warn, the removal standing.
 * - A factor named that is not the subject's is `400`; a store that cannot
 *   answer, or answers outside its port's contract, is `503`, logged once.
 */
import { emitAuditEvent, errorEnvelope, isMfaFactorLabel, isMfaFactorUpdateWritten, loggableError, } from "@o3co/auth-provider-core";
import express from "express";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
import { readFactorRecordAt, } from "./factorState.mjs";
import { recoveryCodesLeft, recoverySetShown } from "./recovery/factor.mjs";
const UNKNOWN_FACTOR = errorEnvelope("invalid_request", "Unknown second factor");
const INVALID_LABEL = errorEnvelope("invalid_request", "Invalid label");
const MFA_UNAVAILABLE = errorEnvelope("temporarily_unavailable", "MFA temporarily unavailable");
const LAST_FACTOR = errorEnvelope("mfa_last_factor", "The last second factor that counts cannot be removed");
const FACTORS_BUSY = errorEnvelope("mfa_factors_busy", "The account's second factors are being changed: try again");
const FACTORS_CHANGED = errorEnvelope("mfa_factors_changed", "The account's second factors changed: read them again");
const FACTOR_CONFLICT = errorEnvelope("mfa_factor_conflict", "The factor changed while it was renamed: try again");
/**
 * Whether `written`, a rename the store answered at the next version, holds
 * the label asked and the record's last use: each read once, the time
 * compared by its value.
 */
function keptAsAsked(written, label, record) {
    try {
        const { label: kept, lastUsedAt } = written;
        const expected = record.lastUsedAt;
        const sameUse = expected === undefined
            ? lastUsedAt === undefined
            : lastUsedAt instanceof Date && lastUsedAt.getTime() === expected.getTime();
        return kept === label && sameUse;
    }
    catch {
        return false;
    }
}
/** A date as the list answers it; none for one that is not a valid date. */
const isoOf = (at) => at instanceof Date && Number.isFinite(at.getTime()) ? at.toISOString() : undefined;
/** The management routes' router (see this file's header). */
export function createMfaManagementRouter(options) {
    const { factors, factorStore, factorSet, sealing, mode, admit, logger, auditSink } = options;
    const router = express.Router();
    /** A store's outage: logged once, answered `503`. */
    const unavailable = (res, step, cause, store = "mfa_factor") => {
        logger.error({ route: "factors", store, step, err: loggableError(cause) }, "mfa_store_unavailable");
        res.status(503).json(MFA_UNAVAILABLE);
    };
    /** The subject's records, oldest first; `undefined` once the outage is answered. */
    const recordsOf = async (res, subject) => {
        try {
            return await factorSet.list(subject);
        }
        catch (cause) {
            unavailable(res, "list", cause);
            return undefined;
        }
    };
    /** `record` as read for `session`. */
    const readFor = (session, record) => readFactorRecordAt({ factors, sealing }, session.subject, record, session.user.email);
    router
        .get("/factors", async (req, res) => {
        const session = await admit(req, res, "mfa.view");
        if (session === undefined)
            return;
        // A retired recovery set is listed so (`readSubjectRecords`).
        let reading;
        try {
            reading = await factorSet.readSubject(session.subject);
        }
        catch (cause) {
            unavailable(res, "list", cause);
            return;
        }
        res.status(200).json({
            factors: reading.records.map((record) => {
                const read = readFactorRecordAt(reading.context, session.subject, record, session.user.email);
                if (read.state === "unreadable" && read.keyId !== undefined) {
                    logger.error({
                        route: "factors",
                        kind: record.kind,
                        factorId: record.id,
                        state: "key_unavailable",
                        keyId: read.keyId,
                    }, "mfa_factor_unreadable");
                }
                const opened = read.state === "usable" || read.state === "exhausted";
                const codesLeft = opened ? recoveryCodesLeft(read.factor, read.data) : undefined;
                const shown = opened ? recoverySetShown(read.factor, read.data) : undefined;
                const createdAt = isoOf(record.createdAt);
                const lastUsedAt = isoOf(record.lastUsedAt);
                return {
                    id: record.id,
                    kind: record.kind,
                    ...(typeof record.label === "string" ? { label: record.label } : {}),
                    ...(createdAt === undefined ? {} : { created_at: createdAt }),
                    ...(lastUsedAt === undefined ? {} : { last_used_at: lastUsedAt }),
                    ...(record.binding === undefined ? {} : { binding: record.binding }),
                    state: read.state,
                    ...(codesLeft === undefined ? {} : { recovery_codes_remaining: codesLeft }),
                    ...(shown === undefined ? {} : { recovery_codes_shown: shown }),
                };
            }),
        });
    })
        .post("/factors/rename", async (req, res) => {
        const session = await admit(req, res, "mfa.manage");
        if (session === undefined)
            return;
        const body = req.body;
        const label = body?.label;
        if (!isMfaFactorLabel(label)) {
            res.status(400).json(INVALID_LABEL);
            return;
        }
        const records = await recordsOf(res, session.subject);
        if (records === undefined)
            return;
        const factorId = body?.factor_id;
        const record = typeof factorId === "string" ? records.find((one) => one.id === factorId) : undefined;
        if (record === undefined) {
            res.status(400).json(UNKNOWN_FACTOR);
            return;
        }
        let written;
        try {
            written = await factorStore.update(session.subject, record.id, record.version, {
                data: record.data,
                label,
                lastUsedAt: record.lastUsedAt,
            });
        }
        catch (cause) {
            unavailable(res, "update", cause);
            return;
        }
        if (written === null) {
            res.status(409).json(FACTOR_CONFLICT);
            return;
        }
        const asked = {
            subject: session.subject,
            id: record.id,
            expectedVersion: record.version,
            next: { data: record.data },
        };
        if (!isMfaFactorUpdateWritten(written, asked) || !keptAsAsked(written, label, record)) {
            unavailable(res, "update", OUTSIDE_CONTRACT);
            return;
        }
        res.status(200).json({ factor: { id: record.id, kind: record.kind, label } });
    })
        .post("/factors/remove", async (req, res) => {
        const session = await admit(req, res, "mfa.manage");
        if (session === undefined)
            return;
        /** Under `required`, an installed counting factor stays unless another usable one does. */
        const lastFactor = (record, records) => mode === "required" &&
            factors.get(record.kind)?.counting === true &&
            !records.some((other) => {
                if (other.id === record.id)
                    return false;
                const read = readFor(session, other);
                return read.state === "usable" && read.factor.counting === true;
            })
            ? LAST_FACTOR
            : undefined;
        const removal = await factorSet.remove(session.factorSetStart, session.subject, req.body?.factor_id, lastFactor);
        if (removal.overran === true) {
            // What the write did stands; a recovery or a reset may have run beside it.
            logger.error({ route: "factors", sub: session.subject }, "mfa_subject_lease_overrun");
        }
        switch (removal.outcome) {
            case "unknown_factor":
                res.status(400).json(UNKNOWN_FACTOR);
                return;
            case "refused":
                res.status(409).json(removal.refusal);
                return;
            case "unavailable":
                unavailable(res, removal.step, removal.cause, removal.store);
                return;
            case "busy":
                res.set("Retry-After", String(Math.max(1, removal.retryAfterSeconds)));
                res.status(409).json(FACTORS_BUSY);
                return;
            case "changed":
                res.status(409).json(FACTORS_CHANGED);
                return;
            case "removed":
                break;
        }
        const { record } = removal;
        emitAuditEvent(auditSink, {
            timestamp: new Date(),
            type: "mfa.factor.removed",
            subject: session.subject,
            ip: req.ip,
            userAgent: req.get("user-agent"),
            details: {
                kind: record.kind,
                factorId: record.id,
                ...(record.binding === undefined ? {} : { binding: record.binding }),
                by: "user",
            },
        });
        if ("unread" in removal) {
            logger.warn({ sub: session.subject, err: loggableError(removal.unread) }, "mfa_factor_removal_unread");
        }
        if (removal.witness?.outcome === "unwritten") {
            logger.warn({ sub: session.subject, err: loggableError(removal.witness.cause) }, "mfa_enrollment_witness_uncleared");
        }
        if (removal.overran === true) {
            res.status(409).json(FACTORS_CHANGED);
            return;
        }
        res.status(200).json({});
    });
    return router;
}
