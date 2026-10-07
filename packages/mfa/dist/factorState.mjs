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
 * The one reading of what a subject's factor record can do now, for the
 * decisions made over the records and for the account page's list.
 *
 * - `not_installed`: no installed factor verifies its kind.
 * - `unreadable`: its data does not open, or a digest it holds names a key
 *   the ring no longer holds (`keyId`, when the key is known).
 * - `retired`, read only over a subject's records as `readSubjectRecords`
 *   reads them: a recovery-code set below the subject's recovery-set floor,
 *   replaced by a newer set and kept until it is removed. Its codes verify
 *   nothing.
 * - `exhausted`: a recovery-code set whose data opened and holds no code
 *   left. It stays on record, for audit.
 * - `address_changed`, read for a signed-in session alone
 *   (`readFactorRecordAt`): an email factor whose recorded digest is not
 *   the address of the session's login `User`. One with no readable digest,
 *   or beside a `User` with no address, is `unreadable`.
 * - `usable`: anything else.
 *
 * The judgments made over these stay apart:
 * - what a transaction offers (`isOffered`): every record but `not_installed`,
 *   `exhausted` and `retired` — an `unreadable` one is offered, and its
 *   verification is the outage. A floor that cannot be read reads every set
 *   as it would without one: the offer locks nobody out, and the
 *   verification, which reads the floor itself, refuses a retired set;
 * - whether the subject holds a factor it can use — a step-up's
 *   `no_qualifying_factor`, a login reopened under `required`: `usable`
 *   alone (`holdsUsableRecord`);
 * - whether a password login asks for a second factor over a record
 *   (`asksForSecondFactor`): every state but `exhausted` and `retired`, so
 *   one the provider cannot read — a TOTP whose key is lost among them — or
 *   whose kind it no longer installs fails closed and asks;
 * - whether a step-up could add `mfa` to a session that lacks it
 *   (`mayAddMfaIn`): a `usable` record, of a factor that adds `mfa`, for a
 *   recovery set one whose codes were answered — a set never shown is a code
 *   nobody holds, and a record the provider cannot read verifies nothing
 *   now — and for an email factor one whose code can be mailed;
 * - every reading that judges a recovery set — the offers, the list, a
 *   step-up's `no_qualifying_factor`, a password login's ask, whether a
 *   step-up could add `mfa` — reads the
 *   subject's records through `readSubjectRecords`, the one place the floor
 *   and the records are read in order, so all agree on what is usable;
 * - whether a first binding may open: `mayCount` (`firstBinding.mts`), which
 *   reads no data.
 */
import { loggableError, } from "@o3co/auth-provider-core";
import { enrolledAddressDigest } from "./email/factor.mjs";
import { matchesRecordedAddress } from "./mail.mjs";
import { isExhaustedRecoverySet, isRecoveryCodeFactor, isRetiredRecoverySet, RECOVERY_CODE_FACTOR_KIND, recoverySetGeneration, recoverySetKeyIds, recoverySetShown, } from "./recovery/factor.mjs";
/** `record` of `subject`, read over `context`; never `address_changed`. */
export function readFactorRecord(context, subject, record) {
    const factor = context.factors.get(record.kind);
    if (factor === undefined)
        return { state: "not_installed" };
    const opened = context.sealing.openFactorData({ subject, id: record.id, kind: record.kind }, record.data);
    if (opened.state === "key_unavailable") {
        return { state: "unreadable", factor, keyId: opened.keyId };
    }
    if (opened.state !== "ok")
        return { state: "unreadable", factor };
    const floor = context.recoverySetFloor;
    if (floor !== undefined && isRetiredRecoverySet(factor, opened.value, floor)) {
        return { state: "retired", factor, data: opened.value };
    }
    const missing = recoverySetKeyIds(factor, opened.value)?.find((keyId) => !context.sealing.holdsKey(keyId));
    if (missing !== undefined)
        return { state: "unreadable", factor, keyId: missing };
    return {
        state: isExhaustedRecoverySet(factor, opened.value) ? "exhausted" : "usable",
        factor,
        data: opened.value,
    };
}
/** `record` of `subject`, read for a signed-in session whose login `User` holds `address`. */
export function readFactorRecordAt(context, subject, record, address) {
    const read = readFactorRecord(context, subject, record);
    if (read.state !== "usable")
        return read;
    const recorded = enrolledAddressDigest(read.factor, read.data);
    if (recorded === undefined)
        return read;
    if (recorded === null)
        return { state: "unreadable", factor: read.factor };
    const compared = matchesRecordedAddress(context.sealing.digestsFor(record.kind), address, recorded);
    if (compared === "match")
        return read;
    if (compared === "mismatch")
        return { ...read, state: "address_changed" };
    return compared === "no_address"
        ? { state: "unreadable", factor: read.factor }
        : { state: "unreadable", factor: read.factor, keyId: compared.keyUnavailable };
}
/** Whether a transaction offers a record read as `read`: every state but `not_installed`, `exhausted` and `retired`. */
export const isOffered = (read) => read.state !== "not_installed" && read.state !== "exhausted" && read.state !== "retired";
/**
 * `subject`'s records, read for a judgment over them, with the floor its
 * recovery-code sets are held to. The records are listed; holding no set of
 * the installed recovery-code factor, no floor is read. Otherwise the floor
 * is read, and when no set listed whose generation can be read stands at or
 * above it, the records are listed again — a floor read after a listing may
 * postdate a regeneration whose new set the listing missed, but a
 * regeneration writes its set before it raises the floor, so the listing
 * after the floor holds it. A floor that cannot be read is said at warn
 * (`mfa_recovery_set_floor_unread`), the records are listed again — the read
 * may have hung while a set was written — and every set reads as without
 * one: an outage offers a set rather than hide one. At most two listings and
 * one floor read. A listing that fails throws.
 */
export async function readSubjectRecords(context, subject, readers) {
    const records = await readers.list(subject);
    const factor = context.factors.get(RECOVERY_CODE_FACTOR_KIND);
    if (factor === undefined ||
        !isRecoveryCodeFactor(factor) ||
        !records.some((record) => record.kind === RECOVERY_CODE_FACTOR_KIND)) {
        return reading(subject, context, records);
    }
    let floor;
    try {
        floor = await readers.recoverySetFloor(subject);
    }
    catch (cause) {
        readers.logger.warn({ sub: subject, err: loggableError(cause) }, "mfa_recovery_set_floor_unread");
        return reading(subject, context, await readers.list(subject));
    }
    const floored = { ...context, recoverySetFloor: floor };
    // A set at or above the floor the listing holds: one it can read the generation of.
    const current = records.some((record) => {
        if (record.kind !== RECOVERY_CODE_FACTOR_KIND)
            return false;
        const opened = context.sealing.openFactorData({ subject, id: record.id, kind: record.kind }, record.data);
        const generation = opened.state === "ok" ? recoverySetGeneration(factor, opened.value) : undefined;
        return generation !== undefined && generation >= floor;
    });
    return reading(subject, floored, current ? records : await readers.list(subject));
}
/** A reading as `readSubjectRecords` makes it, and nothing else does. */
const reading = (subject, context, records) => ({ subject, context, records });
/** Whether the subject `read` holds a usable record of any kind (`holdsUsableRecord`, over its context): a step-up's `no_qualifying_factor`. */
export const holdsUsableIn = (read) => holdsUsableRecord(read.context, read.subject, read.records, { counting: false });
/**
 * Whether the subject `read` holds a record a step-up could add `mfa` with
 * now: a `usable` one — so one that does not open, or whose codes' key left
 * the ring, is not — of a factor that adds `mfa`; a recovery-code set whose
 * codes were answered; and an email factor whose code can be mailed: its
 * recorded address digest readable under a key the ring holds, beside a
 * session whose login held an address (`mailAddress`, as the session
 * recorded it; none recorded leaves that to the challenge). Whether that
 * address is still the one recorded is the challenge's to tell: the
 * session's view does not carry it.
 */
export const mayAddMfaIn = (read, mailAddress) => read.records.some((record) => {
    const state = readFactorRecord(read.context, read.subject, record);
    if (state.state !== "usable" || !state.factor.addsMfa)
        return false;
    if (recoverySetShown(state.factor, state.data) === false)
        return false;
    const recorded = enrolledAddressDigest(state.factor, state.data);
    if (recorded === undefined)
        return true;
    return (recorded !== null &&
        read.context.sealing.holdsKey(recorded.keyId) &&
        mailAddress !== "none" &&
        mailAddress !== "unreadable");
});
/**
 * Whether `subject` holds a usable record that counts among `records`: no
 * floor is read for it, since a recovery-code set never counts.
 */
export const holdsCountingFactor = (context, subject, records) => holdsUsableRecord({ factors: context.factors, sealing: context.sealing }, subject, records, {
    counting: true,
});
/** Whether a password login asks for a second factor over `record`: every state but `exhausted` and `retired`. */
export const asksForSecondFactor = (context, subject, record) => {
    const { state } = readFactorRecord(context, subject, record);
    return state !== "exhausted" && state !== "retired";
};
/** Whether `subject` holds a usable record among `records` — one whose factor counts, when `options.counting` asks it. */
export const holdsUsableRecord = (context, subject, records, options) => records.some((record) => {
    const read = readFactorRecord(context, subject, record);
    return read.state === "usable" && (!options.counting || read.factor.counting === true);
});
