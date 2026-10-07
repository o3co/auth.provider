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
import { type Logger, type MailAddressFact, type MfaFactor, type MfaFactorData, type MfaFactorRecord, type MfaFactorResolver } from "@o3co/auth-provider-core";
import type { MfaSealing } from "./sealing.mjs";
/** What a record is read over: the installed factors and the key ring's sealing. */
export interface MfaRecordContext {
    readonly factors: MfaFactorResolver;
    readonly sealing: MfaSealing;
    /** The subject's recovery-set floor, where it was read: a set below it is `retired`. */
    readonly recoverySetFloor?: number;
}
/** A record as read (this file's header), with the factor of its kind and its data where they are had. */
export type MfaRecordReading = {
    readonly state: "not_installed";
} | {
    readonly state: "unreadable";
    readonly factor: MfaFactor;
    readonly keyId?: string;
} | {
    readonly state: "usable" | "exhausted" | "address_changed" | "retired";
    readonly factor: MfaFactor;
    readonly data: MfaFactorData;
};
type ReadRecord = Pick<MfaFactorRecord, "id" | "kind" | "data">;
/** `record` of `subject`, read over `context`; never `address_changed`. */
export declare function readFactorRecord(context: MfaRecordContext, subject: string, record: ReadRecord): MfaRecordReading;
/** `record` of `subject`, read for a signed-in session whose login `User` holds `address`. */
export declare function readFactorRecordAt(context: MfaRecordContext, subject: string, record: ReadRecord, address: unknown): MfaRecordReading;
/** Whether a transaction offers a record read as `read`: every state but `not_installed`, `exhausted` and `retired`. */
export declare const isOffered: (read: MfaRecordReading) => boolean;
/** A subject's records as one reading holds them, and the context they are read over — the recovery-set floor in it where it was read. */
export interface MfaSubjectRecords {
    readonly subject: string;
    readonly context: MfaRecordContext;
    readonly records: readonly MfaFactorRecord[];
    /** Made by `readSubjectRecords` alone. */
    readonly __mfaSubjectRecords: never;
}
/** What `readSubjectRecords` reads through. */
export interface MfaSubjectRecordsReaders {
    /** The subject's records; throws for a store that cannot answer. */
    readonly list: (subject: string) => Promise<readonly MfaFactorRecord[]>;
    /** The subject's recovery-set floor, bounded; throws for one that cannot be read. */
    readonly recoverySetFloor: (subject: string) => Promise<number>;
    /** Where a floor that could not be read is said, at warn (`mfa_recovery_set_floor_unread`). */
    readonly logger: Logger;
}
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
export declare function readSubjectRecords(context: MfaRecordContext, subject: string, readers: MfaSubjectRecordsReaders): Promise<MfaSubjectRecords>;
/** Whether the subject `read` holds a usable record of any kind (`holdsUsableRecord`, over its context): a step-up's `no_qualifying_factor`. */
export declare const holdsUsableIn: (read: MfaSubjectRecords) => boolean;
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
export declare const mayAddMfaIn: (read: MfaSubjectRecords, mailAddress: MailAddressFact | undefined) => boolean;
/**
 * Whether `subject` holds a usable record that counts among `records`: no
 * floor is read for it, since a recovery-code set never counts.
 */
export declare const holdsCountingFactor: (context: Pick<MfaRecordContext, "factors" | "sealing">, subject: string, records: readonly ReadRecord[]) => boolean;
/** Whether a password login asks for a second factor over `record`: every state but `exhausted` and `retired`. */
export declare const asksForSecondFactor: (context: MfaRecordContext, subject: string, record: ReadRecord) => boolean;
/** Whether `subject` holds a usable record among `records` — one whose factor counts, when `options.counting` asks it. */
export declare const holdsUsableRecord: (context: MfaRecordContext, subject: string, records: readonly ReadRecord[], options: {
    readonly counting: boolean;
}) => boolean;
export {};
//# sourceMappingURL=factorState.d.mts.map