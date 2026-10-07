/**
 * The wire format of the Store's MFA endpoints: the JSON bodies the Store
 * adapter sends and reads, and a Store (or a fake of one) reads and answers.
 * The endpoints, their statuses and what each answer means are
 * `@o3co/auth-provider-foundation`'s README, "The Store's MFA endpoints".
 *
 * Guarantees: times are epoch milliseconds named `…Ms`; an optional field
 * with no value is left out, and `null` is never read as "unset"; the fields
 * a page shows are read only in the record's shape (`isMfaFactorId`,
 * `isMfaFactorKind`, `isMfaFactorLabel`), anything else being a record the
 * provider cannot read; a list is read whole, refused for one unreadable
 * record, one of another subject or a repeated id; what a writer makes, the
 * reader reads back whole, and what the reader refuses, the writer refuses
 * with a `RangeError`; an update names the record by `subject` and `id` and
 * carries the expected version and, as its changes, only `data`, `label` and
 * `lastUsedAtMs`.
 *
 * The factor set's store generation travels under the conditional-write
 * convention's HTTP wire (docs/adapter-surface.md, "Conditional writes"):
 * the versioned list answers `factors` with the set's `generation`, `null`
 * only for an absent set; a conditional create or remove carries
 * `expectedGeneration` (`null`, for a create only: the set was read as
 * absent) and `deadlineMs`, and is answered `200`, `404` or `409` with an
 * outcome body. `deadlineMs` is an instant on the provider's clock, the send
 * time plus the adapter's request timeout. The Store checks it against its own
 * clock in the same atomic step as the conditional write; at or after it, the
 * write is not applied and the answer is `408`. This assumes the provider's
 * and the Store's clocks agree within the clock skew assumed between the two;
 * under that assumption a conditional write commits or fails within W, the
 * request timeout plus that skew. This codec is
 * the only place those field names and statuses meet the port's words: its
 * readers answer the port's types, and throw a `TypeError` for any other
 * answer, a bare `404` or `409` and a `408` included.
 */
import { type ConditionalCreateAnswer, type ConditionalSetRemoveAnswer, type StoreGeneration, type VersionedSet } from "../adapters/conditionalWrite.mjs";
import { type MfaFactorRecord, type MfaFactorRecordUpdate } from "./factorStore.mjs";
/** What authorized a binding, as a record carries it. */
export type MfaStoreFactorBinding = NonNullable<MfaFactorRecord["binding"]>;
/** A factor record on the wire: {@link MfaFactorRecord} with its dates as epoch milliseconds. */
export interface MfaStoreFactor {
    /** 22 base64url characters (`isMfaFactorId`). */
    readonly id: string;
    readonly subject: string;
    /** A hint token (`isMfaFactorKind`). */
    readonly kind: string;
    /** 1 to 64 printable characters (`isMfaFactorLabel`); left out when the factor has none. */
    readonly label?: string;
    /** Left out when none was recorded. */
    readonly binding?: MfaStoreFactorBinding;
    readonly createdAtMs: number;
    /** Left out when the factor was never used. */
    readonly lastUsedAtMs?: number;
    /** A safe non-negative integer; the compare-and-set token. */
    readonly version: number;
    /** Sealed by the provider; the Store keeps it byte for byte and never reads it. */
    readonly data: string;
}
/**
 * The new values of the three fields an update replaces. A `label` or
 * `lastUsedAtMs` left out clears it.
 */
export interface MfaStoreFactorChanges {
    readonly data: string;
    readonly label?: string;
    readonly lastUsedAtMs?: number;
}
/** `listMfaFactors`: every record the Store holds for `subject`. */
export interface MfaStoreListRequest {
    readonly subject: string;
}
/** What `listMfaFactors` answers with a `200`: every record, the ones the provider cannot read included. */
export interface MfaStoreListAnswer {
    readonly factors: readonly unknown[];
}
/**
 * What the list endpoint answers with a `200` to a versioned read: every
 * record, and the set's generation from the same snapshot. `generation` is
 * required, and `null` only for an absent set, which holds no records.
 */
export interface MfaStoreVersionedListAnswer {
    readonly factors: readonly unknown[];
    readonly generation: string | null;
}
/**
 * `createMfaFactor`, conditional: one new record, written only while the
 * subject's set is at `expectedGeneration`; `null`: only while the set is
 * absent.
 */
export interface MfaStoreCreateIfRequest {
    readonly factor: MfaStoreFactor;
    readonly expectedGeneration: string | null;
    /**
     * Epoch milliseconds on the provider's clock, within the Date range: the
     * send time plus the adapter's request timeout. The Store checks it against
     * its own clock in the same atomic step as the write; at or after it, the
     * write is not applied and the answer is `408`.
     */
    readonly deadlineMs: number;
}
/**
 * A conditional create's answer body: `created` with a `200` and the set's
 * new generation, `conflict` with a `409`. A create is never `missing`.
 */
export type MfaStoreCreateIfAnswer = {
    readonly outcome: "created";
    readonly generation: string;
} | {
    readonly outcome: "conflict";
};
/**
 * `deleteMfaFactor`, conditional: the record `(subject, id)`, removed only
 * while the subject's set is at `expectedGeneration`.
 */
export interface MfaStoreRemoveIfRequest {
    readonly subject: string;
    readonly id: string;
    readonly expectedGeneration: string;
    /**
     * Epoch milliseconds on the provider's clock, within the Date range: the
     * send time plus the adapter's request timeout. The Store checks it against
     * its own clock in the same atomic step as the write; at or after it, the
     * write is not applied and the answer is `408`.
     */
    readonly deadlineMs: number;
}
/**
 * A conditional remove's answer body: `removed` with a `200` and the set's
 * new generation, `missing` with a `404`, `conflict` with a `409`.
 */
export type MfaStoreRemoveIfAnswer = {
    readonly outcome: "removed";
    readonly generation: string;
} | {
    readonly outcome: "missing";
} | {
    readonly outcome: "conflict";
};
/**
 * `updateMfaFactor`: `subject` and `id` name the record, `expectedVersion`
 * is the compare-and-set token, and `changes` is all it writes.
 */
export interface MfaStoreUpdateRequest {
    readonly subject: string;
    readonly id: string;
    readonly expectedVersion: number;
    readonly changes: MfaStoreFactorChanges;
}
/** What `updateMfaFactor` answers with a `200`: the record as written, at `expectedVersion + 1`. */
export interface MfaStoreUpdateAnswer {
    readonly factor: unknown;
}
/** `deleteMfaFactor`, the reset: every record of the subject, unconditionally. */
export interface MfaStoreDeleteRequest {
    readonly subject: string;
    readonly all: true;
}
/** `markMfaEnrolled`: the enrollment witness the Store answers back as `User.mfaEnrolled`. */
export interface MfaStoreMarkEnrolledRequest {
    readonly subject: string;
    readonly enrolled: boolean;
}
/** A record as the wire carries it; a `RangeError` for one {@link readMfaStoreFactor} would not read back. */
export declare function toMfaStoreFactor(record: MfaFactorRecord): MfaStoreFactor;
/**
 * `value` as a wire record, when it is one: a fresh object of the record's
 * own fields, any other field left behind. `undefined` for anything else — a
 * field missing, of the wrong type, out of range, out of the record's shape,
 * or `null` — which the provider holds to be a record it cannot read, never
 * an absent one.
 */
export declare function readMfaStoreFactor(value: unknown): MfaStoreFactor | undefined;
/** What {@link readMfaStoreListAnswer} makes of a list's answer. */
export type MfaStoreListReading = {
    readonly ok: true;
    readonly factors: readonly MfaStoreFactor[];
}
/**
 * `malformed`: not `{ factors: [...] }`. `unreadable`: a record the
 * provider cannot read, one naming another subject, or two with one id.
 */
 | {
    readonly ok: false;
    readonly reason: "malformed" | "unreadable";
};
/**
 * A list's answer for `subject`, read whole: every record read by
 * {@link readMfaStoreFactor}, each naming `subject`, no id twice. One that
 * fails refuses the whole list, never reads as fewer records.
 */
export declare function readMfaStoreListAnswer(value: unknown, subject: string): MfaStoreListReading;
/** A wire record {@link readMfaStoreFactor} answered, as the port's record. */
export declare function fromMfaStoreFactor(factor: MfaStoreFactor): MfaFactorRecord;
/**
 * An update's `data`, `label` and `lastUsedAtMs` as the wire carries them,
 * and nothing else of `next`, whatever else it holds; a `RangeError` for
 * changes {@link readMfaStoreFactorChanges} would not read back.
 */
export declare function toMfaStoreFactorChanges(next: MfaFactorRecordUpdate): MfaStoreFactorChanges;
/**
 * `value` as an update's changes, when it is: `data`, and `label` and
 * `lastUsedAtMs` when present, in a fresh object. `undefined` when a field is
 * of the wrong type or `null`, and when any other field is present — one a
 * Store must not change.
 */
export declare function readMfaStoreFactorChanges(value: unknown): MfaStoreFactorChanges | undefined;
/**
 * The body of an update of `(subject, id)` at `expectedVersion`. A
 * `RangeError` for an `expectedVersion` that is no version, or at
 * `Number.MAX_SAFE_INTEGER` (`checkMfaVersionAdvances`), for an id no record
 * can have, and for changes {@link toMfaStoreFactorChanges} refuses.
 */
export declare function toMfaStoreUpdateRequest(subject: string, id: string, expectedVersion: number, next: MfaFactorRecordUpdate): MfaStoreUpdateRequest;
/**
 * The list endpoint's `200` to a versioned read of `subject`, as the port's
 * set: `factors` read as `items` by the convention's `readVersionedSet`,
 * each a record of `subject` ({@link readMfaStoreFactor}), no id twice, and
 * `generation` the set's. `{ factors: [], generation: null }` is an absent
 * set. A fresh frozen answer of fresh frozen records. Throws a `TypeError`
 * for anything else, a missing `generation`, one holding `"`, and a single
 * record that cannot be read included: the Store's fault, never a set with
 * fewer records.
 */
export declare function readMfaStoreVersionedListAnswer(value: unknown, subject: string): VersionedSet<MfaFactorRecord>;
/**
 * The body of a create of `record` while its subject's set is at `expected`;
 * `null`: while the set is absent. `deadlineMs` is the send time plus the
 * adapter's request timeout, in epoch milliseconds. A `RangeError` for an
 * `expected` that is neither a store generation nor `null`, a `deadlineMs`
 * that is not a whole instant above 0 within the Date range, and a record
 * {@link toMfaStoreFactor} refuses.
 */
export declare function toMfaStoreCreateIfRequest(record: MfaFactorRecord, expected: StoreGeneration | null, deadlineMs: number): MfaStoreCreateIfRequest;
/**
 * The body of a removal of `(subject, id)` while the set is at `expected`.
 * `deadlineMs` is the send time plus the adapter's request timeout, in epoch
 * milliseconds. A `RangeError` for an `expected` that is no store generation
 * (`null` included: a removal never targets an absent set), a `deadlineMs`
 * that is not a whole instant above 0 within the Date range, an id no record
 * can have, and a `subject` that is no string.
 */
export declare function toMfaStoreRemoveIfRequest(subject: string, id: string, expected: StoreGeneration, deadlineMs: number): MfaStoreRemoveIfRequest;
/**
 * A conditional create's answer, its `status` and its parsed `body`, as the
 * port's answer (`readConditionalCreateAnswer`): `200` `created` with the
 * set's new generation, `409` `conflict`. A `TypeError` for anything else: a
 * `404` (a create is never `missing`), a `408` (read past its deadline, it
 * wrote nothing), another status, a `409` or `200` without its body, or a
 * body naming another status's outcome.
 */
export declare function readMfaStoreCreateIfAnswer(status: number, body: unknown): ConditionalCreateAnswer;
/**
 * A conditional remove's answer, its `status` and its parsed `body`, as the
 * port's answer (`readConditionalSetRemoveAnswer`): `200` `removed` with the
 * set's new generation, `404` `missing`, `409` `conflict`. A `TypeError` for
 * anything else: a `408` (read past its deadline, it wrote nothing), another
 * status, one of the three without its body, or a body naming another
 * status's outcome.
 */
export declare function readMfaStoreRemoveIfAnswer(status: number, body: unknown): ConditionalSetRemoveAnswer;
//# sourceMappingURL=storeWire.d.mts.map