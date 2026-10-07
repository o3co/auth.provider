/**
 * A subject's factor set as the enrollment witness follows it: the records
 * read, oldest first, and the writes after which the witness is brought in
 * step with them. The one place the subject's lease and generation are used:
 * callers hold an opaque start and read an answer, never the lease.
 *
 * - A write's start (`begin`) reads the subject's generation before the request
 *   that writes is admitted, or before a verification's proof is checked;
 *   a ceremony that writes in a later request carries its start from its
 *   begin, sealed in its own pending state (`carry`, then `resume`), opaque
 *   to it.
 * - The write acquires the subject's lease at that generation — waiting a
 *   bounded while for another holder, then `busy` with the holder's whole
 *   seconds left; `changed` when the generation moved since the start, a
 *   recovery or a reset in between — runs whole under it, and releases it.
 * - The lease stands {@link LEASE_STORE_TIMEOUTS} of `mfa.storeTimeoutMs`: the
 *   most Store calls one writer makes under it ({@link FACTOR_SET_STORE_CALLS}),
 *   the acquire, and one to spare; a timeout whose lease would pass core's
 *   longest is refused (`checkFactorSetStoreTimeout`). From the acquire, a local monotonic
 *   deadline: a read under the lease is given up when it would leave less than
 *   one Store timeout, and so is a write that would start with less — before
 *   the first write, `busy` with nothing written; after it, an overrun.
 * - A transaction-store call (generation, acquire, apply, release) not
 *   answered within one Store timeout is an outage; a write to the factor
 *   store or the directory is never abandoned once started.
 * - A release the store answers `false`, or cannot take, is an overrun: the
 *   lease ended, or another holder moved the generation, while the write ran.
 *   A generation the write itself moved under the lease (an applied recovery
 *   or reset) is no overrun: the release still finds the lease held. Every
 *   answer of a write that overran says so.
 * - `markEnrolled`, a verification's reconciliation: the records read first;
 *   none that may count writes nothing and the witness is in step (`in_step`),
 *   none readable writes nothing (`unwritten`); else the witness marked, the
 *   records read again, and the witness cleared when a write outside the lease
 *   left none — in step again (`in_step`); a clear that fails, or a read again
 *   that fails, is `unwritten`. One that cannot hold the lease, or overran it,
 *   is `unwritten`; a directory that cannot write the witness takes no lease,
 *   and its start reads no generation.
 * - The fence. Every writer of the factor set's membership under the lease —
 *   a removal, a bind — first reads the subject's set, right after the
 *   acquire, through the lease's read (`listVersioned`), and keeps the factor
 *   set's store generation it answers here, handing its caller the records
 *   alone (`MfaFactorSetWriter`). Each membership write is conditional on the
 *   generation held (`createIf`, `removeIf`), and the new one it answers is
 *   held for the next, so a writer's chain of writes is fenced end to end on
 *   its read; `update` keeps the generation. A write the store refuses
 *   (`conflict`) wrote nothing, and is answered `changed`, never tried again:
 *   another membership write landed since the read, and under the lease only
 *   a writer that outlived its own lease can have made it. A removal the
 *   store answers `missing` for a record read is outside its port. The
 *   generation never leaves this file.
 * - `remove`: the set read, the caller's refusal asked, the record removed
 *   only while the set stands as read — `changed` when it does not, nothing
 *   removed — a store that fails after its write is read again, and a record
 *   gone is a removal; then the records read again (or, unreadable, those
 *   read before less the removed one) and, when none may count (`mayCount`),
 *   the witness cleared.
 * - `bind`, an enrollment's completion or a regeneration of recovery codes:
 *   the set read, then the caller's writes run whole under the lease, through
 *   the fenced writer over that read, the witness, the subject's
 *   recovery-set floor and D25's email-proof requirement this file hands it,
 *   each held to the lease's time as above; the floor is raised and the
 *   requirement consumed with the lease this file holds, never handed out.
 *   A set that cannot be read is an outage, nothing written.
 * - `recoverySetFloor`, a read of the subject's recovery-set floor outside
 *   any lease — a verification's — and `readSubject`, the subject's records
 *   read for a judgment over them (`factorState.mts`'s `readSubjectRecords`,
 *   a floor it cannot read said at warn): both bounded by one Store timeout
 *   as every transaction-store call here.
 * - `recover`, the subject's own authorized recovery: the records read under
 *   the lease, the caller's reading of them handed to the store's apply with
 *   the lease. It needs no start of the caller's: the store judges the apply
 *   on its own authorization, and a generation that moved between its read
 *   and its acquire is read again.
 * - The lease owner (`createMfaSubjectLeases`), built by `mfaModule` from
 *   `mfa.storeTimeoutMs` over the MFA transaction store, is handed to every
 *   writer as an opaque handle: every writer — the factor set's and the
 *   operator reset — holds a lease of the same rules.
 * - The operator reset (`createMfaFactorSetReset`): one lease, waited for —
 *   never gone on without — across the lock state's reset, the removal of
 *   every record and the witness's clear, in that order.
 *
 * The lease is logical: it cannot fence a write the directory applies after
 * the deadline check, nor a transaction-store write that was not answered
 * within its bound and lands later. The factor store fences its own
 * membership writes, as above, and the transaction store checks the lease
 * where a write names it — the floor's raise, the consume of D25's flag — so
 * a consume that lands after the lease ended clears nothing a later reset
 * set; the rest is not fenced. The reset's removal is unconditional — it always wins
 * — so one that stalls past the reset's lease still removes what a binding
 * made after it. A conditional write that timed out is unknown: it lands if
 * the set is still as it was read when it arrives. Never throws for a
 * store's failure: `list` alone throws, for its caller to answer.
 */
import { type Logger, type MfaFactorRecord, type MfaFactorRecordUpdate, type MfaFactorResolver, type MfaFactorStore, type MfaSubjectRecoveryAnswer, type MfaTransactionStore } from "@o3co/auth-provider-core";
import { type MfaSubjectRecords } from "./factorState.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";
/**
 * The Store and directory calls one writer may make under the lease — what
 * the lease is sized from, and `factorSetBudget.test.mts` holds every writer
 * to. A first binding by the account-email proof in a session over two
 * standing recovery-code sets (a binding by password keeps the one that
 * stood) makes thirteen: the set read, the first-binding mark read, the
 * first-binding note, the consume, the factor, D25's flag, the recovery-set
 * floor read, the new set, the floor raised, each old set's removal, the set
 * marked shown, the witness. A login's makes twelve, its set marked shown by
 * its answer, past the lease; a regeneration of recovery codes six and one
 * per standing set (the set read,
 * the first-binding mark read, the floor read, the new set, the floor raised,
 * the removals, the set marked shown); the operator reset eight (the read,
 * D25's flag, its authorization, the lock state's reset, the removal, the
 * read again, the witness, D25's flag again); a removal five; a mark four; a
 * release two. More standing sets — past three at a binding, past eight at a
 * regeneration — each add a removal, which the lease's time cuts off when it
 * runs short: every set that stood is already retired by the raised floor,
 * the new set is left unshown, and the writer answers an outage, to be run
 * again.
 */
export declare const FACTOR_SET_STORE_CALLS = 14;
/** The lease a write takes when one Store call may take `storeTimeoutMs`, at least core's shortest. */
export declare const leaseMsFor: (storeTimeoutMs: number) => number;
/**
 * `storeTimeoutMs`, `mfa.storeTimeoutMs`, when the lease it makes fits core's
 * longest; else a `RangeError` naming the key: a write could outlive its
 * lease, and one write at a time would not hold.
 */
export declare function checkFactorSetStoreTimeout(storeTimeoutMs: number): number;
/**
 * A reader of the subject's recovery-set floor over `store`, bounded by
 * `storeTimeoutMs`: throws for a store that cannot answer in time, or
 * answers outside its port. What every reading of a recovery set's
 * usability reads the floor through.
 */
export declare function boundedRecoverySetFloor(store: Pick<MfaTransactionStore, "recoverySetFloor">, storeTimeoutMs: number): (subject: string) => Promise<number>;
/** Where a write began: opaque to its holder, read by this file alone. */
export interface MfaFactorSetStart {
    readonly __mfaFactorSetStart: never;
}
/** A start as a ceremony carries it from one request to the next, sealed in its own pending state: opaque to it. */
export interface MfaFactorSetCarried {
    readonly __mfaFactorSetCarried: never;
}
/** What a start is taken for: a change to the factor set, or a verification's witness mark. */
export type MfaFactorSetWrite = "change" | "mark";
/** A write that could not run under the subject's lease, or gave up before writing. */
export type MfaFactorSetRefusal = 
/** Another write held the lease past the wait, or too little of it was left: try again. */
{
    readonly outcome: "busy";
    readonly retryAfterSeconds: number;
}
/**
 * The subject's generation moved since the write began — a recovery or a
 * reset — or, for a removal, another write of the factor set landed since
 * it was read under the lease: nothing written; read again.
 */
 | {
    readonly outcome: "changed";
} | {
    readonly outcome: "unavailable";
    readonly store: "mfa_factor" | "mfa_transaction";
    readonly step: string;
    readonly cause: unknown;
};
/** What a removal came to; `overran` on any answer when the release did not find the lease held. */
export type MfaFactorRemoval<Refusal> = (MfaFactorSetRefusal | {
    readonly outcome: "unknown_factor";
} | {
    readonly outcome: "refused";
    readonly refusal: Refusal;
} | {
    readonly outcome: "removed";
    readonly record: MfaFactorRecord;
    /** Why the records could not be read again; those read before, less the removed one, decided. */
    readonly unread?: unknown;
    /** The witness's clear, when none that may count was left. */
    readonly witness?: MfaWitnessMark;
}) & {
    /** The lease ended, or another holder moved the generation, before the release — or the time left could not cover the clear. */
    readonly overran?: true;
};
/**
 * The subject's recovery-set floor as a bind reads and raises it under the
 * lease (`MfaTransactionStore.recoverySetFloor`, `raiseRecoverySetFloor`):
 * each call bounded by one Store timeout, and throwing for a store that
 * cannot answer, answers outside its port, or does not find the lease held.
 */
export interface MfaRecoverySetFloor {
    /** The subject's floor, 0 when none was raised. */
    read(subject: string): Promise<number>;
    /** The subject's floor raised to `setGeneration`, a set's generation from 1; never lowered. */
    raise(subject: string, setGeneration: number): Promise<void>;
}
/**
 * The operator reset's email-proof requirement (D25) as a bind consumes it
 * under the lease (`MfaTransactionStore.consumeEmailProofRequirement`), the
 * store checking the lease in the same step: bounded by one Store timeout,
 * and throwing for a store that cannot answer, answers outside its port, or
 * does not find the lease held.
 */
export interface MfaEmailProofRequirement {
    /** The subject's requirement consumed, whether or not one stood. */
    consume(subject: string): Promise<void>;
}
/**
 * The subject's factor set as a bind's writes change it: the records read
 * under the lease when the bind began, and the writes of the set, each held
 * to the lease's time and applied only while the set stands as this writer
 * last left it — read, or written since by this writer. One call at a time.
 */
export interface MfaFactorSetWriter {
    /** The subject's records as read under the lease when the bind began, oldest first. */
    readonly records: readonly MfaFactorRecord[];
    /**
     * `record`, the subject's, added: `created`; or `changed`, nothing
     * written, when another write of the set landed since. Rejects for a
     * store that failed, or answered outside its port: unknown, as the
     * record may have been written.
     */
    create(record: MfaFactorRecord): Promise<"created" | "changed">;
    /**
     * The subject's record `id` removed: `removed`; or `changed`, nothing
     * removed, when another write of the set landed since. Rejects for a
     * store that failed, or answered outside its port — one that holds no
     * such record among those this writer read or wrote — unknown, as for
     * `create`.
     */
    remove(id: string): Promise<"removed" | "changed">;
    /**
     * The subject's record `id` written by compare-and-set at
     * `expectedVersion` (`MfaFactorStore.update`): a record's own update, the
     * set left as it stands.
     */
    update(id: string, expectedVersion: number, next: MfaFactorRecordUpdate): Promise<MfaFactorRecord | null>;
}
/**
 * What a bind's writes go through, each held to the lease's time: the
 * subject's factor set, the witness, the subject's recovery-set floor, D25's
 * email-proof requirement, `read`
 * for any other read and `run` for any other write it makes (the transaction
 * store's). Every write a bind makes goes through one of them, so a bind
 * answered `busy` wrote nothing.
 */
export interface MfaFactorSetWrites {
    readonly factors: MfaFactorSetWriter;
    readonly witness: MfaEnrollmentWitness;
    readonly recoverySetFloor: MfaRecoverySetFloor;
    readonly emailProofRequirement: MfaEmailProofRequirement;
    /** `call`, a transaction-store read, bounded by one Store timeout and the lease's time; throws as the store would. */
    read<T>(call: () => Promise<T>): Promise<T>;
    /**
     * `write`, started only while the lease's time allows a write, and bounded
     * by one Store timeout: `refused(cause)` when it was not started, or not
     * answered in time — which may still land, as a transaction-store call
     * not answered is an outage.
     */
    run<T>(write: () => Promise<T>, refused: (cause: unknown) => T): Promise<T>;
}
/** What a bind came to: the caller's own answer once its writes ran under the lease; `overran` on any answer when they ran past it. */
export type MfaFactorSetBound<Done> = (MfaFactorSetRefusal | {
    readonly outcome: "bound";
    readonly done: Done;
}) & {
    readonly overran?: true;
};
/** What a recovery is applied with, beside the lease this file holds. */
export interface MfaFactorSetRecovery {
    /** The session the authorization was minted in. */
    readonly sid: string;
    /** The caller's time, which the lock state is judged on. */
    readonly nowMs: number;
    /** The subject's sessions boundary, `undefined` when there is none. */
    readonly sessionsBoundaryMs: number | undefined;
    /** What the store is handed as `guessableBoundSinceMs`, read from the subject's records as read under the lease. */
    readonly guessableBoundSince: (records: readonly MfaFactorRecord[]) => number | null;
}
/** What a recovery came to: the store's answer, read as its port promises it. */
export type MfaFactorSetRecovered = Exclude<MfaFactorSetRefusal, {
    readonly outcome: "changed";
}> | {
    readonly outcome: "answered";
    readonly answer: MfaSubjectRecoveryAnswer;
};
export interface MfaFactorSet {
    /**
     * Where a write of `subject`'s begins — `change`, one that changes the
     * factor set; `mark`, a verification's witness mark: read before the
     * request is admitted, or before a proof is checked. Never throws.
     */
    begin(subject: string, write: MfaFactorSetWrite): Promise<MfaFactorSetStart>;
    /**
     * `start` as a ceremony carries it to a later request; the outage of the
     * read that took it, when it read no generation.
     */
    carry(start: MfaFactorSetStart): MfaFactorSetCarried | Extract<MfaFactorSetRefusal, {
        readonly outcome: "unavailable";
    }>;
    /** The start `carried` was, for `subject`; one that is not what `carry` answered is answered `changed` by the write. */
    resume(subject: string, carried: unknown): MfaFactorSetStart;
    /** The subject's records, oldest first; throws for a store that cannot answer, or answers anything but a list of records. */
    list(subject: string): Promise<MfaFactorRecord[]>;
    /**
     * The subject's recovery-set floor, read outside any lease — a
     * verification's — and bounded by one Store timeout; throws for a store
     * that cannot answer in time, or answers outside its port.
     */
    recoverySetFloor(subject: string): Promise<number>;
    /**
     * The subject's records read for a judgment over them, with the floor its
     * recovery-code sets are held to (`readSubjectRecords`), outside any lease;
     * throws for a listing that fails.
     */
    readSubject(subject: string): Promise<MfaSubjectRecords>;
    /**
     * The witness marked under the subject's lease when the records read first
     * hold one that may count; a directory that cannot write the witness takes no lease,
     * and needs no start.
     */
    markEnrolled(start: MfaFactorSetStart | undefined, subject: string): Promise<MfaWitnessMark>;
    /** Under the subject's lease, the record `factorId` names removed, unless `refuse` answers a refusal over it and the records read. */
    remove<Refusal>(start: MfaFactorSetStart, subject: string, factorId: unknown, refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined): Promise<MfaFactorRemoval<Refusal>>;
    /**
     * Under the subject's lease acquired at `start`, the subject's set read,
     * then `write` run whole through the writes it is handed, the set's fenced
     * on that read.
     */
    bind<Done>(start: MfaFactorSetStart, subject: string, write: (writes: MfaFactorSetWrites) => Promise<Done>): Promise<MfaFactorSetBound<Done>>;
    /** Under the subject's lease, the subject's authorized recovery applied (see this file's header). */
    recover(subject: string, recovery: MfaFactorSetRecovery): Promise<MfaFactorSetRecovered>;
}
/** The leases' port as this file uses it. */
type Leases = Pick<MfaTransactionStore, "subjectGeneration" | "acquireSubjectLease" | "releaseSubjectLease" | "applySubjectRecovery" | "recoverySetFloor" | "raiseRecoverySetFloor" | "consumeEmailProofRequirement">;
/**
 * A subject's lease owner over the MFA transaction store and
 * `mfa.storeTimeoutMs`. `mfaModule` builds one for its routes and one for the
 * slot it provides; they share the store and the rules, not the instance, and
 * hold no state of their own, so every writer of a subject's factor set — the
 * factor set's writes and the operator reset — holds a lease of the same
 * rules. Opaque to its holders, read by this file alone.
 */
export interface MfaSubjectLeases {
    readonly __mfaSubjectLeases: never;
}
/**
 * A lease owner over `options.store`, its per-call bound `storeTimeoutMs`
 * (held to {@link checkFactorSetStoreTimeout}: a `RangeError` naming
 * `mfa.storeTimeoutMs` for one whose lease would pass core's longest) and its
 * lease {@link LEASE_STORE_TIMEOUTS} of it.
 */
export declare function createMfaSubjectLeases(options: {
    /** Where the subject's generation and lease are kept, and its recovery applied. */
    readonly store: Leases;
    /** `mfa.storeTimeoutMs`. */
    readonly storeTimeoutMs: number;
    /** A monotonic clock, in milliseconds. Defaults to `performance.now`. */
    readonly monotonicNow?: () => number;
}): MfaSubjectLeases;
/** The factor set over `options` (see this file's header). */
export declare function createMfaFactorSet(options: {
    readonly factors: MfaFactorResolver;
    readonly factorStore: MfaFactorStore;
    readonly witness: MfaEnrollmentWitness;
    /** A lease owner ({@link createMfaSubjectLeases}) of the rules every writer holds. */
    readonly leases: MfaSubjectLeases;
    /** What a record's data is opened with, for a reading of the subject's records. */
    readonly sealing: MfaSealing;
    /** Where `mfa_recovery_set_floor_unread` goes. Absent, core's `consoleLogger`. */
    readonly logger?: Logger;
}): MfaFactorSet;
/** Where the operator reset stopped under its lease: before it, at D25's flag, at the lock state, at the removal, at the witness. */
export type MfaFactorSetResetStop = "lease" | "email_proof" | "lock" | "factors" | "witness";
/** What the operator reset writes under its lease beside the lock state's reset, the removal and the clear. */
export interface MfaFactorSetResetSteps {
    /** The caller's time, which the lock state's reset is applied at. */
    readonly nowMs: number;
    /** D25's flag, set first under the lease when the reset asks it. */
    readonly requireEmailProof?: () => Promise<void>;
    /** The reset's own authorization, recorded under the lease just before it is applied. */
    readonly authorize: () => Promise<void>;
}
/** What the operator reset under the lease came to. */
export type MfaFactorSetResetOutcome = {
    readonly outcome: "reset";
    /** The subject's generation the reset moved it to. */
    readonly generation: number;
    /** The records the removal removed, as read under the lease just before; `undefined` when they could not be read. */
    readonly removed: readonly MfaFactorRecord[] | undefined;
    /** The witness's clear, written last. */
    readonly witness: MfaWitnessMark;
    /** The lease ended before the reset released it: another writer may have run beside it. */
    readonly overran?: true;
} | {
    readonly outcome: "stopped";
    readonly at: MfaFactorSetResetStop;
    readonly cause: unknown;
    /** Once the lock state was reset: the generation it moved to. */
    readonly generation?: number;
    /** Once the removal succeeded: the records it removed, as read just before. */
    readonly removed?: readonly MfaFactorRecord[] | undefined;
    readonly overran?: true;
};
/**
 * The operator reset's writes under one lease of the subject's, held through
 * the lease owner it is handed (see this file's header): the lease waited for up to two
 * of the reset's own leases, at the subject's current generation, pausing on
 * one that moved — then `stopped` at `lease`, nothing written — then, in this
 * order, each write started only with one Store call's time of the lease
 * left: the records read for the report, D25's flag when asked, the reset's
 * own authorization, the lock state's reset, every record removed, the
 * records read again, the witness cleared, D25's flag set again when asked;
 * and the lease released. An authorization the store
 * answers applied before stops it at `lock`: a reset that applied nothing
 * moved no generation. Out of time after a write, it stops where it was.
 */
export declare function createMfaFactorSetReset(options: {
    readonly factorStore: MfaFactorStore;
    readonly witness: MfaEnrollmentWitness;
    /** A lease owner ({@link createMfaSubjectLeases}) of the rules every writer holds. */
    readonly leases: MfaSubjectLeases;
}): {
    reset(subject: string, steps: MfaFactorSetResetSteps): Promise<MfaFactorSetResetOutcome>;
};
export {};
//# sourceMappingURL=factorSet.d.mts.map