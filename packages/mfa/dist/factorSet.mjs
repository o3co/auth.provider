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
import { consoleLogger, MFA_SUBJECT_LEASE_MAX_MS, MFA_SUBJECT_LEASE_MIN_MS, readConditionalCreateAnswer, readConditionalSetRemoveAnswer, readMfaEmailProofRequirementConsumeAnswer, readMfaFactorSet, readMfaRecoverySetFloorAnswer, readMfaSubjectCount, readMfaSubjectLeaseAnswer, readMfaSubjectRecoveryAnswer, } from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
import { readFactorList } from "./factorList.mjs";
import { readSubjectRecords } from "./factorState.mjs";
import { mayCount } from "./firstBinding.mjs";
/** The pauses, in milliseconds, between tries for a lease another write holds: then `busy`. */
const LEASE_WAITS_MS = [25, 50, 100, 200, 400];
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
export const FACTOR_SET_STORE_CALLS = 14;
/**
 * How many Store calls' time a lease stands: the writer's calls, the acquire,
 * and one to spare — sixteen.
 *
 * The lease is also the factor-set writer's issue window, its share of the
 * factor store's write-lifetime bound (docs/adapter-surface.md, "Conditional
 * writes", rule 6): a conditional write is issued only under the lease whose
 * set read gave its expected generation, so at most a lease after that read.
 * `checkFactorSetStoreTimeout` holds sixteen `mfa.storeTimeoutMs` to core's
 * longest lease, `MFA_SUBJECT_LEASE_MAX_MS` (600 000 ms): `mfa.storeTimeoutMs`
 * is at most 37 500 ms, and the window at most 600 s, far inside the bundled
 * stores' bound (`BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 h) less any adapter's
 * write lifetime.
 */
const LEASE_STORE_TIMEOUTS = FACTOR_SET_STORE_CALLS + 2;
/** How many of its own leases the operator reset waits for another holder's to end. */
const RESET_WAIT_LEASES = 2;
/** The longest pause, in milliseconds, between the operator reset's tries for the lease. */
const RESET_PAUSE_MS = 250;
/** The lease a write takes when one Store call may take `storeTimeoutMs`, at least core's shortest. */
export const leaseMsFor = (storeTimeoutMs) => Math.max(LEASE_STORE_TIMEOUTS * storeTimeoutMs, MFA_SUBJECT_LEASE_MIN_MS);
/**
 * `storeTimeoutMs`, `mfa.storeTimeoutMs`, when the lease it makes fits core's
 * longest; else a `RangeError` naming the key: a write could outlive its
 * lease, and one write at a time would not hold.
 */
export function checkFactorSetStoreTimeout(storeTimeoutMs) {
    if (!Number.isSafeInteger(storeTimeoutMs) || storeTimeoutMs < 1) {
        throw new RangeError(`mfa.storeTimeoutMs: ${String(storeTimeoutMs)} is not a whole number of milliseconds from 1`);
    }
    const leaseMs = LEASE_STORE_TIMEOUTS * storeTimeoutMs;
    if (leaseMs > MFA_SUBJECT_LEASE_MAX_MS) {
        throw new RangeError(`mfa.storeTimeoutMs: ${storeTimeoutMs} ms makes a factor-set write's lease ${leaseMs} ms (${LEASE_STORE_TIMEOUTS} Store calls' time), past the longest subject lease, ${MFA_SUBJECT_LEASE_MAX_MS} ms: a write could outlive its lease. Set it to at most ${Math.floor(MFA_SUBJECT_LEASE_MAX_MS / LEASE_STORE_TIMEOUTS)} ms`);
    }
    return storeTimeoutMs;
}
/**
 * A reader of the subject's recovery-set floor over `store`, bounded by
 * `storeTimeoutMs`: throws for a store that cannot answer in time, or
 * answers outside its port. What every reading of a recovery set's
 * usability reads the floor through.
 */
export function boundedRecoverySetFloor(store, storeTimeoutMs) {
    return async (subject) => {
        const floor = readMfaSubjectCount(await within(() => store.recoverySetFloor(subject), storeTimeoutMs, "recoverySetFloor"));
        if (floor === undefined)
            throw OUTSIDE_CONTRACT;
        return floor;
    };
}
/** The subject's records, oldest first: the order a page lists them and a request names them. */
const byAge = (a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
/** A call not answered in the time it was given. */
class NotAnswered extends Error {
}
/** A call not answered within `ms`: {@link NotAnswered}; the timer cleared either way. */
async function within(call, ms, what) {
    let timer;
    try {
        return await Promise.race([
            call(),
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new NotAnswered(`${what} was not answered within ${Math.round(ms)} ms`)), Math.max(0, ms));
            }),
        ]);
    }
    finally {
        clearTimeout(timer);
    }
}
/** Thrown inside a write when too little of the lease is left: nothing more is started. */
class OutOfTime extends Error {
}
/** A transaction-store outage at `step`. */
const leaseOutage = (step, cause) => ({
    outcome: "unavailable",
    store: "mfa_transaction",
    step,
    cause,
});
/** What a refused start of a write is told: too little of the lease was left. Never thrown past this file. */
const LEASE_SPENT = "too little of the subject's lease was left to start this write";
/**
 * The subject's lease over `leases`, the one place it is held: its
 * generation read, the lease acquired at a generation — waiting, and pausing
 * on a generation that moved where the write takes the current one — the
 * write run under it, held to the lease's time, and the lease released.
 */
function subjectLeases(options) {
    const { leases, monotonicNow } = options;
    const storeTimeoutMs = checkFactorSetStoreTimeout(options.storeTimeoutMs);
    const ttlMs = leaseMsFor(storeTimeoutMs);
    /** The subject's generation; throws for one that cannot be read, or is outside the port. */
    const generationOf = async (subject) => {
        const generation = readMfaSubjectCount(await within(() => leases.subjectGeneration(subject), storeTimeoutMs, "subjectGeneration"));
        if (generation === undefined)
            throw OUTSIDE_CONTRACT;
        return generation;
    };
    /** The lease `token` holds released: `true` when the store found it held. */
    const release = async (subject, token) => {
        try {
            return ((await within(() => leases.releaseSubjectLease(subject, token), storeTimeoutMs, "releaseSubjectLease")) === true);
        }
        catch {
            return false;
        }
    };
    /**
     * `write` run under the subject's lease, acquired `at` a generation and
     * waiting as `wait` says; `overran` when the release did not find the lease
     * held, or the write ran out of the time it had after it wrote. Every
     * write the write makes is started through `time.beforeWrite`, so `busy`
     * after the acquire means nothing was written.
     */
    const underLease = async (subject, at, write, wait = {}) => {
        /** Pauses before the next try: `false` when the wait is spent. */
        const paused = async (tries, retryAfterMs) => {
            let pause;
            if (wait.until === undefined) {
                pause = LEASE_WAITS_MS[tries];
            }
            else if (monotonicNow() < wait.until) {
                pause = Math.min(retryAfterMs, RESET_PAUSE_MS);
            }
            if (pause === undefined)
                return false;
            await new Promise((resolve) => setTimeout(resolve, pause));
            return true;
        };
        let token;
        let acquiredFrom = 0;
        let lastBusyMs = RESET_PAUSE_MS;
        for (let tries = 0; token === undefined; tries++) {
            let generation;
            if (at === "current") {
                try {
                    generation = await generationOf(subject);
                }
                catch (cause) {
                    return leaseOutage("subjectGeneration", cause);
                }
            }
            else {
                generation = at.generation;
            }
            const asked = monotonicNow();
            let answer;
            try {
                answer = readMfaSubjectLeaseAnswer(await within(() => leases.acquireSubjectLease(subject, { ttlMs, generation }), storeTimeoutMs, "acquireSubjectLease"));
            }
            catch (cause) {
                return leaseOutage("acquireSubjectLease", cause);
            }
            if (answer === undefined)
                return leaseOutage("acquireSubjectLease", OUTSIDE_CONTRACT);
            if (answer.outcome === "acquired") {
                token = answer.token;
                acquiredFrom = asked;
            }
            else if (answer.outcome === "stale") {
                // A start's generation that moved is final; the current one is read again after a pause.
                if (at !== "current" || !(await paused(tries, LEASE_WAITS_MS[0]))) {
                    return { outcome: "changed" };
                }
            }
            else {
                lastBusyMs = answer.retryAfterMs;
                if (!(await paused(tries, answer.retryAfterMs))) {
                    return {
                        outcome: "busy",
                        retryAfterSeconds: Math.ceil(Math.min(lastBusyMs, MFA_SUBJECT_LEASE_MAX_MS) / 1000),
                    };
                }
            }
        }
        const held = token;
        const deadline = acquiredFrom + ttlMs;
        const left = () => deadline - monotonicNow() - storeTimeoutMs;
        let wrote = false;
        let ranOut = false;
        const outOfTime = () => {
            ranOut = true;
            return new OutOfTime(LEASE_SPENT);
        };
        const time = {
            read: async (call) => {
                const budget = left();
                if (budget <= 0)
                    throw outOfTime();
                try {
                    return await within(call, budget, "a read under the lease");
                }
                catch (cause) {
                    if (cause instanceof NotAnswered)
                        throw outOfTime();
                    throw cause;
                }
            },
            beforeWrite: () => {
                if (ranOut || left() < 0)
                    throw outOfTime();
                wrote = true;
            },
        };
        let done;
        try {
            done = await write(time, held);
        }
        catch (cause) {
            const kept = await release(subject, held);
            if (!(cause instanceof OutOfTime))
                throw cause;
            // Out of time before any write: nothing was written, and a release that lost the lease is still an overrun.
            if (wrote)
                return { outcome: "ran_out" };
            return kept
                ? { outcome: "busy", retryAfterSeconds: 1 }
                : { outcome: "busy", retryAfterSeconds: 1, overran: true };
        }
        const kept = await release(subject, held);
        // A write that answered after it ran out of time before writing anything wrote nothing.
        if (ranOut && !wrote) {
            return kept
                ? { outcome: "busy", retryAfterSeconds: 1 }
                : { outcome: "busy", retryAfterSeconds: 1, overran: true };
        }
        return { outcome: "held", done, overran: ranOut || !kept };
    };
    return { leases, monotonicNow, storeTimeoutMs, ttlMs, release, underLease, generationOf };
}
/** What each owner holds, by the handle its holders are given. */
const owners = new WeakMap();
/**
 * A lease owner over `options.store`, its per-call bound `storeTimeoutMs`
 * (held to {@link checkFactorSetStoreTimeout}: a `RangeError` naming
 * `mfa.storeTimeoutMs` for one whose lease would pass core's longest) and its
 * lease {@link LEASE_STORE_TIMEOUTS} of it.
 */
export function createMfaSubjectLeases(options) {
    const owner = subjectLeases({
        leases: options.store,
        storeTimeoutMs: options.storeTimeoutMs,
        monotonicNow: options.monotonicNow ?? (() => performance.now()),
    });
    const handle = Object.freeze({});
    owners.set(handle, owner);
    return handle;
}
/** The owner `handle` stands for; a `TypeError` for a value this file did not build. */
function ownerOf(handle) {
    const owner = owners.get(handle);
    if (owner === undefined) {
        throw new TypeError("the subject's lease owner is not one createMfaSubjectLeases built");
    }
    return owner;
}
/** The factor set over `options` (see this file's header). */
export function createMfaFactorSet(options) {
    const { factors, factorStore, witness, sealing } = options;
    const logger = options.logger ?? consoleLogger;
    const subjectLease = ownerOf(options.leases);
    const { storeTimeoutMs, leases } = subjectLease;
    const starts = new WeakMap();
    const floorOf = boundedRecoverySetFloor(leases, storeTimeoutMs);
    const list = async (subject) => readFactorList(await factorStore.list(subject)).sort(byAge);
    /** Whether none of `records` may count. */
    const noneCounts = (records) => !records.some((record) => mayCount(factors, record));
    const begin = async (subject, write) => {
        const start = Object.freeze({});
        // A mark a directory cannot write takes no lease: it needs no generation.
        if (write === "mark" && !witness.writable) {
            starts.set(start, {
                subject,
                cause: new Error("no lease is taken for a mark nobody can write"),
            });
            return start;
        }
        let started;
        try {
            started = { subject, generation: await subjectLease.generationOf(subject) };
        }
        catch (cause) {
            started = { subject, cause };
        }
        starts.set(start, started);
        return start;
    };
    /** `write` under the lease acquired at `start`'s generation (`subjectLeases`). */
    const underLease = async (start, subject, write) => {
        const started = start === undefined ? undefined : starts.get(start);
        // A start for another subject, or none, began nowhere this write can tell.
        if (started === undefined || started.subject !== subject)
            return { outcome: "changed" };
        if ("cause" in started)
            return leaseOutage("subjectGeneration", started.cause);
        return subjectLease.underLease(subject, { generation: started.generation }, write);
    };
    /** What a mark is answered when it could not run, or ran, outside a lease it held. */
    const unwritten = (why) => ({
        outcome: "unwritten",
        cause: new Error(`the witness mark ${why}`),
    });
    /**
     * The subject's set read under the lease (`listVersioned`, through
     * `time`'s read) as its port promises it (`readMfaFactorSet`); why it could
     * not be, else. {@link OutOfTime} is thrown.
     */
    const readSet = async (time, subject) => {
        try {
            const read = readMfaFactorSet(await time.read(() => factorStore.listVersioned(subject)), subject);
            return {
                records: Object.freeze([...read.items].sort(byAge)),
                storeGeneration: read.generation,
            };
        }
        catch (cause) {
            if (cause instanceof OutOfTime)
                throw cause;
            return { cause };
        }
    };
    /**
     * The membership writes of `subject`'s set fenced on `read`: each
     * conditional on the store generation held — first the one read, then
     * the one the last write here answered — and each started through
     * `write`. A write the store refuses is `changed`; a removal of a record
     * the set does not hold at that generation is `missing`, which no record
     * read or written here can be.
     */
    const fencedOver = (subject, read, write) => {
        let held = read.storeGeneration;
        return {
            async create(record) {
                if (record.subject !== subject) {
                    throw new RangeError("a record of another subject is not added to this one's set");
                }
                const expected = held;
                const answer = readConditionalCreateAnswer(await write(() => factorStore.createIf(record, expected)));
                if (answer.outcome === "conflict")
                    return "changed";
                held = answer.generation;
                return "created";
            },
            async remove(id) {
                const expected = held;
                // A set never written holds no record.
                if (expected === null)
                    return "missing";
                const answer = readConditionalSetRemoveAnswer(await write(() => factorStore.removeIf(subject, id, expected)));
                if (answer.outcome === "conflict")
                    return "changed";
                if (answer.outcome === "missing")
                    return "missing";
                held = answer.generation;
                return "removed";
            },
        };
    };
    /**
     * The subject's set fenced on `set`, the witness, the recovery-set floor
     * and any other write as a bind's writes go through them: each held to
     * `time`, a refusal never thrown as this file's own error — a store call
     * refused rejects as a store's failure would, a witness write is
     * unwritten, and another write is answered `refused`. The floor is raised
     * with `token`, the lease held.
     */
    const writesUnder = (time, token, subject, set) => {
        /** `time`'s check, as a store's failure: this file's error stays here. */
        const started = (check, call) => {
            try {
                check();
            }
            catch {
                return Promise.reject(new Error(LEASE_SPENT));
            }
            return call();
        };
        const write = (call) => started(time.beforeWrite, call);
        const read = (call) => time.read(call).catch((cause) => {
            throw cause instanceof OutOfTime ? new Error(LEASE_SPENT) : cause;
        });
        /** A witness write the lease's time cannot cover is unwritten: the witness never throws. */
        const witnessWrite = async (call) => {
            try {
                time.beforeWrite();
            }
            catch {
                return unwritten("found too little of the subject's lease left");
            }
            return call();
        };
        const fenced = fencedOver(subject, set, write);
        return {
            factors: Object.freeze({
                records: set.records,
                create: (record) => fenced.create(record),
                remove: async (id) => {
                    const removed = await fenced.remove(id);
                    if (removed === "missing")
                        throw OUTSIDE_CONTRACT;
                    return removed;
                },
                update: (id, expectedVersion, next) => write(() => factorStore.update(subject, id, expectedVersion, next)),
            }),
            witness: {
                writable: witness.writable,
                mark: (subject) => witnessWrite(() => witness.mark(subject)),
                clear: (subject) => witnessWrite(() => witness.clear(subject)),
            },
            recoverySetFloor: {
                read: (subject) => read(() => floorOf(subject)),
                raise: (subject, setGeneration) => write(async () => {
                    const answer = readMfaRecoverySetFloorAnswer(await within(() => leases.raiseRecoverySetFloor(subject, { setGeneration, leaseToken: token }), storeTimeoutMs, "raiseRecoverySetFloor"));
                    if (answer === undefined)
                        throw OUTSIDE_CONTRACT;
                    if (answer.outcome === "refused") {
                        throw new Error("the subject's lease was not held: the recovery-set floor was not raised");
                    }
                    // A floor the store answers below the raise is outside its port.
                    if (answer.floor < setGeneration)
                        throw OUTSIDE_CONTRACT;
                }),
            },
            emailProofRequirement: {
                consume: (subject) => write(async () => {
                    const answer = readMfaEmailProofRequirementConsumeAnswer(await within(() => leases.consumeEmailProofRequirement(subject, { leaseToken: token }), storeTimeoutMs, "consumeEmailProofRequirement"));
                    if (answer === undefined)
                        throw OUTSIDE_CONTRACT;
                    if (answer.outcome === "refused") {
                        throw new Error("the subject's lease was not held: the email-proof requirement was not consumed");
                    }
                }),
            },
            read: (call) => read(() => within(call, storeTimeoutMs, "a transaction-store read under the lease")),
            run: async (call, refused) => {
                try {
                    time.beforeWrite();
                }
                catch {
                    return refused(new Error(LEASE_SPENT));
                }
                try {
                    return await within(call, storeTimeoutMs, "a transaction-store write under the lease");
                }
                catch (cause) {
                    if (cause instanceof NotAnswered)
                        return refused(cause);
                    throw cause;
                }
            },
        };
    };
    return {
        begin,
        carry(start) {
            const started = starts.get(start);
            if (started === undefined) {
                return leaseOutage("subjectGeneration", new Error("the start was not taken here"));
            }
            if ("cause" in started)
                return leaseOutage("subjectGeneration", started.cause);
            return { generation: started.generation };
        },
        resume(subject, carried) {
            const start = Object.freeze({});
            const generation = typeof carried === "object" && carried !== null && !Array.isArray(carried)
                ? readMfaSubjectCount(carried.generation)
                : undefined;
            // One that is not what `carry` answered is left unknown: the write answers it `changed`.
            if (generation !== undefined)
                starts.set(start, { subject, generation });
            return start;
        },
        list,
        recoverySetFloor: floorOf,
        readSubject: (subject) => readSubjectRecords({ factors, sealing }, subject, {
            list,
            recoverySetFloor: floorOf,
            logger,
        }),
        async markEnrolled(start, subject) {
            if (!witness.writable)
                return witness.mark(subject);
            const held = await underLease(start, subject, async (time) => {
                let records;
                try {
                    records = await time.read(() => list(subject));
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    return { outcome: "unwritten", cause };
                }
                if (noneCounts(records))
                    return { outcome: "in_step" };
                time.beforeWrite();
                const marked = await witness.mark(subject);
                if (marked.outcome !== "marked")
                    return marked;
                // A write outside the lease — one that outran its own — may have removed the last one since.
                let after;
                try {
                    after = await time.read(() => list(subject));
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    // Marked, and whether a write outside the lease left none since cannot be told.
                    return {
                        outcome: "unwritten",
                        cause: new Error("the records could not be read again after the witness mark", {
                            cause,
                        }),
                    };
                }
                if (!noneCounts(after))
                    return marked;
                time.beforeWrite();
                const cleared = await witness.clear(subject);
                return cleared.outcome === "marked" ? { outcome: "in_step" } : cleared;
            });
            switch (held.outcome) {
                case "busy":
                    return unwritten("found the subject's lease held, or too little of it left");
                case "changed":
                    return unwritten("found the subject's generation moved since the proof was checked");
                case "unavailable":
                    return { outcome: "unwritten", cause: held.cause };
                case "ran_out":
                    return unwritten("ran out of the subject's lease after it wrote");
                default:
                    return held.overran ? unwritten("outran the subject's lease") : held.done;
            }
        },
        async remove(start, subject, factorId, refuse) {
            let removedRecord;
            const held = await underLease(start, subject, async (time) => {
                const set = await readSet(time, subject);
                if ("cause" in set) {
                    return { outcome: "unavailable", store: "mfa_factor", step: "list", cause: set.cause };
                }
                const { records } = set;
                const record = typeof factorId === "string" ? records.find((one) => one.id === factorId) : undefined;
                if (record === undefined)
                    return { outcome: "unknown_factor" };
                const refusal = refuse(record, records);
                if (refusal !== undefined)
                    return { outcome: "refused", refusal: refusal };
                const others = (all) => all.filter((one) => one.id !== record.id);
                time.beforeWrite();
                removedRecord = record;
                try {
                    const removal = await fencedOver(subject, set, (call) => call()).remove(record.id);
                    if (removal !== "removed") {
                        removedRecord = undefined;
                        // Another write of the set landed since it was read: a writer past its lease.
                        if (removal === "changed")
                            return { outcome: "changed" };
                        return {
                            outcome: "unavailable",
                            store: "mfa_factor",
                            step: "remove",
                            cause: OUTSIDE_CONTRACT,
                        };
                    }
                }
                catch (cause) {
                    // A store may fail after its write: the record gone is a removal.
                    let after;
                    try {
                        after = await time.read(() => list(subject));
                    }
                    catch (unread) {
                        // Whether it stands cannot be told; out of time, it is also an overrun.
                        return {
                            outcome: "unavailable",
                            store: "mfa_factor",
                            step: "remove",
                            cause,
                            ...(unread instanceof OutOfTime ? { overran: true } : {}),
                        };
                    }
                    if (after.some((one) => one.id === record.id)) {
                        return { outcome: "unavailable", store: "mfa_factor", step: "remove", cause };
                    }
                }
                let remaining = others(records);
                let unread;
                let readAgain = false;
                try {
                    remaining = others(await time.read(() => list(subject)));
                    readAgain = true;
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    unread = cause;
                }
                let cleared;
                if (noneCounts(remaining)) {
                    time.beforeWrite();
                    cleared = await witness.clear(subject);
                }
                return {
                    outcome: "removed",
                    record,
                    ...(readAgain ? {} : { unread }),
                    ...(cleared === undefined ? {} : { witness: cleared }),
                };
            });
            if (held.outcome === "ran_out") {
                // Out of time after the removal was written: it stands, the witness not cleared.
                return removedRecord === undefined
                    ? { outcome: "busy", retryAfterSeconds: 1 }
                    : { outcome: "removed", record: removedRecord, overran: true };
            }
            if (held.outcome !== "held")
                return held;
            return held.overran ? { ...held.done, overran: true } : held.done;
        },
        async bind(start, subject, write) {
            const held = await underLease(start, subject, async (time, token) => {
                const set = await readSet(time, subject);
                if ("cause" in set) {
                    return { outcome: "unavailable", store: "mfa_factor", step: "list", cause: set.cause };
                }
                return { outcome: "bound", done: await write(writesUnder(time, token, subject, set)) };
            });
            if (held.outcome === "ran_out") {
                // The writes ran out of time after one was written, and did not answer what they came to.
                return {
                    outcome: "unavailable",
                    store: "mfa_factor",
                    step: "bind",
                    cause: new Error("a bind's writes ran out of the subject's lease after writing"),
                    overran: true,
                };
            }
            if (held.outcome !== "held")
                return held;
            return held.overran ? { ...held.done, overran: true } : held.done;
        },
        async recover(subject, recovery) {
            const held = await subjectLease.underLease(subject, "current", async (time, token) => {
                let records;
                try {
                    records = await time.read(() => list(subject));
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    return { outcome: "unavailable", store: "mfa_factor", step: "list", cause };
                }
                const guessableBoundSinceMs = recovery.guessableBoundSince(records);
                time.beforeWrite();
                let answer;
                try {
                    answer = await within(() => leases.applySubjectRecovery(subject, {
                        operation: "recover",
                        sid: recovery.sid,
                        nowMs: recovery.nowMs,
                        leaseToken: token,
                        sessionsBoundaryMs: recovery.sessionsBoundaryMs,
                        guessableBoundSinceMs,
                    }), storeTimeoutMs, "applySubjectRecovery");
                }
                catch (cause) {
                    return leaseOutage("applySubjectRecovery", cause);
                }
                const read = readMfaSubjectRecoveryAnswer(answer);
                return read === undefined
                    ? leaseOutage("applySubjectRecovery", OUTSIDE_CONTRACT)
                    : { outcome: "answered", answer: read };
            });
            switch (held.outcome) {
                // The store judged the apply under the lease: an overrun after it changes nothing of it.
                case "held":
                    return held.done;
                case "changed":
                case "ran_out":
                    return { outcome: "busy", retryAfterSeconds: 1 };
                case "busy":
                    return { outcome: "busy", retryAfterSeconds: held.retryAfterSeconds };
                default:
                    return { outcome: held.outcome, store: held.store, step: held.step, cause: held.cause };
            }
        },
    };
}
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
export function createMfaFactorSetReset(options) {
    const { factorStore, witness } = options;
    const subjectLease = ownerOf(options.leases);
    const { storeTimeoutMs, ttlMs, leases, monotonicNow } = subjectLease;
    const stopped = (at, cause, after = {}) => ({
        outcome: "stopped",
        at,
        cause,
        ...(after.generation === undefined ? {} : { generation: after.generation }),
        ...(after.removedDone === true ? { removed: after.removed } : {}),
        ...(after.overran === true ? { overran: true } : {}),
    });
    return {
        async reset(subject, steps) {
            /** How far the writes under the lease got: where an overrun or a refusal stops it. */
            const progress = { stage: "email_proof" };
            const held = await subjectLease.underLease(subject, "current", async (time, token) => {
                try {
                    const listed = await time.read(() => factorStore.list(subject));
                    // As listed: a deployment's malformed record must not cost the report.
                    progress.snapshot = Array.isArray(listed)
                        ? [...listed]
                        : undefined;
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    progress.snapshot = undefined;
                }
                if (steps.requireEmailProof !== undefined) {
                    time.beforeWrite();
                    try {
                        await within(steps.requireEmailProof, storeTimeoutMs, "requireEmailProofAtNextBinding");
                    }
                    catch (cause) {
                        return stopped("email_proof", cause);
                    }
                }
                progress.stage = "lock";
                time.beforeWrite();
                try {
                    await within(steps.authorize, storeTimeoutMs, "authorizeSubjectRecovery");
                }
                catch (cause) {
                    return stopped("lock", cause);
                }
                time.beforeWrite();
                let answer;
                try {
                    answer = readMfaSubjectRecoveryAnswer(await within(() => leases.applySubjectRecovery(subject, {
                        operation: "reset",
                        sid: undefined,
                        nowMs: steps.nowMs,
                        leaseToken: token,
                        sessionsBoundaryMs: undefined,
                        guessableBoundSinceMs: undefined,
                    }), storeTimeoutMs, "applySubjectRecovery"));
                }
                catch (cause) {
                    return stopped("lock", cause);
                }
                if (answer === undefined)
                    return stopped("lock", OUTSIDE_CONTRACT);
                if (answer.outcome !== "applied") {
                    return stopped("lock", new Error(answer.outcome === "refused"
                        ? `the store refused the reset: ${answer.reason}`
                        : "the store answered the reset's authorization applied before: it applied nothing"));
                }
                progress.generation = answer.generation;
                progress.stage = "factors";
                time.beforeWrite();
                try {
                    await factorStore.removeAllForSubject(subject);
                }
                catch (cause) {
                    return stopped("factors", cause, { generation: answer.generation });
                }
                // A store that answered the removal and left records stops it before the witness.
                try {
                    const left = readFactorList(await time.read(() => factorStore.list(subject)));
                    if (left.length > 0) {
                        return stopped("factors", new Error("records still stand after the removal, or the list is no list"), { generation: answer.generation });
                    }
                }
                catch (cause) {
                    if (cause instanceof OutOfTime)
                        throw cause;
                    return stopped("factors", cause, { generation: answer.generation });
                }
                progress.removedDone = true;
                progress.stage = "witness";
                time.beforeWrite();
                const cleared = await witness.clear(subject);
                // D25's flag set again, last: a binding's consume that timed out before the reset and landed since does not leave it cleared.
                if (steps.requireEmailProof !== undefined) {
                    progress.stage = "email_proof";
                    time.beforeWrite();
                    try {
                        await within(steps.requireEmailProof, storeTimeoutMs, "requireEmailProofAtNextBinding");
                    }
                    catch (cause) {
                        return stopped("email_proof", cause, {
                            generation: answer.generation,
                            removed: progress.snapshot,
                            removedDone: true,
                        });
                    }
                }
                return {
                    outcome: "reset",
                    generation: answer.generation,
                    removed: progress.snapshot,
                    witness: cleared,
                };
            }, { until: monotonicNow() + RESET_WAIT_LEASES * ttlMs });
            const after = {
                generation: progress.generation,
                removed: progress.snapshot,
                removedDone: progress.removedDone === true,
            };
            switch (held.outcome) {
                case "held":
                    // The reset moved the generation under its own lease: a release that finds it held is no overrun.
                    return held.overran ? { ...held.done, overran: true } : held.done;
                case "ran_out":
                    return stopped(progress.stage, new Error(`${LEASE_SPENT}: run the reset again`), {
                        ...after,
                        overran: true,
                    });
                case "busy":
                case "changed":
                    return stopped("lease", new Error("the subject's lease could not be held long enough for the reset: run it again"), { overran: held.overran === true });
                default:
                    return stopped("lease", held.cause);
            }
        },
    };
}
