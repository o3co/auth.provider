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
 * The in-process {@link MfaTransactionStore}, for development and a single
 * replica: a transaction started on one replica is unknown to another, and
 * attempt limits count per replica. Each operation is one synchronous `Map`
 * step, so atomic; stored and returned values are copies.
 *
 * Transactions expire on this store's clock (`now`, default the wall clock);
 * subject state is judged on the times callers pass, the sweep included (it
 * uses the latest). Sweeps run on writes, paced like the challenge store's,
 * and drop subject state once nothing in it can hold an attempt again (see
 * `prune`; the consecutive run lasts until a success, and the hard hold
 * until an applied recovery lifts it). The email-proof
 * requirement the operator reset records is not lock state: only its
 * consumption at the next first binding removes it.
 *
 * A session's account-email proof, a subject's first-binding mark and a
 * subject's lease and recovery authorizations expire on this store's clock
 * too, and are swept with the transactions. A subject's generation and
 * recovery-set floor are never swept.
 *
 * A binding holds at most {@link MFA_MAX_TRANSACTIONS_PER_BINDING} live
 * transactions: a create past it ends the binding's oldest, as the port says.
 * An index of each binding's transactions is kept exactly, in the same
 * synchronous step as every write that adds or removes a transaction —
 * create, consume, an attempt past `max`, expiry found by a read or a sweep —
 * and a binding with none left is dropped from it.
 *
 * At most `maxEntries` entries are held: transactions, session email proofs,
 * first-binding marks, subject leases and recovery authorizations together. At the cap the store reclaims expired
 * entries (no more often than the sweep floor) and, if still full, refuses a
 * new one with {@link MfaTransactionStoreFullError}, never evicting a live one
 * to make room (that would end the ceremony of a user typing a code, send
 * them to prove again, or trust a session a mark distrusts). Replacing a
 * session's proof, noting a subject's mark again, or a create that ends its
 * binding's oldest, is no new entry. Subject state is uncapped,
 * and so are a subject's generation and recovery-set floor, which the cap
 * does not count: only a login the Store accepted creates a subject (an open
 * sign-up lets anyone mint them). At the cap a new lease is refused too, so a
 * recovery or a reset waits until room frees. Beyond the per-binding bound the cap is
 * global: many bindings together can fill it.
 */
import { randomBytes } from "node:crypto";
import { isStorableExpiry } from "../adapters/expiry.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import { usableMaxEntries } from "../single-use/max-entries.mjs";
import { createAmortizedSweep } from "../single-use/sweep.mjs";
import { checkEmailProofRequirementConsume, checkFirstBindingNote, checkFirstBindingQuestion, checkMfaLockoutPolicy, checkMfaTransactionTransitions, checkRecoverySetFloorRaise, checkSessionEmailProof, checkSessionEmailProofQuestion, checkSubjectLeaseRelease, checkSubjectLeaseRequest, checkSubjectQuestion, checkSubjectRecoveryApplication, checkSubjectRecoveryAuthorization, firstBindingAnswer, laterFirstBindingMark, MFA_CLOCK_SKEW_ALLOWANCE_MS, MFA_MAX_TRANSACTIONS_PER_BINDING, MFA_WEEKLY_WINDOW_MS, mfaTransactionPatchWrites, newMfaTransactionRecord, sessionEmailProofAnswer, } from "./transactionStore.mjs";
import { checkMfaVersionAdvances } from "./version.mjs";
/** Writing `create` calls between two sweeps of expired transactions. */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL = 1_000;
/** The least time between two sweeps, in milliseconds. */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS = 10_000;
/**
 * The default cap, on transactions, session email proofs and first-binding
 * marks together. A
 * transaction carries the login's `User` snapshot, so the cap is lower than
 * the challenge and `jti` stores'. Over the ten-minute default lifetime it
 * allows about 170 new transactions a second on one replica, more password
 * logins than one process verifies.
 */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES = 100_000;
/**
 * Thrown by `create` at the cap when nothing has expired. A store fault, like a
 * Redis write refused at `maxmemory`, not a `RangeError` (which a caller reads
 * as its own mistake); the MFA routes answer `503 temporarily_unavailable`.
 * `reason` survives in a logged projection.
 */
export class MfaTransactionStoreFullError extends Error {
    reason = "full";
    constructor(maxEntries) {
        super(`memory MfaTransactionStore is at its cap of ${maxEntries} resident entries — transactions, session email proofs, first-binding marks, subject leases and recovery authorizations, expired ones not yet swept included; refusing a new one rather than evicting one`);
        this.name = "MfaTransactionStoreFullError";
    }
}
/** Where an authorization is kept for its subject: the operation and the `sid` as one unambiguous key. */
const slotKeyOf = (operation, sid) => JSON.stringify([operation, sid ?? null]);
/** Where a binding's transactions are indexed: the whole binding, kind included, as one unambiguous key. */
const bindingKeyOf = (binding) => JSON.stringify([binding.kind, binding.id]);
/** Where a session's proof is kept: the subject and the `sid` as one unambiguous key. */
const proofKeyOf = (subject, sid) => JSON.stringify([subject, sid]);
/** The transaction as plain data, every field named, its nested values copied. */
const copyOf = (tx) => structuredClone(tx);
const byTime = (attempts) => [...attempts].sort((a, b) => a.atMs - b.atMs);
/**
 * The short backoff at `nowMs`: when the current lock ends, or `undefined`
 * when there is none. The run is replayed in time order: a failure made
 * `memorySeconds` or more after the last lock ended — or, before any lock,
 * after the previous failure — starts the backoff again; from the
 * `threshold`th failure of a backoff, each locks for `baseSeconds`, doubled
 * per further failure, at most `maxSeconds`.
 */
function backoffUntil(run, policy, nowMs) {
    const memoryMs = policy.memorySeconds * 1000;
    let count = 0;
    let lockUntil;
    let lastAt;
    for (const attempt of byTime(run)) {
        const anchor = lockUntil ?? lastAt;
        if (anchor !== undefined && attempt.atMs >= anchor + memoryMs) {
            count = 0;
            lockUntil = undefined;
        }
        count += 1;
        lastAt = attempt.atMs;
        if (count >= policy.threshold) {
            const doublings = Math.min(count - policy.threshold, 64);
            lockUntil =
                attempt.atMs + Math.min(policy.baseSeconds * 2 ** doublings, policy.maxSeconds) * 1000;
        }
    }
    return lockUntil !== undefined && nowMs < lockUntil ? lockUntil : undefined;
}
/** The time a hold fixed at `nowMs` records: never before the run's newest attempt. */
const fixedAt = (run, nowMs) => run.reduce((latest, a) => Math.max(latest, a.atMs), nowMs);
/**
 * From when a rebind counts against a hard hold fixed at `hardAtMs`: a
 * guessable record created after it, in whole milliseconds. The one bound a
 * recover judges a rebind by and an answer carries.
 */
const rebindAfter = (hardAtMs) => Math.floor(hardAtMs + DEFAULT_CLOCK_SKEW_MS);
/** The failures the rolling week counts at `nowMs`. The store keeps them a while longer (see `prune`). */
const inWeek = (week, nowMs) => week.filter((a) => a.atMs + MFA_WEEKLY_WINDOW_MS > nowMs);
/** When the week will count fewer than `weeklyBudget` failures again, or `undefined` when it already does. */
function weeklyUntil(week, policy, nowMs) {
    const counted = byTime(inWeek(week, nowMs));
    if (counted.length < policy.weeklyBudget)
        return undefined;
    const leaving = counted[counted.length - policy.weeklyBudget];
    return leaving === undefined ? undefined : leaving.atMs + MFA_WEEKLY_WINDOW_MS;
}
function checkInstant(nowMs, operation) {
    if (!isStorableExpiry(nowMs)) {
        throw new RangeError(`MfaTransactionStore.${operation}: nowMs must be a finite instant within the Date range`);
    }
}
export function createMemoryMfaTransactionStore(options = {}) {
    const clock = options.now ?? Date.now;
    const maxEntries = usableMaxEntries(
    // Only a cap left out takes the default: an explicit `null` is refused.
    options.maxEntries === undefined
        ? DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES
        : options.maxEntries, "createMemoryMfaTransactionStore");
    const transactions = new Map();
    /** Each binding's resident transactions, by `bindingKeyOf`, in the order they were created. */
    const byBinding = new Map();
    const subjects = new Map();
    /** Each session's account-email proof, by `proofKeyOf`. */
    const proofs = new Map();
    /** Each subject's first-binding mark. */
    const marks = new Map();
    /** Each subject's lease. */
    const leases = new Map();
    /** Each subject's generation, once a recovery moved it: never swept. */
    const generations = new Map();
    /** Each subject's recovery-set floor, once raised: never swept. */
    const floors = new Map();
    /** Each subject's recovery authorizations, by `slotKeyOf`. */
    const recoveries = new Map();
    /** The authorizations held across subjects, for the cap. */
    let slotCount = 0;
    /** Subjects whose next first binding requires the email proof: no expiry, never swept. */
    const emailProofRequired = new Set();
    /** The order of the next reservation. */
    let nextSeq = 0;
    /**
     * The latest time any caller passed: the sweep judges subject state on it,
     * never on this store's clock, as the port requires.
     */
    let latestCallerMs;
    const sawCallerTime = (nowMs) => {
        latestCallerMs = latestCallerMs === undefined ? nowMs : Math.max(latestCallerMs, nowMs);
    };
    const schedule = createAmortizedSweep(options, {
        sweepInterval: DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL,
        minSweepIntervalMs: DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS,
    }, "createMemoryMfaTransactionStore");
    /** Removes a transaction and its place in its binding's index, in one step. */
    function drop(id) {
        const tx = transactions.get(id);
        if (tx === undefined)
            return;
        transactions.delete(id);
        const key = bindingKeyOf(tx.binding);
        const ids = byBinding.get(key);
        if (ids === undefined)
            return;
        ids.delete(id);
        if (ids.size === 0)
            byBinding.delete(key);
    }
    /** Holds a new transaction, and its place in its binding's index, in one step. */
    function hold(tx) {
        transactions.set(tx.id, tx);
        const key = bindingKeyOf(tx.binding);
        const ids = byBinding.get(key);
        if (ids === undefined)
            byBinding.set(key, new Set([tx.id]));
        else
            ids.add(tx.id);
    }
    function live(id, nowMs) {
        const tx = transactions.get(id);
        if (tx === undefined)
            return undefined;
        if (tx.expiresAtMs <= nowMs) {
            drop(id);
            return undefined;
        }
        return tx;
    }
    /**
     * Ends the binding's transactions that expire first until it holds fewer
     * than {@link MFA_MAX_TRANSACTIONS_PER_BINDING} live ones, dropping the
     * expired on the way; answers whether it ended a live one.
     */
    function makeRoomInBinding(binding, nowMs) {
        const ids = byBinding.get(bindingKeyOf(binding));
        if (ids === undefined)
            return false;
        const held = [...ids]
            .map((id) => live(id, nowMs))
            .filter((tx) => tx !== undefined);
        let ended = false;
        while (held.length >= MFA_MAX_TRANSACTIONS_PER_BINDING) {
            // The first that expires soonest, in the order created among equals.
            const soonest = held.reduce((a, b) => (b.expiresAtMs < a.expiresAtMs ? b : a));
            drop(soonest.id);
            held.splice(held.indexOf(soonest), 1);
            ended = true;
        }
        return ended;
    }
    /**
     * Expired transactions, proofs and marks by this store's clock; subject state by
     * the latest time a caller passed, and not at all before one has — but
     * never later than this store's clock (see `prune`).
     */
    function sweep(storeNowMs) {
        for (const [id, tx] of transactions) {
            if (tx.expiresAtMs <= storeNowMs)
                drop(id);
        }
        for (const [key, proof] of proofs) {
            if (proof.untilMs <= storeNowMs)
                proofs.delete(key);
        }
        for (const [subject, mark] of marks) {
            if (mark.untilMs <= storeNowMs)
                marks.delete(subject);
        }
        for (const [subject, lease] of leases) {
            if (lease.untilMs <= storeNowMs)
                leases.delete(subject);
        }
        for (const [subject, slots] of recoveries) {
            for (const [key, slot] of slots) {
                if (slot.expiresAtMs <= storeNowMs)
                    dropSlot(subject, slots, key);
            }
        }
        if (latestCallerMs === undefined)
            return;
        for (const [subject, state] of subjects) {
            prune(state, latestCallerMs);
            if (isEmpty(state))
                subjects.delete(subject);
        }
    }
    /**
     * Drops ended failures, and reservations nothing counts. The horizon is
     * `nowMs` capped at this store's clock, minus
     * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS}, so a caller whose clock runs ahead
     * erases nothing. What is kept still counts only at a caller's own time.
     */
    function prune(state, nowMs) {
        const horizon = Math.min(nowMs, clock()) - MFA_CLOCK_SKEW_ALLOWANCE_MS;
        state.week = state.week.filter((a) => a.atMs + MFA_WEEKLY_WINDOW_MS > horizon);
        for (const id of state.pending.keys()) {
            if (!state.run.some((a) => a.id === id) && !state.week.some((a) => a.id === id)) {
                state.pending.delete(id);
            }
        }
    }
    const isEmpty = (state) => state.hard === undefined &&
        state.run.length === 0 &&
        state.week.length === 0 &&
        state.pending.size === 0;
    function stateOf(subject) {
        let state = subjects.get(subject);
        if (state === undefined) {
            state = { run: [], week: [], pending: new Map(), refusing: false };
            subjects.set(subject, state);
        }
        return state;
    }
    function settleEmpty(subject, state) {
        if (isEmpty(state))
            subjects.delete(subject);
    }
    /** At the cap: reclaims expired entries, then refuses if still full. */
    const resident = () => transactions.size + proofs.size + marks.size + leases.size + slotCount;
    /** Whether `token` holds the subject's lease, standing on this store's clock. */
    function holds(subject, token) {
        const lease = leases.get(subject);
        return lease !== undefined && lease.untilMs > clock() && lease.token === token;
    }
    function dropSlot(subject, slots, key) {
        if (slots.delete(key))
            slotCount -= 1;
        if (slots.size === 0)
            recoveries.delete(subject);
    }
    /**
     * A `recover` of `state` at `nowMs`, past its authorization: what it ends,
     * or the refusal. The week is given back when its earliest failure up to
     * `nowMs` comes before the sessions boundary by more than the skew. The
     * hard hold is lifted on a rebind (no guessable record from before it, by
     * more than the skew), ending the run it counted; while it stands, that
     * run stays.
     */
    function recover(state, nowMs, sessionsBoundaryMs, guessableBoundSinceMs) {
        // What this recovery would give back: the week's failures up to its time.
        const counted = state === undefined ? [] : inWeek(state.week, nowMs).filter((a) => a.atMs <= nowMs);
        const earliest = Math.min(...counted.map((a) => a.atMs));
        const revokedSince = counted.length === 0 ||
            (sessionsBoundaryMs !== undefined && sessionsBoundaryMs > earliest + DEFAULT_CLOCK_SKEW_MS);
        const hard = state?.hard;
        const rebound = hard !== undefined &&
            (guessableBoundSinceMs === null ||
                (guessableBoundSinceMs !== undefined && guessableBoundSinceMs > rebindAfter(hard)));
        if (!revokedSince && !rebound)
            return "not_revoked_since";
        if (state === undefined)
            return { week: true, run: true, hard: false };
        let run = false;
        if (rebound) {
            delete state.hard;
            state.run = [];
            run = true;
        }
        if (revokedSince) {
            state.week = state.week.filter((a) => a.atMs > nowMs);
            if (state.hard === undefined) {
                state.run = state.run.filter((a) => a.atMs > nowMs);
                run = true;
            }
        }
        if (state.hard === undefined)
            state.refusing = false;
        prune(state, nowMs);
        return { week: revokedSince, run, hard: rebound };
    }
    function makeRoom(nowMs) {
        if (resident() < maxEntries)
            return;
        if (schedule.due())
            sweep(nowMs);
        if (resident() >= maxEntries) {
            throw new MfaTransactionStoreFullError(maxEntries);
        }
    }
    return {
        kind: "memory",
        get transactions() {
            return transactions.size;
        },
        get bindings() {
            return byBinding.size;
        },
        get subjects() {
            return subjects.size;
        },
        get sessionEmailProofs() {
            return proofs.size;
        },
        get firstBindingMarks() {
            return marks.size;
        },
        get subjectLeases() {
            return leases.size;
        },
        maxEntries,
        async create(tx) {
            const record = newMfaTransactionRecord(tx);
            const nowMs = clock();
            if (!isStorableExpiry(record.expiresAtMs) || record.expiresAtMs <= nowMs) {
                throw new RangeError("MfaTransactionStore.create: expiresAtMs must be a future instant within the Date range");
            }
            if (live(record.id, nowMs) !== undefined) {
                throw new Error("an MFA transaction with this id already exists");
            }
            // Ending the binding's oldest frees the entry the new one takes.
            if (!makeRoomInBinding(record.binding, nowMs))
                makeRoom(nowMs);
            hold(record);
            if (schedule.wrote())
                sweep(nowMs);
        },
        async get(id) {
            const tx = live(id, clock());
            return tx === undefined ? null : copyOf(tx);
        },
        async update(id, expectedVersion, patch) {
            const writes = mfaTransactionPatchWrites(patch);
            checkMfaVersionAdvances(expectedVersion, "MfaTransactionStore.update");
            const tx = live(id, clock());
            if (tx === undefined || tx.version !== expectedVersion)
                return null;
            checkMfaTransactionTransitions(tx, writes);
            const next = { ...tx, version: tx.version + 1 };
            for (const [key, value] of writes)
                next[key] = value;
            const written = copyOf(next);
            transactions.set(id, written);
            return copyOf(written);
        },
        async reserveAttempt(id, max) {
            if (!Number.isSafeInteger(max) || max <= 0) {
                throw new RangeError("MfaTransactionStore.reserveAttempt: max must be a positive whole number");
            }
            const tx = live(id, clock());
            if (tx === undefined)
                return { ok: false, attempts: 0 };
            const attempts = tx.attempts + 1;
            // Fails closed: a count that is not a number is past every max.
            if (!(attempts <= max)) {
                drop(id);
                return { ok: false, attempts: tx.attempts };
            }
            transactions.set(id, { ...tx, attempts });
            return { ok: true, attempts };
        },
        async takeChallenge(id, expectedVersion) {
            const tx = live(id, clock());
            if (tx === undefined || tx.version !== expectedVersion || tx.challenge === undefined) {
                return null;
            }
            transactions.set(id, { ...tx, challenge: undefined });
            return structuredClone(tx.challenge);
        },
        async consume(id, expectedVersion) {
            const tx = live(id, clock());
            if (tx === undefined || tx.version !== expectedVersion)
                return null;
            drop(id);
            return copyOf(tx);
        },
        async reserveSubjectAttempt(subject, nowMs, policy) {
            // One read of the policy: the values it checks are the values it applies.
            const checked = checkMfaLockoutPolicy(policy);
            checkInstant(nowMs, "reserveSubjectAttempt");
            sawCallerTime(nowMs);
            const state = stateOf(subject);
            prune(state, nowMs);
            const refuse = (hold, retryAfterMs) => {
                const first = !state.refusing;
                state.refusing = true;
                settleEmpty(subject, state);
                return { ok: false, hold, retryAfterMs, first };
            };
            if (state.hard === undefined && state.run.length >= checked.hardLimit) {
                state.hard = fixedAt(state.run, nowMs);
            }
            if (state.hard !== undefined)
                return refuse("hard", null);
            const backoff = backoffUntil(state.run, checked, nowMs);
            const weekly = weeklyUntil(state.week, checked, nowMs);
            if (backoff !== undefined || weekly !== undefined) {
                // The hold that ends later is the one that decides when to come back.
                return (weekly ?? Number.NEGATIVE_INFINITY) >= (backoff ?? Number.NEGATIVE_INFINITY)
                    ? refuse("weekly", weekly - nowMs)
                    : refuse("backoff", backoff - nowMs);
            }
            const attempt = {
                id: randomBytes(16).toString("base64url"),
                atMs: nowMs,
                seq: nextSeq++,
            };
            state.run.push(attempt);
            state.week.push(attempt);
            state.pending.set(attempt.id, attempt.seq);
            state.refusing = false;
            // The attempt that brings the run to the limit holds it in the same
            // step: no later settle or exempt success can bring it back below.
            if (state.run.length >= checked.hardLimit)
                state.hard = fixedAt(state.run, nowMs);
            return { ok: true, reservation: attempt.id };
        },
        async settleSubjectAttempt(subject, reservation, outcome) {
            if (outcome !== "failure" && outcome !== "success" && outcome !== "void") {
                throw new RangeError("MfaTransactionStore.settleSubjectAttempt: outcome must be failure, success or void");
            }
            const state = subjects.get(subject);
            const seq = state?.pending.get(reservation);
            if (state === undefined || seq === undefined)
                return;
            state.pending.delete(reservation);
            if (outcome === "void") {
                state.run = state.run.filter((a) => a.id !== reservation);
                state.week = state.week.filter((a) => a.id !== reservation);
            }
            else if (outcome === "success") {
                // The run up to this success ends; an attempt reserved after it,
                // still in flight, is the start of the next.
                state.run = state.run.filter((a) => a.seq > seq);
                state.week = state.week.filter((a) => a.id !== reservation);
            }
            settleEmpty(subject, state);
        },
        async noteExemptSuccess(subject, nowMs, policy) {
            const { hardLimit } = checkMfaLockoutPolicy(policy);
            checkInstant(nowMs, "noteExemptSuccess");
            sawCallerTime(nowMs);
            const state = subjects.get(subject);
            if (state === undefined)
                return;
            prune(state, nowMs);
            // A run at the limit holds, as at a reservation; held, nothing
            // ends. Otherwise the attempts up to this success end, and a later
            // one stays.
            if (state.hard === undefined && state.run.length >= hardLimit) {
                state.hard = fixedAt(state.run, nowMs);
            }
            if (state.hard === undefined) {
                state.run = state.run.filter((a) => a.atMs > nowMs);
            }
            settleEmpty(subject, state);
            if (schedule.wrote())
                sweep(clock());
        },
        async requireEmailProofAtNextBinding(subject) {
            emailProofRequired.add(subject);
        },
        async emailProofRequiredAtNextBinding(subject) {
            return emailProofRequired.has(subject);
        },
        async consumeEmailProofRequirement(subject, consume) {
            const { leaseToken } = checkEmailProofRequirementConsume(subject, consume);
            if (!holds(subject, leaseToken))
                return { outcome: "refused", reason: "lease_not_held" };
            return { outcome: emailProofRequired.delete(subject) ? "consumed" : "absent" };
        },
        async recordSessionEmailProof(subject, sid, provedAtMs, untilMs) {
            const nowMs = clock();
            checkSessionEmailProof(subject, sid, provedAtMs, untilMs, nowMs);
            const key = proofKeyOf(subject, sid);
            if (!proofs.has(key))
                makeRoom(nowMs);
            proofs.set(key, { provedAtMs, untilMs });
            if (schedule.wrote())
                sweep(nowMs);
        },
        async sessionEmailProofAt(subject, sid, nowMs) {
            checkSessionEmailProofQuestion(subject, sid, nowMs);
            const key = proofKeyOf(subject, sid);
            const proof = proofs.get(key);
            if (proof === undefined)
                return null;
            const storeNowMs = clock();
            // Gone on this store's clock: reclaimed now rather than at a sweep.
            if (proof.untilMs <= storeNowMs)
                proofs.delete(key);
            return sessionEmailProofAnswer(proof, nowMs, storeNowMs);
        },
        async noteFirstBinding(subject, atMs, untilMs) {
            const nowMs = clock();
            checkFirstBindingNote(subject, atMs, untilMs, nowMs);
            const next = { atMs, untilMs };
            const held = marks.get(subject);
            const earlier = held === undefined ? null : firstBindingAnswer(held, nowMs);
            if (held !== undefined && earlier !== null) {
                marks.set(subject, laterFirstBindingMark(held, next));
            }
            else {
                if (held === undefined)
                    makeRoom(nowMs);
                marks.set(subject, next);
            }
            if (schedule.wrote())
                sweep(nowMs);
            return earlier;
        },
        async firstBindingAt(subject, nowMs) {
            checkFirstBindingQuestion(subject, nowMs);
            const mark = marks.get(subject);
            if (mark === undefined)
                return null;
            const storeNowMs = clock();
            // Gone on this store's clock: reclaimed now rather than at a sweep.
            if (mark.untilMs <= storeNowMs)
                marks.delete(subject);
            return firstBindingAnswer(mark, storeNowMs);
        },
        async subjectGeneration(subject) {
            checkSubjectQuestion("subjectGeneration", subject);
            return generations.get(subject) ?? 0;
        },
        async acquireSubjectLease(subject, request) {
            const { ttlMs, generation } = checkSubjectLeaseRequest(subject, request);
            if (generation !== (generations.get(subject) ?? 0)) {
                return { outcome: "stale" };
            }
            const nowMs = clock();
            const held = leases.get(subject);
            if (held !== undefined && held.untilMs > nowMs) {
                return { outcome: "busy", retryAfterMs: held.untilMs - nowMs };
            }
            if (held === undefined)
                makeRoom(nowMs);
            const token = randomBytes(16).toString("base64url");
            leases.set(subject, { token, untilMs: nowMs + ttlMs });
            if (schedule.wrote())
                sweep(nowMs);
            return { outcome: "acquired", token };
        },
        async authorizeSubjectRecovery(subject, authorization) {
            const nowMs = clock();
            const checked = checkSubjectRecoveryAuthorization(subject, authorization, nowMs);
            const key = slotKeyOf(checked.operation, checked.sid);
            if (recoveries.get(subject)?.has(key) !== true)
                makeRoom(nowMs);
            let slots = recoveries.get(subject);
            if (slots === undefined) {
                slots = new Map();
                recoveries.set(subject, slots);
            }
            if (!slots.has(key))
                slotCount += 1;
            slots.set(key, { recoveryId: checked.recoveryId, expiresAtMs: checked.expiresAtMs });
            if (schedule.wrote())
                sweep(nowMs);
        },
        async applySubjectRecovery(subject, application) {
            const { operation, sid, nowMs, leaseToken, sessionsBoundaryMs, guessableBoundSinceMs } = checkSubjectRecoveryApplication(subject, application);
            // The hard hold as it stands now, with from when a rebind counts against it. A
            // hold fixed so early that its bound falls before the epoch is one no answer can
            // carry: an outage, raised before anything changes.
            const hold = () => {
                const hardAtMs = subjects.get(subject)?.hard;
                if (hardAtMs === undefined)
                    return { hard: false, rebindAfterMs: null };
                const rebindAfterMs = rebindAfter(hardAtMs);
                if (!Number.isSafeInteger(rebindAfterMs) || rebindAfterMs < 0) {
                    throw new Error("MfaTransactionStore: the hard hold's bound is not an instant an answer can carry");
                }
                return { hard: true, rebindAfterMs };
            };
            if (operation === "recover")
                hold();
            sawCallerTime(nowMs);
            const storeNowMs = clock();
            const refused = (reason) => ({
                outcome: "refused",
                reason,
                ...hold(),
            });
            if (!holds(subject, leaseToken))
                return refused("lease_not_held");
            const slots = recoveries.get(subject);
            const key = slotKeyOf(operation, sid);
            const slot = slots?.get(key);
            if (slots === undefined || slot === undefined)
                return refused("unauthorized");
            if (slot.expiresAtMs <= storeNowMs) {
                const answer = refused("unauthorized");
                dropSlot(subject, slots, key);
                return answer;
            }
            if (slot.appliedAt !== undefined) {
                return {
                    outcome: "already_applied",
                    recoveryId: slot.recoveryId,
                    generation: slot.appliedAt,
                    ...hold(),
                };
            }
            if (slot.expiresAtMs <= nowMs)
                return refused("expired");
            if (sessionsBoundaryMs !== undefined && sessionsBoundaryMs > nowMs + DEFAULT_CLOCK_SKEW_MS) {
                return refused("boundary_ahead");
            }
            let cleared;
            if (operation === "reset") {
                // The lock state whole, and every other authorization of the subject.
                subjects.delete(subject);
                for (const other of slots.keys())
                    if (other !== key)
                        dropSlot(subject, slots, other);
                cleared = { week: true, run: true, hard: true };
            }
            else {
                const state = subjects.get(subject);
                const recovered = recover(state, nowMs, sessionsBoundaryMs, guessableBoundSinceMs);
                if (recovered === "not_revoked_since")
                    return refused(recovered);
                if (state !== undefined)
                    settleEmpty(subject, state);
                cleared = recovered;
            }
            const generation = (generations.get(subject) ?? 0) + 1;
            generations.set(subject, generation);
            slots.set(key, { ...slot, appliedAt: generation });
            return {
                outcome: "applied",
                recoveryId: slot.recoveryId,
                generation,
                cleared,
                ...hold(),
            };
        },
        async raiseRecoverySetFloor(subject, raise) {
            const { setGeneration, leaseToken } = checkRecoverySetFloorRaise(subject, raise);
            if (!holds(subject, leaseToken))
                return { outcome: "refused", reason: "lease_not_held" };
            const floor = Math.max(floors.get(subject) ?? 0, setGeneration);
            floors.set(subject, floor);
            return { outcome: "raised", floor };
        },
        async recoverySetFloor(subject) {
            checkSubjectQuestion("recoverySetFloor", subject);
            return floors.get(subject) ?? 0;
        },
        async releaseSubjectLease(subject, token) {
            checkSubjectLeaseRelease(subject, token);
            const held = leases.get(subject);
            if (held === undefined)
                return false;
            const standing = held.untilMs > clock();
            if (!standing)
                leases.delete(subject);
            if (!standing || held.token !== token)
                return false;
            leases.delete(subject);
            return true;
        },
    };
}
