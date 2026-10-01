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
 * `prune`; the consecutive run lasts until a success). The email-proof
 * requirement the operator reset records is not lock state: only its
 * consumption at the next first binding removes it.
 *
 * A session's account-email proof and a subject's first-binding mark expire
 * on this store's clock too, and are swept with the transactions.
 *
 * At most `maxEntries` entries are held: transactions, session email proofs
 * and first-binding marks together. At the cap the store reclaims expired
 * entries (no more often than the sweep floor) and, if still full, refuses a
 * new one with {@link MfaTransactionStoreFullError}, never evicting a live one
 * (that would end the ceremony of a user typing a code, send them to prove
 * again, or trust a session a mark distrusts). Replacing a session's proof,
 * or noting a subject's mark again, is no new entry. Subject state is uncapped:
 * only a login the Store accepted creates a subject (an open sign-up lets
 * anyone mint them). The cap is global, so the coordinator bounds the
 * transactions one session holds.
 */

import { randomBytes } from "node:crypto";
import { isStorableExpiry } from "../adapters/expiry.mjs";
import { usableMaxEntries } from "../single-use/max-entries.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../single-use/sweep.mjs";
import {
	checkFirstBindingNote,
	checkFirstBindingQuestion,
	checkMfaLockoutPolicy,
	checkMfaTransactionTransitions,
	checkSessionEmailProof,
	checkSessionEmailProofQuestion,
	type FirstBindingMark,
	firstBindingAnswer,
	laterFirstBindingMark,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	MFA_WEEKLY_WINDOW_MS,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptOutcome,
	type MfaSubjectAttemptReservation,
	type MfaSubjectHold,
	type MfaTransaction,
	type MfaTransactionPatch,
	type MfaTransactionStore,
	mfaTransactionPatchWrites,
	newMfaTransactionRecord,
	type SessionEmailProof,
	sessionEmailProofAnswer,
} from "./transactionStore.mjs";
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

export interface MemoryMfaTransactionStoreOptions extends AmortizedSweepOptions {
	/** The clock a transaction expires by, in epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
	/**
	 * The most entries held — transactions, session email proofs and
	 * first-binding marks, expired-but-unswept included; default
	 * {@link DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES}. Anything but a
	 * positive whole number up to 2^24 (a `Map`'s limit) is a `RangeError`,
	 * never read as no cap.
	 */
	readonly maxEntries?: number;
}

/**
 * Thrown by `create` at the cap when nothing has expired. A store fault, like a
 * Redis write refused at `maxmemory`, not a `RangeError` (which a caller reads
 * as its own mistake); the MFA routes answer `503 temporarily_unavailable`.
 * `reason` survives in a logged projection.
 */
export class MfaTransactionStoreFullError extends Error {
	readonly reason = "full" as const;

	constructor(maxEntries: number) {
		super(
			`memory MfaTransactionStore is at its cap of ${maxEntries} resident entries — transactions, session email proofs and first-binding marks, expired ones not yet swept included; refusing a new one rather than evicting one`,
		);
		this.name = "MfaTransactionStoreFullError";
	}
}

/** In-process transaction store, with what is resident exposed for observability. */
export interface MemoryMfaTransactionStore extends MfaTransactionStore {
	/** Transactions resident, expired-but-unswept included. */
	readonly transactions: number;
	/** Subjects with lock state resident. */
	readonly subjects: number;
	/** Session email proofs resident, expired-but-unswept included. */
	readonly sessionEmailProofs: number;
	/** First-binding marks resident, expired-but-unswept included. */
	readonly firstBindingMarks: number;
	/** The most entries it holds (`maxEntries`), transactions, proofs and marks together; at it, a new one is refused. */
	readonly maxEntries: number;
}

interface Attempt {
	readonly id: string;
	readonly atMs: number;
	/** The order the store reserved it in: a success ends the run up to its own. */
	readonly seq: number;
}

interface SubjectState {
	/** The consecutive run: every attempt since the last success, pending or failed. */
	run: Attempt[];
	/** The attempts the rolling week counts, pending or failed. No success removes one. */
	week: Attempt[];
	/** Reservations not yet settled, by id, with their order. */
	readonly pending: Map<string, number>;
	/** Whether a refusal was answered since an attempt was last let through: an episode is under way. */
	refusing: boolean;
}

/** Where a session's proof is kept: the subject and the `sid` as one unambiguous key. */
const proofKeyOf = (subject: string, sid: string): string => JSON.stringify([subject, sid]);

/** The transaction as plain data, every field named, its nested values copied. */
const copyOf = (tx: MfaTransaction): MfaTransaction => structuredClone(tx);

const byTime = (attempts: readonly Attempt[]): Attempt[] =>
	[...attempts].sort((a, b) => a.atMs - b.atMs);

/**
 * The short backoff at `nowMs`: when the current lock ends, or `undefined`
 * when there is none. The run is replayed in time order: a failure made
 * `memorySeconds` or more after the last lock ended — or, before any lock,
 * after the previous failure — starts the backoff again; from the
 * `threshold`th failure of a backoff, each locks for `baseSeconds`, doubled
 * per further failure, at most `maxSeconds`.
 */
function backoffUntil(
	run: readonly Attempt[],
	policy: MfaLockoutPolicy,
	nowMs: number,
): number | undefined {
	const memoryMs = policy.memorySeconds * 1000;
	let count = 0;
	let lockUntil: number | undefined;
	let lastAt: number | undefined;
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

/** The failures the rolling week counts at `nowMs`. The store keeps them a while longer (see `prune`). */
const inWeek = (week: readonly Attempt[], nowMs: number): Attempt[] =>
	week.filter((a) => a.atMs + MFA_WEEKLY_WINDOW_MS > nowMs);

/** When the week will count fewer than `weeklyBudget` failures again, or `undefined` when it already does. */
function weeklyUntil(
	week: readonly Attempt[],
	policy: MfaLockoutPolicy,
	nowMs: number,
): number | undefined {
	const counted = byTime(inWeek(week, nowMs));
	if (counted.length < policy.weeklyBudget) return undefined;
	const leaving = counted[counted.length - policy.weeklyBudget];
	return leaving === undefined ? undefined : leaving.atMs + MFA_WEEKLY_WINDOW_MS;
}

function checkInstant(nowMs: number, operation: string): void {
	if (!isStorableExpiry(nowMs)) {
		throw new RangeError(
			`MfaTransactionStore.${operation}: nowMs must be a finite instant within the Date range`,
		);
	}
}

export function createMemoryMfaTransactionStore(
	options: MemoryMfaTransactionStoreOptions = {},
): MemoryMfaTransactionStore {
	const clock = options.now ?? Date.now;
	const maxEntries = usableMaxEntries(
		// Only a cap left out takes the default: an explicit `null` is refused.
		options.maxEntries === undefined
			? DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES
			: options.maxEntries,
		"createMemoryMfaTransactionStore",
	);
	const transactions = new Map<string, MfaTransaction>();
	const subjects = new Map<string, SubjectState>();
	/** Each session's account-email proof, by `proofKeyOf`. */
	const proofs = new Map<string, SessionEmailProof>();
	/** Each subject's first-binding mark. */
	const marks = new Map<string, FirstBindingMark>();
	/** Subjects whose next first binding requires the email proof: no expiry, never swept. */
	const emailProofRequired = new Set<string>();
	/** The order of the next reservation. */
	let nextSeq = 0;
	/**
	 * The latest time any caller passed: the sweep judges subject state on it,
	 * never on this store's clock, as the port requires.
	 */
	let latestCallerMs: number | undefined;
	const sawCallerTime = (nowMs: number): void => {
		latestCallerMs = latestCallerMs === undefined ? nowMs : Math.max(latestCallerMs, nowMs);
	};
	const schedule = createAmortizedSweep(
		options,
		{
			sweepInterval: DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL,
			minSweepIntervalMs: DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS,
		},
		"createMemoryMfaTransactionStore",
	);

	function live(id: string, nowMs: number): MfaTransaction | undefined {
		const tx = transactions.get(id);
		if (tx === undefined) return undefined;
		if (tx.expiresAtMs <= nowMs) {
			transactions.delete(id);
			return undefined;
		}
		return tx;
	}

	/**
	 * Expired transactions, proofs and marks by this store's clock; subject state by
	 * the latest time a caller passed, and not at all before one has — but
	 * never later than this store's clock (see `prune`).
	 */
	function sweep(storeNowMs: number): void {
		for (const [id, tx] of transactions) {
			if (tx.expiresAtMs <= storeNowMs) transactions.delete(id);
		}
		for (const [key, proof] of proofs) {
			if (proof.untilMs <= storeNowMs) proofs.delete(key);
		}
		for (const [subject, mark] of marks) {
			if (mark.untilMs <= storeNowMs) marks.delete(subject);
		}
		if (latestCallerMs === undefined) return;
		for (const [subject, state] of subjects) {
			prune(state, latestCallerMs);
			if (isEmpty(state)) subjects.delete(subject);
		}
	}

	/**
	 * Drops ended failures, and reservations nothing counts. The horizon is
	 * `nowMs` capped at this store's clock, minus
	 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS}, so a caller whose clock runs ahead
	 * erases nothing. What is kept still counts only at a caller's own time.
	 */
	function prune(state: SubjectState, nowMs: number): void {
		const horizon = Math.min(nowMs, clock()) - MFA_CLOCK_SKEW_ALLOWANCE_MS;
		state.week = state.week.filter((a) => a.atMs + MFA_WEEKLY_WINDOW_MS > horizon);
		for (const id of state.pending.keys()) {
			if (!state.run.some((a) => a.id === id) && !state.week.some((a) => a.id === id)) {
				state.pending.delete(id);
			}
		}
	}

	const isEmpty = (state: SubjectState): boolean =>
		state.run.length === 0 && state.week.length === 0 && state.pending.size === 0;

	function stateOf(subject: string): SubjectState {
		let state = subjects.get(subject);
		if (state === undefined) {
			state = { run: [], week: [], pending: new Map(), refusing: false };
			subjects.set(subject, state);
		}
		return state;
	}

	function settleEmpty(subject: string, state: SubjectState): void {
		if (isEmpty(state)) subjects.delete(subject);
	}

	/** At the cap: reclaims expired entries, then refuses if still full. */
	const resident = (): number => transactions.size + proofs.size + marks.size;

	function makeRoom(nowMs: number): void {
		if (resident() < maxEntries) return;
		if (schedule.due()) sweep(nowMs);
		if (resident() >= maxEntries) {
			throw new MfaTransactionStoreFullError(maxEntries);
		}
	}

	return {
		kind: "memory",

		get transactions() {
			return transactions.size;
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

		maxEntries,

		async create(tx: MfaTransaction): Promise<void> {
			const record = newMfaTransactionRecord(tx);
			const nowMs = clock();
			if (!isStorableExpiry(record.expiresAtMs) || record.expiresAtMs <= nowMs) {
				throw new RangeError(
					"MfaTransactionStore.create: expiresAtMs must be a future instant within the Date range",
				);
			}
			if (live(record.id, nowMs) !== undefined) {
				throw new Error("an MFA transaction with this id already exists");
			}
			makeRoom(nowMs);
			transactions.set(record.id, record);
			if (schedule.wrote()) sweep(nowMs);
		},

		async get(id: string): Promise<MfaTransaction | null> {
			const tx = live(id, clock());
			return tx === undefined ? null : copyOf(tx);
		},

		async update(
			id: string,
			expectedVersion: number,
			patch: MfaTransactionPatch,
		): Promise<MfaTransaction | null> {
			const writes = mfaTransactionPatchWrites(patch);
			checkMfaVersionAdvances(expectedVersion, "MfaTransactionStore.update");
			const tx = live(id, clock());
			if (tx === undefined || tx.version !== expectedVersion) return null;
			checkMfaTransactionTransitions(tx, writes);
			const next: Record<string, unknown> = { ...tx, version: tx.version + 1 };
			for (const [key, value] of writes) next[key] = value;
			const written = copyOf(next as unknown as MfaTransaction);
			transactions.set(id, written);
			return copyOf(written);
		},

		async reserveAttempt(
			id: string,
			max: number,
		): Promise<{ readonly ok: boolean; readonly attempts: number }> {
			if (!Number.isSafeInteger(max) || max <= 0) {
				throw new RangeError(
					"MfaTransactionStore.reserveAttempt: max must be a positive whole number",
				);
			}
			const tx = live(id, clock());
			if (tx === undefined) return { ok: false, attempts: 0 };
			const attempts = tx.attempts + 1;
			// Fails closed: a count that is not a number is past every max.
			if (!(attempts <= max)) {
				transactions.delete(id);
				return { ok: false, attempts: tx.attempts };
			}
			transactions.set(id, { ...tx, attempts });
			return { ok: true, attempts };
		},

		async takeChallenge(
			id: string,
			expectedVersion: number,
		): Promise<MfaTransaction["challenge"] | null> {
			const tx = live(id, clock());
			if (tx === undefined || tx.version !== expectedVersion || tx.challenge === undefined) {
				return null;
			}
			transactions.set(id, { ...tx, challenge: undefined });
			return structuredClone(tx.challenge);
		},

		async consume(id: string, expectedVersion: number): Promise<MfaTransaction | null> {
			const tx = live(id, clock());
			if (tx === undefined || tx.version !== expectedVersion) return null;
			transactions.delete(id);
			return copyOf(tx);
		},

		async reserveSubjectAttempt(
			subject: string,
			nowMs: number,
			policy: MfaLockoutPolicy,
		): Promise<MfaSubjectAttemptReservation> {
			checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "reserveSubjectAttempt");
			sawCallerTime(nowMs);
			const state = stateOf(subject);
			prune(state, nowMs);

			const refuse = (
				hold: MfaSubjectHold,
				retryAfterMs: number | null,
			): MfaSubjectAttemptReservation => {
				const first = !state.refusing;
				state.refusing = true;
				settleEmpty(subject, state);
				return { ok: false, hold, retryAfterMs, first };
			};

			if (state.run.length >= policy.hardLimit) return refuse("hard", null);

			const backoff = backoffUntil(state.run, policy, nowMs);
			const weekly = weeklyUntil(state.week, policy, nowMs);
			if (backoff !== undefined || weekly !== undefined) {
				// The hold that ends later is the one that decides when to come back.
				return (weekly ?? Number.NEGATIVE_INFINITY) >= (backoff ?? Number.NEGATIVE_INFINITY)
					? refuse("weekly", (weekly as number) - nowMs)
					: refuse("backoff", (backoff as number) - nowMs);
			}

			const attempt: Attempt = {
				id: randomBytes(16).toString("base64url"),
				atMs: nowMs,
				seq: nextSeq++,
			};
			state.run.push(attempt);
			state.week.push(attempt);
			state.pending.set(attempt.id, attempt.seq);
			state.refusing = false;
			return { ok: true, reservation: attempt.id };
		},

		async settleSubjectAttempt(
			subject: string,
			reservation: string,
			outcome: MfaSubjectAttemptOutcome,
		): Promise<void> {
			if (outcome !== "failure" && outcome !== "success" && outcome !== "void") {
				throw new RangeError(
					"MfaTransactionStore.settleSubjectAttempt: outcome must be failure, success or void",
				);
			}
			const state = subjects.get(subject);
			const seq = state?.pending.get(reservation);
			if (state === undefined || seq === undefined) return;
			state.pending.delete(reservation);
			if (outcome === "void") {
				state.run = state.run.filter((a) => a.id !== reservation);
				state.week = state.week.filter((a) => a.id !== reservation);
			} else if (outcome === "success") {
				// The run up to this success ends; an attempt reserved after it,
				// still in flight, is the start of the next.
				state.run = state.run.filter((a) => a.seq > seq);
				state.week = state.week.filter((a) => a.id !== reservation);
			}
			settleEmpty(subject, state);
		},

		async noteExemptSuccess(
			subject: string,
			nowMs: number,
			policy: MfaLockoutPolicy,
		): Promise<void> {
			const { hardLimit } = checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "noteExemptSuccess");
			sawCallerTime(nowMs);
			const state = subjects.get(subject);
			if (state === undefined) return;
			prune(state, nowMs);
			// The attempts up to this success end while fewer than the hard
			// limit; at it they stand until cleared. A later attempt stays.
			const upTo = state.run.filter((a) => a.atMs <= nowMs);
			if (upTo.length < hardLimit) {
				state.run = state.run.filter((a) => a.atMs > nowMs);
			}
			settleEmpty(subject, state);
			if (schedule.wrote()) sweep(clock());
		},

		async clearSubjectState(subject: string): Promise<void> {
			// The email-proof requirement is not lock state: it stays.
			subjects.delete(subject);
		},

		async requireEmailProofAtNextBinding(subject: string): Promise<void> {
			emailProofRequired.add(subject);
		},

		async emailProofRequiredAtNextBinding(subject: string): Promise<boolean> {
			return emailProofRequired.has(subject);
		},

		async consumeEmailProofRequirement(subject: string): Promise<boolean> {
			return emailProofRequired.delete(subject);
		},

		async recordSessionEmailProof(
			subject: string,
			sid: string,
			provedAtMs: number,
			untilMs: number,
		): Promise<void> {
			const nowMs = clock();
			checkSessionEmailProof(subject, sid, provedAtMs, untilMs, nowMs);
			const key = proofKeyOf(subject, sid);
			if (!proofs.has(key)) makeRoom(nowMs);
			proofs.set(key, { provedAtMs, untilMs });
			if (schedule.wrote()) sweep(nowMs);
		},

		async sessionEmailProofAt(subject: string, sid: string, nowMs: number): Promise<number | null> {
			checkSessionEmailProofQuestion(subject, sid, nowMs);
			const key = proofKeyOf(subject, sid);
			const proof = proofs.get(key);
			if (proof === undefined) return null;
			const storeNowMs = clock();
			// Gone on this store's clock: reclaimed now rather than at a sweep.
			if (proof.untilMs <= storeNowMs) proofs.delete(key);
			return sessionEmailProofAnswer(proof, nowMs, storeNowMs);
		},

		async noteFirstBinding(subject: string, atMs: number, untilMs: number): Promise<void> {
			const nowMs = clock();
			checkFirstBindingNote(subject, atMs, untilMs, nowMs);
			const next = { atMs, untilMs };
			const held = marks.get(subject);
			if (held !== undefined && held.untilMs > nowMs) {
				marks.set(subject, laterFirstBindingMark(held, next));
			} else {
				if (held === undefined) makeRoom(nowMs);
				marks.set(subject, next);
			}
			if (schedule.wrote()) sweep(nowMs);
		},

		async firstBindingAt(subject: string, nowMs: number): Promise<number | null> {
			checkFirstBindingQuestion(subject, nowMs);
			const mark = marks.get(subject);
			if (mark === undefined) return null;
			const storeNowMs = clock();
			// Gone on this store's clock: reclaimed now rather than at a sweep.
			if (mark.untilMs <= storeNowMs) marks.delete(subject);
			return firstBindingAnswer(mark, nowMs, storeNowMs);
		},
	};
}
