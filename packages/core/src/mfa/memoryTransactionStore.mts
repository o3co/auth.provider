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
 * The in-process {@link MfaTransactionStore}: development and a single
 * replica. A transaction started on one replica is unknown to the one that
 * receives the verification, and the attempt limits are counted per replica.
 *
 * Every operation is one synchronous step on a `Map`, with no `await` between
 * its read and its write, so each is atomic. What it stores and what it hands
 * out are copies.
 *
 * A transaction expires on this store's clock (`now`, the wall clock unless
 * given); the subject state is judged on the time each caller passes, as the
 * port requires — the sweep too, which reads the latest time a caller passed
 * and never this store's clock. Expired transactions are swept as the store is
 * written to, paced like the challenge store's sweep, and a subject's state is
 * dropped once nothing in it can hold an attempt again: a failure and a trust
 * are kept {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} after they stop counting, and a
 * failure in the consecutive run is kept until a success ends the run. The
 * email-proof requirement the operator reset records is kept apart from the
 * lock state: no sweep and no `clearSubjectState` removes it, only its
 * consumption at the next first binding.
 *
 * It holds at most `maxEntries` transactions. A transaction is opened at every
 * password login that needs a second factor and at every step-up or enrollment
 * a session starts, and one the user abandons is never presented again: the
 * sweep bounds the store by time, and the login rate decides its size. At the
 * cap the store reclaims what has expired, no more often than the sweep floor,
 * and if it is still full refuses the new transaction with
 * {@link MfaTransactionStoreFullError}, a store fault. It never evicts a live
 * transaction, which would end the ceremony of a user already typing a code.
 * The subject state is not counted: it is keyed by subjects, which only a
 * login the Store accepted creates, not by values a caller can mint — though
 * where the Store lets anyone sign up, anyone can mint subjects, and a run is
 * kept until a success ends it. The cap is global: one account can open as
 * many transactions as the login rate limit lets it, so the coordinator bounds
 * the transactions one session holds.
 */

import { createHash, randomBytes } from "node:crypto";
import { isStorableExpiry } from "../adapters/expiry.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
import { usableMaxEntries } from "../single-use/max-entries.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../single-use/sweep.mjs";
import {
	checkMfaLockoutPolicy,
	checkNewMfaTransaction,
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
} from "./transactionStore.mjs";

/** Writing `create` calls between two sweeps of expired transactions. */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_SWEEP_INTERVAL = 1_000;

/** The least time between two sweeps, in milliseconds. */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MIN_SWEEP_INTERVAL_MS = 10_000;

/**
 * The most transactions the in-process store holds by default. A transaction
 * carries the login's `User` snapshot, so it is larger than a challenge or a
 * seen `jti`, and the cap is lower than theirs. Within the ten-minute default
 * lifetime it is about 170 new transactions a second on one replica — more
 * password logins than one process verifies.
 */
export const DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES = 100_000;

export interface MemoryMfaTransactionStoreOptions extends AmortizedSweepOptions {
	/** The clock a transaction expires by, in epoch milliseconds. Default `Date.now`. */
	readonly now?: () => number;
	/**
	 * The most transactions the store holds, expired-but-unswept ones included;
	 * {@link DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES} when absent. A
	 * value that is not a positive whole number, or is above 2^24 (the most
	 * entries a `Map` holds), is a `RangeError`, never read as no cap.
	 */
	readonly maxEntries?: number;
}

/**
 * What `create` throws when the store is at its cap and none of its
 * transactions has expired: a store fault, as a Redis store's refused write
 * at `maxmemory` is — not the port's refusal of a bad expiry (a `RangeError`),
 * which a caller reads as something it did. The MFA routes answer it `503
 * temporarily_unavailable`. `reason` is `"full"`, which a logged projection
 * keeps.
 */
export class MfaTransactionStoreFullError extends Error {
	readonly reason = "full" as const;

	constructor(maxEntries: number) {
		super(
			`memory MfaTransactionStore is at its cap of ${maxEntries} live transactions; refusing a new one rather than evicting one`,
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
	/** The most transactions it holds (`maxEntries`); at it, a new transaction is refused. */
	readonly maxEntries: number;
}

interface Attempt {
	readonly id: string;
	readonly atMs: number;
	/** The order the store reserved it in: a success ends the run up to its own. */
	readonly seq: number;
}

interface TrustedBrowser {
	readonly digest: string;
	readonly createdAtMs: number;
	/**
	 * `createdAtMs` + `trustedBrowserDays` under the policy it was granted by,
	 * so the sweep, which has no policy, can let an ended trust go.
	 */
	readonly trustedUntilMs: number;
	/**
	 * When the weekly window this trust outlives empties; `undefined` while no
	 * failure has entered the window since the trust began. Each failure
	 * recorded while the trust holds moves it to that failure's leaving time.
	 */
	windowUntilMs: number | undefined;
}

interface SubjectState {
	/** The consecutive run: every attempt since the last success, pending or failed. */
	run: Attempt[];
	/** The attempts the rolling week counts, pending or failed. No success removes one. */
	week: Attempt[];
	/** Reservations not yet settled, by id, with their order. */
	readonly pending: Map<string, number>;
	trusted: TrustedBrowser[];
}

const DAY_MS = 86_400_000;

/** The transaction as plain data, every field named, its nested values copied. */
const copyOf = (tx: MfaTransaction): MfaTransaction => structuredClone(tx);

const digestOf = (browser: string): string =>
	createHash("sha256").update(browser, "utf8").digest("base64url");

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

/** When a trust ends, as far as the store can tell without a policy (with one, it may end sooner). */
const trustEndsAt = (trust: TrustedBrowser, policy?: MfaLockoutPolicy): number =>
	Math.min(
		trust.trustedUntilMs,
		policy === undefined
			? Number.POSITIVE_INFINITY
			: trust.createdAtMs + policy.trustedBrowserDays * DAY_MS,
		trust.windowUntilMs ?? Number.POSITIVE_INFINITY,
	);

const trustHolds = (trust: TrustedBrowser, policy: MfaLockoutPolicy, nowMs: number): boolean =>
	nowMs < trustEndsAt(trust, policy);

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
	/** Subjects whose next first binding requires the email proof (D25): no expiry, never swept. */
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
	 * Expired transactions by this store's clock; subject state by the latest
	 * time a caller passed, and not at all before one has — but never later
	 * than this store's clock (see `prune`).
	 */
	function sweep(storeNowMs: number): void {
		for (const [id, tx] of transactions) {
			if (tx.expiresAtMs <= storeNowMs) transactions.delete(id);
		}
		if (latestCallerMs === undefined) return;
		for (const [subject, state] of subjects) {
			prune(state, latestCallerMs);
			if (isEmpty(state)) subjects.delete(subject);
		}
	}

	/**
	 * What the state no longer needs at `nowMs`, judged no later than this
	 * store's clock — so a caller whose clock runs far ahead, on this subject
	 * or another, erases nothing — and minus {@link MFA_CLOCK_SKEW_ALLOWANCE_MS},
	 * so one ahead of the store by less than that erases nothing either: the
	 * failures and trusts that ended before, and the reservations nothing
	 * counts any more. What is kept still counts only at a caller's own time.
	 */
	function prune(state: SubjectState, nowMs: number, policy?: MfaLockoutPolicy): void {
		const horizon = Math.min(nowMs, clock()) - MFA_CLOCK_SKEW_ALLOWANCE_MS;
		state.week = state.week.filter((a) => a.atMs + MFA_WEEKLY_WINDOW_MS > horizon);
		state.trusted = state.trusted.filter((t) => trustEndsAt(t, policy) > horizon);
		for (const id of state.pending.keys()) {
			if (!state.run.some((a) => a.id === id) && !state.week.some((a) => a.id === id)) {
				state.pending.delete(id);
			}
		}
	}

	const isEmpty = (state: SubjectState): boolean =>
		state.run.length === 0 &&
		state.week.length === 0 &&
		state.pending.size === 0 &&
		state.trusted.length === 0;

	function stateOf(subject: string): SubjectState {
		let state = subjects.get(subject);
		if (state === undefined) {
			state = { run: [], week: [], pending: new Map(), trusted: [] };
			subjects.set(subject, state);
		}
		return state;
	}

	function settleEmpty(subject: string, state: SubjectState): void {
		if (isEmpty(state)) subjects.delete(subject);
	}

	return {
		kind: "memory",

		get transactions() {
			return transactions.size;
		},

		get subjects() {
			return subjects.size;
		},

		maxEntries,

		async create(tx: MfaTransaction): Promise<void> {
			checkNewMfaTransaction(tx);
			const nowMs = clock();
			if (!isStorableExpiry(tx.expiresAtMs) || tx.expiresAtMs <= nowMs) {
				throw new RangeError(
					"MfaTransactionStore.create: expiresAtMs must be a future instant within the Date range",
				);
			}
			if (live(tx.id, nowMs) !== undefined) {
				throw new Error("an MFA transaction with this id already exists");
			}
			// At the cap: reclaim what has expired, no more often than the sweep
			// floor, and refuse if the store is still full. See the file header.
			if (transactions.size >= maxEntries) {
				if (schedule.due()) sweep(nowMs);
				if (transactions.size >= maxEntries) throw new MfaTransactionStoreFullError(maxEntries);
			}
			transactions.set(tx.id, copyOf(tx));
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
			const tx = live(id, clock());
			if (tx === undefined || tx.version !== expectedVersion) return null;
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
			browser: string | undefined,
		): Promise<MfaSubjectAttemptReservation> {
			checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "reserveSubjectAttempt");
			sawCallerTime(nowMs);
			const state = stateOf(subject);
			prune(state, nowMs, policy);

			const refuse = (
				hold: MfaSubjectHold,
				retryAfterMs: number | null,
			): MfaSubjectAttemptReservation => {
				settleEmpty(subject, state);
				return { ok: false, hold, retryAfterMs };
			};

			if (state.run.length >= policy.hardLimit) return refuse("hard", null);

			const backoff = backoffUntil(state.run, policy, nowMs);
			const digest = browser === undefined ? undefined : digestOf(browser);
			const trusted =
				digest !== undefined &&
				state.trusted.some(
					(t) => trustHolds(t, policy, nowMs) && constantTimeStringEqual(t.digest, digest),
				);
			const weekly = trusted ? undefined : weeklyUntil(state.week, policy, nowMs);
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
			for (const trust of state.trusted) {
				// Only a trust that holds is extended: one already ended stays ended.
				if (!trustHolds(trust, policy, nowMs)) continue;
				trust.windowUntilMs = Math.max(
					trust.windowUntilMs ?? Number.NEGATIVE_INFINITY,
					nowMs + MFA_WEEKLY_WINDOW_MS,
				);
			}
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
			presented: string | undefined,
		): Promise<{ readonly browser: string }> {
			checkMfaLockoutPolicy(policy);
			checkInstant(nowMs, "noteExemptSuccess");
			sawCallerTime(nowMs);
			const state = stateOf(subject);
			prune(state, nowMs, policy);
			// The run up to this success ends; an attempt reserved later stays.
			state.run = state.run.filter((a) => a.atMs > nowMs);
			// A browser already trusted is renewed under a fresh value, not added.
			if (presented !== undefined) {
				const digest = digestOf(presented);
				state.trusted = state.trusted.filter((t) => !constantTimeStringEqual(t.digest, digest));
			}
			const browser = randomBytes(32).toString("base64url");
			const newest = inWeek(state.week, nowMs).reduce<number | undefined>(
				(latest, a) => (latest === undefined || a.atMs > latest ? a.atMs : latest),
				undefined,
			);
			state.trusted.push({
				digest: digestOf(browser),
				createdAtMs: nowMs,
				trustedUntilMs: nowMs + policy.trustedBrowserDays * DAY_MS,
				windowUntilMs: newest === undefined ? undefined : newest + MFA_WEEKLY_WINDOW_MS,
			});
			if (state.trusted.length > policy.trustedBrowsers) {
				state.trusted = [...state.trusted]
					.sort((a, b) => a.createdAtMs - b.createdAtMs)
					.slice(state.trusted.length - policy.trustedBrowsers);
			}
			if (schedule.wrote()) sweep(clock());
			return { browser };
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
	};
}
