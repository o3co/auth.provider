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
 * - `remove`: the records read, the caller's refusal asked, the record removed
 *   — a store that fails after its write is read again, and a record gone is a
 *   removal — then the records read again (or, unreadable, those read before
 *   less the removed one) and, when none may count (`mayCount`), the witness
 *   cleared.
 * - `bind`, an enrollment's completion or a regeneration of recovery codes:
 *   the caller's writes run whole under the lease, through the factor store,
 *   the witness and the subject's recovery-set floor this file hands it, each
 *   held to the lease's time as above; the floor is raised with the lease
 *   this file holds, never handed out.
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
 * The lease is logical: it cannot fence a write the factor store or the
 * directory applies after the deadline check, nor a transaction-store write
 * that was not answered within its bound and lands later. A binding's
 * consume of D25's flag that timed out may so land after the lease is
 * released and clear the flag a later reset set: the reset sets the flag
 * again as its last write under its lease, which narrows this to a consume
 * landing after the reset's own release, until the stores fence their
 * writes. Never throws for a store's failure: `list` alone throws, for its
 * caller to answer.
 */

import {
	consoleLogger,
	type Logger,
	loggableError,
	MFA_SUBJECT_LEASE_MAX_MS,
	MFA_SUBJECT_LEASE_MIN_MS,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	type MfaSubjectRecoveryAnswer,
	type MfaTransactionStore,
	readMfaRecoverySetFloorAnswer,
	readMfaSubjectCount,
	readMfaSubjectLeaseAnswer,
	readMfaSubjectRecoveryAnswer,
} from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
import { type MfaSubjectRecords, readSubjectRecords } from "./factorState.mjs";
import { mayCount } from "./firstBinding.mjs";
import type { MfaSealing } from "./sealing.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";

/** The pauses, in milliseconds, between tries for a lease another write holds: then `busy`. */
const LEASE_WAITS_MS = [25, 50, 100, 200, 400] as const;

/**
 * The most Store and directory calls one writer makes under the lease — what
 * the lease is sized from, and `factorSetBudget.test.mts` holds every writer
 * to: a first binding by the account-email proof over two standing
 * recovery-code sets (a binding by password keeps the one that stood) makes
 * fourteen (the first-binding note, the consume, the factor, the records read
 * again, D25's flag, the sets read, the recovery-set floor read, the new set,
 * the floor raised, each old set's removal, the records read again, the set
 * marked shown, the witness); a regeneration of recovery codes seven and one
 * per standing set (the records read, the first-binding mark read, the floor
 * read, the new set, the floor raised, the removals, the records read again,
 * the set marked shown); the
 * operator reset eight (the read, D25's flag, its authorization, the lock
 * state's reset, the removal, the read again, the witness, D25's flag again);
 * a removal five; a mark four; a release two. More standing sets — past two at
 * a binding, past seven at a regeneration — each add a removal, which the
 * lease's time cuts off when it runs short: every set that stood is already
 * retired by the raised floor, the new set is left unshown, and the writer
 * answers an outage, to be run again.
 */
export const FACTOR_SET_STORE_CALLS = 14;

/** How many Store calls' time a lease stands: the writer's calls, the acquire, and one to spare. */
const LEASE_STORE_TIMEOUTS = FACTOR_SET_STORE_CALLS + 2;

/** How many of its own leases the operator reset waits for another holder's to end. */
const RESET_WAIT_LEASES = 2;

/** The longest pause, in milliseconds, between the operator reset's tries for the lease. */
const RESET_PAUSE_MS = 250;

/** The lease a write takes when one Store call may take `storeTimeoutMs`, at least core's shortest. */
const leaseMsFor = (storeTimeoutMs: number): number =>
	Math.max(LEASE_STORE_TIMEOUTS * storeTimeoutMs, MFA_SUBJECT_LEASE_MIN_MS);

/**
 * `storeTimeoutMs`, `mfa.storeTimeoutMs`, when the lease it makes fits core's
 * longest; else a `RangeError` naming the key: a write could outlive its
 * lease, and one write at a time would not hold.
 */
export function checkFactorSetStoreTimeout(storeTimeoutMs: number): number {
	if (!Number.isSafeInteger(storeTimeoutMs) || storeTimeoutMs < 1) {
		throw new RangeError(
			`mfa.storeTimeoutMs: ${String(storeTimeoutMs)} is not a whole number of milliseconds from 1`,
		);
	}
	const leaseMs = LEASE_STORE_TIMEOUTS * storeTimeoutMs;
	if (leaseMs > MFA_SUBJECT_LEASE_MAX_MS) {
		throw new RangeError(
			`mfa.storeTimeoutMs: ${storeTimeoutMs} ms makes a factor-set write's lease ${leaseMs} ms (${LEASE_STORE_TIMEOUTS} Store calls' time), past the longest subject lease, ${MFA_SUBJECT_LEASE_MAX_MS} ms: a write could outlive its lease. Set it to at most ${Math.floor(MFA_SUBJECT_LEASE_MAX_MS / LEASE_STORE_TIMEOUTS)} ms`,
		);
	}
	return storeTimeoutMs;
}

/**
 * A reader of the subject's recovery-set floor over `store`, bounded by
 * `storeTimeoutMs`: throws for a store that cannot answer in time, or
 * answers outside its port. What every reading of a recovery set's
 * usability reads the floor through.
 */
export function boundedRecoverySetFloor(
	store: Pick<MfaTransactionStore, "recoverySetFloor">,
	storeTimeoutMs: number,
): (subject: string) => Promise<number> {
	return async (subject) => {
		const floor = readMfaSubjectCount(
			await within(() => store.recoverySetFloor(subject), storeTimeoutMs, "recoverySetFloor"),
		);
		if (floor === undefined) throw OUTSIDE_CONTRACT;
		return floor;
	};
}

/** The subject's records, oldest first: the order a page lists them and a request names them. */
const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

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

/** What a start holds. */
type Started =
	| { readonly subject: string; readonly generation: number }
	| { readonly subject: string; readonly cause: unknown };

/** A write that could not run under the subject's lease, or gave up before writing. */
export type MfaFactorSetRefusal =
	/** Another write held the lease past the wait, or too little of it was left: try again. */
	| { readonly outcome: "busy"; readonly retryAfterSeconds: number }
	/** The generation moved since the write began — a recovery or a reset: read again. */
	| { readonly outcome: "changed" }
	| {
			readonly outcome: "unavailable";
			readonly store: "mfa_factor" | "mfa_transaction";
			readonly step: string;
			readonly cause: unknown;
	  };

/** What a removal came to; `overran` on any answer when the release did not find the lease held. */
export type MfaFactorRemoval<Refusal> = (
	| MfaFactorSetRefusal
	| { readonly outcome: "unknown_factor" }
	| { readonly outcome: "refused"; readonly refusal: Refusal }
	| {
			readonly outcome: "removed";
			readonly record: MfaFactorRecord;
			/** Why the records could not be read again; those read before, less the removed one, decided. */
			readonly unread?: unknown;
			/** The witness's clear, when none that may count was left. */
			readonly witness?: MfaWitnessMark;
	  }
) & {
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
 * What a bind's writes go through, each held to the lease's time: the factor
 * store, the witness, the subject's recovery-set floor, `read` for any other
 * read and `run` for any other write it makes (the transaction store's).
 * Every write a bind makes goes through one of them, so a bind answered
 * `busy` wrote nothing.
 */
export interface MfaFactorSetWrites {
	readonly factorStore: MfaFactorStore;
	readonly witness: MfaEnrollmentWitness;
	readonly recoverySetFloor: MfaRecoverySetFloor;
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
export type MfaFactorSetBound<Done> = (
	| MfaFactorSetRefusal
	| { readonly outcome: "bound"; readonly done: Done }
) & {
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
export type MfaFactorSetRecovered =
	| Exclude<MfaFactorSetRefusal, { readonly outcome: "changed" }>
	| { readonly outcome: "answered"; readonly answer: MfaSubjectRecoveryAnswer };

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
	carry(
		start: MfaFactorSetStart,
	): MfaFactorSetCarried | Extract<MfaFactorSetRefusal, { readonly outcome: "unavailable" }>;
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
	remove<Refusal>(
		start: MfaFactorSetStart,
		subject: string,
		factorId: unknown,
		refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined,
	): Promise<MfaFactorRemoval<Refusal>>;
	/** Under the subject's lease acquired at `start`, `write` run whole through the writes it is handed. */
	bind<Done>(
		start: MfaFactorSetStart,
		subject: string,
		write: (writes: MfaFactorSetWrites) => Promise<Done>,
	): Promise<MfaFactorSetBound<Done>>;
	/** Under the subject's lease, the subject's authorized recovery applied (see this file's header). */
	recover(subject: string, recovery: MfaFactorSetRecovery): Promise<MfaFactorSetRecovered>;
}

/** A call not answered in the time it was given. */
class NotAnswered extends Error {}

/** A call not answered within `ms`: {@link NotAnswered}; the timer cleared either way. */
async function within<T>(call: () => Promise<T>, ms: number, what: string): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			call(),
			new Promise<never>((_, reject) => {
				timer = setTimeout(
					() => reject(new NotAnswered(`${what} was not answered within ${Math.round(ms)} ms`)),
					Math.max(0, ms),
				);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

/** Thrown inside a write when too little of the lease is left: nothing more is started. */
class OutOfTime extends Error {}

/** What a write is handed: the read and the check it runs before each Store call under the lease. */
interface LeaseTime {
	/** `call`, a read, given up when it would leave less than one Store timeout of the lease. */
	read<T>(call: () => Promise<T>): Promise<T>;
	/** Throws {@link OutOfTime} when less than one Store timeout of the lease is left: no write is started. */
	beforeWrite(): void;
}

/** The leases' port as this file uses it. */
type Leases = Pick<
	MfaTransactionStore,
	| "subjectGeneration"
	| "acquireSubjectLease"
	| "releaseSubjectLease"
	| "applySubjectRecovery"
	| "recoverySetFloor"
	| "raiseRecoverySetFloor"
>;

/** A transaction-store outage at `step`. */
const leaseOutage = (
	step: string,
	cause: unknown,
): Extract<MfaFactorSetRefusal, { readonly outcome: "unavailable" }> => ({
	outcome: "unavailable",
	store: "mfa_transaction",
	step,
	cause,
});

/** What holding a subject's lease for a write came to. */
type Held<T> =
	| { readonly outcome: "held"; readonly done: T; readonly overran: boolean }
	/** Out of time after a write was started: what was written stands. */
	| { readonly outcome: "ran_out" }
	| (MfaFactorSetRefusal & { readonly overran?: true });

/**
 * Where a write is acquired: at the generation its start read — a moved one
 * is `changed` — or at the subject's current one, read again after a pause
 * whenever it moved before the acquire.
 */
type LeaseAt = { readonly generation: number } | "current";

/**
 * How long a write waits for the lease: by default the bounded pauses of
 * {@link LEASE_WAITS_MS}; with `until`, a local monotonic instant, pauses of
 * at most {@link RESET_PAUSE_MS} until then.
 */
interface LeaseWait {
	readonly until?: number;
}

/** What a refused start of a write is told: too little of the lease was left. Never thrown past this file. */
const LEASE_SPENT = "too little of the subject's lease was left to start this write";

/**
 * The subject's lease over `leases`, the one place it is held: its
 * generation read, the lease acquired at a generation — waiting, and pausing
 * on a generation that moved where the write takes the current one — the
 * write run under it, held to the lease's time, and the lease released.
 */
function subjectLeases(options: {
	readonly leases: Leases;
	readonly storeTimeoutMs: number;
	readonly monotonicNow: () => number;
}) {
	const { leases, monotonicNow } = options;
	const storeTimeoutMs = checkFactorSetStoreTimeout(options.storeTimeoutMs);
	const ttlMs = leaseMsFor(storeTimeoutMs);

	/** The subject's generation; throws for one that cannot be read, or is outside the port. */
	const generationOf = async (subject: string): Promise<number> => {
		const generation = readMfaSubjectCount(
			await within(() => leases.subjectGeneration(subject), storeTimeoutMs, "subjectGeneration"),
		);
		if (generation === undefined) throw OUTSIDE_CONTRACT;
		return generation;
	};

	/** The lease `token` holds released: `true` when the store found it held. */
	const release = async (subject: string, token: string): Promise<boolean> => {
		try {
			return (
				(await within(
					() => leases.releaseSubjectLease(subject, token),
					storeTimeoutMs,
					"releaseSubjectLease",
				)) === true
			);
		} catch {
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
	const underLease = async <T,>(
		subject: string,
		at: LeaseAt,
		write: (time: LeaseTime, token: string) => Promise<T>,
		wait: LeaseWait = {},
	): Promise<Held<T>> => {
		/** Pauses before the next try: `false` when the wait is spent. */
		const paused = async (tries: number, retryAfterMs: number): Promise<boolean> => {
			let pause: number | undefined;
			if (wait.until === undefined) {
				pause = LEASE_WAITS_MS[tries];
			} else if (monotonicNow() < wait.until) {
				pause = Math.min(retryAfterMs, RESET_PAUSE_MS);
			}
			if (pause === undefined) return false;
			await new Promise((resolve) => setTimeout(resolve, pause));
			return true;
		};
		let token: string | undefined;
		let acquiredFrom = 0;
		let lastBusyMs = RESET_PAUSE_MS;
		for (let tries = 0; token === undefined; tries++) {
			let generation: number;
			if (at === "current") {
				try {
					generation = await generationOf(subject);
				} catch (cause) {
					return leaseOutage("subjectGeneration", cause);
				}
			} else {
				generation = at.generation;
			}
			const asked = monotonicNow();
			let answer: ReturnType<typeof readMfaSubjectLeaseAnswer>;
			try {
				answer = readMfaSubjectLeaseAnswer(
					await within(
						() => leases.acquireSubjectLease(subject, { ttlMs, generation }),
						storeTimeoutMs,
						"acquireSubjectLease",
					),
				);
			} catch (cause) {
				return leaseOutage("acquireSubjectLease", cause);
			}
			if (answer === undefined) return leaseOutage("acquireSubjectLease", OUTSIDE_CONTRACT);
			if (answer.outcome === "acquired") {
				token = answer.token;
				acquiredFrom = asked;
			} else if (answer.outcome === "stale") {
				// A start's generation that moved is final; the current one is read again after a pause.
				if (at !== "current" || !(await paused(tries, LEASE_WAITS_MS[0]))) {
					return { outcome: "changed" };
				}
			} else {
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
		const outOfTime = (): OutOfTime => {
			ranOut = true;
			return new OutOfTime(LEASE_SPENT);
		};
		const time: LeaseTime = {
			read: async (call) => {
				const budget = left();
				if (budget <= 0) throw outOfTime();
				try {
					return await within(call, budget, "a read under the lease");
				} catch (cause) {
					if (cause instanceof NotAnswered) throw outOfTime();
					throw cause;
				}
			},
			beforeWrite: () => {
				if (ranOut || left() < 0) throw outOfTime();
				wrote = true;
			},
		};
		let done: T;
		try {
			done = await write(time, held);
		} catch (cause) {
			const kept = await release(subject, held);
			if (!(cause instanceof OutOfTime)) throw cause;
			// Out of time before any write: nothing was written, and a release that lost the lease is still an overrun.
			if (wrote) return { outcome: "ran_out" };
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

/** What each owner holds, by the handle its holders are given. */
const owners = new WeakMap<MfaSubjectLeases, ReturnType<typeof subjectLeases>>();

/**
 * A lease owner over `options.store`, its per-call bound `storeTimeoutMs`
 * (held to {@link checkFactorSetStoreTimeout}: a `RangeError` naming
 * `mfa.storeTimeoutMs` for one whose lease would pass core's longest) and its
 * lease {@link LEASE_STORE_TIMEOUTS} of it.
 */
export function createMfaSubjectLeases(options: {
	/** Where the subject's generation and lease are kept, and its recovery applied. */
	readonly store: Leases;
	/** `mfa.storeTimeoutMs`. */
	readonly storeTimeoutMs: number;
	/** A monotonic clock, in milliseconds. Defaults to `performance.now`. */
	readonly monotonicNow?: () => number;
}): MfaSubjectLeases {
	const owner = subjectLeases({
		leases: options.store,
		storeTimeoutMs: options.storeTimeoutMs,
		monotonicNow: options.monotonicNow ?? (() => performance.now()),
	});
	const handle = Object.freeze({}) as MfaSubjectLeases;
	owners.set(handle, owner);
	return handle;
}

/** The owner `handle` stands for; a `TypeError` for a value this file did not build. */
function ownerOf(handle: MfaSubjectLeases): ReturnType<typeof subjectLeases> {
	const owner = owners.get(handle);
	if (owner === undefined) {
		throw new TypeError("the subject's lease owner is not one createMfaSubjectLeases built");
	}
	return owner;
}

/** The factor set over `options` (see this file's header). */
export function createMfaFactorSet(options: {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly witness: MfaEnrollmentWitness;
	/** A lease owner ({@link createMfaSubjectLeases}) of the rules every writer holds. */
	readonly leases: MfaSubjectLeases;
	/** What a record's data is opened with, for a reading of the subject's records. */
	readonly sealing: MfaSealing;
	/** Where `mfa_recovery_set_floor_unread` goes. Absent, core's `consoleLogger`. */
	readonly logger?: Logger;
}): MfaFactorSet {
	const { factors, factorStore, witness, sealing } = options;
	const logger = options.logger ?? consoleLogger;
	const subjectLease = ownerOf(options.leases);
	const { storeTimeoutMs, leases } = subjectLease;
	const starts = new WeakMap<MfaFactorSetStart, Started>();
	const floorOf = boundedRecoverySetFloor(leases, storeTimeoutMs);

	const list = async (subject: string): Promise<MfaFactorRecord[]> => {
		const records: unknown = await factorStore.list(subject);
		if (!Array.isArray(records)) {
			throw new TypeError("MfaFactorStore.list answered something that is not a list");
		}
		return [...(records as MfaFactorRecord[])].sort(byAge);
	};

	/** Whether none of `records` may count. */
	const noneCounts = (records: readonly MfaFactorRecord[]): boolean =>
		!records.some((record) => mayCount(factors, record));

	const begin = async (subject: string, write: MfaFactorSetWrite): Promise<MfaFactorSetStart> => {
		const start = Object.freeze({}) as MfaFactorSetStart;
		// A mark a directory cannot write takes no lease: it needs no generation.
		if (write === "mark" && !witness.writable) {
			starts.set(start, {
				subject,
				cause: new Error("no lease is taken for a mark nobody can write"),
			});
			return start;
		}
		let started: Started;
		try {
			started = { subject, generation: await subjectLease.generationOf(subject) };
		} catch (cause) {
			started = { subject, cause };
		}
		starts.set(start, started);
		return start;
	};

	/** `write` under the lease acquired at `start`'s generation (`subjectLeases`). */
	const underLease = async <T,>(
		start: MfaFactorSetStart | undefined,
		subject: string,
		write: (time: LeaseTime, token: string) => Promise<T>,
	): Promise<Held<T>> => {
		const started = start === undefined ? undefined : starts.get(start);
		// A start for another subject, or none, began nowhere this write can tell.
		if (started === undefined || started.subject !== subject) return { outcome: "changed" };
		if ("cause" in started) return leaseOutage("subjectGeneration", started.cause);
		return subjectLease.underLease(subject, { generation: started.generation }, write);
	};

	/** What a mark is answered when it could not run, or ran, outside a lease it held. */
	const unwritten = (why: string): MfaWitnessMark => ({
		outcome: "unwritten",
		cause: new Error(`the witness mark ${why}`),
	});

	/**
	 * The factor store, the witness, the recovery-set floor and any other
	 * write as a bind's writes go through them: each held to `time`, a refusal
	 * never thrown as this file's own error — a store call refused rejects as a
	 * store's failure would, a witness write is unwritten, and another write
	 * is answered `refused`. The floor is raised with `token`, the lease held.
	 */
	const writesUnder = (time: LeaseTime, token: string): MfaFactorSetWrites => {
		/** `time`'s check, as a store's failure: this file's error stays here. */
		const started = <T,>(check: () => void, call: () => Promise<T>): Promise<T> => {
			try {
				check();
			} catch {
				return Promise.reject(new Error(LEASE_SPENT));
			}
			return call();
		};
		const write = <T,>(call: () => Promise<T>): Promise<T> => started(time.beforeWrite, call);
		const read = <T,>(call: () => Promise<T>): Promise<T> =>
			time.read(call).catch((cause: unknown) => {
				throw cause instanceof OutOfTime ? new Error(LEASE_SPENT) : cause;
			});
		/** A witness write the lease's time cannot cover is unwritten: the witness never throws. */
		const witnessWrite = async (call: () => Promise<MfaWitnessMark>): Promise<MfaWitnessMark> => {
			try {
				time.beforeWrite();
			} catch {
				return unwritten("found too little of the subject's lease left");
			}
			return call();
		};
		return {
			factorStore: {
				kind: factorStore.kind,
				list: (subject) => read(() => factorStore.list(subject)),
				create: (record) => write(() => factorStore.create(record)),
				update: (subject, id, expectedVersion, next) =>
					write(() => factorStore.update(subject, id, expectedVersion, next)),
				remove: (subject, id) => write(() => factorStore.remove(subject, id)),
				removeAllForSubject: (subject) => write(() => factorStore.removeAllForSubject(subject)),
			},
			witness: {
				writable: witness.writable,
				mark: (subject) => witnessWrite(() => witness.mark(subject)),
				clear: (subject) => witnessWrite(() => witness.clear(subject)),
			},
			recoverySetFloor: {
				read: (subject) => read(() => floorOf(subject)),
				raise: (subject, setGeneration) =>
					write(async () => {
						const answer = readMfaRecoverySetFloorAnswer(
							await within(
								() => leases.raiseRecoverySetFloor(subject, { setGeneration, leaseToken: token }),
								storeTimeoutMs,
								"raiseRecoverySetFloor",
							),
						);
						if (answer === undefined) throw OUTSIDE_CONTRACT;
						if (answer.outcome === "refused") {
							throw new Error(
								"the subject's lease was not held: the recovery-set floor was not raised",
							);
						}
						// A floor the store answers below the raise is outside its port.
						if (answer.floor < setGeneration) throw OUTSIDE_CONTRACT;
					}),
			},
			read: (call) =>
				read(() => within(call, storeTimeoutMs, "a transaction-store read under the lease")),
			run: async (call, refused) => {
				try {
					time.beforeWrite();
				} catch {
					return refused(new Error(LEASE_SPENT));
				}
				try {
					return await within(call, storeTimeoutMs, "a transaction-store write under the lease");
				} catch (cause) {
					if (cause instanceof NotAnswered) return refused(cause);
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
			if ("cause" in started) return leaseOutage("subjectGeneration", started.cause);
			return { generation: started.generation } as unknown as MfaFactorSetCarried;
		},

		resume(subject, carried) {
			const start = Object.freeze({}) as MfaFactorSetStart;
			const generation =
				typeof carried === "object" && carried !== null && !Array.isArray(carried)
					? readMfaSubjectCount((carried as { readonly generation?: unknown }).generation)
					: undefined;
			// One that is not what `carry` answered is left unknown: the write answers it `changed`.
			if (generation !== undefined) starts.set(start, { subject, generation });
			return start;
		},

		list,

		recoverySetFloor: floorOf,

		readSubject: (subject) =>
			readSubjectRecords({ factors, sealing }, subject, {
				list,
				recoverySetFloor: floorOf,
				floorUnread: (unread, cause) =>
					logger.warn({ sub: unread, err: loggableError(cause) }, "mfa_recovery_set_floor_unread"),
			}),

		async markEnrolled(start, subject) {
			if (!witness.writable) return witness.mark(subject);
			const held = await underLease(start, subject, async (time): Promise<MfaWitnessMark> => {
				let records: MfaFactorRecord[];
				try {
					records = await time.read(() => list(subject));
				} catch (cause) {
					if (cause instanceof OutOfTime) throw cause;
					return { outcome: "unwritten", cause };
				}
				if (noneCounts(records)) return { outcome: "in_step" };
				time.beforeWrite();
				const marked = await witness.mark(subject);
				if (marked.outcome !== "marked") return marked;
				// A write outside the lease — one that outran its own — may have removed the last one since.
				let after: MfaFactorRecord[];
				try {
					after = await time.read(() => list(subject));
				} catch (cause) {
					if (cause instanceof OutOfTime) throw cause;
					// Marked, and whether a write outside the lease left none since cannot be told.
					return {
						outcome: "unwritten",
						cause: new Error("the records could not be read again after the witness mark", {
							cause,
						}),
					};
				}
				if (!noneCounts(after)) return marked;
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

		async remove<Refusal>(
			start: MfaFactorSetStart,
			subject: string,
			factorId: unknown,
			refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined,
		): Promise<MfaFactorRemoval<Refusal>> {
			let removedRecord: MfaFactorRecord | undefined;
			const held = await underLease(
				start,
				subject,
				async (time): Promise<MfaFactorRemoval<Refusal>> => {
					let records: MfaFactorRecord[];
					try {
						records = await time.read(() => list(subject));
					} catch (cause) {
						if (cause instanceof OutOfTime) throw cause;
						return { outcome: "unavailable", store: "mfa_factor", step: "list", cause };
					}
					const record =
						typeof factorId === "string" ? records.find((one) => one.id === factorId) : undefined;
					if (record === undefined) return { outcome: "unknown_factor" };
					const refusal = refuse(record, records);
					if (refusal !== undefined) return { outcome: "refused", refusal: refusal as Refusal };
					const others = (all: readonly MfaFactorRecord[]) =>
						all.filter((one) => one.id !== record.id);
					time.beforeWrite();
					removedRecord = record;
					try {
						await factorStore.remove(subject, record.id);
					} catch (cause) {
						// A store may fail after its write: the record gone is a removal.
						let after: MfaFactorRecord[];
						try {
							after = await time.read(() => list(subject));
						} catch (unread) {
							// Whether it stands cannot be told; out of time, it is also an overrun.
							return {
								outcome: "unavailable",
								store: "mfa_factor",
								step: "remove",
								cause,
								...(unread instanceof OutOfTime ? { overran: true as const } : {}),
							};
						}
						if (after.some((one) => one.id === record.id)) {
							return { outcome: "unavailable", store: "mfa_factor", step: "remove", cause };
						}
					}
					let remaining = others(records);
					let unread: unknown;
					let readAgain = false;
					try {
						remaining = others(await time.read(() => list(subject)));
						readAgain = true;
					} catch (cause) {
						if (cause instanceof OutOfTime) throw cause;
						unread = cause;
					}
					let cleared: MfaWitnessMark | undefined;
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
				},
			);
			if (held.outcome === "ran_out") {
				// Out of time after the removal was written: it stands, the witness not cleared.
				return removedRecord === undefined
					? { outcome: "busy", retryAfterSeconds: 1 }
					: { outcome: "removed", record: removedRecord, overran: true };
			}
			if (held.outcome !== "held") return held;
			return held.overran ? { ...held.done, overran: true } : held.done;
		},

		async bind(start, subject, write) {
			const held = await underLease(start, subject, (time, token) =>
				write(writesUnder(time, token)),
			);
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
			if (held.outcome !== "held") return held;
			return held.overran
				? { outcome: "bound", done: held.done, overran: true }
				: { outcome: "bound", done: held.done };
		},

		async recover(subject, recovery) {
			const held = await subjectLease.underLease(
				subject,
				"current",
				async (time, token): Promise<MfaFactorSetRecovered> => {
					let records: MfaFactorRecord[];
					try {
						records = await time.read(() => list(subject));
					} catch (cause) {
						if (cause instanceof OutOfTime) throw cause;
						return { outcome: "unavailable", store: "mfa_factor", step: "list", cause };
					}
					const guessableBoundSinceMs = recovery.guessableBoundSince(records);
					time.beforeWrite();
					let answer: unknown;
					try {
						answer = await within(
							() =>
								leases.applySubjectRecovery(subject, {
									operation: "recover",
									sid: recovery.sid,
									nowMs: recovery.nowMs,
									leaseToken: token,
									sessionsBoundaryMs: recovery.sessionsBoundaryMs,
									guessableBoundSinceMs,
								}),
							storeTimeoutMs,
							"applySubjectRecovery",
						);
					} catch (cause) {
						return leaseOutage("applySubjectRecovery", cause);
					}
					const read = readMfaSubjectRecoveryAnswer(answer);
					return read === undefined
						? leaseOutage("applySubjectRecovery", OUTSIDE_CONTRACT)
						: { outcome: "answered", answer: read };
				},
			);
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
export type MfaFactorSetResetOutcome =
	| {
			readonly outcome: "reset";
			/** The subject's generation the reset moved it to. */
			readonly generation: number;
			/** The records the removal removed, as read under the lease just before; `undefined` when they could not be read. */
			readonly removed: readonly MfaFactorRecord[] | undefined;
			/** The witness's clear, written last. */
			readonly witness: MfaWitnessMark;
			/** The lease ended before the reset released it: another writer may have run beside it. */
			readonly overran?: true;
	  }
	| {
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
export function createMfaFactorSetReset(options: {
	readonly factorStore: MfaFactorStore;
	readonly witness: MfaEnrollmentWitness;
	/** A lease owner ({@link createMfaSubjectLeases}) of the rules every writer holds. */
	readonly leases: MfaSubjectLeases;
}): { reset(subject: string, steps: MfaFactorSetResetSteps): Promise<MfaFactorSetResetOutcome> } {
	const { factorStore, witness } = options;
	const subjectLease = ownerOf(options.leases);
	const { storeTimeoutMs, ttlMs, leases, monotonicNow } = subjectLease;

	const stopped = (
		at: MfaFactorSetResetStop,
		cause: unknown,
		after: {
			readonly generation?: number | undefined;
			readonly removed?: readonly MfaFactorRecord[] | undefined;
			readonly removedDone?: boolean;
			readonly overran?: boolean;
		} = {},
	): MfaFactorSetResetOutcome => ({
		outcome: "stopped",
		at,
		cause,
		...(after.generation === undefined ? {} : { generation: after.generation }),
		...(after.removedDone === true ? { removed: after.removed } : {}),
		...(after.overran === true ? { overran: true as const } : {}),
	});

	return {
		async reset(subject, steps) {
			/** How far the writes under the lease got: where an overrun or a refusal stops it. */
			const progress: {
				stage: MfaFactorSetResetStop;
				generation?: number;
				snapshot?: readonly MfaFactorRecord[] | undefined;
				removedDone?: boolean;
			} = { stage: "email_proof" };
			const held = await subjectLease.underLease(
				subject,
				"current",
				async (time, token): Promise<MfaFactorSetResetOutcome> => {
					try {
						const listed: unknown = await time.read(() => factorStore.list(subject));
						// As listed: a deployment's malformed record must not cost the report.
						progress.snapshot = Array.isArray(listed)
							? [...(listed as MfaFactorRecord[])]
							: undefined;
					} catch (cause) {
						if (cause instanceof OutOfTime) throw cause;
						progress.snapshot = undefined;
					}
					if (steps.requireEmailProof !== undefined) {
						time.beforeWrite();
						try {
							await within(
								steps.requireEmailProof,
								storeTimeoutMs,
								"requireEmailProofAtNextBinding",
							);
						} catch (cause) {
							return stopped("email_proof", cause);
						}
					}
					progress.stage = "lock";
					time.beforeWrite();
					try {
						await within(steps.authorize, storeTimeoutMs, "authorizeSubjectRecovery");
					} catch (cause) {
						return stopped("lock", cause);
					}
					time.beforeWrite();
					let answer: ReturnType<typeof readMfaSubjectRecoveryAnswer>;
					try {
						answer = readMfaSubjectRecoveryAnswer(
							await within(
								() =>
									leases.applySubjectRecovery(subject, {
										operation: "reset",
										sid: undefined,
										nowMs: steps.nowMs,
										leaseToken: token,
										sessionsBoundaryMs: undefined,
										guessableBoundSinceMs: undefined,
									}),
								storeTimeoutMs,
								"applySubjectRecovery",
							),
						);
					} catch (cause) {
						return stopped("lock", cause);
					}
					if (answer === undefined) return stopped("lock", OUTSIDE_CONTRACT);
					if (answer.outcome !== "applied") {
						return stopped(
							"lock",
							new Error(
								answer.outcome === "refused"
									? `the store refused the reset: ${answer.reason}`
									: "the store answered the reset's authorization applied before: it applied nothing",
							),
						);
					}
					progress.generation = answer.generation;
					progress.stage = "factors";
					time.beforeWrite();
					try {
						await factorStore.removeAllForSubject(subject);
					} catch (cause) {
						return stopped("factors", cause, { generation: answer.generation });
					}
					// A store that answered the removal and left records stops it before the witness.
					try {
						const left: unknown = await time.read(() => factorStore.list(subject));
						if (!Array.isArray(left) || left.length > 0) {
							return stopped(
								"factors",
								new Error("records still stand after the removal, or the list is no list"),
								{ generation: answer.generation },
							);
						}
					} catch (cause) {
						if (cause instanceof OutOfTime) throw cause;
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
							await within(
								steps.requireEmailProof,
								storeTimeoutMs,
								"requireEmailProofAtNextBinding",
							);
						} catch (cause) {
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
				},
				{ until: monotonicNow() + RESET_WAIT_LEASES * ttlMs },
			);
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
					return stopped(
						"lease",
						new Error(
							"the subject's lease could not be held long enough for the reset: run it again",
						),
						{ overran: held.overran === true },
					);
				default:
					return stopped("lease", held.cause);
			}
		},
	};
}
