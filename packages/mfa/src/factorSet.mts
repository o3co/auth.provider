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
 * read, oldest first, and the two writes after which the witness is brought
 * in step with them. The one place the subject's lease and generation are
 * used: callers hold an opaque start and read an answer, never the lease.
 *
 * - A write's start (`begin`) reads the subject's generation before the
 *   request that writes is admitted, or before a verification's proof is
 *   checked; ceremonies that write later carry theirs from their begin.
 * - The write acquires the subject's lease at that generation — waiting a
 *   bounded while for another holder, then `busy` with the holder's whole
 *   seconds left; `changed` when the generation moved since the start, a
 *   recovery or a reset in between — runs whole under it, and releases it.
 * - The lease stands six of `mfa.storeTimeoutMs`, one more than the most
 *   Store calls a write makes; a timeout whose six pass core's longest lease
 *   is refused (`checkFactorSetStoreTimeout`). From the acquire, a local
 *   monotonic deadline: a read under the lease is given up when it would
 *   leave less than one Store timeout, and so is a write that would start
 *   with less — before the first write, `busy` with nothing written; after
 *   it, an overrun.
 * - A transaction-store call (generation, acquire, release) not answered
 *   within one Store timeout is an outage; a write to the factor store or the
 *   directory is never abandoned once started.
 * - A release the store answers `false`, or cannot take, is an overrun: the
 *   lease ended, or another holder moved the generation, while the write ran.
 *   Every answer of a write that overran says so.
 * - `markEnrolled`, a verification's reconciliation: the records read first;
 *   none that may count, or none readable, writes nothing (`in_step`, or
 *   `unwritten`); else the witness marked, the records read again, and the
 *   witness cleared when a write outside the lease left none — a clear that
 *   fails is `unwritten`. One that cannot hold the lease, or overran it, is
 *   `unwritten`; a directory that cannot write the witness takes no lease.
 * - `remove`: the records read, the caller's refusal asked, the record
 *   removed — a store that fails after its write is read again, and a record
 *   gone is a removal — then the records read again (or, unreadable, those
 *   read before less the removed one) and, when none may count
 *   (`mayCount`), the witness cleared.
 *
 * The lease is logical: it cannot fence a write the factor store or the
 * directory applies after the deadline check. Never throws for a store's
 * failure: `list` alone throws, for its caller to answer.
 */

import {
	MFA_SUBJECT_LEASE_MAX_MS,
	MFA_SUBJECT_LEASE_MIN_MS,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	type MfaTransactionStore,
	readMfaSubjectCount,
	readMfaSubjectLeaseAnswer,
} from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
import { mayCount } from "./firstBinding.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";

/** The pauses, in milliseconds, between tries for a lease another write holds: then `busy`. */
const LEASE_WAITS_MS = [25, 50, 100, 200, 400] as const;

/** The most Store calls one write makes: a removal's read, removal, read after a failed removal, read again and clear (a mark makes four). */
const STORE_CALLS_PER_WRITE = 5;

/** The lease a write takes when one Store call may take `storeTimeoutMs`: one more than the most a write makes, at least core's shortest. */
const leaseMsFor = (storeTimeoutMs: number): number =>
	Math.max((STORE_CALLS_PER_WRITE + 1) * storeTimeoutMs, MFA_SUBJECT_LEASE_MIN_MS);

/**
 * `storeTimeoutMs`, `mfa.storeTimeoutMs`, when the lease it makes fits core's
 * longest; else a `RangeError` naming the key: a write could outlive its
 * lease, and one write at a time would not hold.
 */
export function checkFactorSetStoreTimeout(storeTimeoutMs: number): number {
	const leaseMs = (STORE_CALLS_PER_WRITE + 1) * storeTimeoutMs;
	if (leaseMs > MFA_SUBJECT_LEASE_MAX_MS) {
		throw new RangeError(
			`mfa.storeTimeoutMs: ${storeTimeoutMs} ms makes a factor-set write's lease ${leaseMs} ms (${STORE_CALLS_PER_WRITE + 1} Store calls' time), past the longest subject lease, ${MFA_SUBJECT_LEASE_MAX_MS} ms: a write could outlive its lease. Set it to at most ${Math.floor(MFA_SUBJECT_LEASE_MAX_MS / (STORE_CALLS_PER_WRITE + 1))} ms`,
		);
	}
	return storeTimeoutMs;
}

/** The subject's records, oldest first: the order a page lists them and a request names them. */
const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/** Where a write began: opaque to its holder, read by this file alone. */
export interface MfaFactorSetStart {
	readonly __mfaFactorSetStart: never;
}

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

export interface MfaFactorSet {
	/** Where a write of `subject`'s begins: read before the request is admitted, or before a proof is checked. Never throws. */
	begin(subject: string): Promise<MfaFactorSetStart>;
	/** The subject's records, oldest first; throws for a store that cannot answer, or answers anything but a list of records. */
	list(subject: string): Promise<MfaFactorRecord[]>;
	/**
	 * The witness marked under the subject's lease when the records read first
	 * hold one that may count; a directory that cannot write it takes no lease,
	 * and needs no start.
	 */
	markEnrolled(start: MfaFactorSetStart | undefined, subject: string): Promise<MfaWitnessMark>;
	/** Under the subject's lease, the record `factorId` names removed, unless `refuse` answers a refusal over it and the records read. */
	remove<Refusal>(
		start: MfaFactorSetStart | undefined,
		subject: string,
		factorId: unknown,
		refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined,
	): Promise<MfaFactorRemoval<Refusal>>;
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

/** The factor set over `options` (see this file's header). */
export function createMfaFactorSet(options: {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly witness: MfaEnrollmentWitness;
	/** Where the subject's generation and lease are kept. */
	readonly leases: Pick<
		MfaTransactionStore,
		"subjectGeneration" | "acquireSubjectLease" | "releaseSubjectLease"
	>;
	/** `mfa.storeTimeoutMs`, held to {@link checkFactorSetStoreTimeout}. */
	readonly storeTimeoutMs: number;
	/** A monotonic clock, in milliseconds. Defaults to `performance.now`. */
	readonly monotonicNow?: () => number;
}): MfaFactorSet {
	const { factors, factorStore, witness, leases } = options;
	const storeTimeoutMs = checkFactorSetStoreTimeout(options.storeTimeoutMs);
	const ttlMs = leaseMsFor(storeTimeoutMs);
	const monotonicNow = options.monotonicNow ?? (() => performance.now());
	const starts = new WeakMap<MfaFactorSetStart, Started>();

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

	const leaseOutage = (step: string, cause: unknown): MfaFactorSetRefusal => ({
		outcome: "unavailable",
		store: "mfa_transaction",
		step,
		cause,
	});

	const begin = async (subject: string): Promise<MfaFactorSetStart> => {
		const start = Object.freeze({}) as MfaFactorSetStart;
		let started: Started;
		try {
			const generation = readMfaSubjectCount(
				await within(() => leases.subjectGeneration(subject), storeTimeoutMs, "subjectGeneration"),
			);
			started =
				generation === undefined ? { subject, cause: OUTSIDE_CONTRACT } : { subject, generation };
		} catch (cause) {
			started = { subject, cause };
		}
		starts.set(start, started);
		return start;
	};

	/**
	 * `write` run under the subject's lease, acquired at `start`'s generation;
	 * `overran` when the release did not find the lease held, or the write
	 * ran out of the time it had after it wrote.
	 */
	const underLease = async <T,>(
		start: MfaFactorSetStart | undefined,
		subject: string,
		write: (time: LeaseTime) => Promise<T>,
	): Promise<
		{ readonly outcome: "held"; readonly done: T; readonly overran: boolean } | MfaFactorSetRefusal
	> => {
		const started = start === undefined ? undefined : starts.get(start);
		// A start for another subject, or none, began nowhere this write can tell.
		if (started === undefined || started.subject !== subject) return { outcome: "changed" };
		if ("cause" in started) return leaseOutage("subjectGeneration", started.cause);
		let token: string | undefined;
		let acquiredFrom = 0;
		for (let tries = 0; token === undefined; tries++) {
			const asked = monotonicNow();
			let answer: ReturnType<typeof readMfaSubjectLeaseAnswer>;
			try {
				answer = readMfaSubjectLeaseAnswer(
					await within(
						() => leases.acquireSubjectLease(subject, { ttlMs, generation: started.generation }),
						storeTimeoutMs,
						"acquireSubjectLease",
					),
				);
			} catch (cause) {
				return leaseOutage("acquireSubjectLease", cause);
			}
			if (answer === undefined) return leaseOutage("acquireSubjectLease", OUTSIDE_CONTRACT);
			if (answer.outcome === "stale") return { outcome: "changed" };
			if (answer.outcome === "acquired") {
				token = answer.token;
				acquiredFrom = asked;
			} else {
				const pause = LEASE_WAITS_MS[tries];
				if (pause === undefined) {
					return { outcome: "busy", retryAfterSeconds: Math.ceil(answer.retryAfterMs / 1000) };
				}
				await new Promise((resolve) => setTimeout(resolve, pause));
			}
		}
		const deadline = acquiredFrom + ttlMs;
		const left = () => deadline - monotonicNow() - storeTimeoutMs;
		let wrote = false;
		const time: LeaseTime = {
			read: async (call) => {
				const budget = left();
				if (budget <= 0) throw new OutOfTime();
				try {
					return await within(call, budget, "a read under the lease");
				} catch (cause) {
					if (cause instanceof NotAnswered) throw new OutOfTime();
					throw cause;
				}
			},
			beforeWrite: () => {
				if (left() < 0) throw new OutOfTime();
				wrote = true;
			},
		};
		const release = async (): Promise<boolean> => {
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
		let done: T;
		try {
			done = await write(time);
		} catch (cause) {
			await release();
			if (!(cause instanceof OutOfTime)) throw cause;
			// Out of time before any write: nothing was written. After one: an overrun.
			return wrote
				? { outcome: "held", done: undefined as T, overran: true }
				: { outcome: "busy", retryAfterSeconds: 1 };
		}
		return { outcome: "held", done, overran: !(await release()) };
	};

	/** What a mark is answered when it could not run, or ran, outside a lease it held. */
	const unwritten = (why: string): MfaWitnessMark => ({
		outcome: "unwritten",
		cause: new Error(`the witness mark ${why}`),
	});

	return {
		begin,

		list,

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
					return marked;
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
				default:
					return held.overran ? unwritten("outran the subject's lease") : held.done;
			}
		},

		async remove<Refusal>(
			start: MfaFactorSetStart | undefined,
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
						} catch {
							return { outcome: "unavailable", store: "mfa_factor", step: "remove", cause };
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
			if (held.outcome !== "held") return held;
			if (held.done === undefined) {
				// Out of time after the removal was written: it stands, the witness not cleared.
				return removedRecord === undefined
					? { outcome: "busy", retryAfterSeconds: 1 }
					: { outcome: "removed", record: removedRecord, overran: true };
			}
			return held.overran ? { ...held.done, overran: true } : held.done;
		},
	};
}
