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
 * used: callers read an answer, never the lease.
 *
 * Each write reads the subject's generation, acquires the subject's lease
 * at it — waiting a bounded while for another holder, then `busy`; `stale`
 * when the generation moved since it was read, a recovery or a reset in
 * between — runs whole under it, and releases it. A release the store
 * answers `false`, or cannot take, is an overrun: the lease ended, or
 * another holder moved the generation, while the write ran. The write reads
 * the records it acts on under the lease, so nothing it relies on predates
 * the generation it holds.
 *
 * - `markEnrolled`, a verification's reconciliation: the witness marked, then
 *   the records read again — when none may count, the witness is cleared
 *   again. A mark that cannot hold the lease, or overran it, is answered
 *   `unwritten`, never `marked`; a directory that cannot write the witness
 *   takes no lease.
 * - `remove`: the records read, the caller's refusal asked, the record
 *   removed — a store that fails after its write is read again, and a record
 *   gone is a removal — then the records read again (or, unreadable, those
 *   read before less the removed one) and, when none may count
 *   (`mayCount`), the witness cleared.
 *
 * Never throws for a store's failure — an outage is answered as one, a
 * lease never assumed: `list` alone throws, for its caller to answer.
 */

import {
	DEFAULT_MFA_SUBJECT_LEASE_MS,
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

/** The subject's records, oldest first: the order a page lists them and a request names them. */
const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/** A write that could not run under the subject's lease. */
export type MfaFactorSetRefusal =
	/** Another write held the lease past the wait: try again. */
	| { readonly outcome: "busy" }
	/** The generation moved since the write began — a recovery or a reset: read again. */
	| { readonly outcome: "changed" }
	| {
			readonly outcome: "unavailable";
			readonly store: "mfa_factor" | "mfa_transaction";
			readonly step: string;
			readonly cause: unknown;
	  };

/** What a removal came to. */
export type MfaFactorRemoval<Refusal> =
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
			/** The lease ended, or another holder moved the generation, before the release. */
			readonly overran?: true;
	  };

export interface MfaFactorSet {
	/** The subject's records, oldest first; throws for a store that cannot answer, or answers anything but a list of records. */
	list(subject: string): Promise<MfaFactorRecord[]>;
	/** The witness marked under the subject's lease, then cleared again when the records read after it hold none that may count; answers the mark. */
	markEnrolled(subject: string): Promise<MfaWitnessMark>;
	/** Under the subject's lease, the record `factorId` names removed, unless `refuse` answers a refusal over it and the records read. */
	remove<Refusal>(
		subject: string,
		factorId: unknown,
		refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined,
	): Promise<MfaFactorRemoval<Refusal>>;
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
	/** How long a write's lease stands; `DEFAULT_MFA_SUBJECT_LEASE_MS` unless given. */
	readonly leaseMs?: number;
}): MfaFactorSet {
	const { factors, factorStore, witness, leases } = options;
	const ttlMs = options.leaseMs ?? DEFAULT_MFA_SUBJECT_LEASE_MS;

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

	/**
	 * `write` run under the subject's lease, acquired at the generation read
	 * first; `overran` when the release did not find the lease held.
	 */
	const underLease = async <T,>(
		subject: string,
		write: () => Promise<T>,
	): Promise<
		{ readonly outcome: "held"; readonly done: T; readonly overran: boolean } | MfaFactorSetRefusal
	> => {
		let generation: number | undefined;
		try {
			generation = readMfaSubjectCount(await leases.subjectGeneration(subject));
		} catch (cause) {
			return leaseOutage("subjectGeneration", cause);
		}
		if (generation === undefined) return leaseOutage("subjectGeneration", OUTSIDE_CONTRACT);
		let token: string | undefined;
		for (let tries = 0; token === undefined; tries++) {
			let answer: ReturnType<typeof readMfaSubjectLeaseAnswer>;
			try {
				answer = readMfaSubjectLeaseAnswer(
					await leases.acquireSubjectLease(subject, { ttlMs, generation }),
				);
			} catch (cause) {
				return leaseOutage("acquireSubjectLease", cause);
			}
			if (answer === undefined) return leaseOutage("acquireSubjectLease", OUTSIDE_CONTRACT);
			if (answer.outcome === "stale") return { outcome: "changed" };
			if (answer.outcome === "acquired") {
				token = answer.token;
			} else {
				const pause = LEASE_WAITS_MS[tries];
				if (pause === undefined) return { outcome: "busy" };
				await new Promise((resolve) => setTimeout(resolve, pause));
			}
		}
		let done: T;
		try {
			done = await write();
		} catch (cause) {
			await leases.releaseSubjectLease(subject, token).catch(() => false);
			throw cause;
		}
		let held: boolean;
		try {
			held = (await leases.releaseSubjectLease(subject, token)) === true;
		} catch {
			held = false;
		}
		return { outcome: "held", done, overran: !held };
	};

	/** What a mark is answered when it could not run, or ran, outside a lease it held. */
	const unwritten = (why: string): MfaWitnessMark => ({
		outcome: "unwritten",
		cause: new Error(`the witness mark ${why}`),
	});

	return {
		list,

		async markEnrolled(subject) {
			if (!witness.writable) return witness.mark(subject);
			const held = await underLease(subject, async () => {
				const marked = await witness.mark(subject);
				if (marked.outcome !== "marked") return marked;
				let records: MfaFactorRecord[];
				try {
					records = await list(subject);
				} catch {
					return marked;
				}
				if (noneCounts(records)) await witness.clear(subject);
				return marked;
			});
			switch (held.outcome) {
				case "busy":
					return unwritten("found the subject's lease held");
				case "changed":
					return unwritten("found the subject's generation moved");
				case "unavailable":
					return { outcome: "unwritten", cause: held.cause };
				default:
					return held.overran ? unwritten("outran the subject's lease") : held.done;
			}
		},

		async remove<Refusal>(
			subject: string,
			factorId: unknown,
			refuse: (record: MfaFactorRecord, records: readonly MfaFactorRecord[]) => Refusal | undefined,
		): Promise<MfaFactorRemoval<Refusal>> {
			const held = await underLease(subject, async (): Promise<MfaFactorRemoval<Refusal>> => {
				let records: MfaFactorRecord[];
				try {
					records = await list(subject);
				} catch (cause) {
					return { outcome: "unavailable", store: "mfa_factor", step: "list", cause };
				}
				const record =
					typeof factorId === "string" ? records.find((one) => one.id === factorId) : undefined;
				if (record === undefined) return { outcome: "unknown_factor" };
				const refusal = refuse(record, records);
				if (refusal !== undefined) return { outcome: "refused", refusal: refusal as Refusal };
				const others = (all: readonly MfaFactorRecord[]) =>
					all.filter((one) => one.id !== record.id);
				try {
					await factorStore.remove(subject, record.id);
				} catch (cause) {
					// A store may fail after its write: the record gone is a removal.
					let after: MfaFactorRecord[];
					try {
						after = await list(subject);
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
					remaining = others(await list(subject));
					readAgain = true;
				} catch (cause) {
					unread = cause;
				}
				const cleared = noneCounts(remaining) ? await witness.clear(subject) : undefined;
				return {
					outcome: "removed",
					record,
					...(readAgain ? {} : { unread }),
					...(cleared === undefined ? {} : { witness: cleared }),
				};
			});
			if (held.outcome !== "held") return held;
			const removal = held.done;
			return held.overran && removal.outcome === "removed"
				? { ...removal, overran: true }
				: removal;
		},
	};
}
