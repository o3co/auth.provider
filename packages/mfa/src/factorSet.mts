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
 * in step with them. Each write runs whole in one function, so one
 * per-subject guard can wrap it.
 *
 * - `markEnrolled`, a verification's reconciliation: the witness marked, then
 *   the records read again — a removal that cleared the witness while the
 *   mark was in flight leaves none that may count, and the witness is
 *   cleared again.
 * - `remove`: the records read, the caller's refusal asked, the record
 *   removed — a store that fails after its write is read again, and a record
 *   gone is a removal — then the records read again (or, unreadable, those
 *   read before less the removed one) and, when none may count
 *   (`mayCount`), the witness cleared.
 *
 * Never throws for a store's failure: `list` alone does, for its caller to
 * answer as an outage.
 */

import type { MfaFactorRecord, MfaFactorResolver, MfaFactorStore } from "@o3co/auth-provider-core";
import { mayCount } from "./firstBinding.mjs";
import type { MfaEnrollmentWitness, MfaWitnessMark } from "./witness.mjs";

/** The subject's records, oldest first: the order a page lists them and a request names them. */
const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/** What a removal came to. */
export type MfaFactorRemoval<Refusal> =
	| { readonly outcome: "unknown_factor" }
	| { readonly outcome: "refused"; readonly refusal: Refusal }
	| { readonly outcome: "unavailable"; readonly step: "list" | "remove"; readonly cause: unknown }
	| {
			readonly outcome: "removed";
			readonly record: MfaFactorRecord;
			/** Why the records could not be read again; those read before, less the removed one, decided. */
			readonly unread?: unknown;
			/** The witness's clear, when none that may count was left. */
			readonly witness?: MfaWitnessMark;
	  };

export interface MfaFactorSet {
	/** The subject's records, oldest first; throws for a store that cannot answer, or answers anything but a list of records. */
	list(subject: string): Promise<MfaFactorRecord[]>;
	/** The witness marked, then cleared again when the records read after it hold none that may count; answers the mark. */
	markEnrolled(subject: string): Promise<MfaWitnessMark>;
	/** The record `factorId` names removed, unless `refuse` answers a refusal over it and the records read. */
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
}): MfaFactorSet {
	const { factors, factorStore, witness } = options;

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

	return {
		list,

		async markEnrolled(subject) {
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
		},

		async remove(subject, factorId, refuse) {
			let records: MfaFactorRecord[];
			try {
				records = await list(subject);
			} catch (cause) {
				return { outcome: "unavailable", step: "list", cause };
			}
			const record =
				typeof factorId === "string" ? records.find((one) => one.id === factorId) : undefined;
			if (record === undefined) return { outcome: "unknown_factor" };
			const refusal = refuse(record, records);
			if (refusal !== undefined) return { outcome: "refused", refusal };
			const others = (all: readonly MfaFactorRecord[]) => all.filter((one) => one.id !== record.id);
			try {
				await factorStore.remove(subject, record.id);
			} catch (cause) {
				// A store may fail after its write: the record gone is a removal.
				let after: MfaFactorRecord[];
				try {
					after = await list(subject);
				} catch {
					return { outcome: "unavailable", step: "remove", cause };
				}
				if (after.some((one) => one.id === record.id)) {
					return { outcome: "unavailable", step: "remove", cause };
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
		},
	};
}
