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
 * The in-process {@link MfaFactorStore}, for development and a single replica.
 * Records fork per replica and vanish on restart, after which every subject
 * reads as having nothing enrolled; the enrollment witness catches that loss.
 *
 * Each operation is one synchronous `Map` step, so atomic: no `await` falls
 * between a check and its write. Records are copied in and out: changing a
 * returned or written record changes nothing kept here.
 *
 * A subject's set is an entry holding its records and its store generation,
 * a random UUID made fresh at every membership write. The entry is made by
 * the first membership write and never deleted: removing the last record,
 * or a reset, leaves it empty at a new generation. Every entry holds a
 * generation from the write that made it, so no set here is ever without
 * one and `listVersioned` has nothing to mint. One process is one instance,
 * so a second instance on the same backend is this one.
 */

import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	newStoreGeneration,
	type StoreGeneration,
	type VersionedSet,
} from "./conditionalWriteStandIn.mjs";
import type { MfaFactorRecord, MfaFactorRecordUpdate, MfaFactorStore } from "./factorStore.mjs";
import { checkMfaVersionAdvances } from "./version.mjs";

/** The record as plain data, every field named, its dates copied. */
const copyOf = (record: MfaFactorRecord): MfaFactorRecord => ({
	id: record.id,
	subject: record.subject,
	kind: record.kind,
	label: record.label,
	binding: record.binding,
	createdAt: new Date(record.createdAt.getTime()),
	lastUsedAt: record.lastUsedAt === undefined ? undefined : new Date(record.lastUsedAt.getTime()),
	version: record.version,
	data: record.data,
});

/** A subject's set: its records by id, and the generation its last membership write issued. */
interface FactorSet {
	readonly records: Map<string, MfaFactorRecord>;
	generation: StoreGeneration;
}

export function createMemoryMfaFactorStore(): MfaFactorStore {
	const bySubject = new Map<string, FactorSet>();

	/** `subject`'s set at a new generation, made when the subject has none: every membership write's last step. */
	const moved = (subject: string): FactorSet => {
		const set = bySubject.get(subject);
		if (set !== undefined) {
			set.generation = newStoreGeneration();
			return set;
		}
		const made: FactorSet = { records: new Map(), generation: newStoreGeneration() };
		bySubject.set(subject, made);
		return made;
	};

	return {
		kind: "memory",

		async list(subject: string): Promise<readonly MfaFactorRecord[]> {
			return [...(bySubject.get(subject)?.records.values() ?? [])].map(copyOf);
		},

		async listVersioned(subject: string): Promise<VersionedSet<MfaFactorRecord>> {
			const set = bySubject.get(subject);
			return set === undefined
				? { generation: null, items: [] }
				: { generation: set.generation, items: [...set.records.values()].map(copyOf) };
		},

		async createIf(
			record: MfaFactorRecord,
			expected: StoreGeneration | null,
		): Promise<ConditionalCreateAnswer> {
			const set = bySubject.get(record.subject);
			const atExpected = expected === null ? set === undefined : set?.generation === expected;
			if (!atExpected || set?.records.has(record.id) === true) return { outcome: "conflict" };
			const written = moved(record.subject);
			written.records.set(record.id, copyOf(record));
			return { outcome: "created", generation: written.generation };
		},

		async removeIf(
			subject: string,
			id: string,
			expected: StoreGeneration,
		): Promise<ConditionalSetRemoveAnswer> {
			const set = bySubject.get(subject);
			if (set === undefined) return { outcome: "missing" };
			if (set.generation !== expected) return { outcome: "conflict" };
			if (!set.records.delete(id)) return { outcome: "missing" };
			return { outcome: "removed", generation: moved(subject).generation };
		},

		async create(record: MfaFactorRecord): Promise<void> {
			if (bySubject.get(record.subject)?.records.has(record.id) === true) {
				throw new Error("an MFA factor record with this id already exists for the subject");
			}
			moved(record.subject).records.set(record.id, copyOf(record));
		},

		async update(
			subject: string,
			id: string,
			expectedVersion: number,
			next: MfaFactorRecordUpdate,
		): Promise<MfaFactorRecord | null> {
			checkMfaVersionAdvances(expectedVersion, "MfaFactorStore.update");
			const records = bySubject.get(subject)?.records;
			const current = records?.get(id);
			if (records === undefined || current === undefined || current.version !== expectedVersion) {
				return null;
			}
			const written = copyOf({
				...current,
				data: next.data,
				label: next.label,
				lastUsedAt: next.lastUsedAt,
				version: current.version + 1,
			});
			records.set(id, written);
			return copyOf(written);
		},

		async remove(subject: string, id: string): Promise<void> {
			if (bySubject.get(subject)?.records.delete(id) === true) moved(subject);
		},

		async removeAllForSubject(subject: string): Promise<void> {
			moved(subject).records.clear();
		},
	};
}
