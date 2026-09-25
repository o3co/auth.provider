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
 * The in-process {@link MfaFactorStore}: development and a single replica.
 * Its records fork per replica and are gone at the next restart, after which
 * every subject reads as one with nothing enrolled — the loss the enrollment
 * witness (the MFA ADR's D12) is there to catch.
 *
 * Every operation is one synchronous step on a `Map`, so each is atomic. What
 * it stores and what it hands out are copies: a caller changing a returned
 * record, or one it wrote, changes nothing kept here.
 */

import type { MfaFactorRecord, MfaFactorRecordUpdate, MfaFactorStore } from "./factorStore.mjs";

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

export function createMemoryMfaFactorStore(): MfaFactorStore {
	const bySubject = new Map<string, Map<string, MfaFactorRecord>>();

	return {
		kind: "memory",

		async list(subject: string): Promise<readonly MfaFactorRecord[]> {
			return [...(bySubject.get(subject)?.values() ?? [])].map(copyOf);
		},

		async create(record: MfaFactorRecord): Promise<void> {
			const records = bySubject.get(record.subject) ?? new Map<string, MfaFactorRecord>();
			if (records.has(record.id)) {
				throw new Error("an MFA factor record with this id already exists for the subject");
			}
			records.set(record.id, copyOf(record));
			bySubject.set(record.subject, records);
		},

		async update(
			subject: string,
			id: string,
			expectedVersion: number,
			next: MfaFactorRecordUpdate,
		): Promise<MfaFactorRecord | null> {
			const records = bySubject.get(subject);
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
			const records = bySubject.get(subject);
			if (records === undefined) return;
			records.delete(id);
			if (records.size === 0) bySubject.delete(subject);
		},

		async removeAllForSubject(subject: string): Promise<void> {
			bySubject.delete(subject);
		},
	};
}
