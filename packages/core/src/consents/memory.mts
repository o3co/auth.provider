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

import type { ConsentRecord, ConsentStore } from "./types.mjs";

/** In-process consent store, with the record count exposed for observability. */
export interface MemoryConsentStore extends ConsentStore {
	/** Records currently resident, expired-but-unswept included. */
	readonly size: number;
}

/**
 * In-process Map-backed {@link ConsentStore} (#527).
 *
 * Bounded by population: one record per (`sub`, `clientId`), so it grows with
 * users × clients and never with time — unlike a jti denylist there is
 * nothing here that only expiry can reclaim. An expired record is dropped
 * when it is next read; `grant` overwrites in place.
 *
 * Single-replica only. Consent forks per replica: a "yes" recorded on one
 * replica is asked for again on every other, which is why the module that
 * provides this declares itself replica-unsafe and `deployment.mode = "multi"`
 * refuses it by name.
 */
export function createMemoryConsentStore(): MemoryConsentStore {
	const records = new Map<string, ConsentRecord>();
	// JSON keeps the pair unambiguous whatever characters a subject or client
	// id contains; a separator would not.
	const key = (sub: string, clientId: string): string => JSON.stringify([sub, clientId]);

	return {
		kind: "memory",

		get size() {
			return records.size;
		},

		async find(sub, clientId) {
			const record = records.get(key(sub, clientId));
			if (record === undefined) return null;
			if (record.expiresAt !== undefined && record.expiresAt <= Date.now()) {
				records.delete(key(sub, clientId));
				return null;
			}
			return record;
		},

		async grant(record) {
			records.set(key(record.sub, record.clientId), {
				...record,
				scopes: [...record.scopes],
			});
		},

		async revoke(sub, clientId) {
			return records.delete(key(sub, clientId));
		},
	};
}
