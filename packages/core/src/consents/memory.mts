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

import type {
	ConsentRecord,
	ConsentStore,
	PendingConsentRecord,
	PendingConsentStore,
} from "./types.mjs";

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
			// The union, per the port's contract: a concurrent accept for other
			// scopes must not lose the consent this one records. Single-threaded
			// here, so reading and writing around no await is atomic.
			const id = key(record.sub, record.clientId);
			const current = records.get(id);
			const live =
				current !== undefined && (current.expiresAt === undefined || current.expiresAt > Date.now())
					? current.scopes
					: [];
			records.set(id, {
				...record,
				scopes: [...new Set([...live, ...record.scopes])],
			});
		},

		async revoke(sub, clientId) {
			return records.delete(key(sub, clientId));
		},
	};
}

/** In-process pending-consent store, with the record count exposed for observability. */
export interface MemoryPendingConsentStore extends PendingConsentStore {
	/** Records currently resident, expired-but-unswept included. */
	readonly size: number;
}

/**
 * Sweep expired records once the map has grown to this many, and then again
 * each time it doubles: a page that is never answered leaves a record nobody
 * touches, and touch-on-read alone would keep it forever.
 */
const PENDING_SWEEP_FLOOR = 1024;

/**
 * In-process Map-backed {@link PendingConsentStore} (#552).
 *
 * `consume` reads and deletes with no `await` between them, which in a
 * single-threaded process is the atomic step the port asks for. Bounded by
 * traffic rather than population — one record per parked request, gone when
 * answered or expired — so an expired record is dropped when it is next
 * touched, and the whole map is swept when it has grown past a floor and
 * doubled since, which keeps abandoned pages from accumulating without a
 * timer of our own.
 *
 * Single-replica only, for the same reason as the consent store it is
 * provided with: a challenge parked on one replica is unknown to every other.
 */
export function createMemoryPendingConsentStore(): MemoryPendingConsentStore {
	const records = new Map<string, PendingConsentRecord>();
	let sweepAt = PENDING_SWEEP_FLOOR;

	const live = (challenge: string): PendingConsentRecord | null => {
		const record = records.get(challenge);
		if (record === undefined) return null;
		if (record.expiresAt <= Date.now()) {
			records.delete(challenge);
			return null;
		}
		return record;
	};

	const sweep = (): void => {
		const now = Date.now();
		for (const [challenge, record] of records) {
			if (record.expiresAt <= now) records.delete(challenge);
		}
		sweepAt = Math.max(PENDING_SWEEP_FLOOR, records.size * 2);
	};

	return {
		kind: "memory",

		get size() {
			return records.size;
		},

		async set(record) {
			if (records.size >= sweepAt) sweep();
			records.set(record.challenge, {
				...record,
				scopes: [...record.scopes],
				grantedScopes: [...record.grantedScopes],
			});
		},

		async get(challenge) {
			return live(challenge);
		},

		async consume(challenge) {
			// No await between the read and the delete: this is the one step.
			const record = live(challenge);
			if (record !== null) records.delete(challenge);
			return record;
		},
	};
}
