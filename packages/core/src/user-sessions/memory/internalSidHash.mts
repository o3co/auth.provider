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
 * Private memory helper used by `SessionRPRegistry`. Mirrors the Redis
 * `createRedisSidHash` semantics: id-keyed upsert under a single sid-scoped
 * envelope, TTL-synced to `expiresAt`, no-op writes after expiry. Per A4 §7.1
 * (lines 510-531 of the spec).
 */
export interface MemorySidHash<T> {
	setField(sid: string, entry: T, expiresAt: Date): void;
	listValues(sid: string): T[];
	removeBySid(sid: string): void;
}

interface Bucket<T> {
	entries: Map<string, T>;
	expiresAtMs: number;
}

export function createMemorySidHash<T>(idOf: (t: T) => string): MemorySidHash<T> {
	const store = new Map<string, Bucket<T>>();

	return {
		setField(sid, entry, expiresAt) {
			const expiresAtMs = expiresAt.getTime();
			// Codex finding: writes after expiry MUST NOT recreate a zombie
			// entry. Mirror redis adapter's PEXPIREAT-after-expiry no-op.
			if (expiresAtMs <= Date.now()) return;
			const existing = store.get(sid);
			// Lazy GC: same rationale as createMemorySidSortedSet.add — drop a
			// prior expired bucket's entries so a re-used sid doesn't leak
			// RPs from a prior session.
			const isStale = existing != null && existing.expiresAtMs <= Date.now();
			const entries = isStale ? new Map<string, T>() : (existing?.entries ?? new Map<string, T>());
			entries.set(idOf(entry), entry);
			store.set(sid, { entries, expiresAtMs });
		},
		listValues(sid) {
			const it = store.get(sid);
			if (!it) return [];
			if (it.expiresAtMs <= Date.now()) {
				store.delete(sid);
				return [];
			}
			return [...it.entries.values()];
		},
		removeBySid(sid) {
			store.delete(sid);
		},
	};
}
