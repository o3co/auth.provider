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
import { RefreshTokenStorageError } from "../errors.mjs";
import type {
	RefreshTokenFamily,
	RefreshTokenFamilyStore,
	RefreshTokenFamilyUpdateResult,
} from "../types.mjs";

interface Entry {
	readonly family: RefreshTokenFamily;
	readonly expiresAtMs: number;
}

/**
 * Memory-backed RefreshTokenFamilyStore.
 *
 * Atomicity argument (single-process, single-event-loop):
 *   - All read/check/write sequences inside `registerFamily` and
 *     `updateFamily` are SYNCHRONOUS — there is no `await` between the
 *     Map.get (or Map.has) and the Map.set (or Map.delete). Node's
 *     microtask queue cannot interleave non-async work, so concurrent
 *     callers do not race.
 *   - CAS conflict cannot occur (no cross-instance concurrency); the
 *     memory adapter therefore never throws "conflict-exhausted".
 *
 * Lazy GC: an expired entry is removed on the next access via getLive().
 *
 * Per A3 §7.1.
 */
export function createMemoryRefreshTokenFamilyStore(): RefreshTokenFamilyStore {
	const families = new Map<string, Entry>();

	const getLive = (familyId: string): RefreshTokenFamily | null => {
		const entry = families.get(familyId);
		if (entry === undefined) return null;
		if (entry.expiresAtMs <= Date.now()) {
			families.delete(familyId);
			return null;
		}
		return entry.family;
	};

	return {
		kind: "memory",

		async registerFamily(family) {
			if (family.expiresAt.getTime() <= Date.now()) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			if (getLive(family.familyId) !== null) {
				throw new RefreshTokenStorageError({ reason: "duplicate-family" });
			}
			families.set(family.familyId, {
				family: Object.freeze({ ...family }),
				expiresAtMs: family.expiresAt.getTime(),
			});
		},

		async findFamily(familyId) {
			return getLive(familyId);
		},

		async updateFamily(familyId, updater): Promise<RefreshTokenFamilyUpdateResult> {
			const current = getLive(familyId);
			if (current === null) {
				return { outcome: "not-found" };
			}
			const next = updater(current);
			if (next === null) {
				return { outcome: "aborted" };
			}
			// Fail-closed parity with registerFamily: an updater that returns a
			// family with expiresAt <= now() would commit a dead-on-arrival entry
			// (lazy-GC'd on next read) and silently diverge from the Redis
			// adapter's behavior. Symmetric throw aligns both adapters.
			if (next.expiresAt.getTime() <= Date.now()) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			const frozen = Object.freeze({ ...next });
			families.set(familyId, {
				family: frozen,
				expiresAtMs: frozen.expiresAt.getTime(),
			});
			return { outcome: "committed", family: frozen };
		},
	};
}
