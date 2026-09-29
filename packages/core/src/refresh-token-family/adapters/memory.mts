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

import { isStorableExpiry } from "../../adapters/expiry.mjs";
import { RefreshTokenStorageError } from "../errors.mjs";
import { withReason } from "../reason.mjs";
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
 * NaN is never `<= now`, so a family registered or committed with one would
 * never expire and never be reclaimed; ±Infinity is no expiry either. A
 * caller fault, refused with the RangeError the Redis adapter throws for it.
 */
const requireFiniteExpiry = (expiresAtMs: number, operation: string): void => {
	if (!isStorableExpiry(expiresAtMs)) {
		throw new RangeError(
			`RefreshTokenFamilyStore.${operation}: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
		);
	}
};

/**
 * Memory-backed RefreshTokenFamilyStore.
 *
 * Atomic within one process: every read/check/write in `registerFamily` and
 * `updateFamily` is synchronous, with no `await` between the Map read and the
 * Map write, so concurrent callers cannot interleave. With no cross-instance
 * concurrency there is no CAS conflict, so it never throws
 * `conflict-exhausted`.
 *
 * Expired entries are removed lazily, on the next access via `getLive()`.
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
			requireFiniteExpiry(family.expiresAtMs, "registerFamily");
			if (family.expiresAtMs <= Date.now()) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			if (getLive(family.familyId) !== null) {
				throw new RefreshTokenStorageError({ reason: "duplicate-family" });
			}
			families.set(family.familyId, {
				family: Object.freeze({ ...family }),
				expiresAtMs: family.expiresAtMs,
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
			const decision = updater(current);
			if (decision.action === "abort") {
				// `reason` is echoed verbatim; classification belongs to the wrapper
				// layer. Spread conditionally: `reason` is optional, and a key holding
				// `undefined` differs from an absent key to `in`, `Object.keys`,
				// `toStrictEqual` and serialisation.
				return { outcome: "aborted", ...withReason(decision.reason) };
			}
			const next = decision.family;
			requireFiniteExpiry(next.expiresAtMs, "updateFamily");
			// Fail closed as registerFamily does, and as the Redis adapter does
			// here: committing `expiresAtMs <= now()` would store a dead entry.
			if (next.expiresAtMs <= Date.now()) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			const frozen = Object.freeze({ ...next });
			families.set(familyId, {
				family: frozen,
				expiresAtMs: frozen.expiresAtMs,
			});
			return { outcome: "committed", family: frozen, ...withReason(decision.reason) };
		},
	};
}
