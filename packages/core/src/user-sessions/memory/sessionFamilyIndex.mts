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

import { DEFAULT_CLOCK_SKEW_MS } from "../../jwt/verify.mjs";
import type { SessionFamilyIndex, SupportsSessionEnd } from "../types.mjs";
import { createMemorySidSortedSet } from "./internalSidSortedSet.mjs";

/**
 * In-memory SessionFamilyIndex, with the session-end capability. Wraps
 * `createMemorySidSortedSet` for insertion-order-preserving, idempotent-add
 * family-id tracking, and keeps each sid's "ended" mark beside it until
 * `expiresAt` plus the clock-skew allowance, whatever `removeBySid` does to
 * the families.
 *
 * Every call runs with no `await`, so what it writes and what it reads are
 * one step: no other call on the sid falls between them. An end's mark is
 * therefore in place before its listing, and an add's family before it reads
 * the mark; an add reads the clock once, for its deadline and the mark's.
 *
 * Insertion order is informational (aids debugging / mirrors Redis ZRANGE
 * output) but NOT load-bearing for cascade revoke — callers iterate
 * order-independently.
 */
export function createInMemorySessionFamilyIndex(): SessionFamilyIndex & SupportsSessionEnd {
	const set = createMemorySidSortedSet();
	/** sid → when its "ended" mark lapses, in epoch ms. Dropped lazily, as the families are. */
	const ended = new Map<string, number>();

	const validExpiry = (expiresAt: Date): number => {
		const expiresAtMs = expiresAt.getTime();
		if (!Number.isFinite(expiresAtMs)) {
			throw new RangeError("expiresAt must be a valid date");
		}
		return expiresAtMs;
	};
	const isEnded = (sid: string, now: number): boolean => {
		const until = ended.get(sid);
		if (until === undefined) return false;
		if (until <= now) {
			ended.delete(sid);
			return false;
		}
		return true;
	};

	return {
		kind: "memory",
		async addFamilyId(sid: string, familyId: string, expiresAt: Date): Promise<void> {
			set.add(sid, familyId, expiresAt);
		},
		async listFamilyIds(sid: string): Promise<ReadonlyArray<string>> {
			return set.list(sid);
		},
		async removeBySid(sid: string): Promise<void> {
			set.removeBySid(sid);
		},
		async endSession(sid: string, expiresAt: Date): Promise<ReadonlyArray<string>> {
			const until = validExpiry(expiresAt) + DEFAULT_CLOCK_SKEW_MS;
			if (until > Date.now()) ended.set(sid, until);
			return set.list(sid);
		},
		async addFamilyIdUnlessEnded(
			sid: string,
			familyId: string,
			expiresAt: Date,
		): Promise<"added" | "ended"> {
			const now = Date.now();
			if (validExpiry(expiresAt) <= now || !set.add(sid, familyId, expiresAt)) return "ended";
			return isEnded(sid, now) ? "ended" : "added";
		},
	};
}
