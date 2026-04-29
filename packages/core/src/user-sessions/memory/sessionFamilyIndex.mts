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

import type { SessionFamilyIndex } from "../types.mjs";
import { createMemorySidSortedSet } from "./internalSidSortedSet.mjs";

/**
 * In-memory SessionFamilyIndex. Wraps `createMemorySidSortedSet` for
 * insertion-order-preserving, idempotent-add family-id tracking.
 *
 * Insertion order is informational (aids debugging / mirrors Redis ZRANGE
 * output) but NOT load-bearing for cascade revoke — callers iterate
 * order-independently. Per A4 §5.3 + §7.1.
 */
export function createInMemorySessionFamilyIndex(): SessionFamilyIndex {
	const set = createMemorySidSortedSet();

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
	};
}
