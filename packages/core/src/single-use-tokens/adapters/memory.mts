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

import { canonicalKey } from "../keyEncoding.mjs";
import {
	SingleUseTokenError,
	type SingleUseConsumeOutcome,
	type SingleUseMarkSeenOutcome,
	type SingleUseTokenStoreBase,
} from "../types.mjs";

interface Entry {
	expiresAtMs: number;
	consumed: boolean;
}

export function createInMemorySingleUseTokenStore(): SingleUseTokenStoreBase {
	const store = new Map<string, Entry>();

	const gc = (composite: string, nowMs: number): void => {
		const e = store.get(composite);
		if (e !== undefined && e.expiresAtMs <= nowMs) store.delete(composite);
	};

	return {
		kind: "memory",

		async issue(scope, key, expiresAt) {
			const nowMs = Date.now();
			const expMs = expiresAt.getTime();
			if (expMs <= nowMs) {
				throw new SingleUseTokenError({ reason: "expired-at-issue" });
			}
			const composite = canonicalKey(scope, key);
			gc(composite, nowMs);
			if (store.has(composite)) {
				throw new SingleUseTokenError({ reason: "duplicate" });
			}
			store.set(composite, { expiresAtMs: expMs, consumed: false });
		},

		async consume(scope, key): Promise<SingleUseConsumeOutcome> {
			const nowMs = Date.now();
			const composite = canonicalKey(scope, key);
			gc(composite, nowMs);
			const e = store.get(composite);
			if (e === undefined) return { outcome: "unknown" };
			// Synchronous block: no `await` between `get` and `set`, so the JS
			// event loop cannot interleave another consume into this critical
			// section. This is what guarantees concurrent fairness.
			if (e.consumed) return { outcome: "replayed" };
			e.consumed = true;
			return { outcome: "consumed" };
		},

		async markSeen(_scope, _key, _expiresAt): Promise<SingleUseMarkSeenOutcome> {
			// Implemented in Task 5.
			throw new Error("markSeen not implemented yet");
		},
	};
}
