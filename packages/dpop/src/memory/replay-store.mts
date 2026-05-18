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
import type { DPoPReplayStore } from "../replay-store.mjs";

interface MemoryReplayStoreOptions {
	/** Override the clock for tests. Default: `() => Date.now()`. */
	readonly now?: () => number;
}

export const createMemoryDPoPReplayStore = (
	options: MemoryReplayStoreOptions = {},
): DPoPReplayStore => {
	const now = options.now ?? (() => Date.now());
	// key = `${jkt}:${jti}`, value = expiry epoch ms
	const seen = new Map<string, number>();

	return {
		async seen(jti, jkt, ttlSeconds) {
			const key = `${jkt}:${jti}`;
			const nowMs = now();
			const existing = seen.get(key);
			if (existing !== undefined && existing > nowMs) {
				return true;
			}
			seen.set(key, nowMs + ttlSeconds * 1000);
			// Opportunistic sweep — drop one expired key per call to amortize
			// cleanup. Real production deployments use Redis where TTL is
			// backend-native.
			for (const [k, expiry] of seen) {
				if (expiry <= nowMs) {
					seen.delete(k);
					break;
				}
			}
			return false;
		},
	};
};
