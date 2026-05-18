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
import type { DPoPReplayStore } from "@o3co/auth-provider-dpop";

/**
 * Minimal backing client for the DPoP replay store.
 * Separate from the general `ReplaySeenSetClient` because the DPoP store
 * needs only the atomic SET NX PX operation — no `exists` query, no
 * challenge lifecycle ops.
 */
export interface DPoPReplayStoreClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
}

export interface RedisDPoPReplayStoreOptions {
	readonly client: DPoPReplayStoreClient;
	readonly keyPrefix?: string; // default: "dpop:replay:"
}

/**
 * Redis-backed DPoPReplayStore. Uses `SET key 1 NX PX ttlMs` for atomic
 * check-and-mark — a single round-trip with no TOCTOU window.
 *
 *   result === "OK"   → key was SET (not previously seen) → return false
 *   result === null   → key already existed (replay)      → return true
 *
 * Per Wave 2 Phase 2 spec §5.5 and design principle §3.3 (atomicity).
 * Required for multi-process / clustered deployments where the in-memory
 * adapter cannot share state across processes.
 */
export const createRedisDPoPReplayStore = (
	options: RedisDPoPReplayStoreOptions,
): DPoPReplayStore => {
	const prefix = options.keyPrefix ?? "dpop:replay:";
	return {
		async seen(jti, jkt, ttlSeconds) {
			const key = `${prefix}${jkt}:${jti}`;
			// SET key value NX PX ttlMillis — atomic check-and-set
			const result = await options.client.set(key, "1", "PX", ttlSeconds * 1000, "NX");
			// result === "OK" → set succeeded → was NOT seen before
			// result === null → key already existed → IS a replay
			return result === null;
		},
	};
};
