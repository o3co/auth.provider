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
	CreateUserSessionInput,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import type { RedisClient } from "./types.mjs";

export interface RedisUserSessionStoreOptions {
	readonly client: RedisClient;
	readonly keyPrefix: string;
}

interface Envelope {
	sid: string;
	sub: string;
	authTimeMs: number;
	createdAtMs: number;
	expiresAtMs: number;
	claims: Record<string, unknown>;
}

const toEnvelope = (input: CreateUserSessionInput, createdAtMs: number): Envelope => ({
	sid: input.sid,
	sub: input.sub,
	authTimeMs: input.authTime.getTime(),
	createdAtMs,
	expiresAtMs: input.expiresAt.getTime(),
	claims: { ...input.claims },
});

const fromEnvelope = (e: Envelope): UserSession => ({
	sid: e.sid,
	sub: e.sub,
	authTime: new Date(e.authTimeMs),
	createdAt: new Date(e.createdAtMs),
	expiresAt: new Date(e.expiresAtMs),
	claims: { ...e.claims } as UserSessionClaims,
});

/**
 * Redis-backed UserSessionStore. Per A4 §5.1 + §7.2.
 *
 * Storage shape: each session is a single Redis string key
 * `${keyPrefix}${sid}` whose value is a JSON-encoded envelope, with TTL
 * applied via SET PX. The v0.4.x lost-update window is **structurally
 * absent**: this adapter exposes only `create` (atomic SET NX),
 * `get`, `delete`. No GET → mutate → SET path exists at the v0.5.0
 * `UserSessionStore` interface level; claims update lives in the
 * Future-Use `MutableUserSessionStore` (no v0.5.0 implementation).
 *
 * Atomicity:
 *  - `create` uses SET NX PX — atomic insert-only, same primitive as A1
 *    ChallengeStore.issue and A3 registerFamily.
 *  - `get` is a read-only GET (no PTTL round-trip needed; expiresAtMs is
 *    embedded in the JSON envelope and the SET PX TTL eventually deletes
 *    the key).
 *  - `delete` is single-key DEL.
 */
export function createRedisUserSessionStore(
	opts: RedisUserSessionStoreOptions,
): UserSessionStore {
	const k = (sid: string) => `${opts.keyPrefix}${sid}`;
	return {
		kind: "redis",
		async create(input) {
			const ttlMs = input.expiresAt.getTime() - Date.now();
			if (ttlMs <= 0) {
				throw new Error(`UserSession ${input.sid}: expiresAt is in the past`);
			}
			const envelope = toEnvelope(input, Date.now());
			const result = await opts.client.set(
				k(input.sid),
				JSON.stringify(envelope),
				"PX",
				ttlMs,
				"NX",
			);
			if (result === null) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
		},
		async get(sid) {
			const raw = await opts.client.get(k(sid));
			if (raw === null) return null;
			const env = JSON.parse(raw) as Envelope;
			if (env.expiresAtMs <= Date.now()) return null;
			return fromEnvelope(env);
		},
		async delete(sid) {
			await opts.client.del(k(sid));
		},
	};
}
