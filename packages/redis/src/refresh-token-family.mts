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
import {
	type AdapterBuilder,
	defineModule,
	type RefreshTokenFamily,
	type RefreshTokenFamilyStore,
	type RefreshTokenFamilyUpdateResult,
	RefreshTokenStorageError,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RedisClient } from "./types.mjs";

/**
 * Options for createRedisRefreshTokenFamilyStore.
 */
export interface RedisRefreshTokenFamilyStoreOptions {
	readonly client: RedisClient;
	readonly keyPrefix: string;
	/**
	 * Maximum CAS retry attempts before throwing
	 * RefreshTokenStorageError({ reason: "conflict-exhausted" }). Default 3
	 * matches A3 §7.2 recommendation.
	 */
	readonly casRetryLimit?: number;
}

interface SerializedFamily {
	readonly familyId: string;
	readonly activeJti: string;
	readonly revoked: boolean;
	readonly expiresAtMs: number;
}

const serialize = (fam: RefreshTokenFamily): string =>
	JSON.stringify(fam satisfies SerializedFamily);

const deserialize = (raw: string): RefreshTokenFamily =>
	Object.freeze(JSON.parse(raw) as SerializedFamily);

/**
 * Redis-backed RefreshTokenFamilyStore.
 *
 * Storage shape: each family is stored as a single Redis string key
 * `${keyPrefix}${familyId}` whose value is a JSON serialisation of the
 * RefreshTokenFamily aggregate, with a TTL set via the SET command's PX
 * argument. JSON serialisation (rather than a Redis hash) keeps the
 * RedisClient surface narrow (no HSET/HGETALL needed) and matches A1's
 * single-key SET-NX pattern.
 *
 * Atomicity:
 *   - registerFamily uses `SET key value PX ttlMs NX` — atomic insert-only,
 *     same primitive as A1's ChallengeStore.issue.
 *   - updateFamily uses single-key WATCH/GET/MULTI/SET/EXEC — the canonical
 *     Redis CAS primitive. Single-key only (not a multi-key transaction).
 *
 * Connection isolation: WATCH is connection-scoped in Redis, so each
 * `updateFamily` call obtains its own connection via `client.duplicate()`
 * (disposed via `await using` on function exit). Within that connection
 * the CAS retry loop reuses the SAME duplicate across attempts — Redis
 * auto-clears WATCH on every EXEC, so a fresh `WATCH` at the top of
 * each iteration sets up a clean CAS context without churning
 * connections per retry (1 connection per call, not per attempt).
 *
 * The base `client` is used only for non-WATCH ops (registerFamily,
 * findFamily) where command serialisation is sufficient.
 *
 * Per A3 §7.2.
 */
export function createRedisRefreshTokenFamilyStore(
	opts: RedisRefreshTokenFamilyStoreOptions,
): RefreshTokenFamilyStore {
	const { client, keyPrefix } = opts;
	const casRetryLimit = opts.casRetryLimit ?? 3;
	const fullKey = (familyId: string): string => `${keyPrefix}${familyId}`;

	return {
		kind: "redis",

		async registerFamily(family) {
			const ttlMs = family.expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(
				fullKey(family.familyId),
				serialize(family),
				"PX",
				ttlMs,
				"NX",
			);
			if (result === null) {
				throw new RefreshTokenStorageError({ reason: "duplicate-family" });
			}
		},

		async findFamily(familyId) {
			const key = fullKey(familyId);
			const raw = await client.get(key);
			if (raw === null) return null;
			const pttl = await client.pttl(key);
			if (pttl <= 0) return null; // -2 nonexistent, -1 no-TTL (defensive), 0 expired
			const fam = deserialize(raw);
			// Reconstruct expiresAtMs from PTTL to match the drift contract
			// (epoch-ms eliminates the Date mutation surface).
			return Object.freeze({ ...fam, expiresAtMs: Date.now() + pttl });
		},

		async updateFamily(familyId, updater): Promise<RefreshTokenFamilyUpdateResult> {
			const key = fullKey(familyId);

			// One isolated connection per call (NOT per retry): WATCH is
			// connection-scoped in Redis, so concurrent updateFamily calls
			// would interleave their WATCH contexts on a shared client.
			// `await using` closes the duplicate on every exit path including
			// thrown errors. Across retries we reuse this single connection;
			// Redis auto-clears WATCH on every EXEC, and we re-WATCH at the
			// top of each iteration.
			await using conn = client.duplicate();

			for (let attempt = 0; attempt <= casRetryLimit; attempt++) {
				await conn.watch(key);
				const raw = await conn.get(key);

				if (raw === null) {
					await conn.unwatch();
					return { outcome: "not-found" };
				}

				const pttl = await conn.pttl(key);
				if (pttl <= 0) {
					await conn.unwatch();
					return { outcome: "not-found" };
				}

				const current = Object.freeze({
					...deserialize(raw),
					expiresAtMs: Date.now() + pttl,
				});
				const next = updater(current);

				if (next === null) {
					await conn.unwatch();
					return { outcome: "aborted" };
				}

				const newTtlMs = next.expiresAtMs - Date.now();
				if (newTtlMs <= 0) {
					// Updater returned past expiresAtMs — fail-closed parity with
					// memory adapter (and symmetric with registerFamily's
					// expired-at-issue throw). See updateFamily contract bullet
					// in @o3co/auth-provider-core RefreshTokenFamilyStore.
					await conn.unwatch();
					throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
				}

				const multi = conn.multi();
				multi.set(key, serialize(next), "PX", newTtlMs);
				const execResult = await multi.exec();

				if (execResult === null) {
					// CAS conflict — Redis auto-clears WATCH on EXEC; loop and
					// re-WATCH at the top of the next iteration on the SAME
					// connection (no per-retry duplicate churn).
					continue;
				}

				// Reconstructing expiresAtMs as `Date.now() + newTtlMs` here
				// (post-EXEC) drifts forward by the EXEC round-trip vs PTTL
				// reconstruction in findFamily, which counts down from the
				// SET commit moment. Concretely, `findFamily(...)?.expiresAtMs
				// <= updateFamily(...).committed.family.expiresAtMs` for the
				// same write — typically by single-digit ms in healthy
				// networks. The drift is benign: callers using expiresAtMs
				// to populate JWT `exp` claims still respect the original
				// caller-supplied window (TTL never extends beyond what the
				// updater asked for), and JWT validators tolerate seconds-
				// scale clock skew. PTTL-after-EXEC reconstruction would
				// add a redundant round-trip with no security benefit.
				const committed = Object.freeze({
					...next,
					expiresAtMs: Date.now() + newTtlMs,
				});
				return { outcome: "committed", family: committed };
			}

			throw new RefreshTokenStorageError({ reason: "conflict-exhausted" });
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisRefreshTokenFamilyStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "rtfam:", casRetryLimit: 3 });
 */
export const redisRefreshTokenFamilyStoreBuilder: AdapterBuilder<RefreshTokenFamilyStore> = (
	config,
) => {
	const c = config as { client: RedisClient; keyPrefix?: string; casRetryLimit?: number };
	return createRedisRefreshTokenFamilyStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "rtfam:",
		casRetryLimit: c.casRetryLimit,
	});
};

/**
 * `defineModule` manifest for the Redis RefreshTokenFamilyStore. Static
 * composition path (A3 §8.1). For runtime-config-driven selection use the
 * builder above.
 *
 * configSchema: top-level key `redisRefreshTokenFamilyStore`
 * (module-namespaced per master roadmap §3.5).
 */
export const redisRefreshTokenFamilyStoreModule = defineModule({
	name: "redis-refresh-token-family-store",
	requires: ["redisClient", "config"] as const,
	configSchema: z.object({
		redisRefreshTokenFamilyStore: z
			.object({
				keyPrefix: z.string().default("rtfam:"),
				casRetryLimit: z.number().int().min(1).max(10).default(3),
			})
			.default({ keyPrefix: "rtfam:", casRetryLimit: 3 }),
	}),
	provides: {
		refreshTokenFamilyStore: (deps) => {
			const cfg = (
				deps.config as unknown as {
					redisRefreshTokenFamilyStore: { keyPrefix: string; casRetryLimit: number };
				}
			).redisRefreshTokenFamilyStore;
			return createRedisRefreshTokenFamilyStore({
				client: deps.redisClient,
				keyPrefix: cfg.keyPrefix,
				casRetryLimit: cfg.casRetryLimit,
			});
		},
	},
});
