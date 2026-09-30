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
	isStorableExpiry,
	type RefreshTokenFamily,
	type RefreshTokenFamilyStore,
	type RefreshTokenFamilyUpdateResult,
	RefreshTokenStorageError,
	withReason,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { RefreshTokenFamilyClient } from "./clients.mjs";
import { redisReference } from "./internal/section.mjs";

/**
 * Options for createRedisRefreshTokenFamilyStore.
 */
export interface RedisRefreshTokenFamilyStoreOptions {
	readonly client: RefreshTokenFamilyClient;
	readonly keyPrefix: string;
	/**
	 * Maximum CAS retry attempts before throwing
	 * RefreshTokenStorageError({ reason: "conflict-exhausted" }). Default 3.
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

/**
 * A family's expiry as stored: refused unless a finite instant, then rounded up
 * to a whole epoch millisecond, both for `PX` (which takes nothing else) and
 * for the stored JSON ({@link SerializedFamilySchema} reads integers only). Up,
 * so the family lives at least as long as asked.
 */
const storedExpiry = (expiresAtMs: number, operation: string): number => {
	if (!isStorableExpiry(expiresAtMs)) {
		throw new RangeError(
			`RefreshTokenFamilyStore.${operation}: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
		);
	}
	return Math.ceil(expiresAtMs);
};

/**
 * Runtime schema for `SerializedFamily`: a bare cast would let a corrupt value
 * carry `undefined` into rotation, where `activeJti` comparisons are always
 * false. `.strict()` makes a record with extra fields (a newer schema)
 * `corrupt-data` rather than silently truncated; a caller that must tolerate
 * them across rolling deploys can wrap the store.
 */
const SerializedFamilySchema = z
	.object({
		familyId: z.string(),
		activeJti: z.string(),
		revoked: z.boolean(),
		// A positive integer: `Infinity` would defeat the `pttl <= 0` expiry
		// gate, and a fraction does not survive a `new Date(ms)` round-trip.
		expiresAtMs: z.number().int().positive().finite(),
	})
	.strict();

/**
 * Parse and validate a stored family. Any failure is
 * `RefreshTokenStorageError({ reason: "corrupt-data" })`, never a raw
 * `ZodError`: callers expect only that error type from the adapter.
 */
const deserialize = (raw: string): RefreshTokenFamily => {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (cause) {
		throw new RefreshTokenStorageError({ reason: "corrupt-data", cause });
	}
	const result = SerializedFamilySchema.safeParse(parsed);
	if (!result.success) {
		throw new RefreshTokenStorageError({ reason: "corrupt-data", cause: result.error });
	}
	return Object.freeze(result.data satisfies SerializedFamily);
};

/**
 * Redis-backed RefreshTokenFamilyStore. Each family is one string key,
 * `${keyPrefix}${familyId}`, holding the family as JSON (which keeps
 * `RefreshTokenFamilyClient` narrow) with a `PX` TTL; see `storedExpiry`.
 *
 * - `registerFamily` is `SET key value PX ttlMs NX`: atomic insert-only.
 * - `updateFamily` is single-key `WATCH`/`GET`/`MULTI`/`SET`/`EXEC`: the
 *   updater's decision is applied to exactly the state it read, or `EXEC`
 *   answers `null` and the loop re-reads and re-decides. So a caller can fuse
 *   "detect a condition" and "write the response" into one operation, as
 *   refresh-replay detection and family revocation do.
 *
 * Not Lua: the updater is JavaScript because the rotation ceremony is
 * classified in the wrapper layer shared with the in-memory adapter, keeping
 * the store a plain storage primitive; `WATCH`/`MULTI`/`EXEC` gives the same
 * indivisibility for a decision made in the client.
 *
 * `WATCH` is connection-scoped, so each `updateFamily` call takes its own
 * `client.duplicate()` and reuses it across retries (`EXEC` clears the watch);
 * `registerFamily` and `findFamily` use the base client.
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
			const expiresAtMs = storedExpiry(family.expiresAtMs, "registerFamily");
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
			}
			const result = await client.set(
				fullKey(family.familyId),
				serialize({ ...family, expiresAtMs }),
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

			// One connection per call, not per retry (see above); `await using`
			// closes it on every exit path, thrown errors included.
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
				const decision = updater(current);

				if (decision.action === "abort") {
					await conn.unwatch();
					// `reason` is echoed verbatim, never interpreted here. `withReason`
					// omits the key when there is none, keeping the result
					// shape-identical to the in-memory adapter's (see its JSDoc).
					return { outcome: "aborted", ...withReason(decision.reason) };
				}

				let expiresAtMs: number;
				try {
					expiresAtMs = storedExpiry(decision.family.expiresAtMs, "updateFamily");
				} catch (err) {
					await conn.unwatch();
					throw err;
				}
				const next = { ...decision.family, expiresAtMs };
				const newTtlMs = expiresAtMs - Date.now();
				if (newTtlMs <= 0) {
					// The updater returned a past expiry: fail closed, as the memory
					// adapter and `registerFamily` do (see core's
					// `RefreshTokenFamilyStore.updateFamily`).
					await conn.unwatch();
					throw new RefreshTokenStorageError({ reason: "expired-at-issue" });
				}

				const multi = conn.multi();
				multi.set(key, serialize(next), "PX", newTtlMs);
				const execResult = await multi.exec();

				if (execResult === null) {
					// CAS conflict: re-WATCH on the same connection next iteration.
					continue;
				}

				// Taken after EXEC, this runs up to one round-trip later than what
				// `findFamily` reconstructs from PTTL for the same write. Benign:
				// the TTL never exceeds what the updater asked for, and JWT
				// validators tolerate far more skew; reading PTTL here would add a
				// round-trip for nothing.
				const committed = Object.freeze({
					...next,
					expiresAtMs: Date.now() + newTtlMs,
				});
				// The reason of the decision that won the CAS; earlier attempts'
				// reasons go with their failed commits, which is why the reason
				// rides on the decision rather than in a caller's closure.
				return { outcome: "committed", family: committed, ...withReason(decision.reason) };
			}

			throw new RefreshTokenStorageError({ reason: "conflict-exhausted" });
		},
	};
}

/** AdapterFactory builder for runtime-config-driven backend selection. */
export const redisRefreshTokenFamilyStoreBuilder: AdapterBuilder<RefreshTokenFamilyStore> = (
	config,
	_ctx,
) => {
	const c = config as {
		client?: RefreshTokenFamilyClient;
		keyPrefix?: string;
		casRetryLimit?: number;
	};
	// Fail at boot rather than with a cryptic `TypeError` at the first Redis call.
	if (!c.client) {
		throw new Error("redisRefreshTokenFamilyStoreBuilder: 'client' option is required");
	}
	return createRedisRefreshTokenFamilyStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "rtfam:",
		casRetryLimit: c.casRetryLimit,
	});
};

/**
 * The schema of `redis-refresh-token-family-store {}`, the module's own
 * section: its key namespace and the compare-and-set retry bound (1 to 10),
 * read from the string a variable carries. Strict.
 */
export const redisRefreshTokenFamilyStoreSectionSchema = z
	.object({
		keyPrefix: z.string().default("rtfam:"),
		casRetryLimit: z.coerce.number().int().min(1).max(10).default(3),
	})
	.strict()
	.default(() => ({ keyPrefix: "rtfam:", casRetryLimit: 3 }));

/**
 * `defineModule` manifest for the Redis RefreshTokenFamilyStore (static
 * composition; the builder above is for runtime selection), read from its own
 * section, `redis-refresh-token-family-store`. `redisRefreshTokenFamilyStore`,
 * the section's old path, and the variables' old names
 * (`REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX`,
 * `REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT`) refuse boot naming the new
 * ones.
 */
export const redisRefreshTokenFamilyStoreModule = defineModule({
	name: "redis-refresh-token-family-store",
	section: {
		schema: redisRefreshTokenFamilyStoreSectionSchema,
		reference: redisReference(),
		relocatedFrom: {
			redisRefreshTokenFamilyStore: { to: "", environmentVariable: null },
			"redisRefreshTokenFamilyStore.keyPrefix": "keyPrefix",
			"redisRefreshTokenFamilyStore.casRetryLimit": "casRetryLimit",
		},
		renamedVariables: {
			REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX: "redisRefreshTokenFamilyStore.keyPrefix",
			REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT: "redisRefreshTokenFamilyStore.casRetryLimit",
		},
	},
	requires: ["refreshTokenFamilyClient"] as const,
	provides: {
		refreshTokenFamilyStore: ({ section, refreshTokenFamilyClient }) =>
			createRedisRefreshTokenFamilyStore({
				client: refreshTokenFamilyClient,
				keyPrefix: section.keyPrefix,
				casRetryLimit: section.casRetryLimit,
			}),
	},
});
