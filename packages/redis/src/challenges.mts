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
	type Challenge,
	ChallengeStorageError,
	type ChallengeStore,
	canonicalChallengeKey,
	DEFAULT_CLOCK_SKEW_MS,
	defineModule,
	isStorableExpiry,
} from "@o3co/auth-provider-core";
import type { ChallengeStoreClient } from "./clients.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/**
 * Options for createRedisChallengeStore.
 */
export interface RedisChallengeStoreOptions {
	readonly client: ChallengeStoreClient;
	readonly keyPrefix: string;
}

/** The value of a challenge issued with `issuedAtMs`; any other value carries none. */
const ISSUED_PREFIX = "i:";

/** The issuance a stored value carries, or undefined: `"1"` (no issuance, or written before it was kept) and anything malformed carry none. */
const issuanceOf = (value: string | null): number | undefined => {
	if (value === null || !value.startsWith(ISSUED_PREFIX)) return undefined;
	const text = value.slice(ISSUED_PREFIX.length);
	const issuedAtMs = Number(text);
	// Only what `issue` writes: a storable instant in its own shortest form.
	return isStorableExpiry(issuedAtMs) && String(issuedAtMs) === text ? issuedAtMs : undefined;
};

/**
 * Redis-backed ChallengeStore. Each op is single-key:
 *   - issue:   SET <prefix><key> <value> PX <ttlMs> NX → "OK" | null. The value
 *              is `i:<issuedAtMs>` when the caller gave an issuance, else "1".
 *              `PX` takes whole milliseconds, so a fractional remaining life
 *              is rounded up; a non-finite expiry, or an issuance core's
 *              contract refuses, is refused before Redis is asked.
 *   - find:    PTTL <prefix><key>                   → -2 absent, -1 no-TTL, ≥0 ms;
 *              the expiry is the instant find asked plus that remaining life.
 *              Then GET <prefix><key> for the issuance; a value without one
 *              answers none.
 *   - consume: DEL <prefix><key>                    → count deleted
 *
 * No Lua, no MULTI/EXEC: the contract is split into primitives so that no
 * transaction block is needed. If PTTL returns -1 (key without expiry, e.g.
 * external mutation), `find` returns null (fail-closed); so does a key gone
 * by the GET.
 */
export function createRedisChallengeStore(opts: RedisChallengeStoreOptions): ChallengeStore {
	const { client, keyPrefix } = opts;
	const fullKey = (scope: string, value: string): string =>
		`${keyPrefix}${canonicalChallengeKey(scope, value)}`;

	return {
		kind: "redis",

		async issue(scope, value, expiresAtMs, issuedAtMs) {
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`ChallengeStore.issue: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const nowMs = Date.now();
			if (
				issuedAtMs !== undefined &&
				!(
					isStorableExpiry(issuedAtMs) &&
					issuedAtMs <= expiresAtMs &&
					issuedAtMs <= nowMs + DEFAULT_CLOCK_SKEW_MS
				)
			) {
				throw new RangeError(
					`ChallengeStore.issue: issuedAtMs must be a finite instant within the Date range, not after expiresAtMs (${String(expiresAtMs)}) nor further ahead of the store's clock than DEFAULT_CLOCK_SKEW_MS (got ${String(issuedAtMs)})`,
				);
			}
			const ttlMs = expiresAtMs - nowMs;
			if (ttlMs <= 0) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const stored = issuedAtMs === undefined ? "1" : `${ISSUED_PREFIX}${String(issuedAtMs)}`;
			const result = await client.set(fullKey(scope, value), stored, "PX", Math.ceil(ttlMs), "NX");
			if (result === null) {
				throw new ChallengeStorageError({ reason: "duplicate" });
			}
		},

		async find(scope, value): Promise<Challenge | null> {
			// Read before asking: PTTL is the life left when Redis answered, so the
			// expiry rebuilt from this instant is never later than the key's.
			const askedAtMs = Date.now();
			const key = fullKey(scope, value);
			const pttl = await client.pttl(key);
			if (pttl <= 0) {
				// -2 absent, -1 no-TTL, 0 expired exactly now → all treated as null.
				return null;
			}
			const expiresAtMs = askedAtMs + pttl;
			const stored = await client.get(key);
			if (stored === null) return null;
			const issuedAtMs = issuanceOf(stored);
			return issuedAtMs === undefined ? { expiresAtMs } : { expiresAtMs, issuedAtMs };
		},

		async consume(scope, value) {
			const count = await client.del(fullKey(scope, value));
			return count > 0;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection.
 * Consumer registers via:
 *   factory.register("redis", redisChallengeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "chal:" });
 */
export const redisChallengeStoreBuilder: AdapterBuilder<ChallengeStore> = (config, _ctx) => {
	const c = config as { client?: ChallengeStoreClient; keyPrefix?: string };
	// Structural guard: fail at boot rather than at the first Redis op with
	// a cryptic `Cannot read properties of undefined`.
	if (!c.client) {
		throw new Error("redisChallengeStoreBuilder: 'client' option is required");
	}
	return createRedisChallengeStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "chal:",
	});
};

/**
 * `defineModule` manifest for the Redis ChallengeStore. Static composition
 * path. For runtime-config-driven selection use the builder above.
 *
 * Its section, `redis-challenge-store`, holds `keyPrefix` (strict).
 */
export const redisChallengeStoreModule = defineModule({
	name: "redis-challenge-store",
	requires: ["challengeStoreClient"] as const,
	section: {
		schema: keyPrefixSection,
		reference: redisReference(),
		relocatedFrom: { redisChallengeStore: { to: "", environmentVariable: null } },
	},
	provides: {
		challengeStore: ({ section, challengeStoreClient }) =>
			createRedisChallengeStore({
				client: challengeStoreClient,
				keyPrefix: section.keyPrefix,
			}),
	},
});
