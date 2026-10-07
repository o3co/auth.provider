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
	type AccessTokenDenylist,
	type AdapterBuilder,
	defineModule,
	isStorableExpiry,
} from "@o3co/auth-provider-core";
import type { AccessTokenDenylistClient } from "./clients.mjs";
import { requireNoEviction } from "./internal/eviction-policy.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/**
 * Options for {@link createRedisAccessTokenDenylist}.
 */
export interface RedisAccessTokenDenylistOptions {
	readonly client: AccessTokenDenylistClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed AccessTokenDenylist. Two 1-op primitives:
 *   - add: SET <prefix><jti> "1" PX <remaining lifetime>, rounded up to whole
 *     milliseconds — `exp * 1000` is fractional for a non-integer JWT
 *     NumericDate, and a fractional `PX` is a Redis error the revoke route
 *     would swallow, leaving the token valid. A non-finite expiry is refused.
 *   - has: EXISTS <prefix><jti> → 1 | 0
 *
 * The denylist a multi-replica deployment can wire: the in-process one forks
 * per replica, so a revocation served by one replica leaves the token working
 * on every other, and core's replica-safety guard refuses
 * `core-access-token-denylist-memory` under `core.deployment.mode = "multi"`.
 *
 * **The TTL is the token's own remaining lifetime, and that is the entire GC
 * strategy.** Past `exp` the token fails verification on its own claims, so a
 * longer entry protects nothing. Redis expiry does the sweeping.
 *
 * **An already-expired token is a legal revocation target** (RFC 7009 §2.1;
 * the revoke route verifies with `ignoreExpiration: true`). `SET ... PX 0` is
 * a Redis error, so that case writes nothing instead of turning a legal
 * request into a logged failure.
 *
 * Unlike ReplaySeenSet's `NX`, `add` is a plain `SET`: re-revoking the same
 * jti is idempotent and last-write-wins on the expiry, matching the memory
 * adapter's `Map.set`.
 *
 * It resolves once the server's eviction policy passes the gate
 * (`internal/eviction-policy.mts`).
 */
export async function createRedisAccessTokenDenylist(
	opts: RedisAccessTokenDenylistOptions,
): Promise<AccessTokenDenylist> {
	const denylist = buildRedisAccessTokenDenylist(opts);
	await requireNoEviction("accessTokenDenylist", () => opts.client.durability(), {
		reason: "access-token-denylist-evictable",
		holds:
			"revoked access tokens' jtis, each keyed with a TTL until its token expires, and a jti evicted before then lets that token read as not revoked",
	});
	return denylist;
}

function buildRedisAccessTokenDenylist(opts: RedisAccessTokenDenylistOptions): AccessTokenDenylist {
	const { client, keyPrefix } = opts;
	const fullKey = (jti: string): string => `${keyPrefix}${jti}`;

	return {
		kind: "redis",

		async add(jti, expiresAtMs) {
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`AccessTokenDenylist.add: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				// Already expired: nothing to deny. See the note above — this is a
				// success, not a swallowed error.
				return;
			}
			await client.set(fullKey(jti), "1", "PX", Math.ceil(ttlMs));
		},

		async has(jti) {
			return (await client.exists(fullKey(jti))) === 1;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection.
 * Consumer registers via:
 *   factory.register("redis", redisAccessTokenDenylistBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "atdeny:" });
 */
export const redisAccessTokenDenylistBuilder: AdapterBuilder<AccessTokenDenylist> = async (
	config,
	_ctx,
) => {
	const c = config as { client?: AccessTokenDenylistClient; keyPrefix?: string };
	// Structural guard, mirroring `redisReplaySeenSetBuilder`: fail where the
	// composition is assembled rather than on the first revocation attempt —
	// which, for this particular adapter, would be during an incident.
	if (!c.client) {
		throw new Error("redisAccessTokenDenylistBuilder: 'client' option is required");
	}
	return createRedisAccessTokenDenylist({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "atdeny:",
	});
};

/**
 * `defineModule` manifest for the Redis AccessTokenDenylist. Static composition
 * path; for runtime-config-driven selection use the builder above.
 *
 * Its section, `redis-access-token-denylist`, holds `keyPrefix` (strict).
 * Multi-tenant deployments override it so one tenant's revocations cannot mask
 * or be masked by another's.
 */
export const redisAccessTokenDenylistModule = defineModule({
	name: "redis-access-token-denylist",
	requires: ["accessTokenDenylistClient"] as const,
	section: {
		schema: keyPrefixSection,
		reference: redisReference(),
		relocatedFrom: {
			redisAccessTokenDenylist: { to: "", environmentVariable: null },
			"redisAccessTokenDenylist.keyPrefix": "keyPrefix",
		},
	},
	provides: {
		accessTokenDenylist: ({ section, accessTokenDenylistClient }) =>
			createRedisAccessTokenDenylist({
				client: accessTokenDenylistClient,
				keyPrefix: section.keyPrefix,
			}),
	},
});
