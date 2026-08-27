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
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { AccessTokenDenylistClient } from "./clients.mjs";

/**
 * Options for {@link createRedisAccessTokenDenylist}.
 */
export interface RedisAccessTokenDenylistOptions {
	readonly client: AccessTokenDenylistClient;
	readonly keyPrefix: string;
}

/**
 * Redis-backed AccessTokenDenylist (#277). Two 1-op primitives:
 *   - add: SET <prefix><jti> "1" PX <remaining lifetime>
 *   - has: EXISTS <prefix><jti> → 1 | 0
 *
 * **Why this adapter exists at all.** The in-process denylist forks per
 * replica, so a revocation served by one replica leaves the token working on
 * every other one — which is why core's replica-safety guard refuses
 * `core-access-token-denylist-memory` under `deployment.mode = "multi"`. That
 * left a scaled deployment with no denylist it was allowed to wire, and
 * `/oauth/revoke` answering RFC 7009's mandatory 200 with nothing behind it.
 *
 * **TTL is the token's own remaining lifetime, and that is the entire GC
 * strategy.** Past `exp` the token fails verification on its own claims, so a
 * denylist entry that outlives it protects nothing and the keyspace would grow
 * without bound. Redis expiry does the sweeping; there is no background job.
 *
 * **An already-expired token is a legal revocation target.** RFC 7009 §2.1
 * treats revoking an expired token as harmless idempotency, and the revoke
 * route verifies with `ignoreExpiration: true` precisely so a client that does
 * not know its token expired still gets a 200. `SET ... PX 0` is a Redis
 * error, so that case writes nothing instead of turning a legal request into a
 * logged failure.
 *
 * Unlike ReplaySeenSet's `NX`, `add` is a plain `SET`: re-revoking the same
 * jti is idempotent and last-write-wins on the expiry, matching the memory
 * adapter's `Map.set`.
 */
export function createRedisAccessTokenDenylist(
	opts: RedisAccessTokenDenylistOptions,
): AccessTokenDenylist {
	const { client, keyPrefix } = opts;
	const fullKey = (jti: string): string => `${keyPrefix}${jti}`;

	return {
		kind: "redis",

		async add(jti, expiresAtMs) {
			const ttlMs = expiresAtMs - Date.now();
			if (ttlMs <= 0) {
				// Already expired: nothing to deny. See the note above — this is a
				// success, not a swallowed error.
				return;
			}
			await client.set(fullKey(jti), "1", "PX", ttlMs);
		},

		async has(jti) {
			return (await client.exists(fullKey(jti))) === 1;
		},
	};
}

/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisAccessTokenDenylistBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "atdeny:" });
 */
export const redisAccessTokenDenylistBuilder: AdapterBuilder<AccessTokenDenylist> = (
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
 * path (§8.1); for runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisAccessTokenDenylist` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key). Multi-tenant
 * deployments override `keyPrefix` so one tenant's revocations cannot mask or
 * be masked by another's.
 */
export const redisAccessTokenDenylistModule = defineModule({
	name: "redis-access-token-denylist",
	requires: ["accessTokenDenylistClient", "config"] as const,
	configSchema: z.object({
		redisAccessTokenDenylist: z
			.object({
				keyPrefix: z.string().default("atdeny:"),
			})
			.default({ keyPrefix: "atdeny:" }),
	}),
	provides: {
		accessTokenDenylist: (deps) => {
			const cfg = (deps.config as unknown as { redisAccessTokenDenylist: { keyPrefix: string } })
				.redisAccessTokenDenylist;
			return createRedisAccessTokenDenylist({
				client: deps.accessTokenDenylistClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
