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

import type { AdapterBuilder, RegisteredRP, SessionRPRegistry } from "@o3co/auth-provider-core";
import type { SessionRPRegistryClient } from "./clients.mjs";
import { createRedisSidHash } from "./internal/redisSidHash.mjs";

export interface RedisSessionRPRegistryOptions {
	readonly client: SessionRPRegistryClient;
	readonly keyPrefix: string;
}

/**
 * JSON envelope stored as a single HSET field value.
 *
 * Rationale for `registeredAtMs: number` (epochMs hardening):
 *   Storing Date as a JSON string is susceptible to timezone / precision
 *   drift on deserialize. Storing epochMs as a plain number is loss-free
 *   and unambiguous.
 *
 * Rationale for undefined-as-absent (not "null"):
 *   Optional RP fields MUST survive the JSON round-trip as `undefined`,
 *   not `""` or `null`. We achieve this by only writing keys that are
 *   actually defined, and by parsing absent keys as `undefined`.
 */
interface RPEnvelope {
	clientId: string;
	registeredAtMs: number;
	backchannelLogoutUri?: string;
	backchannelLogoutSessionRequired?: boolean;
	frontchannelLogoutUri?: string;
	frontchannelLogoutSessionRequired?: boolean;
}

function serialize(rp: RegisteredRP): string {
	const env: RPEnvelope = { clientId: rp.clientId, registeredAtMs: rp.registeredAt.getTime() };
	// Only write defined optional fields to avoid "" / false coercion on round-trip.
	if (rp.backchannelLogoutUri !== undefined) env.backchannelLogoutUri = rp.backchannelLogoutUri;
	if (rp.backchannelLogoutSessionRequired !== undefined)
		env.backchannelLogoutSessionRequired = rp.backchannelLogoutSessionRequired;
	if (rp.frontchannelLogoutUri !== undefined) env.frontchannelLogoutUri = rp.frontchannelLogoutUri;
	if (rp.frontchannelLogoutSessionRequired !== undefined)
		env.frontchannelLogoutSessionRequired = rp.frontchannelLogoutSessionRequired;
	return JSON.stringify(env);
}

function deserialize(json: string): RegisteredRP {
	const env = JSON.parse(json) as RPEnvelope;
	return {
		clientId: env.clientId,
		registeredAt: new Date(env.registeredAtMs),
		// Absent keys are `undefined` — do not fallback to false/null/empty.
		backchannelLogoutUri: env.backchannelLogoutUri,
		backchannelLogoutSessionRequired: env.backchannelLogoutSessionRequired,
		frontchannelLogoutUri: env.frontchannelLogoutUri,
		frontchannelLogoutSessionRequired: env.frontchannelLogoutSessionRequired,
	};
}

/**
 * Redis-backed SessionRPRegistry. Per A4 §5.2 + §7.2.1.
 *
 * Storage shape: one Redis HASH per sid, key = `${keyPrefix}${sid}`.
 * Each field in the hash is a `clientId`; its value is a JSON-encoded
 * `RPEnvelope`. HSET deduplication: writing the same `clientId` replaces
 * the earlier value (upsert semantics), satisfying the "same clientId
 * upserts" contract without any CAS loop.
 *
 * Why HSET-keyed-by-clientId over SADD-of-JSON:
 *   SADD-of-JSON cannot dedup when other RP fields change: a different
 *   `backchannelLogoutUri` produces different bytewise JSON for the same
 *   logical clientId, creating duplicate set members. HSET uses the field
 *   name as the dedup key, which is exactly `clientId`.
 *
 * TTL: a `PEXPIREAT … NX` + `PEXPIREAT … GT` pair is applied atomically in
 * the same pipeline as HSET via `createRedisSidHash.setField` (the bare GT
 * form silently no-ops on a key with no existing TTL — Redis treats no-TTL
 * as infinite TTL for the GT flag). The NX clause sets the TTL on first
 * write; the GT clause prevents TTL truncation under stale-`expiresAt`
 * concurrent writes. The timestamp is `session.expiresAt`, which is
 * post-create immutable per A4 §5.1. Required Redis floor is 7.2 LTS
 * per D-10.
 */
export function createRedisSessionRPRegistry(
	opts: RedisSessionRPRegistryOptions,
): SessionRPRegistry {
	const hash = createRedisSidHash({ client: opts.client, keyPrefix: opts.keyPrefix });
	return {
		kind: "redis",
		async registerRP(sid, rp, expiresAt) {
			await hash.setField(sid, rp.clientId, serialize(rp), expiresAt);
		},
		async listRPs(sid) {
			const values = await hash.listValues(sid);
			return values.map(deserialize);
		},
		async removeBySid(sid) {
			await hash.removeBySid(sid);
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SessionRPRegistry` (AS-9).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:rp:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Mirrors the boot-time guard pattern of `redisChallengeStoreBuilder`
 * (TS-M2): missing `client` throws at boot rather than crashing at first
 * Redis op.
 */
export const redisSessionRPRegistryBuilder: AdapterBuilder<SessionRPRegistry> = (config, _ctx) => {
	const c = config as { client?: SessionRPRegistryClient; keyPrefix?: string };
	if (!c.client) {
		throw new Error("redisSessionRPRegistryBuilder: 'client' option is required");
	}
	return createRedisSessionRPRegistry({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:rp:",
	});
};
