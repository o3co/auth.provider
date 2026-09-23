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
	AdapterBuilder,
	Logger,
	RegisteredRP,
	SessionRPRegistry,
} from "@o3co/auth-provider-core";
import type { SessionRPRegistryClient } from "./clients.mjs";
import { createRedisSidHash } from "./internal/redisSidHash.mjs";

export interface RedisSessionRPRegistryOptions {
	readonly client: SessionRPRegistryClient;
	readonly keyPrefix: string;
	readonly logger?: Logger;
}

/**
 * JSON envelope stored as a single HSET field value: a `RegisteredRP` with
 * `registeredAt` held as epoch milliseconds.
 *
 * Derived from `RegisteredRP` rather than written out, so every key the record
 * requires the envelope requires too — a write into it that forgot a logout
 * field fails to compile, where it would otherwise drop the RP from the logout
 * cascade — and a field added to the record cannot be left out of what the
 * store writes.
 *
 * `registeredAtMs: number` (epochMs hardening): a Date stored as a JSON string
 * is susceptible to timezone / precision drift on deserialize; epochMs is
 * loss-free and unambiguous.
 *
 * An unset logout field is `undefined`, which `JSON.stringify` leaves out, so
 * it is absent on the wire and read back as `undefined` — never `""` or
 * `null`. `isValidRPEnvelope` checks every field's type, present or not.
 */
type RPEnvelope = Omit<RegisteredRP, "registeredAt"> & { readonly registeredAtMs: number };

function serialize(rp: RegisteredRP): string {
	// A literal naming every field, so forgetting one is a compile error rather
	// than an RP silently dropped from the logout cascade. An unset field is
	// `undefined`, which `JSON.stringify` leaves out — nothing is coerced to
	// `""` or `false` on the way through.
	const env: RPEnvelope = {
		clientId: rp.clientId,
		registeredAtMs: rp.registeredAt.getTime(),
		backchannelLogoutUri: rp.backchannelLogoutUri,
		backchannelLogoutSessionRequired: rp.backchannelLogoutSessionRequired,
		frontchannelLogoutUri: rp.frontchannelLogoutUri,
		frontchannelLogoutSessionRequired: rp.frontchannelLogoutSessionRequired,
	};
	return JSON.stringify(env);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	// Reject arrays explicitly: `typeof [] === "object"` and `[] !== null`,
	// so without this guard a JSON payload like `["client-1", ...]` would
	// pass isRecord and be probed as an envelope (the field accesses would
	// return undefined and `isValidRPEnvelope` would reject, but only by
	// accident). Match the userSessionStore envelope guard's explicit
	// `!Array.isArray(...)` so the shape check fails closed at the same
	// layer as its sibling adapter.
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isOptional = (value: unknown, type: "string" | "boolean"): boolean =>
	value === undefined || typeof value === type;

/**
 * Every field, including the four logout ones: a stored record is data this
 * store did not necessarily write (D5). `backchannelLogoutSessionRequired:
 * "false"` would otherwise come back typed as a boolean and read as truthy —
 * `sid` sent to an RP that asked not to receive it — so a field of the wrong
 * type makes the whole record corrupt, as a bad `clientId` already does.
 */
function isValidRPEnvelope(env: unknown): env is RPEnvelope {
	if (!isRecord(env)) return false;
	return (
		typeof env.clientId === "string" &&
		typeof env.registeredAtMs === "number" &&
		Number.isFinite(env.registeredAtMs) &&
		isOptional(env.backchannelLogoutUri, "string") &&
		isOptional(env.backchannelLogoutSessionRequired, "boolean") &&
		isOptional(env.frontchannelLogoutUri, "string") &&
		isOptional(env.frontchannelLogoutSessionRequired, "boolean")
	);
}

function deserialize(json: string, sid: string, logger?: Logger): RegisteredRP | null {
	// Mirror the userSessionStore corrupt-envelope warn shape: object-first
	// `{ sid, reason, cause? }` so `sid` and `reason` are reliably emitted
	// as structured fields, and the parse error context is preserved as
	// `cause`. The previous implementation logged a raw JSON snippet,
	// which risked leaking sensitive data if a corrupt value happened to
	// contain credentials — drop it entirely.
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch (cause) {
		logger?.warn(
			{ sid, reason: "json_parse", cause },
			"session_rp_registry_corrupt_envelope: JSON.parse failed",
		);
		return null;
	}
	if (!isValidRPEnvelope(parsed)) {
		logger?.warn(
			{ sid, reason: "shape_invalid" },
			"session_rp_registry_corrupt_envelope: shape invalid",
		);
		return null;
	}
	const env = parsed;
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
	const logger = opts.logger;
	return {
		kind: "redis",
		async registerRP(sid, rp, expiresAt) {
			await hash.setField(sid, rp.clientId, serialize(rp), expiresAt);
		},
		async listRPs(sid) {
			const values = await hash.listValues(sid);
			return values
				.map((value) => deserialize(value, sid, logger))
				.filter((rp): rp is RegisteredRP => rp !== null);
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
 * Redis op. Optional `logger` is forwarded to the adapter for the
 * corrupt-envelope warn path emitted inside `listRPs()`; the
 * fail-closed behavior (corrupt entries are dropped from the result)
 * is independent of logger presence — when the logger is absent the
 * warn is silently swallowed but the security gate still triggers. The
 * spread idiom omits the field when the caller did not supply one
 * (preserves "absent" semantics under `exactOptionalPropertyTypes`).
 */
export const redisSessionRPRegistryBuilder: AdapterBuilder<SessionRPRegistry> = (config, _ctx) => {
	const c = config as {
		client?: SessionRPRegistryClient;
		keyPrefix?: string;
		logger?: Logger;
	};
	if (!c.client) {
		throw new Error("redisSessionRPRegistryBuilder: 'client' option is required");
	}
	return createRedisSessionRPRegistry({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:rp:",
		...(c.logger !== undefined ? { logger: c.logger } : {}),
	});
};
