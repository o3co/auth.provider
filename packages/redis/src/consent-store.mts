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

/**
 * Redis-backed `ConsentStore` and `PendingConsentStore`: consent records and
 * parked consent requests every replica reads, so the consent step for
 * non-first-party clients can run under `deployment.mode = "multi"`. One module
 * provides both slots; `createOAuthRouter` refuses a composition with one and
 * not the other.
 *
 *     <keyPrefix>rec:<len>:<sub>|<len>:<clientId>   HASH   a consent record
 *     <keyPrefix>{pending}:ch:<challenge>           HASH   a parked request
 *     <keyPrefix>{pending}:sess:<sessionId>         ZSET   that session's challenges
 *
 * A consent record is one key, so it needs no hash tag. The pair is
 * length-prefixed because a subject or client id may contain any separator:
 * `("a|b", "c")` and `("a", "b|c")` must not share a record.
 *
 * `consume` reaches the session index through the record, and `set` reaches the
 * session's other requests through the index, each in one script; Redis Cluster
 * runs a script in one slot, so the constant `{pending}` tag puts every parked
 * request on one slot (acceptable for a human-paced ceremony, bounded per
 * session and gone in minutes). The challenge and the session id each follow a
 * fixed segment after the tag, so neither can spell the other's key or move it.
 *
 * Expiry is each record's own `expiresAt` against the caller's `Date.now()`.
 * The key TTL only reclaims records nobody reads again and runs
 * {@link CONSENT_EXPIRY_SLACK_MS} past the expiry, so it never fires first. A
 * consent recorded until revoked has no TTL, even if an earlier grant had one.
 *
 * `PENDING_CONSENT_PER_SESSION_LIMIT` is held in the parking script: expired
 * requests leave first, then the oldest, as in the memory adapter. A stored
 * value that is not the port's shape reads as absent (see "Reading what Redis
 * hands back" below).
 */

import {
	type AdapterBuilder,
	type ConsentRecord,
	type ConsentStore,
	canonicalChallengeKey,
	defineModule,
	isStorableExpiry,
	PENDING_CONSENT_PER_SESSION_LIMIT,
	type PendingConsentRecord,
	type PendingConsentStore,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type {
	ConsentRecordFields,
	ConsentStoreClient,
	PendingConsentKeyspace,
	PendingConsentStoreClient,
} from "./clients.mjs";

/**
 * How far past a record's `expiresAt` its key's TTL runs: five minutes.
 *
 * The TTL runs on the Redis server's clock; expiry is judged on the reading
 * replica's. Without slack, a replica running behind would find a live consent
 * or an open consent page's request already gone. Five minutes is `verifyJwt`'s
 * default `clockSkewMs`. The slack decides nothing (expiry is still the
 * timestamp), so erring long costs only memory.
 */
export const CONSENT_EXPIRY_SLACK_MS = 5 * 60 * 1000;

/** The TTL that keeps a record past `expiresAt` by the slack, measured from `nowMs`. */
const safetyNetTtlMs = (expiresAt: number, nowMs: number): number =>
	Math.ceil(expiresAt - nowMs) + CONSENT_EXPIRY_SLACK_MS;

/**
 * The hash tag every parked request and session index shares. Constant on
 * purpose: it is what puts a record and the index that bounds it in one slot
 * (see the file header).
 */
const PENDING_CONSENT_HASH_TAG = "{pending}";

// ---------------------------------------------------------------------------
// Reading what Redis hands back
//
// A value edited by hand, restored from a mismatched backup or written by
// another version must not leave this file unless it is the port's shape: the
// consent route calls `Buffer.from(pending.sessionId)`, which throws on
// anything but a string.
//
// A corrupt record reads as absent (`null`), never a throw. A throw means the
// store could not answer (`temporarily_unavailable`); absence fails closed (the
// user is asked again, or told the page expired), where a throw would make one
// bad key a permanent 503 for that user and client.
//
// The checks live here rather than in Lua so one definition covers any wired
// client, and JSON is judged by `JSON.parse`, not `cjson` (which cannot tell
// `[]` from `{}`). Records are rebuilt field by field, so nothing beyond the
// port's fields reaches the caller.
// ---------------------------------------------------------------------------

const isString = (value: unknown): value is string => typeof value === "string";

const isStringArray = (value: unknown): value is string[] =>
	Array.isArray(value) && value.every(isString);

const isFiniteNumber = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

/** A stored decimal: `Number("")` is 0, so emptiness is refused before conversion. */
const storedNumber = (value: string): number | null => {
	if (value.trim() === "") return null;
	const parsed = Number(value);
	return Number.isFinite(parsed) ? parsed : null;
};

const toConsentRecord = (
	sub: string,
	clientId: string,
	fields: ConsentRecordFields,
): ConsentRecord | null => {
	if (!isString(fields.scopes) || !isString(fields.grantedAt)) return null;
	let scopes: unknown;
	try {
		scopes = JSON.parse(fields.scopes);
	} catch {
		return null;
	}
	if (!isStringArray(scopes)) return null;
	const grantedAt = storedNumber(fields.grantedAt);
	if (grantedAt === null) return null;
	if (fields.expiresAt === undefined)
		return { sub, clientId, scopes, grantedAt, expiresAt: undefined };
	const expiresAt = isString(fields.expiresAt) ? storedNumber(fields.expiresAt) : null;
	if (expiresAt === null) return null;
	return { sub, clientId, scopes, grantedAt, expiresAt };
};

/**
 * The parked request `json` holds, if it is one — every field the port
 * declares, of its declared type — and it was parked under `challenge`.
 */
const toPendingRecord = (json: string, challenge: string): PendingConsentRecord | null => {
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		return null;
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
	const r = parsed as Record<string, unknown>;
	// Bound to the key it was read from: a record naming another challenge
	// would have the route consume a request other than the one it showed.
	if (r.challenge !== challenge) return null;
	const state = r.state;
	if (
		!isString(r.sessionId) ||
		!isString(r.sub) ||
		!isString(r.clientId) ||
		!isStringArray(r.scopes) ||
		!isStringArray(r.grantedScopes) ||
		!isString(r.authorizeUrl) ||
		!isString(r.redirectUri) ||
		!isFiniteNumber(r.createdAt) ||
		!isFiniteNumber(r.expiresAt) ||
		(state !== undefined && !isString(state))
	) {
		return null;
	}
	return {
		challenge,
		sessionId: r.sessionId,
		sub: r.sub,
		clientId: r.clientId,
		scopes: r.scopes,
		grantedScopes: r.grantedScopes,
		authorizeUrl: r.authorizeUrl,
		redirectUri: r.redirectUri,
		state,
		createdAt: r.createdAt,
		expiresAt: r.expiresAt,
	};
};

/** Options for {@link createRedisConsentStore}. */
export interface RedisConsentStoreOptions {
	readonly client: ConsentStoreClient;
	/** Outer namespace; the `rec:` segment follows it. */
	readonly keyPrefix: string;
}

export function createRedisConsentStore(opts: RedisConsentStoreOptions): ConsentStore {
	const { client, keyPrefix } = opts;
	const key = (sub: string, clientId: string): string =>
		`${keyPrefix}rec:${canonicalChallengeKey(sub, clientId)}`;

	return {
		kind: "redis",

		async find(sub, clientId) {
			// A corrupt record reads as no consent and is left in place: the grant
			// script gives it no weight either, so the user's next answer replaces
			// it whole. A record with a TTL still ages out on it.
			const fields = await client.find(key(sub, clientId), Date.now());
			return fields === null ? null : toConsentRecord(sub, clientId, fields);
		},

		async grant(record) {
			// The script writes the record before it sets the TTL, so a NaN or
			// infinite expiry would leave a consent that nothing ages out.
			// "Until revoked" is `undefined`, not Infinity.
			if (record.expiresAt !== undefined && !isStorableExpiry(record.expiresAt)) {
				throw new RangeError(
					`ConsentStore.grant: expiresAt must be undefined or a finite instant within the Date range (got ${String(record.expiresAt)})`,
				);
			}
			const nowMs = Date.now();
			await client.grant(key(record.sub, record.clientId), {
				nowMs,
				scopes: record.scopes,
				grantedAt: record.grantedAt,
				expiry:
					record.expiresAt === undefined
						? undefined
						: {
								expiresAt: record.expiresAt,
								ttlMs: safetyNetTtlMs(record.expiresAt, nowMs),
							},
			});
		},

		async revoke(sub, clientId) {
			return client.revoke(key(sub, clientId));
		},
	};
}

/** Options for {@link createRedisPendingConsentStore}. */
export interface RedisPendingConsentStoreOptions {
	readonly client: PendingConsentStoreClient;
	/** Outer namespace; the `{pending}` hash tag and the `ch:` / `sess:` segments follow it. */
	readonly keyPrefix: string;
}

export function createRedisPendingConsentStore(
	opts: RedisPendingConsentStoreOptions,
): PendingConsentStore {
	const { client, keyPrefix } = opts;
	const keys: PendingConsentKeyspace = {
		recordKeyPrefix: `${keyPrefix}${PENDING_CONSENT_HASH_TAG}:ch:`,
		sessionKeyPrefix: `${keyPrefix}${PENDING_CONSENT_HASH_TAG}:sess:`,
	};

	return {
		kind: "redis",

		async set(record) {
			// Refused before the script writes the request it would then fail to
			// expire.
			if (!isStorableExpiry(record.expiresAt)) {
				throw new RangeError(
					`PendingConsentStore.set: expiresAt must be a finite instant within the Date range (got ${String(record.expiresAt)})`,
				);
			}
			const nowMs = Date.now();
			await client.set(keys, {
				challenge: record.challenge,
				sessionId: record.sessionId,
				expiresAt: record.expiresAt,
				nowMs,
				ttlMs: safetyNetTtlMs(record.expiresAt, nowMs),
				// Serialised here, so the caller mutating its arrays afterwards
				// changes nothing that was parked.
				record: JSON.stringify(record),
				perSessionLimit: PENDING_CONSENT_PER_SESSION_LIMIT,
			});
		},

		async get(challenge) {
			const json = await client.get(keys, challenge, Date.now());
			if (json === null) return null;
			const record = toPendingRecord(json, challenge);
			if (record === null) {
				// Reclaimed by a separate compare-and-delete, since the shape is
				// judged here, not in the read script (see "Reading what Redis hands
				// back"); the compare spares a request re-parked in between. A failed
				// reclaim leaves it to its TTL and still answers `null`.
				await client.discard(keys, challenge, json).catch(() => false);
			}
			return record;
		},

		async consume(challenge) {
			// The consume script has already removed the record and its index
			// entry, corrupt or not, so there is nothing left to reclaim.
			const json = await client.consume(keys, challenge, Date.now());
			return json === null ? null : toPendingRecord(json, challenge);
		},
	};
}

/**
 * AdapterFactory builder for the Redis `ConsentStore`. Register it next to
 * {@link redisPendingConsentStoreBuilder}: `createOAuthRouter` refuses a
 * composition with one consent slot and not the other.
 */
export const redisConsentStoreBuilder: AdapterBuilder<ConsentStore> = (config, _ctx) => {
	const c = config as { client?: ConsentStoreClient; keyPrefix?: string };
	// Fail at boot rather than at the first `/authorize` for a third-party client.
	if (!c.client) {
		throw new Error("redisConsentStoreBuilder: 'client' option is required");
	}
	return createRedisConsentStore({ client: c.client, keyPrefix: c.keyPrefix ?? "consent:" });
};

/**
 * AdapterFactory builder for the Redis `PendingConsentStore` — the sibling of
 * {@link redisConsentStoreBuilder}, with the same default namespace.
 */
export const redisPendingConsentStoreBuilder: AdapterBuilder<PendingConsentStore> = (
	config,
	_ctx,
) => {
	const c = config as { client?: PendingConsentStoreClient; keyPrefix?: string };
	if (!c.client) {
		throw new Error("redisPendingConsentStoreBuilder: 'client' option is required");
	}
	return createRedisPendingConsentStore({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "consent:",
	});
};

/**
 * `defineModule` manifest providing both consent slots off the shared Redis
 * clients, the counterpart of core's `memoryConsentStoreModule`. Declares no
 * `replicaSafety`, so a composition using it may declare
 * `deployment.mode = "multi"`. Its client slots come from `makeIoredisClients`
 * (or the standalone's shared clients module); config lives under
 * `redisConsentStore`, never a bare top-level `keyPrefix`.
 */
export const redisConsentStoreModule = defineModule({
	name: "redis-consent-store",
	requires: ["consentStoreClient", "pendingConsentStoreClient", "config"] as const,
	configSchema: z.object({
		redisConsentStore: z
			.object({
				keyPrefix: z.string().default("consent:"),
			})
			.default({ keyPrefix: "consent:" }),
	}),
	provides: {
		consentStore: (deps) => {
			const cfg = (deps.config as unknown as { redisConsentStore: { keyPrefix: string } })
				.redisConsentStore;
			return createRedisConsentStore({
				client: deps.consentStoreClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
		pendingConsentStore: (deps) => {
			const cfg = (deps.config as unknown as { redisConsentStore: { keyPrefix: string } })
				.redisConsentStore;
			return createRedisPendingConsentStore({
				client: deps.pendingConsentStoreClient,
				keyPrefix: cfg.keyPrefix,
			});
		},
	},
});
