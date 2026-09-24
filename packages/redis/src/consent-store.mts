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
 * Redis-backed `ConsentStore` and `PendingConsentStore` (#561) — what lets
 * the consent step for clients that are not first-party run under
 * `deployment.mode = "multi"`.
 *
 * The memory module is refused there, correctly: a consent granted on one
 * replica is asked for again on every other, and a request parked under a
 * challenge on one replica is unknown to the replica that receives the
 * answer. These adapters put both where every replica reads them. They are
 * provided together by one module, as the memory ones are: the consent step
 * needs both slots, and `createOAuthRouter` refuses a composition with one
 * and not the other.
 *
 * ### Keys
 *
 *     <keyPrefix>rec:<len>:<sub>|<len>:<clientId>   HASH   a consent record
 *     <keyPrefix>{pending}:ch:<challenge>           HASH   a parked request
 *     <keyPrefix>{pending}:sess:<sessionId>         ZSET   that session's challenges
 *
 * A consent record is one key, and every script over it touches that key
 * alone, so it needs no hash tag and its records spread across a Cluster.
 * The pair is encoded with length prefixes — the form the challenge and
 * replay stores use — because a subject or a client id may contain any
 * separator: `("a|b", "c")` and `("a", "b|c")` must not share a record.
 *
 * A parked request and its session's index are two keys, and `consume`
 * arrives with the challenge alone: it reaches the index through the record,
 * and `set` reaches the session's other requests through the index. Redis
 * Cluster runs a script in one slot, so the constant `{pending}` hash tag
 * puts them all there — at the cost of concentrating every parked request on
 * one slot, the trade `redisDeviceCodeStoreModule` makes with `{devauth}`
 * and for the same reason: a human-paced ceremony, bounded per session and
 * gone in minutes, not per-request traffic. The challenge and the session id
 * each follow a fixed segment of their own, after the tag, so neither can
 * spell the other's key or move the tag.
 *
 * ### Expiry is the timestamp; the TTL is a safety net
 *
 * Both records carry their own `expiresAt`, and every read compares it with
 * the caller's `Date.now()` — the port's contract is the timestamp, as it is
 * for `DeviceCodeStore`. The key TTL a write sets only reclaims records
 * nobody reads again (an abandoned consent page, a consent that lapsed
 * unasked), and it runs {@link CONSENT_EXPIRY_SLACK_MS} past the logical
 * expiry, so it never fires first. A consent recorded until revoked carries
 * no TTL at all — including when an earlier grant for the pair had one.
 *
 * ### The per-session bound
 *
 * `PENDING_CONSENT_PER_SESSION_LIMIT`, held in the script that parks a
 * request, through the session's index: expired requests leave first, then
 * the first-parked go until there is room — the memory adapter's rule, which
 * the shared contract suite checks for both.
 *
 * ### Corrupt records
 *
 * A stored value that is not the shape the port declares reads as absent, never
 * as a throw or a half-typed record — see "Reading what Redis hands back"
 * below for why absence, not an outage.
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
 * The TTL is measured from the write on the Redis server's clock; the expiry
 * is judged on the clock of whichever replica reads next. A reader running
 * behind the writer still holds the record live after the TTL — measured by
 * the writer — has run out, so without slack a skewed replica would find a
 * live consent missing (the user asked again) or an open consent page's
 * request gone. Both fail closed, but both are visible to a user who did
 * nothing wrong.
 *
 * Five minutes is the allowance `verifyJwt` grants for clock skew between
 * hosts by default (`clockSkewMs`), so a fleet whose clocks that verifier
 * tolerates is one this store tolerates too. Nothing is decided by the slack
 * — expiry is still the timestamp — so erring long costs only the memory of
 * an abandoned record for five more minutes; erring short costs a user.
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
// Nothing this package writes fails these checks. A value edited by hand,
// restored from a mismatched backup or written by another version can, and a
// record that is not the shape the port promises must not leave this file:
// the consent route binds a parked request to the session with
// `Buffer.from(pending.sessionId)`, which throws on anything but a string, and
// looks a request up by one challenge before consuming by the challenge the
// record names.
//
// A corrupt record reads as **absent** — `null` — and never throws. The port
// reserves a throw for a store that could not answer, which surfaces as
// `temporarily_unavailable`; a store that answered with garbage did answer,
// and "there is no consent" / "there is no pending request" is the answer
// that fails closed: the user is asked again, or told the page has expired.
// Turning corruption into an outage would instead make one bad key a
// permanent 503 for that user and client.
//
// The checks live here rather than in the Lua scripts so there is one
// definition of the shape, applied to whatever `ConsentStoreClient` or
// `PendingConsentStoreClient` a deployment wires, and so a JSON document is
// judged by `JSON.parse` rather than by `cjson`, which cannot tell `[]` from
// `{}`. The returned record is rebuilt field by field: nothing the store held
// beyond the port's fields reaches the caller.
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
			// infinite expiry left a consent with no TTL that no read could age
			// out. "Until revoked" is `undefined`, not Infinity.
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
				// Reclaimed as a second, compare-and-delete step rather than inside
				// the read script: the shape is judged here, once, for any client
				// (see "Reading what Redis hands back"), and the comparison keeps a
				// request re-parked in between from being taken with it. The answer
				// does not depend on the reclaim — the record is corrupt whether or
				// not it goes — so a failure to reclaim leaves it to its TTL and
				// still answers `null` rather than turning corruption into an
				// outage.
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
 * AdapterFactory builder for the Redis `ConsentStore` (composition pattern
 * §8.4). Register it next to {@link redisPendingConsentStoreBuilder}: the
 * consent step needs both slots, and `createOAuthRouter` refuses a
 * composition with one and not the other.
 *
 *   consentFactory.register("redis", redisConsentStoreBuilder);
 *   consentFactory.create({ type: "redis", client, keyPrefix: "consent:" });
 */
export const redisConsentStoreBuilder: AdapterBuilder<ConsentStore> = (config, _ctx) => {
	const c = config as { client?: ConsentStoreClient; keyPrefix?: string };
	// Same structural guard as `redisDeviceCodeStoreBuilder`: fail at boot
	// rather than at the first `/authorize` for a third-party client.
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
 * clients — the counterpart of core's `memoryConsentStoreModule`, one switch
 * for one feature.
 *
 * Declares no `replicaSafety`, which is the point: a composition wiring the
 * consent step with this module may declare `deployment.mode = "multi"`. The
 * `consentStoreClient` and `pendingConsentStoreClient` slots it requires come
 * from `makeIoredisClients` (or the standalone's shared clients module).
 *
 * configSchema: top-level key `redisConsentStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
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
