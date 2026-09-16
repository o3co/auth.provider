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
 */

import {
	type AdapterBuilder,
	type ConsentRecord,
	type ConsentStore,
	canonicalChallengeKey,
	defineModule,
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

const parseScopes = (json: string): readonly string[] => {
	// The script only ever writes a JSON array of strings; anything else is
	// external mutation and reads as no scope, which covers only an empty
	// request — the fail-closed direction for a consent.
	try {
		const parsed: unknown = JSON.parse(json);
		return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === "string") : [];
	} catch {
		return [];
	}
};

const toConsentRecord = (
	sub: string,
	clientId: string,
	fields: ConsentRecordFields,
): ConsentRecord => ({
	sub,
	clientId,
	scopes: parseScopes(fields.scopes),
	grantedAt: Number(fields.grantedAt),
	...(fields.expiresAt === undefined ? {} : { expiresAt: Number(fields.expiresAt) }),
});

const toPendingRecord = (json: string | null): PendingConsentRecord | null => {
	if (json === null) return null;
	// Written by `set` from `JSON.stringify` of the record; a value that does
	// not parse to an object is external mutation, and a challenge with nothing
	// behind it answers nothing.
	try {
		const parsed: unknown = JSON.parse(json);
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as PendingConsentRecord)
			: null;
	} catch {
		return null;
	}
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
			const fields = await client.find(key(sub, clientId), Date.now());
			return fields === null ? null : toConsentRecord(sub, clientId, fields);
		},

		async grant(record) {
			const nowMs = Date.now();
			await client.grant(key(record.sub, record.clientId), {
				nowMs,
				scopes: record.scopes,
				grantedAt: record.grantedAt,
				...(record.expiresAt === undefined
					? {}
					: {
							expiry: {
								expiresAt: record.expiresAt,
								ttlMs: safetyNetTtlMs(record.expiresAt, nowMs),
							},
						}),
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
			return toPendingRecord(await client.get(keys, challenge, Date.now()));
		},

		async consume(challenge) {
			return toPendingRecord(await client.consume(keys, challenge, Date.now()));
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
