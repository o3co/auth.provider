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
 * The consent stores' clients: the recorded consent, one key per subject and client, and the
 * parked requests, whose records and per-session index hash to one slot.
 */

// --- ConsentStoreClient ----------------------------------------------------

/**
 * A consent record as it lives in Redis: one hash per (`sub`, `clientId`),
 * every field a string. The field names are part of the contract because the
 * scripts read them by name.
 *
 * The scopes are one JSON array rather than a Redis set, so a scope value is
 * stored byte-for-byte and the order they were first granted in survives —
 * and so the record and its `grantedAt` / `expiresAt` are one key that one
 * script rewrites whole. The hash has no `expiresAt` field for a consent
 * recorded until revoked; a client reports that as `expiresAt: undefined`.
 */
export interface ConsentRecordFields {
	/** JSON array of the scopes agreed to. */
	readonly scopes: string;
	/** Epoch milliseconds. */
	readonly grantedAt: string;
	/**
	 * Epoch milliseconds; `undefined` when the hash holds none — until revoked.
	 * A required key: a client whose `find` forgot to pass the field on
	 * would have the adapter read a consent meant to lapse as one until revoked
	 * — unless, as `makeIoredisClients`' script does, `find` already refuses a
	 * record past its expiry.
	 */
	readonly expiresAt: string | undefined;
}

export interface GrantConsentInput {
	/** The caller's clock, in epoch milliseconds: what "still live" is judged against. */
	readonly nowMs: number;
	/** The scopes this grant adds. */
	readonly scopes: readonly string[];
	readonly grantedAt: number;
	/**
	 * The new record's expiry. `undefined`, the record is until revoked and the
	 * key carries **no** TTL afterwards — whatever an earlier grant set is
	 * removed. A required key: a store that forgot to pass it would
	 * record every consent until revoked.
	 */
	readonly expiry:
		| {
				/** Epoch milliseconds, stored as the record's `expiresAt`. */
				readonly expiresAt: number;
				/**
				 * The key's TTL in milliseconds — a safety net for a record nobody reads
				 * again, never what expiry is judged by. Not positive: the new record is
				 * dead on arrival, so the key is removed and nothing is written.
				 */
				readonly ttlMs: number;
		  }
		| undefined;
}

/**
 * Backing client for the `ConsentStore` adapter.
 *
 * Semantic operations rather than commands, as {@link DeviceCodeStoreClient},
 * because `grant` is the port's union: as `HGET` then `HSET` from the client,
 * two browsers consenting to different scopes at once each write back what
 * they read, and one grant is lost. Lua is the obvious implementation (see
 * `makeIoredisClients`) but anything indivisible over the one key satisfies
 * this. Every operation touches exactly the one key it is handed, so this
 * client needs no hash tag to run on Cluster.
 */
export interface ConsentStoreClient {
	/**
	 * The record at `key`, or `null` when there is none or its `expiresAt` is
	 * at or before `nowMs`. An expired record is removed on the way, in the same
	 * step as the read — a separate `DEL` could remove a grant written in
	 * between. The fields are returned as stored; judging their shape is the
	 * adapter's.
	 */
	find(key: string, nowMs: number): Promise<ConsentRecordFields | null>;
	/**
	 * Atomically replace the record at `key` with one whose scopes are the
	 * union of `input.scopes` and those of the record already there — only if
	 * that record is still live at `input.nowMs` and well-formed (`scopes` a
	 * JSON array of strings, `grantedAt` a number); an expired or corrupt one
	 * contributes nothing, as `find` reports it absent. `grantedAt` and the
	 * expiry are the new record's, and so is the key's TTL: set from
	 * `expiry.ttlMs`, or removed when there is no expiry.
	 */
	grant(key: string, input: GrantConsentInput): Promise<void>;
	/** Remove the record. Resolves whether there was one. */
	revoke(key: string): Promise<boolean>;
}

// --- PendingConsentStoreClient ---------------------------------------------

/**
 * Where parked consent requests live: `recordKeyPrefix + challenge` holds a
 * request, `sessionKeyPrefix + sessionId` holds the challenges that session
 * has parked, in the order it parked them.
 *
 * **The two prefixes must hash to the same slot.** `consume` arrives with the
 * challenge alone and takes the request out of its session's index in the
 * same script, reaching the index through the record — a key the caller could
 * not declare up front — and `set` reaches the session's other records
 * through the index. `createRedisPendingConsentStore` guarantees this with
 * one constant `{pending}` hash tag in both prefixes; a custom keyspace has to
 * guarantee it too.
 */
export interface PendingConsentKeyspace {
	readonly recordKeyPrefix: string;
	readonly sessionKeyPrefix: string;
}

export interface ParkPendingConsentInput {
	readonly challenge: string;
	readonly sessionId: string;
	/** Epoch milliseconds on the caller's clock. What expiry is judged by — not the TTL. */
	readonly expiresAt: number;
	/** The caller's clock, in epoch milliseconds. */
	readonly nowMs: number;
	/**
	 * The record key's TTL in milliseconds, a safety net only; the session index
	 * is kept alive at least as long as its longest-lived member. Not positive:
	 * the request is dead on arrival and is not parked.
	 */
	readonly ttlMs: number;
	/** The request, serialised by the adapter, stored and returned byte-for-byte. */
	readonly record: string;
	/** How many requests the session may have parked once this one is. A positive integer. */
	readonly perSessionLimit: number;
}

/**
 * Backing client for the `PendingConsentStore` adapter.
 *
 * Semantic operations, for the reason {@link DeviceCodeStoreClient} gives:
 * `consume` is the port's reason to exist — as a `GET` then a `DEL`, two
 * answers in flight for one challenge are both handed the request, and a
 * denial and an acceptance both apply — and the per-session bound only holds
 * if the index and the records move together.
 */
export interface PendingConsentStoreClient {
	/**
	 * Park `input.record` under its challenge — atomically:
	 *
	 *   - a request already parked under the challenge is replaced, and leaves
	 *     its own session's index (which may be another session's)
	 *   - requests of this session that have expired at `nowMs`, or whose record
	 *     is already gone, leave its index before the bound is judged
	 *   - while the session holds `perSessionLimit` or more, the one it parked
	 *     first is removed, record and index entry together
	 *   - the record is written with its TTL and appended to the index
	 */
	set(keys: PendingConsentKeyspace, input: ParkPendingConsentInput): Promise<void>;
	/**
	 * The serialised request, or `null` when there is none or it has expired at
	 * `nowMs`. Does not spend a live request; an expired one is removed with its
	 * index entry on the way.
	 */
	get(keys: PendingConsentKeyspace, challenge: string, nowMs: number): Promise<string | null>;
	/**
	 * The serialised request, removed with its index entry in the same step —
	 * or `null` when there was nothing live to remove. An expired request is
	 * removed too, and answers `null`.
	 */
	consume(keys: PendingConsentKeyspace, challenge: string, nowMs: number): Promise<string | null>;
	/**
	 * Remove the request parked under `challenge`, with its index entry — but
	 * only while the stored serialisation is still exactly `record`, compared
	 * and removed atomically. Resolves whether it was removed.
	 *
	 * The adapter's reclaim for a record `get` read and found corrupt. The
	 * comparison is what makes it safe to issue after the read: a valid request
	 * re-parked under the challenge in between is a different value, and stays.
	 */
	discard(keys: PendingConsentKeyspace, challenge: string, record: string): Promise<boolean>;
}
