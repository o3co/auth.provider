/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

/**
 * One upstream connection's tokens, as a `FederationTokenStore` holds them.
 *
 * Every field is a required key, holding `undefined` when there is nothing to
 * record: a store that copies the record field by field and forgets one fails
 * to compile instead of silently dropping it (a marker field would be dropped
 * too). `record-fields.types.test.mts` lists what each field's loss changes.
 */
export interface FederationTokens {
	readonly accessToken: string;
	/**
	 * Absent means the connection cannot be refreshed: the token route answers
	 * `410 refresh_token_absent` and the user has to sign in again. `undefined`
	 * when the upstream issued none (GitHub OAuth App tokens).
	 */
	readonly refreshToken: string | undefined;
	/**
	 * What `POST /oauth/federation/:name/logout` sends the upstream as
	 * `id_token_hint`. `undefined` when the upstream issued none.
	 */
	readonly idToken: string | undefined;
	/**
	 * Absolute expiry of `accessToken`. `null` means the upstream issued no
	 * finite expiry (e.g. GitHub OAuth App classic tokens): do not attempt
	 * refresh; reuse until the provider invalidates it. Required, so each
	 * adapter decides explicitly per provider. A `Date`, as for {@link UserSession}.
	 */
	readonly expiresAt: Date | null;
	/**
	 * How the upstream said this token is presented, in its own spelling
	 * (oauth4webapi lower-cases it). Written at link time, moved by a refresh
	 * that names one, and carried verbatim so a value that is not a token type
	 * reaches the consumer. A non-string an adapter named is recorded as `""`,
	 * which the consumer refuses.
	 *
	 * A store MUST round-trip this field through `attach`, `update` and `get`.
	 * A store that drops it fails OPEN: the token is then handed on as Bearer
	 * even when it is sender-constrained. The required key catches this only
	 * in TypeScript code that builds a `FederationTokens` (and in a storage
	 * shape declaring the same key, as the Redis envelope does); plain
	 * JavaScript, casts, `JSON.parse`, `Object.assign` or a spread writing
	 * `undefined` are held to the MUST alone.
	 *
	 * A store MUST hand back an unset value as `undefined` or absent, never
	 * `null`: the disclosure point refuses `null`, so a serialiser that writes
	 * `undefined` as `null` (MongoDB's driver unless `ignoreUndefined` is set)
	 * turns every connection whose adapter named no type into a refused one.
	 *
	 * Only `undefined` means the adapter named none (including records from
	 * adapters that predate the field). RFC 6749 §5.1 makes `token_type`
	 * REQUIRED, so `POST /oauth/federation/:name/token` reads it as `Bearer` and
	 * refuses every other non-bearer spelling, `null` included: a
	 * sender-constrained token cannot go to a caller that holds no proof key.
	 */
	readonly tokenType: string | undefined;
	/**
	 * What the token holds now, space-delimited (RFC 6749 §3.3). A refresh may
	 * narrow it, and this field moves with the token. `undefined` when the
	 * adapter named none and no requested list stood in for it.
	 */
	readonly scope: string | undefined;
	/**
	 * What the user consented to at link time: the ceiling a refreshed scope is
	 * bounded by (RFC 6749 §6). Written once and never moved by a refresh.
	 *
	 * Separate from `scope` because `scope` moves: bounding a refresh by the
	 * current value would make the first narrowing permanent, although an
	 * upstream may later answer with the full grant again.
	 *
	 * `undefined` on older records and when the adapter named no scope; the
	 * consumer then bounds by `scope`, which is conservative. A required key for
	 * the same reason, and with the same gaps, as `tokenType`.
	 */
	readonly grantedScope: string | undefined;
}

/**
 * Adapter primitive for federation token storage.
 */
export interface FederationTokenStore {
	readonly kind: string;

	/**
	 * Persist tokens for a session + federation. Production implementations
	 * MUST encrypt refreshToken at rest. Plaintext persistence is supported
	 * only as an explicit opt-in — the built-in redis adapter exposes this via
	 * `encryption.mode = "allow-plaintext"` (with a startup warning), and the
	 * built-in in-memory adapter is plaintext by design because the process
	 * boundary already contains it. Both opt-outs are intended for
	 * development / testing use only.
	 */
	attach(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	get(sid: string, federationName: string): Promise<FederationTokens | null>;

	/** Atomic replace. Called after a successful federation refresh. */
	update(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	/** Remove all federation entries for a session. Idempotent. */
	removeBySid(sid: string): Promise<void>;

	/** Delete a specific (sid, federationName) entry. Idempotent. */
	delete(sid: string, federationName: string): Promise<void>;
}

export type FederationTokenStoreFactory = AdapterFactory<FederationTokenStore>;

// ComponentMap declaration-merge: an optional slot, so oauthModule can list
// "federationTokenStore" as optional. When absent, federation-token routes
// answer 503.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationTokenStore?: FederationTokenStore;
	}
}

/**
 * Input for `acquireLock`: the (sid, federationName) lock identity and its
 * timeouts. `acquireLock` rejects with a `RangeError`, taking nothing, when
 * `ttlMs` is not a positive finite number, `waitForMs` is not a non-negative
 * finite one, or either ends past the Date range (`isStorableLifetime`): a NaN
 * TTL would never hold the lock and a NaN wait would never end.
 */
export interface AcquireLockOptions {
	readonly sid: string;
	readonly federationName: string;
	/** Lock TTL in milliseconds. Defaults to 5000. Rounded up to a whole millisecond where the store needs one. */
	readonly ttlMs?: number;
	/** Max wait for acquisition in milliseconds. Defaults to 4000 (just under ttlMs). */
	readonly waitForMs?: number;
}

/**
 * Result of `acquireLock`. `"held"` is reserved for a future non-blocking
 * acquire; implementations return `"timeout"` when the wait elapses with the
 * lock still held elsewhere. Lock-backend errors reject instead (see
 * {@link SupportsLock}).
 */
export type LockResult =
	| { readonly acquired: true; readonly release: () => Promise<void> }
	| { readonly acquired: false; readonly reason: "held" | "timeout" };

/**
 * Optional capability: advisory lock on (sid, federationName), used by
 * `POST /oauth/federation/:name/token` to keep concurrent refreshes from
 * stampeding the upstream. Detect it with {@link supportsLock}; without it the
 * refresh proceeds uncoordinated, which low-concurrency deployments accept.
 *
 * A rejected `acquireLock` is a backend failure (network, cluster down, auth)
 * the caller must handle, e.g. with 503 or an unlocked refresh.
 * Implementations SHOULD NOT turn such errors into `{ acquired: false }`: the
 * caller's response depends on telling the two apart.
 */
export interface SupportsLock {
	acquireLock(opts: AcquireLockOptions): Promise<LockResult>;
}

/**
 * Type guard for {@link SupportsLock}: `true` when `store.acquireLock` is a
 * function; `false` for `null`/`undefined`, so a lookup result can be passed
 * directly.
 */
export function supportsLock(
	store: FederationTokenStore | undefined | null,
): store is FederationTokenStore & SupportsLock {
	if (store == null) return false;
	return typeof (store as { acquireLock?: unknown }).acquireLock === "function";
}
