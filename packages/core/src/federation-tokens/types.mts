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
 * Every field is a REQUIRED key; a field with nothing to record holds
 * `undefined`. A store often copies this record field by field, and a field it
 * forgets is dropped without a sound — while every field here changes what
 * happens when it is gone (`record-fields.types.test.mts` lists what). No
 * marker in the record could catch that, since a store that drops fields drops
 * the marker too; a required key makes an object literal that forgets one fail
 * to compile. `expiresAt` was the first field held to this, and for the same
 * reason.
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
	 * Absolute expiry time of `accessToken`. `null` means the upstream provider
	 * did not issue a finite expiry (e.g. GitHub OAuth Apps classic tokens).
	 * Consumers MUST treat `null` as "do not attempt refresh; reuse until the
	 * provider explicitly invalidates". Required (no `undefined`) so adapters
	 * are forced to make an explicit decision per provider.
	 *
	 * Expiry encoding: `Date` per A4 two-tier design — see {@link UserSession}
	 * for rationale.
	 */
	readonly expiresAt: Date | null;
	/**
	 * How the upstream said this token is presented, in the upstream's own
	 * spelling (oauth4webapi lower-cases it). Written at link time and moved by
	 * a refresh that names one; carried verbatim, so a value that is not a token
	 * type reaches the consumer rather than being erased into silence. An
	 * adapter that named something which is not a string is recorded as `""`,
	 * which this field can hold and the consumer already refuses.
	 *
	 * A store MUST round-trip this field through `attach`, `update` and `get`.
	 * One that copies the record field by field and forgets it fails OPEN: the
	 * record comes back silent, silence is read as a record written before
	 * #645, and a sender-constrained token is handed on as Bearer — the
	 * behaviour #645 removed, restored for that store alone. Both bundled
	 * stores round-trip it and are pinned on it (the in-memory store's
	 * defensive copy is exactly that field-by-field pattern). No marker in the
	 * record could detect a store that drops fields — it would drop the marker
	 * too — so the TYPE does what it can: the key is required, and an object
	 * literal of this type that leaves it out fails to compile
	 * (`record-fields.types.test.mts`). That reaches code that BUILDS a
	 * `FederationTokens`: a store's `get`, and every caller of `attach` and
	 * `update`. It does not reach a store's own storage shape unless the
	 * adapter declares the same required key there — the bundled Redis store's
	 * envelope does, so a projection into it that forgets the field fails too.
	 * Nor does it reach a store in plain JavaScript, or code that steps around
	 * the checker: `as FederationTokens` on an incomplete literal,
	 * `JSON.parse(raw) as FederationTokens`, `Object.assign`, or a spread that
	 * overwrites the field with `undefined`. Those are held to the MUST alone.
	 *
	 * A store MUST also hand back an unset value as `undefined` or absent — never
	 * `null`. The disclosure point refuses `null` (a store is not believed), so a
	 * serialiser that writes `undefined` as `null` turns every connection whose
	 * adapter named no type into a refused one: MongoDB's driver does this unless
	 * `ignoreUndefined` is set. Records carry the key as `undefined` whenever the
	 * adapter named none, both at link time and after a refresh.
	 *
	 * `undefined` — and only `undefined` — means the adapter named none: every bundled
	 * adapter but `federation-oidc`, and every record written before #645. RFC
	 * 6749 §5.1 makes `token_type` REQUIRED, so `POST /oauth/federation/:name/
	 * token` reads that as `Bearer` and refuses everything else that is not a
	 * bearer spelling, `null` included: a sender-constrained token cannot be
	 * handed to a caller that holds no proof key, and a malformed record is not
	 * a second spelling of silence.
	 */
	readonly tokenType: string | undefined;
	/**
	 * What the token holds now, space-delimited (RFC 6749 §3.3). A refresh may
	 * narrow it, and this field moves with the token. `undefined` when the
	 * adapter named none and no requested list stood in for it.
	 */
	readonly scope: string | undefined;
	/**
	 * What the user consented to when the federation was linked: the ceiling a
	 * refreshed scope is bounded by, per RFC 6749 §6 — "the scope of the access
	 * token … MUST NOT include any scope not originally granted". Written once,
	 * at link time, and never moved by a refresh.
	 *
	 * It has to be its own field because `scope` moves. Judging a refresh
	 * against the current value makes the first narrowing permanent: an upstream
	 * that narrows once and later answers with the full grant again is within
	 * its rights, and the record could never be repaired (#647).
	 *
	 * `undefined` on a record written before #647, and on one whose adapter
	 * named no scope. The consumer then has only `scope` to bound against, which
	 * is conservative rather than wrong.
	 *
	 * A required key for the same reason as `tokenType`, with the same reach
	 * and the same gaps: a store that copies the record field by field and
	 * forgets this one drops the consent it records without a sound, and the
	 * type is what can notice.
	 */
	readonly grantedScope: string | undefined;
	/**
	 * The upstream's raw token response. Carried forward by every refresh and
	 * encrypted by the Redis store (#293) — but no producer in this repository
	 * writes it: no adapter reports the raw response, and both link-time
	 * `attach` sites record `undefined`. It has been that way since the field
	 * was added (#74).
	 */
	readonly rawParams: Readonly<Record<string, unknown>> | undefined;
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
	 * development / testing use only. See spec Section 5.
	 */
	attach(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	get(sid: string, federationName: string): Promise<FederationTokens | null>;

	/** Atomic replace. Called after a successful federation refresh. */
	update(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	/**
	 * Remove all federation entries for a session. Idempotent.
	 *
	 * Verb-aligned with sibling session stores
	 * ({@link UserSessionStore}, {@link SessionRPRegistry},
	 * {@link SessionFamilyIndex}, {@link SessionFederationIndex}) which all
	 * expose `removeBySid(sid)` for the same "bulk-remove records scoped to
	 * a session id" responsibility.
	 *
	 * Renamed from `deleteBySession` in v0.5.1 (AS-3); the old name is no
	 * longer accepted because `FederationTokenStore` was new in v0.5.0
	 * and the v0.5.1 hotfix policy explicitly permits this rename for
	 * interfaces that have had no external consumers.
	 */
	removeBySid(sid: string): Promise<void>;

	/** Delete a specific (sid, federationName) entry. Idempotent. */
	delete(sid: string, federationName: string): Promise<void>;
}

export type FederationTokenStoreFactory = AdapterFactory<FederationTokenStore>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A2-α §6.1 — optional slot)
//
// Declared here so oauthModule can list "federationTokenStore" in its
// `optional` array and the DI graph types deps.federationTokenStore as
// FederationTokenStore | undefined.
// The slot is optional: when absent, federation-token routes return 503
// (no store available to retrieve / refresh upstream tokens).
// Phase 9 Task 4 augmentation.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationTokenStore?: FederationTokenStore;
	}
}

/**
 * Input for acquireLock — identifies the lock by (sid, federationName) pair
 * and provides timeout knobs.
 */
export interface AcquireLockOptions {
	readonly sid: string;
	readonly federationName: string;
	/** Lock TTL in milliseconds. Defaults to 5000. */
	readonly ttlMs?: number;
	/** Max wait for acquisition in milliseconds. Defaults to 4000 (just under ttlMs). */
	readonly waitForMs?: number;
}

/**
 * Result of `acquireLock`. The `"held"` reason is reserved for future use
 * where a non-blocking acquire semantics is added; current implementations
 * return `"timeout"` whenever the wait deadline elapses with the lock still
 * held by another owner.
 *
 * Note: lock-implementation-level errors (e.g. redis network outage) are NOT
 * surfaced here — `acquireLock` rejects instead. See {@link SupportsLock}.
 */
export type LockResult =
	| { readonly acquired: true; readonly release: () => Promise<void> }
	| { readonly acquired: false; readonly reason: "held" | "timeout" };

/**
 * Optional capability: advisory lock on (sid, federationName) pairs, used by
 * `POST /oauth/federation/:name/token` (TODO-F-6) to prevent concurrent
 * federation-refresh thundering herd. Consumers detect presence with
 * {@link supportsLock}; when absent, the refresh path proceeds without
 * coordination — acceptable for low-concurrency deployments.
 *
 * ## Error semantics
 *
 * `acquireLock` returns a `LockResult` discriminated union for the two expected
 * outcomes — acquired or wait-timed-out. A thrown/rejected Promise from
 * `acquireLock` indicates a **client-level failure** (network partition,
 * cluster down, authentication error) that the caller must decide how to
 * handle: typical choices are to surface HTTP 503 or to fall back to an
 * unlocked refresh. Lock implementations SHOULD NOT internalize these errors
 * as `{ acquired: false }` because the caller's response code depends on
 * whether the failure is transient-operational or protocol-level.
 */
export interface SupportsLock {
	acquireLock(opts: AcquireLockOptions): Promise<LockResult>;
}

/**
 * Structural type guard for the {@link SupportsLock} capability.
 *
 * Returns `false` for `null` / `undefined` so consumers can call this directly on
 * results without an explicit existence check. When `store` is non-null, returns
 * `true` when `store.acquireLock` is a function. Inside a `true` branch, TypeScript
 * narrows `store` to `FederationTokenStore & SupportsLock`, so
 * `store.acquireLock(...)` is callable without a cast.
 */
export function supportsLock(
	store: FederationTokenStore | undefined | null,
): store is FederationTokenStore & SupportsLock {
	if (store == null) return false;
	return typeof (store as { acquireLock?: unknown }).acquireLock === "function";
}

// ---------------------------------------------------------------------------
// Backing client interface (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

// FederationTokenStoreClient backing-client interface relocated to
// @o3co/auth-provider-redis (v0.5.0 pre-tag interface review S3).
