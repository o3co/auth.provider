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

export interface FederationTokens {
	readonly accessToken: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	/**
	 * Absolute expiry time of `accessToken`. `null` means the upstream provider
	 * did not issue a finite expiry (e.g. GitHub OAuth Apps classic tokens).
	 * Consumers MUST treat `null` as "do not attempt refresh; reuse until the
	 * provider explicitly invalidates". Required (no `undefined`) so adapters
	 * are forced to make an explicit decision per provider.
	 */
	readonly expiresAt: Date | null;
	readonly tokenType?: string;
	readonly scope?: string;
	readonly rawParams?: Readonly<Record<string, unknown>>;
}

export interface FederationTokenStoreBase {
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

	/** Delete all federation entries for a session. Idempotent. */
	deleteBySession(sid: string): Promise<void>;

	/** Delete a specific (sid, federationName) entry. Idempotent. */
	delete(sid: string, federationName: string): Promise<void>;
}

export type FederationTokenStoreFactory = AdapterFactory<FederationTokenStoreBase>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A2-α §6.1 — optional slot)
//
// Declared here so oauthModule can list "federationTokenStore" in its
// `optional` array and the DI graph types deps.federationTokenStore as
// FederationTokenStoreBase | undefined.
// The slot is optional: when absent, federation-token routes return 503
// (no store available to retrieve / refresh upstream tokens).
// Phase 9 Task 4 augmentation.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationTokenStore?: FederationTokenStoreBase;
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
 * narrows `store` to `FederationTokenStoreBase & SupportsLock`, so
 * `store.acquireLock(...)` is callable without a cast.
 */
export function supportsLock(
	store: FederationTokenStoreBase | undefined | null,
): store is FederationTokenStoreBase & SupportsLock {
	if (store == null) return false;
	return typeof (store as { acquireLock?: unknown }).acquireLock === "function";
}

// ---------------------------------------------------------------------------
// Backing client interface (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

/**
 * Backing client for FederationTokenStore adapters. Declares `get`, `set`
 * (positional PX form, no NX condition), variadic `del`, and `scanIterator`
 * for the cursor-based key scan used by `deleteBySession`.
 *
 * Per Phase 10 addendum §3.
 */
export interface FederationTokenStoreClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number): Promise<"OK" | null>;
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	del(...keys: string[]): Promise<number>;
	scanIterator(opts: { MATCH: string; COUNT?: number }): AsyncIterable<string>;
}

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
	}
}
