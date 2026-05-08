/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createInProcessLock } from "../lock/memory.mjs";
import type { FederationTokenStoreBase, FederationTokens, SupportsLock } from "../types.mjs";

const key = (sid: string, name: string) => `${sid}\u0000${name}`;

/**
 * In-memory FederationTokenStore adapter (dev/test only).
 *
 * Expiry semantics: this adapter does NOT auto-expire entries. Unlike
 * UserSessionStore where the session's `expiresAt` bounds the record lifetime,
 * federation `tokens.expiresAt` is the access_token's expiry, which is shorter
 * than the refresh_token lifetime — deleting the record at access_token expiry
 * would strand the refresh_token. Token lifecycle (refresh vs expiry decision)
 * is the consumer's responsibility in F-6 flows.
 *
 * Cleanup of stale entries happens via UserSessionStore logout cascade, which
 * calls `removeBySid(sid)` when a session ends. For process longevity
 * consider redis instead (production-grade TTL + cross-instance replication).
 */
const cloneTokens = (t: FederationTokens): FederationTokens => ({
	accessToken: t.accessToken,
	refreshToken: t.refreshToken,
	idToken: t.idToken,
	// Copy Date so caller-held references can't mutate stored state.
	// `null` means upstream provider issued no finite expiry — pass through as-is.
	expiresAt: t.expiresAt === null ? null : new Date(t.expiresAt.getTime()),
	tokenType: t.tokenType,
	scope: t.scope,
	// Shallow-copy rawParams; sufficient since consumers treat it as read-only.
	rawParams: t.rawParams ? { ...t.rawParams } : undefined,
});

export function createInMemoryFederationTokenStore(): FederationTokenStoreBase & SupportsLock {
	const store = new Map<string, FederationTokens>();
	const lock = createInProcessLock();

	return {
		kind: "memory",
		async attach(sid, name, tokens) {
			store.set(key(sid, name), cloneTokens(tokens));
		},
		async get(sid, name) {
			const t = store.get(key(sid, name));
			return t ? cloneTokens(t) : null;
		},
		async update(sid, name, tokens) {
			store.set(key(sid, name), cloneTokens(tokens));
		},
		async removeBySid(sid) {
			for (const k of [...store.keys()]) {
				if (k.startsWith(`${sid}\u0000`)) store.delete(k);
			}
		},
		async delete(sid, name) {
			store.delete(key(sid, name));
		},
		acquireLock(opts) {
			return lock.acquireLock(opts);
		},
	};
}
