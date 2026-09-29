/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createInProcessLock } from "../lock/memory.mjs";
import type { FederationTokenStore, FederationTokens, SupportsLock } from "../types.mjs";

const key = (sid: string, name: string) => `${sid}\u0000${name}`;

const cloneTokens = (t: FederationTokens): FederationTokens => ({
	accessToken: t.accessToken,
	refreshToken: t.refreshToken,
	idToken: t.idToken,
	// Copy the Date so caller-held references can't mutate stored state;
	// `null` (no finite upstream expiry) passes through.
	expiresAt: t.expiresAt === null ? null : new Date(t.expiresAt.getTime()),
	tokenType: t.tokenType,
	scope: t.scope,
	grantedScope: t.grantedScope,
});

/**
 * In-memory FederationTokenStore adapter (dev/test only).
 *
 * Entries never auto-expire: `tokens.expiresAt` is the access token's expiry,
 * and deleting the record then would strand the longer-lived refresh token.
 * Refresh-or-expire is the consumer's call. Stale entries go when logout
 * calls `removeBySid(sid)`; long-lived processes should use redis.
 */
export function createInMemoryFederationTokenStore(): FederationTokenStore & SupportsLock {
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
