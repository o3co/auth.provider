/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type { FederationTokenStoreBase, FederationTokens } from "../types.mjs";

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
 * calls `deleteBySession(sid)` when a session ends. For process longevity
 * consider redis instead (production-grade TTL + cross-instance replication).
 */
export function createInMemoryFederationTokenStore(): FederationTokenStoreBase {
	const store = new Map<string, FederationTokens>();

	return {
		kind: "memory",
		async attach(sid, name, tokens) {
			store.set(key(sid, name), { ...tokens });
		},
		async get(sid, name) {
			return store.get(key(sid, name)) ?? null;
		},
		async update(sid, name, tokens) {
			store.set(key(sid, name), { ...tokens });
		},
		async deleteBySession(sid) {
			for (const k of [...store.keys()]) {
				if (k.startsWith(`${sid}\u0000`)) store.delete(k);
			}
		},
		async delete(sid, name) {
			store.delete(key(sid, name));
		},
	};
}
