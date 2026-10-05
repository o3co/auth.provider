/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { newStoreGeneration, type StoreGeneration } from "../../adapters/conditionalWrite.mjs";
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
	// Copied like `expiresAt`; an unknown age stays `undefined`, the key named.
	obtainedAt: t.obtainedAt === undefined ? undefined : new Date(t.obtainedAt.getTime()),
});

/**
 * In-memory FederationTokenStore adapter (dev/test only).
 *
 * Entries never auto-expire: `tokens.expiresAt` is the access token's expiry,
 * and deleting the record then would strand the longer-lived refresh token.
 * Refresh-or-expire is the consumer's call. Stale entries go when logout
 * calls `removeBySid(sid)`; long-lived processes should use redis.
 *
 * Every write stores a copy at a new store generation. Each conditional
 * member checks and writes with no `await` between, so the check and the
 * write are one step in this process.
 */
export function createInMemoryFederationTokenStore(): FederationTokenStore & SupportsLock {
	const store = new Map<string, { tokens: FederationTokens; generation: StoreGeneration }>();
	const lock = createInProcessLock();
	const write = (sid: string, name: string, tokens: FederationTokens): StoreGeneration => {
		const generation = newStoreGeneration();
		store.set(key(sid, name), { tokens: cloneTokens(tokens), generation });
		return generation;
	};

	return {
		kind: "memory",
		async attach(sid, name, tokens) {
			write(sid, name, tokens);
		},
		async get(sid, name) {
			const entry = store.get(key(sid, name));
			return entry ? cloneTokens(entry.tokens) : null;
		},
		async getVersioned(sid, name) {
			const entry = store.get(key(sid, name));
			return entry ? { value: cloneTokens(entry.tokens), generation: entry.generation } : null;
		},
		async replaceIf(sid, name, expected, tokens) {
			const entry = store.get(key(sid, name));
			if (entry === undefined) return { outcome: "missing" };
			if (entry.generation !== expected) return { outcome: "conflict" };
			return { outcome: "updated", generation: write(sid, name, tokens) };
		},
		async removeIf(sid, name, expected) {
			const entry = store.get(key(sid, name));
			if (entry === undefined) return { outcome: "missing" };
			if (entry.generation !== expected) return { outcome: "conflict" };
			store.delete(key(sid, name));
			return { outcome: "removed" };
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
