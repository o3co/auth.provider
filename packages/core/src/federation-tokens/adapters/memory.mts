/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type { FederationTokenStoreBase, FederationTokens } from "../types.mjs";

const key = (sid: string, name: string) => `${sid}\u0000${name}`;

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
