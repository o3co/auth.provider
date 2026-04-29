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

import type {
	CreateUserSessionInput,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
} from "../types.mjs";

interface Stored {
	sid: string;
	sub: string;
	authTime: Date;
	createdAt: Date;
	expiresAt: Date;
	claims: Record<string, unknown>;
}

/**
 * Defensive deep-copy of claims. `groups` is the only known array-valued
 * standard claim — extend when new array-valued claims are added to
 * UserSessionClaims.
 */
const cloneClaims = (c: UserSessionClaims | Record<string, unknown>): Record<string, unknown> => {
	const out: Record<string, unknown> = { ...c };
	const groups = (c as { groups?: unknown }).groups;
	if (Array.isArray(groups)) {
		out.groups = [...groups];
	}
	return out;
};

/**
 * In-memory UserSessionStore. Single-process only. Atomicity comes from
 * Node's single event loop — `Map.get/set/delete` are synchronous.
 *
 * Per A4 §5.1 + §7.1 (lines 469-505).
 */
export function createInMemoryUserSessionStore(): UserSessionStore {
	const sessions = new Map<string, Stored>();

	const readLive = (sid: string): Stored | null => {
		const s = sessions.get(sid);
		if (!s) return null;
		if (s.expiresAt.getTime() <= Date.now()) {
			sessions.delete(sid);
			return null;
		}
		return s;
	};

	return {
		kind: "memory",
		async create(input: CreateUserSessionInput) {
			if (input.expiresAt.getTime() <= Date.now()) {
				throw new Error(`UserSession ${input.sid}: expiresAt is in the past`);
			}
			// GC expired entry first so duplicate-check semantics match `get()`.
			if (readLive(input.sid) !== null) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
			sessions.set(input.sid, {
				sid: input.sid,
				sub: input.sub,
				authTime: new Date(input.authTime.getTime()),
				createdAt: new Date(),
				expiresAt: new Date(input.expiresAt.getTime()),
				claims: cloneClaims(input.claims),
			});
		},
		async get(sid: string): Promise<UserSession | null> {
			const s = readLive(sid);
			if (!s) return null;
			return {
				sid: s.sid,
				sub: s.sub,
				authTime: new Date(s.authTime.getTime()),
				createdAt: new Date(s.createdAt.getTime()),
				expiresAt: new Date(s.expiresAt.getTime()),
				claims: cloneClaims(s.claims) as UserSessionClaims,
			};
		},
		async delete(sid: string) {
			sessions.delete(sid);
		},
	};
}
