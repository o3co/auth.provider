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
 * The `UserSession` records read by tests that mount the verification handler
 * behind a fixed cookie session: `user-1`'s live session under
 * {@link LIVE_SID}, which that cookie names, and `user-2`'s under `sid-2`, for
 * a cookie that names another subject's session, with the lifecycle records
 * their logins opened. Fixed records rather than a
 * bundled adapter: these tests pin what the endpoint does with the answer,
 * and what the adapters answer is their contract suite's business.
 */

import {
	createInMemorySessionLifecycleStore,
	passwordSessionAuthentication,
	type SessionLifecycleStore,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";

/** The durable session a fixed cookie session names by default. */
export const LIVE_SID = "sid-1";

/** The cookie session a signed-in `user-1` holds: authenticated, naming {@link LIVE_SID}. */
export const liveCookieSession = (): Record<string, unknown> => ({
	isAuthenticated: true,
	user: { id: "user-1" },
	sid: LIVE_SID,
});

/** When every fixed session authenticated, in epoch milliseconds. */
export const LIVE_AUTH_TIME_MS = 1_800_000_000_000;

/** When every fixed session ends, in epoch milliseconds. */
const LIVE_EXPIRES_AT_MS = 1_900_000_000_000;

const sessionRecord = (sid: string, sub: string): UserSession => ({
	sid,
	sub,
	authTime: new Date(LIVE_AUTH_TIME_MS),
	createdAt: new Date(LIVE_AUTH_TIME_MS),
	expiresAt: new Date(LIVE_EXPIRES_AT_MS),
	claims: {},
	// A password login's record.
	...passwordSessionAuthentication(),
});

/** `user-1`'s live session and `user-2`'s, held until a test deletes one. */
export const liveSessionStore = (): UserSessionStore => {
	const bySid = new Map<string, UserSession>([
		[LIVE_SID, sessionRecord(LIVE_SID, "user-1")],
		["sid-2", sessionRecord("sid-2", "user-2")],
	]);
	return {
		kind: "fixed",
		create: async () => {
			throw new Error("the fixed sessions are the only ones");
		},
		get: async (sid) => bySid.get(sid) ?? null,
		delete: async (sid) => {
			bySid.delete(sid);
		},
	};
};

/**
 * Core's in-memory lifecycle store holding the records the fixed sessions'
 * logins opened, active: a session with no record reads as closed. Opened
 * before any member answers.
 */
export const liveSessionLifecycleStore = (): SessionLifecycleStore => {
	const store = createInMemorySessionLifecycleStore();
	const opened = (async () => {
		for (const [sid, sub] of [
			[LIVE_SID, "user-1"],
			["sid-2", "user-2"],
		] as const) {
			await store.open(sid, sub, new Date(LIVE_EXPIRES_AT_MS));
		}
	})();
	const after =
		<A extends unknown[], R>(call: (...args: A) => Promise<R>) =>
		async (...args: A): Promise<R> => {
			await opened;
			return call(...args);
		};
	return {
		kind: store.kind,
		open: after(store.open.bind(store)),
		join: after(store.join.bind(store)),
		beginClose: after(store.beginClose.bind(store)),
		completeIf: after(store.completeIf.bind(store)),
		read: after(store.read.bind(store)),
		listClosing: after(store.listClosing.bind(store)),
	};
};
