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
 * The `UserSession` records the tests that mount the verification handler
 * behind a fixed cookie session read: `user-1`'s live session under
 * {@link LIVE_SID}, which the fixed cookie session names, and `user-2`'s
 * under `sid-2`, for a cookie that names another subject's session.
 *
 * A store over fixed records rather than a bundled adapter: these tests pin
 * what the endpoint does with the answer, and what the adapters answer is
 * their contract suite's business. The composition tests sign in through
 * `/session/login` against the bundled memory store instead.
 */

import type { UserSession, UserSessionStore } from "@o3co/auth-provider-core";

/** The durable session a fixed cookie session names by default. */
export const LIVE_SID = "sid-1";

/** The cookie session a signed-in `user-1` holds: authenticated, naming {@link LIVE_SID}. */
export const liveCookieSession = (): Record<string, unknown> => ({
	isAuthenticated: true,
	user: { id: "user-1" },
	sid: LIVE_SID,
});

const sessionRecord = (sid: string, sub: string): UserSession => ({
	sid,
	sub,
	authTime: new Date(1_800_000_000_000),
	createdAt: new Date(1_800_000_000_000),
	expiresAt: new Date(1_900_000_000_000),
	claims: {},
	amr: ["pwd"],
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
