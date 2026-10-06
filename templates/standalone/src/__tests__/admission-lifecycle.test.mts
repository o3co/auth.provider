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
 * The oauth package's consumers of session admission read the session
 * lifecycle's record the template's session stores provide: a session whose
 * record is closing is refused at `/authorize`, the code exchange and the
 * refresh grant, while its user session is still there.
 */

import type { SessionLifecycleStore, UserSessionStore } from "@o3co/auth-provider-core";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
	authorize,
	basic,
	codeFrom,
	compose,
	login,
	redeem,
	WEB,
} from "./all-modules-composition.fixture.mjs";

/** A JWT's claims, unverified. */
const claimsOf = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

describe("a session whose lifecycle record is closing", () => {
	it("is refused at /authorize, the code exchange and the refresh grant", async () => {
		const { app, handle } = await compose();
		try {
			const components = handle.components as Record<string, unknown>;
			const store = components.sessionLifecycleStore as SessionLifecycleStore;
			const sessions = components.userSessionStore as UserSessionStore;
			const { cookies } = await login(app);
			const tokens = (await redeem(app, codeFrom(await authorize(app, cookies)))).body as Record<
				string,
				string
			>;
			const sid = String(claimsOf(tokens.id_token ?? "").sid);
			const pendingCode = codeFrom(await authorize(app, cookies));

			// The session's close commits, its work pending: the user session stays.
			const session = await sessions.get(sid);
			if (session === null) throw new Error("the login wrote no session");
			expect((await store.open(sid, session.sub, session.expiresAt)).outcome).toBe("opened");
			const closing = await store.beginClose(sid, {
				cause: "rp_logout",
				steps: ["held_open"],
				perParticipant: [],
				retainMs: 0,
			});
			expect(closing.outcome).toBe("closing");
			expect(await sessions.get(sid)).not.toBeNull();

			const again = await authorize(app, cookies);
			// Sent to log in again, with no code.
			expect(again.status).toBe(302);
			expect(String(again.headers.location)).not.toMatch(/[?&]code=/);

			expect((await redeem(app, pendingCode)).body).toMatchObject({ error: "invalid_grant" });

			const refreshed = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(WEB))
				.type("form")
				.send({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
			expect(refreshed.status).toBe(400);
			expect(refreshed.body).toMatchObject({ error: "invalid_grant" });
		} finally {
			await handle.dispose();
		}
	});
});
