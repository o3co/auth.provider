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
 * The template with core's session lifecycle module: `POST /session/logout`
 * closes the session through it, so the browser's own logout revokes the
 * session's refresh-token families and tells its relying parties, as
 * `/oauth/logout` does.
 */

import {
	type RefreshTokenFamilyRevocation,
	readVersionedSessionLifecycle,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authorize, codeFrom, compose, login, redeem } from "./all-modules-composition.fixture.mjs";

afterEach(() => {
	vi.restoreAllMocks();
});

/** A JWT's claims, unverified. */
const claimsOf = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

/** The CSRF token a login reissued, read off its double-submit cookie. */
const csrfTokenOf = (cookies: readonly string[]): string => {
	const cookie = cookies.find((c) => /^[^=]*\.csrf=/.test(c));
	if (cookie === undefined) throw new Error("the login reissued no CSRF cookie");
	return decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1).split(";")[0] ?? "");
};

describe("POST /session/logout with the session lifecycle module", () => {
	it("revokes the session's families, tells its relying parties and closes its record", async () => {
		const { app, handle } = await compose({
			extraClients: {
				"rp-bc": {
					tokenEndpointAuthMethod: "client_secret_basic",
					clientSecret: "rp-bc-secret-long-enough",
					allowedRedirectUris: ["https://rp-bc.test/cb"],
					allowedScopes: ["openid"],
					allowedGrantTypes: ["authorization_code"],
					backchannelLogoutUri: "https://rp-bc.test/logout",
				},
			},
		});
		try {
			const components = handle.components as Record<string, unknown>;
			const lifecycle = components.sessionLifecycle as SessionLifecycle;
			const sessions = components.userSessionStore as UserSessionStore;
			const families = components.refreshTokenFamilyRevocation as RefreshTokenFamilyRevocation;
			const { cookies } = await login(app);
			const exchanged = await redeem(app, codeFrom(await authorize(app, cookies)));
			expect(exchanged.status).toBe(200);
			const claims = claimsOf(exchanged.body.refresh_token as string);
			const sid = String(claims.sid);
			const familyId = String(claims.family_id);
			expect(
				await lifecycle.join(sid, {
					rp: {
						clientId: "rp-bc",
						backchannelLogoutUri: "https://rp-bc.test/logout",
						backchannelLogoutSessionRequired: true,
						frontchannelLogoutUri: undefined,
						frontchannelLogoutSessionRequired: undefined,
						registeredAt: new Date(),
					},
				}),
			).toEqual({ outcome: "joined" });
			const posted = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async () => new Response(null, { status: 200 }));

			const csrfToken = csrfTokenOf(cookies);
			const res = await request(app)
				.post("/session/logout")
				.set("Cookie", cookies)
				.set("x-csrf-token", csrfToken);

			expect(res.status).toBe(200);
			expect(await families.isFamilyRevoked(familyId)).toBe(true);
			expect(posted.mock.calls.map(([url]) => String(url))).toEqual(["https://rp-bc.test/logout"]);
			expect(await sessions.get(sid)).toBeNull();
			const store = components.sessionLifecycleStore as SessionLifecycleStore;
			expect(readVersionedSessionLifecycle(await store.read(sid))?.value.state).toBe("closed");
		} finally {
			await handle.dispose();
		}
	});

	it("answers 503 when the close cannot commit, and the cookie still admits the session for a retry", async () => {
		const { app, handle } = await compose();
		try {
			const { cookies } = await login(app);
			const components = handle.components as Record<string, unknown>;
			const store = components.sessionLifecycleStore as SessionLifecycleStore;
			vi.spyOn(store, "beginClose").mockRejectedValue(new Error("lifecycle store down"));

			const res = await request(app)
				.post("/session/logout")
				.set("Cookie", cookies)
				.set("x-csrf-token", csrfTokenOf(cookies));

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
			// The session is still live and its cookie still admits it.
			const authorized = await authorize(app, cookies);
			expect(codeFrom(authorized)).toEqual(expect.any(String));
		} finally {
			await handle.dispose();
		}
	});
});
