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
 * The template with core's session lifecycle module: a close whose
 * relying-party notice fails stays pending, its user session still there,
 * and from its commit no token reader treats the session as live —
 * introspection, userinfo and the session grant all refuse it.
 */

import {
	type SessionLifecycle,
	sessionLifecycleModule,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { basic, compose, login, WEB } from "./all-modules-composition.fixture.mjs";

afterEach(() => {
	vi.restoreAllMocks();
});

/** A JWT's claims, unverified. */
const claimsOf = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

describe("a session whose close is pending on a failed relying-party notice", () => {
	it("is refused by introspection, userinfo and the session grant, its user session still there", async () => {
		const { app, handle } = await compose({
			extraModules: () => [sessionLifecycleModule],
			extraClients: {
				"rp-down": {
					tokenEndpointAuthMethod: "client_secret_basic",
					clientSecret: "rp-down-secret-long-enough",
					allowedRedirectUris: ["https://rp-down.test/cb"],
					allowedScopes: ["openid"],
					allowedGrantTypes: ["authorization_code"],
					backchannelLogoutUri: "https://rp-down.test/logout",
				},
			},
		});
		try {
			const components = handle.components as Record<string, unknown>;
			const lifecycle = components.sessionLifecycle as SessionLifecycle;
			const sessions = components.userSessionStore as UserSessionStore;
			const { cookies } = await login(app);
			const sessionGrant = () =>
				request(app)
					.post("/oauth/token")
					.set("Authorization", basic(WEB))
					.set("Cookie", cookies)
					.type("form")
					.send({ grant_type: "session", scope: "openid profile" });
			const issued = await sessionGrant();
			expect(issued.status).toBe(200);
			const accessToken = issued.body.access_token as string;
			const sid = String(claimsOf(accessToken).sid);
			const introspect = () =>
				request(app)
					.post("/oauth/introspect")
					.set("Authorization", basic(WEB))
					.type("form")
					.send({ token: accessToken });
			const userinfo = () =>
				request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${accessToken}`);
			expect((await introspect()).body.active).toBe(true);
			expect((await userinfo()).status).toBe(200);

			// A relying party joins with its family; its back-channel endpoint is
			// down, so the close commits with its notice pending.
			expect(
				await lifecycle.join(sid, {
					rp: {
						clientId: "rp-down",
						backchannelLogoutUri: "https://rp-down.test/logout",
						backchannelLogoutSessionRequired: true,
						frontchannelLogoutUri: undefined,
						frontchannelLogoutSessionRequired: undefined,
						registeredAt: new Date(),
					},
					familyId: "family-down",
				}),
			).toEqual({ outcome: "joined" });
			const posted = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async () => new Response(null, { status: 503 }));
			expect((await lifecycle.close(sid, "rp_logout")).outcome).toBe("pending");
			expect(posted).toHaveBeenCalled();
			expect(await sessions.get(sid)).not.toBeNull();

			const afterIntrospect = await introspect();
			expect(afterIntrospect.status).toBe(200);
			expect(afterIntrospect.body).toEqual({ active: false });

			const afterUserinfo = await userinfo();
			expect(afterUserinfo.status).toBe(401);
			expect(afterUserinfo.body.error_description).toBe("session_invalid");

			const again = await sessionGrant();
			expect(again.status).toBe(400);
			expect(again.body).toMatchObject({
				error: "invalid_grant",
				error_description: "session_invalid",
			});
		} finally {
			await handle.dispose();
		}
	});
});
