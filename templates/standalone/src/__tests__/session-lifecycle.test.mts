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
 * The template's composition with core's session lifecycle module added:
 * it serves relying parties, so boot holds it to a session-close notifier,
 * which the oauth module contributes.
 */

import {
	readVersionedSessionLifecycle,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type SubjectSessionIndex,
	sessionLifecycleModule,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ALICE,
	compose,
	ISSUER,
	login,
	WEB,
	webTokens,
} from "./all-modules-composition.fixture.mjs";

afterEach(() => {
	vi.restoreAllMocks();
});

/** A JWT's claims, unverified. */
const claimsOf = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

describe("the template with the session lifecycle module", () => {
	it("boots, the oauth module's notifier contributed", async () => {
		const { handle } = await compose({ extraModules: () => [sessionLifecycleModule] });
		try {
			const lifecycle = handle.components.sessionLifecycle as SessionLifecycle | undefined;
			expect(lifecycle).toBeDefined();
			expect(handle.components.sessionCloseNotifierResolver?.get()).toBeDefined();
			expect(await lifecycle?.close("no-such-session", "expiry")).toEqual({
				outcome: "done",
				rps: [],
				federations: [],
			});
		} finally {
			await handle.dispose();
		}
	});

	it("tells a relying party that joined, through the oauth module's notifier, when the session closes", async () => {
		const { handle } = await compose({
			extraModules: () => [sessionLifecycleModule],
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
			const expiresAt = new Date(Date.now() + 3_600_000);
			await sessions.create({
				sid: "sid-bc",
				sub: "u-bc",
				authTime: new Date(),
				expiresAt,
				claims: {},
				amr: ["pwd"],
				authentication: undefined,
			});
			const rp = {
				clientId: "rp-bc",
				backchannelLogoutUri: "https://rp-bc.test/logout",
				backchannelLogoutSessionRequired: true,
				frontchannelLogoutUri: undefined,
				frontchannelLogoutSessionRequired: undefined,
				registeredAt: new Date(),
			};
			expect(await lifecycle.join("sid-bc", { rp, familyId: "family-bc" })).toEqual({
				outcome: "joined",
			});
			const posted = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async () => new Response(null, { status: 200 }));
			expect((await lifecycle.close("sid-bc", "rp_logout")).outcome).toBe("done");
			expect(posted).toHaveBeenCalledTimes(1);
			const [url, init] = posted.mock.calls[0] as [string, RequestInit];
			expect(url).toBe("https://rp-bc.test/logout");
			const token = new URLSearchParams(String(init.body)).get("logout_token");
			expect(claimsOf(token ?? "")).toMatchObject({
				iss: ISSUER,
				aud: "rp-bc",
				sub: "u-bc",
				sid: "sid-bc",
			});
		} finally {
			await handle.dispose();
		}
	});

	it("opens a password login's session in the lifecycle, active with nothing joined yet", async () => {
		const { app, handle } = await compose({ extraModules: () => [sessionLifecycleModule] });
		try {
			expect((await login(app)).res.status).toBe(200);
			const components = handle.components as Record<string, unknown>;
			const [sid] = await (components.subjectSessionIndex as SubjectSessionIndex).listSids(
				ALICE.sub,
			);
			const store = components.sessionLifecycleStore as SessionLifecycleStore;
			const record = readVersionedSessionLifecycle(await store.read(String(sid)));
			expect(record?.value).toMatchObject({ sub: ALICE.sub, state: "active", participants: [] });
		} finally {
			await handle.dispose();
		}
	});

	it("joins a code exchange's relying party and family to the session's lifecycle record", async () => {
		const { app, handle } = await compose({ extraModules: () => [sessionLifecycleModule] });
		try {
			const tokens = await webTokens(app);
			const claims = claimsOf(tokens.refresh_token ?? "");
			const sid = String(claims.sid);
			const store = (handle.components as Record<string, unknown>)
				.sessionLifecycleStore as SessionLifecycleStore;
			const record = readVersionedSessionLifecycle(await store.read(sid));
			expect(record?.value.state).toBe("active");
			expect(record?.value.participants.map((p) => `${p.kind}:${p.id}`)).toEqual([
				`rp:${WEB.id}`,
				`family:${String(claims.family_id)}`,
			]);
		} finally {
			await handle.dispose();
		}
	});
});
