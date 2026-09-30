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
 * The federation callback's login establishes without asking (ADR
 * 2026-09-28-session-admission, D5): core builds its `Establishment` from the
 * federation's own facts (`establishWithoutAsking`), no requirement's
 * `admitPrimary` is consulted, and the record is what
 * `federatedSessionAuthentication` composes. The rest of the callback's login
 * is pinned by `Federation.test.mts`.
 */

import {
	codeChallenge,
	type FederationProvider,
	type PrimaryAuthentication,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { buildFederationApp, makeUserRepository } from "./federation-harness.mjs";

const CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";

/** A query-mode provider whose IdP asserted `amr` of its own. */
const provider: FederationProvider = {
	name: "test",
	scope: ["openid"],
	buildAuthorizationUrl: ({ state, codeVerifier }) => {
		const url = new URL("https://idp.example.com/authorize");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
		return url;
	},
	exchangeCode: vi.fn(async () => ({
		issuer: "https://idp.example.com",
		sub: "external-42",
		accessToken: "at",
		expiresAt: new Date(Date.now() + 3_600_000),
		scope: "openid",
		amr: ["otp"],
	})),
};

/** A requirement that interrupts every login it is asked about, recording what it was asked. */
function interruptingEveryLogin(): {
	requirement: SessionRequirement;
	asked: PrimaryAuthentication[];
} {
	const asked: PrimaryAuthentication[] = [];
	return {
		asked,
		requirement: {
			name: "fixture",
			reach: new Set<string>(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
			admitPrimary: async (primary) => {
				asked.push(primary);
				return {
					open: async () => ({ status: 403, body: { error: "fixture_required" } }),
				};
			},
		},
	};
}

describe("the federation callback's login establishes without asking", () => {
	it("is not interrupted by a requirement that would interrupt a password login: the session is established, the requirement never asked", async () => {
		const { requirement, asked } = interruptingEveryLogin();
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			userRepository: makeUserRepository({
				id: "user-1",
				username: "alice",
				email: "alice@example.com",
			}),
			requirements: resolverForTests([requirement], { actions: SESSION_ADMISSION_ACTIONS }),
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(302);
		expect(asked).toEqual([]);
		expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
		const created = harness.userSessionStore.create.mock.calls[0]?.[0] as Record<string, unknown>;
		// What `federatedSessionAuthentication` composes for an untrusted
		// federation (no switch in this config): `fed` alone, the IdP's values
		// kept apart.
		expect(created).toMatchObject({
			sub: "user-1",
			claims: { email: "alice@example.com" },
			amr: ["fed"],
			authentication: {
				primary: "fed",
				federation: "test",
				upstreamAmr: ["otp"],
				mfaAt: undefined,
			},
		});
		// The session is the established one, and carries no `redirectTo`: the
		// callback redirects by its policy and never wrote one.
		const session = harness.store.get("browser")?.data;
		expect(session).toMatchObject({
			isAuthenticated: true,
			sid: created.sid,
			user: { id: "user-1", username: "alice", email: "alice@example.com" },
		});
		expect(session).not.toHaveProperty("redirectTo");
	});
});

describe("the federation callback's login — a user core cannot copy into the primary", () => {
	it("answers 500 with nothing written, as the password login does: no record, no index entry, no tokens, no authenticated session", async () => {
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			// `establishWithoutAsking` holds a structured-clone copy of the user:
			// a function cannot be copied.
			userRepository: makeUserRepository({
				id: "user-1",
				username: "alice",
				greet: () => "hello",
			}),
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(500);
		expect(harness.userSessionStore.create).not.toHaveBeenCalled();
		expect(harness.sessionFederationIndex.addFederation).not.toHaveBeenCalled();
		expect(harness.federationTokenStore.attach).not.toHaveBeenCalled();
		const session = harness.store.get("browser")?.data ?? {};
		for (const field of ["isAuthenticated", "user", "sid"]) {
			expect(session, field).not.toHaveProperty(field);
		}
	});
});
