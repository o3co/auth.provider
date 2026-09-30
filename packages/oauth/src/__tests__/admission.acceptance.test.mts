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
 * One fixture requirement across `oauth`'s consumers, on the wire (see ADR
 * 2026-09-28-session-admission): it answers `step_up`, with a page, for
 * `oauth.authorize` until the step-up is recorded, `step_up` for the `session`
 * grant, and `unmet` for a token carrier while a flag is set. One resolver,
 * one router, as a composition wires them.
 */

import crypto, { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type SessionRequirement,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestLoginEntry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createSessionGrant } from "#/grants/session.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { authorizationServerRegistry } from "./_helpers/authorizationServerRegistry.mjs";

const ISSUER = "https://issuer.test";
const SECRET = "acceptance-test-secret-32-bytes-long!";
const CLIENT_ID = "app";
const REDIRECT_URI = "https://app.example/cb";
const SID = "sid-1";
const SUBJECT = "user-1";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const config = {
	federations: {},
	oauth: {
		jwt: { issuer: ISSUER, secret: SECRET },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject" },
		oidcMode: "dual",
		grants: { session: { enabled: true }, refresh_token: { enabled: true } },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const session: UserSession = {
	sid: SID,
	sub: SUBJECT,
	authTime: new Date(Date.now() - 5 * 60_000),
	createdAt: new Date(Date.now() - 5 * 60_000),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
};

/** The fixture: its answers are knobs the scenario turns, as a real step-up and a real policy change would. */
const fixtureRequirement = () => {
	const state = { steppedUp: false, tokensUnmet: true };
	const requirement: SessionRequirement = {
		name: "fixture",
		reach: new Set(),
		stepUpPage: { url: "/step-up", params: { kind: "fixture" } },
		remediations: ["fixture.step_up"],
		hintKeys: [],
		async admit(input) {
			if (input.carrier === "token") {
				return state.tokensUnmet ? { outcome: "unmet" } : { outcome: "met" };
			}
			if (input.action.name === "oauth.authorize" || input.action.name === "oauth.session_grant") {
				return state.steppedUp
					? { outcome: "met" }
					: { outcome: "step_up", whenStillUnmet: "unmet" };
			}
			return { outcome: "met" };
		},
	};
	return { requirement, state };
};

const buildApp = async (requirement: SessionRequirement) => {
	const requirements = resolverForTests([requirement], {
		issuer: ISSUER,
		actions: OAUTH_ADMISSION_ACTIONS,
	});
	const userSessionStore = {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async (sid: string) => (sid === SID ? session : null)),
		delete: vi.fn(async () => {}),
	} as unknown as UserSessionStore;
	const keyStore = createSymmetricKeyStore(SECRET);
	const client = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		defaultScopes: ["read"],
		allowedGrantTypes: ["authorization_code", "session", "refresh_token"],
		firstParty: true,
	};
	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? client : null),
		authenticate: async () => null,
	};
	const createCode = vi.fn(async () => ({
		code: "code-x",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
	}));
	const codeRepository = {
		createCode,
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	} as unknown as CodeRepository;
	const registry = authorizationServerRegistry();
	registry.register(
		"session",
		createSessionGrant({
			config,
			keyStore,
			userSessionStore,
			sessionRequirementResolver: requirements,
		}),
	);
	registry.register(
		"refresh_token",
		createRefreshTokenGrant({
			config,
			keyStore,
			userSessionStore,
			sessionRequirementResolver: requirements,
		}),
	);
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore,
		userSessionStore,
		requirements,
	});
	const records = new Map<string, unknown>();
	const sessionStore = {
		get: (sid: string, cb: (err: unknown, rec?: unknown) => void) => cb(null, records.get(sid)),
		set: (sid: string, rec: unknown, cb?: (err?: unknown) => void) => {
			records.set(sid, rec);
			cb?.();
		},
		destroy: (sid: string, cb?: (err?: unknown) => void) => {
			records.delete(sid);
			cb?.();
		},
	};
	const app = express();
	app.use((req, _res, next) => {
		const holder = req as unknown as { session: unknown; sessionStore: unknown };
		holder.session = { isAuthenticated: true, sid: SID, user: { id: SUBJECT } };
		holder.sessionStore = sessionStore;
		next();
	});
	app.use("/oauth", router);
	return { app, createCode };
};

const refreshToken = (): Promise<string> =>
	new SignJWT({ sub: SUBJECT, azp: CLIENT_ID, scope: "read", sid: SID, amr: ["pwd"] })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuedAt()
		.setIssuer(ISSUER)
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

describe("one fixture requirement across oauth's consumers", () => {
	it("/authorize steps up to the page with redirect_to, then admits once the fixture answers met", async () => {
		const { requirement, state } = fixtureRequirement();
		const { app, createCode } = await buildApp(requirement);
		const query = {
			response_type: "code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			state: "xyz",
			code_challenge: CHALLENGE,
			code_challenge_method: "S256",
		};
		const first = await request(app).get("/oauth/authorize").query(query);
		expect(first.status).toBe(302);
		const page = new URL(first.headers.location as string);
		expect(page.origin + page.pathname).toBe(`${ISSUER}/step-up`);
		expect(page.searchParams.get("kind")).toBe("fixture");
		const back = new URL(page.searchParams.get("redirect_to") as string);
		expect(back.origin + back.pathname).toBe(`${ISSUER}/oauth/authorize`);
		expect(createCode).not.toHaveBeenCalled();

		// The page's ceremony completes: the fixture now answers met.
		state.steppedUp = true;
		const second = await request(app)
			.get("/oauth/authorize")
			.query(Object.fromEntries(back.searchParams.entries()));
		expect(second.status).toBe(302);
		expect(new URL(second.headers.location as string).searchParams.get("code")).toBe("code-x");
	});

	it("the session grant answers invalid_grant with step_up naming the requirement", async () => {
		const { requirement } = fixtureRequirement();
		const { app } = await buildApp(requirement);
		const res = await request(app)
			.post("/oauth/token")
			.type("form")
			.send({ grant_type: "session", client_id: CLIENT_ID, scope: "read" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
		expect(res.body.step_up).toBe("fixture");
	});

	it("the refresh grant answers invalid_grant for a token the fixture holds unmet, and refreshes once it does not", async () => {
		const { requirement, state } = fixtureRequirement();
		const { app } = await buildApp(requirement);
		const refresh = async () =>
			request(app)
				.post("/oauth/token")
				.type("form")
				.send({
					grant_type: "refresh_token",
					client_id: CLIENT_ID,
					refresh_token: await refreshToken(),
				});
		const refused = await refresh();
		expect(refused.status).toBe(400);
		expect(refused.body.error).toBe("invalid_grant");
		expect(refused.body).not.toHaveProperty("step_up");

		state.tokensUnmet = false;
		const refreshed = await refresh();
		expect(refreshed.status).toBe(200);
		expect(refreshed.body.access_token).toEqual(expect.any(String));
	});
});
