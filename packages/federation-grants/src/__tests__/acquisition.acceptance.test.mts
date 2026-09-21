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
 * A grant created end to end through the composed application (#593 slice 6):
 * a client lodges an intent, the user's browser connects, reads the consent,
 * approves, comes back from the upstream — and the client then spends the
 * grant on `/token`.
 *
 * Booted with `createApp` and the real modules, so what is proven is the
 * composition: that the two route contributions mount where they must (the
 * browser half after the session middleware, which reads the session it
 * sets), that the module hands every piece what it needs, and that a grant
 * created by acquisition is one retrieval accepts. The route-level suites test
 * each rule; this tests that they are the same deployment.
 */

import type { BootstrapMap, ClientRepository, UserSession } from "@o3co/auth-provider-core";
import {
	createApp,
	createInMemorySubjectRevocation,
	createMemoryFederationGrantIntentStore,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
	InMemoryUserRepository,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import type { Request, RequestHandler } from "express";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import { ACQUISITION_ENDPOINTS, callbackUrlFor } from "./acquisitionFixture.mjs";

const ISSUER = (makeValidCoreConfig() as { oauth: { jwt: { issuer: string } } }).oauth.jwt.issuer;
const REDIRECT = "https://client.test/connected";
const CLIENT_ID = "worker";
const SECRET = "worker-secret-value";
const basic = `Basic ${Buffer.from(`${CLIENT_ID}:${SECRET}`).toString("base64")}`;

const client = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [],
	allowedFederationGrantConnections: ["calendar"],
	federationGrantRedirectUris: [REDIRECT],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? (client as never) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === SECRET ? (client as never) : null,
};

/** The upstream: an authorization endpoint the test never visits, and a token endpoint it answers. */
const upstream = {
	name: "upstream",
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL("https://issuer.example/login"),
	exchangeCode: async () => {
		throw new Error("the login exchange must not be used for a grant");
	},
	buildDelegatedAuthorizationUrl: (params: { state: string }) => {
		const url = new URL("https://issuer.example/authorize");
		url.searchParams.set("state", params.state);
		return url;
	},
	exchangeDelegatedCode: async () => ({
		upstream: { issuer: "https://issuer.example", subject: "00u-alice" },
		tokens: {
			accessToken: "upstream-access-token",
			refreshToken: "upstream-refresh-token",
			expiresIn: 3600,
			expiresAt: new Date(Date.now() + 3_600_000),
			tokenType: "bearer",
			scope: "openid offline_access calendar.read",
		},
	}),
	refreshDelegatedToken: async () => ({}),
};

const federationModule = defineModule({
	name: "test-federation-upstream",
	contributes: {
		federations: { upstream: () => upstream },
		federationRedirectPolicies: {
			upstream: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	} as never,
});

interface Browser {
	readonly isAuthenticated: boolean;
	readonly user: { readonly id: string };
	readonly sid: string;
}
const browsers = new Map<string, Browser>();
const durable = new Map<string, UserSession>();

/**
 * Stands in for express-session under the id the browser half mounts after.
 * Declared LAST in the module list on purpose: it is `after`, not the order
 * modules happen to be listed in, that puts the browser half behind it.
 */
const sessionMiddleware = defineModule({
	name: "test-session-middleware",
	contributes: {
		routes: [
			() => ({
				id: "session-middleware",
				mountPath: "/",
				handler: ((req: Request, _res: unknown, next: () => void) => {
					const id = req.get("x-browser");
					if (id !== undefined && browsers.has(id)) {
						(req as unknown as { sessionID: string }).sessionID = id;
						(req as unknown as { session: Browser }).session = browsers.get(id) as Browser;
					}
					next();
				}) as RequestHandler,
			}),
		],
	},
});

const boot = async () => {
	const full = makeValidFullSections();
	const handle = await createApp({
		modules: [
			federationModule,
			...federationGrantsModules,
			defineModule({
				name: "test-stores",
				provides: {
					federationGrantStore: () => createMemoryFederationGrantStore(),
					federationGrantIntentStore: () => createMemoryFederationGrantIntentStore(),
				} as never,
			}),
			sessionMiddleware,
		],
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				federations: {
					upstream: {
						enabled: true,
						issuer: "https://issuer.example",
						clientId: "provider-client",
					},
				},
				rateLimit: { ...full.rateLimit, failMode: "closed" },
				audit: { sink: { type: "none" } },
				endpoints: ACQUISITION_ENDPOINTS,
				federationGrants: {
					enabled: true,
					consent: { url: "/consent/grants" },
					connections: {
						calendar: {
							federation: "upstream",
							scopes: ["openid", "offline_access", "calendar.read"],
							boundary: "production",
							maxAccessTokenLifetime: 3600,
							callbackURL: callbackUrlFor("calendar"),
						},
					},
				},
			},
			pathResolver: (s: string) => s,
			clientRepository,
			// The bundled repository, not a stub: a class whose lookup reads its
			// own fields. Codex found the callback calling it detached from its
			// receiver, which every stub written as an arrow function hid.
			userRepository: new InMemoryUserRepository(
				new Map([["alice", { password: "unused", id: "alice" }]]),
			),
			userSessionStore: { get: async (sid: string) => durable.get(sid) ?? null },
			sessionRPRegistry: {},
			sessionFamilyIndex: {},
			sessionFederationIndex: {},
			federationTokenStore: {},
			refreshTokenFamilyRevocation: {},
			subjectRevocation: createInMemorySubjectRevocation(),
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 1000, windowSeconds: 60 },
			}),
		} as unknown as BootstrapMap,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

describe("a grant created end to end, and spent", () => {
	it("goes from a client's request to a token the client can use, through the composed deployment", async () => {
		const { handle, app } = await boot();
		try {
			// The client lodges an intent.
			const lodged = await request(app)
				.post("/oauth/federation-grants")
				.set("Authorization", basic)
				.send({
					connection: "calendar",
					sub: "alice",
					redirect_uri: REDIRECT,
					state: "client-state",
				});
			expect(lodged.status).toBe(201);
			const grantId = lodged.body.grant_id as string;
			const connect = new URL(lodged.body.connect_uri as string);
			expect(connect.origin).toBe(new URL(ISSUER).origin);

			// The user's browser, signed in, follows the link.
			browsers.set("b-1", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-1" });
			durable.set("sid-1", {
				sid: "sid-1",
				sub: "alice",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 86_400_000),
				claims: {},
			} as UserSession);
			const started = await request(app)
				.get(`${connect.pathname}${connect.search}`)
				.set("x-browser", "b-1");
			// Not a redirect to the login page: the session was there, which is
			// what mounting after the session middleware is for.
			expect(started.status).toBe(303);
			const consent = new URL(started.headers.location as string, ISSUER);
			expect(consent.pathname).toBe("/consent/grants");
			const challenge = consent.searchParams.get("challenge") ?? "";

			// The deployment's page reads the question and posts the answer.
			const shown = await request(app)
				.get("/session/federation-grants/consent")
				.query({ challenge })
				.set("x-browser", "b-1");
			expect(shown.status).toBe(200);
			expect(shown.body).toMatchObject({ client_id: CLIENT_ID, continues_after_logout: true });
			const approved = await request(app)
				.post("/session/federation-grants/consent")
				.set("x-browser", "b-1")
				.send({ challenge, decision: "accept" });
			expect(approved.status).toBe(303);
			const state = new URL(approved.headers.location as string).searchParams.get("state") ?? "";

			// Back from the upstream.
			const returned = await request(app)
				.get("/session/federation-grants/callback/calendar")
				.query({ state, code: "code-1" })
				.set("x-browser", "b-1");
			expect(returned.status).toBe(303);
			const back = new URL(returned.headers.location as string);
			expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
			expect(back.searchParams.get("grant_id")).toBe(grantId);
			expect(back.searchParams.get("state")).toBe("client-state");
			expect(back.searchParams.has("error")).toBe(false);

			// And the client spends it, with no user present.
			const status = await request(app)
				.post(`/oauth/federation-grants/${grantId}/status`)
				.set("Authorization", basic)
				.send({ sub: "alice" });
			expect(status.status).toBe(200);
			expect(status.body.status).toBe("active");
			const token = await request(app)
				.post(`/oauth/federation-grants/${grantId}/token`)
				.set("Authorization", basic)
				.send({ sub: "alice" });
			expect(token.status).toBe(200);
			expect(token.body).toMatchObject({
				access_token: "upstream-access-token",
				token_type: "bearer",
			});
		} finally {
			await handle.dispose();
		}
	});

	/** A client lodges an intent for alice; the connect link's path and query. */
	const lodgeFor = async (app: express.Express): Promise<URL> => {
		const lodged = await request(app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic)
			.send({ connection: "calendar", sub: "alice", redirect_uri: REDIRECT, state: "s" });
		expect(lodged.status).toBe(201);
		return new URL(lodged.body.connect_uri as string);
	};

	it("sends a browser that is not signed in to the configured login page, and back to exactly this link", async () => {
		const { handle, app } = await boot();
		try {
			const connect = await lodgeFor(app);
			const anonymous = await request(app).get(`${connect.pathname}${connect.search}`);
			expect(anonymous.status).toBe(303);
			const login = new URL(anonymous.headers.location as string, ISSUER);
			expect(login.pathname).toBe(ACQUISITION_ENDPOINTS.login.url);
			expect(login.searchParams.get("redirect_to")).toBe(connect.href);
		} finally {
			await handle.dispose();
		}
	});
});
