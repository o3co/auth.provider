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
 * The rotation budget an operator writes in `federation-grants {}` is the one
 * retrieval holds a grant to: booted with `createApp` and the real modules, a
 * grant whose token runs out between calls refreshes until the configured
 * budget is spent, is refused with the wait until the configured window
 * closes, and refreshes again once it has.
 */

import type { BootstrapMap, Client, ClientRepository } from "@o3co/auth-provider-core";
import {
	createApp,
	createInMemorySubjectRevocation,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "@o3co/auth-provider-core";
import { coreConfigForTests, makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import {
	ACQUISITION_GRANT_SETTINGS,
	acquisitionComponents,
	callbackUrlFor,
	sessionMiddlewareModule,
} from "./acquisitionFixture.mjs";
import { basic, CLIENT_ID, CLIENT_SECRET, connection, DAY, MIN, SUBJECT } from "./harness.mjs";

/** Seconds. How long every token, the seeded one and each refreshed one, lives. */
const TOKEN_LIFE = 60;

const client = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [],
	allowedFederationGrantConnections: [connection.name],
} as unknown as Client;

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? (client as never) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? (client as never) : null,
};

/** What core's federation guard asks for once a federation is enabled. */
const SESSION_FEDERATION_STORES = {
	userSessionStore: {},
	sessionRPRegistry: {},
	sessionFamilyIndex: {},
	sessionFederationIndex: {},
	federationTokenStore: {},
	refreshTokenFamilyRevocation: {},
};

const boot = async (settings: Record<string, unknown>) => {
	const refreshDelegatedToken = vi.fn(async () => ({
		accessToken: `access-${refreshDelegatedToken.mock.calls.length}`,
		refreshToken: `refresh-${refreshDelegatedToken.mock.calls.length}`,
		expiresIn: TOKEN_LIFE,
		expiresAt: new Date(Date.now() + TOKEN_LIFE * 1000),
		tokenType: "Bearer",
	}));
	const federationModule = defineModule({
		name: "test-federation-upstream",
		contributes: {
			federations: {
				upstream: () => ({
					name: "upstream",
					buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
					exchangeDelegatedCode: async () => ({}),
					refreshDelegatedToken,
				}),
			},
			federationRedirectPolicies: {
				upstream: () => ({
					validateRedirect: () => ({ ok: true as const, value: undefined }),
					resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
				}),
			},
		} as never,
	});
	const store = createMemoryFederationGrantStore();
	const handle = await createApp({
		modules: [federationModule, sessionMiddlewareModule, ...federationGrantsModules],
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				rateLimit: { failMode: "closed" },
				...coreConfigForTests({
					declaredAbsent: ["auditSink"],
					federations: {
						upstream: {
							enabled: true,
							issuer: connection.upstreamIssuer,
							clientId: connection.upstreamClientId,
						},
					},
				}),
				"federation-grants": {
					enabled: true,
					connections: {
						[connection.name]: {
							federation: "upstream",
							scopes: [...connection.scopes],
							boundary: connection.boundary,
							maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
							callbackURL: callbackUrlFor(connection.name),
						},
					},
					...ACQUISITION_GRANT_SETTINGS,
					...settings,
				},
			},
			pathResolver: (s: string) => s,
			clientRepository,
			...acquisitionComponents(),
			...SESSION_FEDERATION_STORES,
			subjectRevocation: createInMemorySubjectRevocation(),
			federationGrantStore: store,
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 100, windowSeconds: 60 },
			}),
		} as unknown as BootstrapMap,
	});

	const resolved = { ...connection, allowScopeSubsets: true, authorizationParams: {} };
	const at = new Date();
	await store.createPending({
		id: "g-1",
		subject: SUBJECT,
		clientId: CLIENT_ID,
		connection: connection.name,
		intent: { handle: "h", expiresAt: new Date(at.getTime() + 10 * MIN) },
		now: at,
	});
	await store.activate({
		grantId: "g-1",
		intentHandle: "h",
		authorization: {
			identityRevision: federationGrantIdentityRevision(resolved),
			authorizationRevision: federationGrantAuthorizationRevision(resolved),
			upstream: { issuer: connection.upstreamIssuer, subject: "upstream-subject" },
			scopes: [...connection.scopes],
			consent: { at, sid: "sid", scopes: [...connection.scopes] },
			authorizedAt: at,
			expiresAt: new Date(at.getTime() + 30 * DAY),
			resource: undefined,
		},
		credentials: {
			refreshToken: "refresh-0",
			accessToken: {
				value: "access-0",
				tokenType: "Bearer",
				obtainedAt: at,
				issuedLifetime: TOKEN_LIFE,
				effectiveExpiresAt: new Date(at.getTime() + TOKEN_LIFE * 1000),
				scopes: [...connection.scopes],
			},
		},
		now: at,
	});

	const app = express();
	app.use(handle.router);
	return { handle, app, refreshDelegatedToken };
};

/** Lets the stored token run out, then asks for one. */
const afterTheTokenRunsOut = (app: express.Express) => {
	vi.setSystemTime(new Date(Date.now() + (TOKEN_LIFE + 1) * 1000));
	return request(app)
		.post("/oauth/federation-grants/g-1/token")
		.set("Authorization", basic())
		.send({ sub: SUBJECT });
};

describe("the rotation budget a deployment configures", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("refuses the third refresh in a window under a budget of 2, and refreshes once the window closes", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		// The window opens at the first refresh, 61 seconds in, and closes 150
		// seconds later, at 211.
		const { handle, app, refreshDelegatedToken } = await boot({
			rotationBudget: 2,
			rotationWindow: "150",
		});
		try {
			expect((await afterTheTokenRunsOut(app)).status).toBe(200);
			expect((await afterTheTokenRunsOut(app)).status).toBe(200);
			expect(refreshDelegatedToken).toHaveBeenCalledTimes(2);

			const refused = await afterTheTokenRunsOut(app);
			expect(refused.status).toBe(429);
			expect(refused.body).toEqual({ error: "rate_limited", error_description: "provider" });
			// At 183 seconds: 28 seconds until the window closes.
			expect(refused.headers["retry-after"]).toBe("28");
			expect(refreshDelegatedToken).toHaveBeenCalledTimes(2);

			const served = await afterTheTokenRunsOut(app);
			expect(served.status).toBe(200);
			expect(served.body.access_token).toBe("access-3");
			expect(refreshDelegatedToken).toHaveBeenCalledTimes(3);
		} finally {
			await handle.dispose();
		}
	});

	it("refreshes a third time in the window under the default budget", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const { handle, app, refreshDelegatedToken } = await boot({});
		try {
			for (let call = 1; call <= 3; call += 1) {
				expect((await afterTheTokenRunsOut(app)).status, `call ${call}`).toBe(200);
			}
			expect(refreshDelegatedToken).toHaveBeenCalledTimes(3);
		} finally {
			await handle.dispose();
		}
	});
});
