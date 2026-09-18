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
 * The subject's grants boundary, as the module wires it (#593, D13).
 *
 * A grant outlives the session it was made in, so the thing that makes a
 * subject-wide revocation reach it is the backstop: every disclosure is
 * compared against a watermark for that subject. A deployment with no
 * subject-revocation capability has no watermark — and the whole question here
 * is what it should do about that.
 *
 * It answers 503. The tempting alternative is `null`, which the port uses for
 * "nothing was revoked for this subject" — but that is a statement, and an
 * absent capability is not in a position to make it. Reading the two as the
 * same switches core's backstop off silently, on exactly the deployments that
 * never noticed they needed one.
 *
 * Slice 5 turns this into a boot refusal, where it belongs. Until then it is a
 * per-request failure that an operator can see.
 */

import type {
	BootstrapMap,
	Client,
	ClientRepository,
	FederationProvider,
	MemoryFederationGrantStore,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import { basic, CLIENT_ID, CLIENT_SECRET, connection, DAY, MIN, SUBJECT } from "./harness.mjs";

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

const delegated = {
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	refreshDelegatedToken: async () => ({}),
} as unknown as FederationProvider;

const federationModule = defineModule({
	name: "test-federation-upstream",
	contributes: {
		federations: { upstream: () => delegated },
		federationRedirectPolicies: {
			upstream: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	} as never,
});

const storeModule = defineModule({
	name: "test-federation-grant-store",
	provides: { federationGrantStore: () => createMemoryFederationGrantStore() },
});

/** Everything core's federation guard asks for the moment a federation is enabled. */
const SESSION_FEDERATION_STORES = {
	userSessionStore: {},
	sessionRPRegistry: {},
	sessionFamilyIndex: {},
	sessionFederationIndex: {},
	federationTokenStore: {},
	refreshTokenFamilyRevocation: {},
};

const boot = async (withRevocation: boolean | "malformed") => {
	const full = makeValidFullSections();
	const handle = await createApp({
		modules: [federationModule, ...federationGrantsModules, storeModule],
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				federations: {
					upstream: {
						enabled: true,
						issuer: connection.upstreamIssuer,
						// The pair the grant's identity is pinned to: a different client id
						// here is a different upstream account, and the grant is retired.
						clientId: connection.upstreamClientId,
					},
				},
				rateLimit: { ...full.rateLimit, failMode: "closed" },
				audit: { sink: { type: "none" } },
				federationGrants: {
					enabled: true,
					connections: {
						[connection.name]: {
							federation: "upstream",
							scopes: [...connection.scopes],
							boundary: connection.boundary,
							maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
						},
					},
				},
			},
			pathResolver: (s: string) => s,
			clientRepository,
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 100, windowSeconds: 60 },
			}),
			...SESSION_FEDERATION_STORES,
			...(withRevocation === false
				? {}
				: {
						subjectRevocation: {
							revokedBefore: async () =>
								withRevocation === "malformed" ? (undefined as unknown as null) : null,
						},
					}),
		} as unknown as BootstrapMap,
	});
	const store = handle.components.federationGrantStore as MemoryFederationGrantStore;
	// The connection as the module resolved it, defaults included — the
	// revisions are computed from that and not from the literal above.
	const resolved = { ...connection, allowScopeSubsets: true, authorizationParams: {} };
	// The module gives core the real clock, so the fixture runs on it too —
	// the harness's three-day offset exists for a seam this composition does
	// not have, and a grant dated into the future reads as an upstream token
	// nobody may use.
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
		},
		credentials: {
			refreshToken: "r",
			accessToken: {
				value: "upstream-access-token",
				tokenType: "Bearer",
				obtainedAt: at,
				issuedLifetime: 3600,
				scopes: [...connection.scopes],
			},
		},
		now: at,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

describe("the grants boundary the module wires", () => {
	it("answers 503 storage where the deployment has no subject revocation", async () => {
		const { handle, app } = await boot(false);
		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
		await handle.dispose();
	});

	it("refuses an answer that is neither a date nor null, on both routes", async () => {
		// Found by review. `null` is a statement — nothing was revoked for this
		// subject — and an adapter that answers `undefined` has made none. The
		// two routes read it through the same bridge, so they cannot disagree:
		// before this, `/status` reported `active` while `/token` on the same
		// input failed closed.
		const { handle, app } = await boot("malformed");

		const described = await request(app)
			.post("/oauth/federation-grants/g-1/status")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });
		expect(described.status).toBe(503);
		expect(described.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});

		const disclosed = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });
		expect(disclosed.status).toBe(503);
		expect(disclosed.body.error).toBe("temporarily_unavailable");

		await handle.dispose();
	});

	it("discloses the token once a watermark can actually be read", async () => {
		const { handle, app } = await boot(true);
		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("upstream-access-token");
		await handle.dispose();
	});
});
