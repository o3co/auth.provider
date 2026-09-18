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
 * A subject-wide revocation, and what a grant disclosure makes of it (#593, D13).
 *
 * Three packages have to agree for this to work, and each of them is tested on
 * its own elsewhere: core writes the two boundaries and orchestrates,
 * `@o3co/auth-provider-oauth` wires the service over the session cascade, and
 * this package compares a grant against the boundary on every disclosure.
 * What none of those can show is whether the agreement HOLDS — so these run the
 * real service against the real route, through one composed application.
 *
 * Two claims, and they are the two an operator is actually making:
 *
 *  - a revocation asked to KEEP this subject's grants leaves an established
 *    grant usable, while their sessions and tokens end;
 *  - a full revocation ends it **even when the explicit grant pass never ran**
 *    — the boundary is a backstop, and a backstop that only works when the
 *    cleanup worked is not one.
 */

import type {
	BootstrapMap,
	Client,
	ClientRepository,
	FederationProvider,
	MemoryFederationGrantStore,
	SubjectRevocationService,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createInMemorySubjectRevocation,
	createInMemorySubjectSessionIndex,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	revokeAllForSubject,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import { cascadeLogout, subjectRevocationServiceModule } from "@o3co/auth-provider-oauth";
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
	refreshDelegatedToken: async () => ({
		accessToken: "rotated-access-token",
		refreshToken: "rotated-refresh-token",
		expiresIn: 3600,
		expiresAt: new Date(Date.now() + 3_600_000),
		tokenType: "Bearer",
	}),
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

/** One boundary pair and one grant store, shared by the service and the routes. */
const shared = () => ({
	subjectRevocation: createInMemorySubjectRevocation(),
	subjectSessionIndex: createInMemorySubjectSessionIndex(),
	federationGrantStore: createMemoryFederationGrantStore(),
});

/** What `cascadeLogout` fans out to. Nothing here logs anyone in; the sessions are the service's business. */
const CASCADE_STORES = {
	userSessionStore: { delete: async () => undefined },
	sessionRPRegistry: { removeBySid: async () => undefined },
	sessionFamilyIndex: { listFamilyIds: async () => [], removeBySid: async () => undefined },
	sessionFederationIndex: { removeBySid: async () => undefined },
	federationTokenStore: { removeBySid: async () => undefined },
	refreshTokenFamilyRevocation: { revokeFamily: async () => undefined },
};

const boot = async (allowKeep: boolean) => {
	const full = makeValidFullSections();
	const components = shared();
	const handle = await createApp({
		modules: [federationModule, ...federationGrantsModules, subjectRevocationServiceModule],
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				// The service sizes the boundary from the lifetimes it has to
				// outlive, and reads them here.
				session: full.session,
				federations: {
					upstream: {
						enabled: true,
						issuer: connection.upstreamIssuer,
						clientId: connection.upstreamClientId,
					},
				},
				rateLimit: { ...full.rateLimit, failMode: "closed" },
				audit: { sink: { type: "none" } },
				federationGrants: {
					enabled: true,
					allowKeepOnSubjectRevocation: allowKeep,
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
			...CASCADE_STORES,
			...components,
		} as unknown as BootstrapMap,
	});

	const store = components.federationGrantStore as MemoryFederationGrantStore;
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
	const service = handle.components.subjectRevocationService as SubjectRevocationService;
	return { handle, app, service, ...components };
};

const disclose = (app: express.Express) =>
	request(app)
		.post("/oauth/federation-grants/g-1/token")
		.set("Authorization", basic())
		.send({ sub: SUBJECT });

describe("a subject-wide revocation, from the service to the disclosure", () => {
	it("leaves an established grant usable when the operator allows keeping it", async () => {
		const { handle, app, service, subjectRevocation } = await boot(true);

		const result = await service.revokeAllForSubject({
			subject: SUBJECT,
			federationGrants: "keep",
		});
		expect(result.federationGrants.applied).toBe("keep");

		const response = await disclose(app);
		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("upstream-access-token");
		// And the subject's sessions and tokens did end: keeping the grants is
		// not keeping the session they were agreed through.
		expect(await subjectRevocation.revokedBefore(SUBJECT)).not.toBeNull();
		await handle.dispose();
	});

	it("ends it when the operator does not", async () => {
		const { handle, app, service } = await boot(false);

		const result = await service.revokeAllForSubject({
			subject: SUBJECT,
			federationGrants: "keep",
		});
		expect(result.federationGrants).toEqual({
			requested: "keep",
			applied: "revoke",
			reason: "keep_not_allowed",
		});

		const response = await disclose(app);
		expect(response.status).toBe(410);
		expect(response.body.error).toBe("grant_revoked");
		await handle.dispose();
	});

	it("ends it through the boundary alone, with no grant pass at all", async () => {
		// The case the backstop exists for. A caller written before #593 passes
		// no grant store, so nothing enumerates the subject's grants — and the
		// disclosure must still stop. A backstop that only works when the
		// cleanup worked is not a backstop.
		const { handle, app, subjectRevocation, subjectSessionIndex, federationGrantStore } =
			await boot(true);

		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: 400 * DAY,
			cascadeSession: async () => ({ ok: true }),
			subjectSessionIndex,
			subjectRevocation,
		});
		expect(result.complete).toBe(true);
		expect(result.grantsRequested).toBe(false);
		// Nothing wrote to the record: it is still `active` in the store.
		expect((await federationGrantStore.find("g-1", new Date()))?.status).toBe("active");

		const response = await disclose(app);
		expect(response.status).toBe(410);
		expect(response.body.error).toBe("grant_revoked");
		// And the disclosure wrote the revocation down rather than recomputing
		// it for ever: the record is over from here on for every reader.
		expect((await federationGrantStore.find("g-1", new Date()))?.status).toBe("revoked");
		await handle.dispose();
	});

	it("is not what an ordinary logout does", async () => {
		// A logout ends a session. A grant outlives the session it was agreed
		// through — that is the whole of what a federation grant is — so the
		// four-store cascade both logout endpoints run must leave it, and its
		// credential, exactly as they were. The composition here has the grant
		// store in it, so a cascade that grew a path to it would fail this.
		const { handle, app, federationGrantStore } = await boot(true);

		const result = await cascadeLogout({
			sid: "sid",
			...(CASCADE_STORES as unknown as Parameters<typeof cascadeLogout>[0]),
		});
		expect(result.outcome).toBe("done");

		const grant = await federationGrantStore.find("g-1", new Date());
		expect(grant?.status).toBe("active");
		expect((await federationGrantStore.open("g-1", new Date()))?.credentials.state).toBe("ok");
		// And the grant is still spendable, which is the fact a backend cares about.
		const response = await disclose(app);
		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("upstream-access-token");
		await handle.dispose();
	});

	it("ends it even when the grant pass ran and failed", async () => {
		const { handle, app, subjectRevocation, subjectSessionIndex, federationGrantStore } =
			await boot(true);
		const store = {
			...federationGrantStore,
			listBySubject: async () => {
				throw new Error("store is down");
			},
		};

		const result = await revokeAllForSubject({
			subject: SUBJECT,
			watermarkTtlMs: 400 * DAY,
			cascadeSession: async () => ({ ok: true }),
			subjectSessionIndex,
			subjectRevocation,
			federationGrantStore: store as unknown as MemoryFederationGrantStore,
		});
		expect(result.complete).toBe(false);

		const response = await disclose(app);
		expect(response.status).toBe(410);
		await handle.dispose();
	});
});
