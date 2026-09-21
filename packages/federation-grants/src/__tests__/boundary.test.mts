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
 * Slice 5 answers it at boot: a deployment with no capability, or with one
 * that carries only the boundary #296 shipped, does not start. `boot.test.mts`
 * holds those refusals. What is left here is what boot cannot establish — what
 * a backend will say about a subject when it is asked — and which of the two
 * boundaries the answer is read from.
 *
 * That last part is the whole of D13 from a disclosure's point of view. The
 * grants boundary and the sessions boundary move independently: a subject-wide
 * revocation asked to keep this subject's grants advances the sessions one
 * alone. Reading that one here would end the grants an operator's policy just
 * chose to keep, and the feature would look implemented while doing the
 * opposite.
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
import { describe, expect, it, vi } from "vitest";
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

const refreshed = vi.fn(async () => ({
	accessToken: "rotated-access-token",
	refreshToken: "rotated-refresh-token",
	expiresIn: 3600,
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: "Bearer",
}));

const delegated = {
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	exchangeDelegatedCode: async () => ({
		upstream: { issuer: "https://issuer.example", subject: "upstream-1" },
		tokens: {},
	}),
	refreshDelegatedToken: refreshed,
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

/**
 * What the adapter answers for the subject's boundaries: `null` from both, a
 * grants boundary in the past, or an answer that is neither a date nor null.
 */
type Boundaries = { grants?: Date | null | "malformed" | "invalid"; sessions?: Date | null };

const boot = async (boundaries: Boundaries = {}, spent = false) => {
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
			subjectRevocation: {
				kind: "memory",
				revokeBefore: async () => undefined,
				revokeSessionsBefore: async () => undefined,
				revokedBefore: async () => boundaries.sessions ?? null,
				grantsRevokedBefore: async () =>
					boundaries.grants === "malformed"
						? (undefined as unknown as null)
						: boundaries.grants === "invalid"
							? new Date("not a date")
							: (boundaries.grants ?? null),
			},
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
				// Ten seconds left of an hour: past half spent AND inside the
				// refresh buffer, which is what makes a refresh due — and the
				// only way the module's own refresher wiring is exercised.
				obtainedAt: spent ? new Date(at.getTime() - 3_590_000) : at,
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
	it("refuses an answer that is neither a date nor null, on both routes", async () => {
		// Found by review. `null` is a statement — nothing was revoked for this
		// subject — and an adapter that answers `undefined` has made none. The
		// two routes read it through the same bridge, so they cannot disagree:
		// before this, `/status` reported `active` while `/token` on the same
		// input failed closed.
		const { handle, app } = await boot({ grants: "malformed" });

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

	it("refuses a date that cannot be compared, which is not the same as no revocation", async () => {
		// `new Date("nope")` is an instance of Date, so a check that stops at
		// the type lets it through — and every comparison against NaN is
		// false, which reads as "this subject has revoked nothing".
		const { handle, app } = await boot({ grants: "invalid" });

		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(503);
		expect(response.body.error).toBe("temporarily_unavailable");
		await handle.dispose();
	});

	it("reaches the federation adapter through the capability the module resolved", async () => {
		// The refresher the module builds is only exercised by a grant that
		// actually needs a refresh; everything else in this file is answered
		// from the stored token.
		refreshed.mockClear();
		const { handle, app } = await boot({}, true);

		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("rotated-access-token");
		expect(refreshed).toHaveBeenCalledTimes(1);
		await handle.dispose();
	});

	it("discloses the token where neither boundary has been stamped", async () => {
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("upstream-access-token");
		await handle.dispose();
	});

	it("ends a grant the subject's grants boundary covers", async () => {
		const { handle, app } = await boot({ grants: new Date(Date.now() + 60_000) });
		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		// 410 and not 403: the backstop does not merely refuse the disclosure,
		// it writes the revocation the boundary implies (D13), so the grant is
		// over from then on for everyone.
		expect(response.status).toBe(410);
		expect(response.body.error).toBe("grant_revoked");
		await handle.dispose();
	});

	it("keeps a grant the sessions boundary alone covers", async () => {
		// The subject's sessions and tokens ended; the operator's policy let
		// their grants stand. Reading `revokedBefore` here would revoke them
		// anyway, and nothing in the response would say so.
		const { handle, app } = await boot({ sessions: new Date(Date.now() + 60_000) });
		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
		expect(response.body.access_token).toBe("upstream-access-token");
		await handle.dispose();
	});
});
