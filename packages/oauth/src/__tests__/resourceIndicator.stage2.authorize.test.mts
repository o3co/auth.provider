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
 * RFC 8707 Stage 2 at the AUTHORIZATION endpoint (#173).
 *
 * The design decision this pins: for `authorization_code`, the audience is
 * decided ONCE at `/authorize` and persisted on the code (C-2 / D-1
 * evaluate-once-at-authorize). So `resource` is forwarded to the policy hook
 * HERE — this is the only place a policy may narrow the audience — and the
 * token endpoint does enforcement only, never re-evaluation.
 *
 * `/authorize` also rejects an unsatisfiable request rather than issuing a
 * code that the token endpoint is guaranteed to refuse later, which would
 * otherwise surface only after the user finished the redirect.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantPolicyHook,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const CLIENT_ID = "client-1";
const REDIRECT = "https://example.test/cb";
const API = "https://api.example";
const OTHER = "https://other.example";

const clientRepo: ClientRepository = {
	findById: async () => ({
		clientId: CLIENT_ID,
		allowedRedirectUris: [REDIRECT],
		firstParty: true,
		allowedScopes: ["openid", "profile"],
		allowedAudiences: [API, OTHER],
	}),
	authenticate: async () => null,
};

async function buildApp(opts: {
	enabled?: boolean;
	grantPolicy?: GrantPolicyHook;
	captureCode?: (params: Parameters<CodeRepository["createCode"]>[0]) => void;
}) {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});

	const codeRepo: CodeRepository = {
		createCode: async (params) => {
			opts.captureCode?.(params);
			return { code: "auth-code", client_id: params.client_id, redirect_uri: params.redirect_uri };
		},
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const config = {
		oauth: {
			jwt: { issuer: "https://auth.example" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			oidcMode: "oidc-required",
			...(opts.enabled !== undefined && { resourceIndicator: { enabled: opts.enabled } }),
		},
		endpoints: { login: { url: "/login" } },
	} as unknown as AppConfig;

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository: clientRepo,
		codeRepository: codeRepo,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.grantPolicy && { grantPolicy: opts.grantPolicy }),
	});
	app.use("/oauth", router);
	return app;
}

const authorizeUrl = (params: Record<string, string | string[]>) => {
	const qs = new URLSearchParams();
	qs.append("response_type", "code");
	qs.append("client_id", CLIENT_ID);
	qs.append("redirect_uri", REDIRECT);
	qs.append("scope", "openid");
	// #273: PKCE/S256 is mandatory at /authorize for every client.
	qs.append("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	qs.append("code_challenge_method", "S256");
	for (const [k, v] of Object.entries(params)) {
		for (const one of Array.isArray(v) ? v : [v]) qs.append(k, one);
	}
	return `/oauth/authorize?${qs.toString()}`;
};

const locationOf = (res: { headers: Record<string, string> }) => new URL(res.headers.location);

describe("Stage 2 — /authorize forwards `resource` to the policy hook", () => {
	it("passes the requested resource so the policy can narrow the audience", async () => {
		const evaluate = vi.fn(async () => ({
			outcome: "allow" as const,
			grantedAudience: [API],
		}));
		const captured: Parameters<CodeRepository["createCode"]>[0][] = [];
		const app = await buildApp({
			enabled: true,
			grantPolicy: { kind: "stub", evaluate },
			captureCode: (p) => captured.push(p),
		});

		const res = await request(app).get(authorizeUrl({ resource: API }));

		expect(res.status).toBe(302);
		expect(evaluate).toHaveBeenCalledWith(
			expect.objectContaining({ grantType: "authorization_code", resource: [API] }),
			expect.anything(),
		);
		// The narrowed audience is what the token endpoint will later read.
		expect(captured[0]?.grantedAudience).toEqual([API]);
	});

	it("supports a repeated `resource` query parameter", async () => {
		// Express surfaces `?resource=a&resource=b` as an array; the same
		// extractor the token endpoint uses handles both shapes, so the two
		// endpoints cannot disagree on what was requested.
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const app = await buildApp({ enabled: true, grantPolicy: { kind: "stub", evaluate } });

		await request(app).get(authorizeUrl({ resource: [API, OTHER] }));

		expect(evaluate).toHaveBeenCalledWith(
			expect.objectContaining({ resource: [API, OTHER] }),
			expect.anything(),
		);
	});

	it("omits `resource` from the policy request when the flag is off", async () => {
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const app = await buildApp({ enabled: false, grantPolicy: { kind: "stub", evaluate } });

		await request(app).get(authorizeUrl({ resource: API }));

		expect(evaluate).toHaveBeenCalledWith(
			expect.not.objectContaining({ resource: expect.anything() }),
			expect.anything(),
		);
	});
});

describe("Stage 2 — /authorize rejects an unsatisfiable resource request", () => {
	it("redirects invalid_target when the narrowed audience cannot represent it", async () => {
		const app = await buildApp({
			enabled: true,
			grantPolicy: {
				kind: "stub",
				evaluate: async () => ({ outcome: "allow", grantedAudience: [API] }),
			},
		});

		const res = await request(app).get(authorizeUrl({ resource: OTHER, state: "s1" }));

		expect(res.status).toBe(302);
		const url = locationOf(res);
		expect(url.searchParams.get("error")).toBe("invalid_target");
		expect(url.searchParams.get("error_description")).toContain(OTHER);
		// RFC 6749 §4.1.2.1: `state` round-trips on the error redirect.
		expect(url.searchParams.get("state")).toBe("s1");
	});

	it("does not issue a code when the request is rejected", async () => {
		// The point of failing here rather than at /token: no code should exist
		// for a request that can never be exchanged successfully.
		const captured: unknown[] = [];
		const app = await buildApp({
			enabled: true,
			grantPolicy: {
				kind: "stub",
				evaluate: async () => ({ outcome: "allow", grantedAudience: [API] }),
			},
			captureCode: (p) => captured.push(p),
		});

		await request(app).get(authorizeUrl({ resource: OTHER }));

		expect(captured).toHaveLength(0);
	});

	it("rejects two distinct resources — a single aud cannot represent both", async () => {
		const app = await buildApp({
			enabled: true,
			grantPolicy: {
				kind: "stub",
				evaluate: async () => ({ outcome: "allow", grantedAudience: [API] }),
			},
		});

		const res = await request(app).get(authorizeUrl({ resource: [API, OTHER] }));

		expect(locationOf(res).searchParams.get("error")).toBe("invalid_target");
	});

	it("derives and persists the audience when no policy narrows one", async () => {
		// Acceptance criterion 1, third bullet, at the authorization endpoint:
		// the derived audience is what gets persisted on the code, so the token
		// endpoint's later enforcement passes without ever consulting a policy.
		const captured: Parameters<CodeRepository["createCode"]>[0][] = [];
		const app = await buildApp({ enabled: true, captureCode: (p) => captured.push(p) });

		const res = await request(app).get(authorizeUrl({ resource: API }));

		expect(locationOf(res).searchParams.get("error")).toBeNull();
		expect(locationOf(res).searchParams.get("code")).toBe("auth-code");
		expect(captured[0]?.grantedAudience).toEqual([API]);
	});

	it("rejects a resource the client is not allowed, even with no policy", async () => {
		// Derivation is bounded by allowedAudiences ∪ {client_id}; naming a
		// resource must not be enough to have it persisted as the audience.
		const captured: unknown[] = [];
		const app = await buildApp({ enabled: true, captureCode: (p) => captured.push(p) });

		const res = await request(app).get(authorizeUrl({ resource: "https://evil.example" }));

		expect(locationOf(res).searchParams.get("error")).toBe("invalid_target");
		expect(captured).toHaveLength(0);
	});

	it("flag off: `resource` is ignored and the code is issued", async () => {
		const app = await buildApp({ enabled: false });

		const res = await request(app).get(authorizeUrl({ resource: OTHER }));

		expect(locationOf(res).searchParams.get("error")).toBeNull();
		expect(locationOf(res).searchParams.get("code")).toBe("auth-code");
	});
});
