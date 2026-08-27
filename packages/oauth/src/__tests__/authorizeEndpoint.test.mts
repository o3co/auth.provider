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
 * `GET /authorize` — error and edge paths of the RFC 6749 §4.1 sequence
 * (#328). The endpoint's happy paths and per-invariant gates already have
 * suites (firstPartyAuthorize, emailVerifiedGate, resourceIndicator.stage2,
 * hooks); this file pins the request-boundary failures those suites step
 * over: the A-1 400-JSON phase before `redirect_uri` is trusted, the
 * malformed-parameter rejects (response_type, nonce, PKCE), the policy /
 * repository failure modes, and the unauthenticated login redirect.
 */

import {
	type AppConfig,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantPolicyHook,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";

const makeConfig = (oauthOverrides: Record<string, unknown>): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			// `dual` so requests without `openid` reach the branch under test
			// instead of tripping the IH-6 gate first.
			oidcMode: "dual",
			grants: {},
			...oauthOverrides,
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	}) as unknown as AppConfig;

const makeApp = async (opts: {
	/** Overrides merged into the client record; `firstParty: true` is the base. */
	client?: Record<string, unknown>;
	/** `findById` returns null (unknown client). */
	clientNotFound?: boolean;
	/** `findById` rejects (repository outage). */
	findByIdThrows?: boolean;
	/** `createCode` rejects (code store outage). */
	createCodeThrows?: boolean;
	/** Spy target: receives the createCode params. */
	createCode?: ReturnType<typeof vi.fn>;
	/** Session object the request carries; default authenticated user-1. */
	session?: Record<string, unknown>;
	/** Merged into `config.oauth`. */
	oauth?: Record<string, unknown>;
	grantPolicy?: GrantPolicyHook;
	auditSink?: AuditSink;
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		firstParty: true,
		...(opts.client ?? {}),
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => {
			if (opts.findByIdThrows) throw new Error("repo down");
			if (opts.clientNotFound) return null;
			return id === CLIENT_ID ? record : null;
		},
		authenticate: async () => null,
	};
	const createCode =
		opts.createCode ??
		vi.fn(async () => ({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }));
	const codeRepository: CodeRepository = {
		createCode: async (params) => {
			if (opts.createCodeThrows) throw new Error("store down");
			return createCode(params) as ReturnType<CodeRepository["createCode"]>;
		},
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: makeConfig(opts.oauth ?? {}),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
	});

	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = opts.session ?? {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});
	app.use("/oauth", router);
	return { app, createCode };
};

type Query = Record<string, string | string[]>;

const baseQuery: Query = {
	response_type: "code",
	client_id: CLIENT_ID,
	redirect_uri: REDIRECT_URI,
	state: "xyz",
};

const authorize = (app: express.Express, query: Query) =>
	request(app).get("/oauth/authorize").query(query);

/** Parses the error redirect this endpoint answers with past A-1 validation. */
const redirectParams = (res: request.Response): URLSearchParams => {
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string);
	expect(location.origin + location.pathname).toBe(REDIRECT_URI);
	return location.searchParams;
};

describe("/authorize — unauthenticated session", () => {
	it("redirects to the configured login page, round-tripping the original URL", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		const location = res.headers.location as string;
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
		expect(decodeURIComponent(location.split("redirect_to=")[1] as string)).toContain(
			"/oauth/authorize",
		);
	});
});

describe("/authorize — A-1 pre-redirect validation (400/500 JSON)", () => {
	it("rejects a request without client_id", async () => {
		const { app } = await makeApp({});
		const { client_id: _omitted, ...query } = baseQuery;
		const res = await authorize(app, query);
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "client_id is required",
		});
	});

	it("rejects a request without redirect_uri", async () => {
		const { app } = await makeApp({});
		const { redirect_uri: _omitted, ...query } = baseQuery;
		const res = await authorize(app, query);
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "redirect_uri is required",
		});
	});

	it("answers 500 server_error when the client repository is down", async () => {
		const { app } = await makeApp({ findByIdThrows: true });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			error: "server_error",
			error_description: "Failed to fetch client",
		});
	});

	it("rejects an unknown client without redirecting — its redirect_uri is untrusted", async () => {
		const { app } = await makeApp({ clientNotFound: true });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(400);
		expect(res.body).toEqual({ error: "invalid_client", error_description: "client not found" });
	});

	it("rejects a redirect_uri outside the client allowlist without redirecting", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, redirect_uri: "https://evil.example/cb" });
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "redirect_uri not allowed",
		});
	});
});

describe("/authorize — response_type validation", () => {
	it("answers 400 JSON for a non-code response_type (no validated redirect_uri)", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, response_type: "token" });
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "unsupported_response_type",
			error_description: 'response_type "token" is not supported',
		});
	});

	it("redirects unsupported_response_type for a repeated response_type that includes code", async () => {
		// `?response_type=code&response_type=token` passes the dispatch
		// (`includes("code")`) but is not the single string "code".
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, response_type: ["code", "token"] });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("unsupported_response_type");
		expect(params.get("state")).toBe("xyz");
		expect(params.get("code")).toBeNull();
	});
});

describe("/authorize — PKCE required (B-8)", () => {
	it("rejects a confidential-client request without code_challenge when pkce.required", async () => {
		const { app } = await makeApp({
			oauth: { grants: { authorization_code: { pkce: { required: true } } } },
		});
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
	});

	it("rejects an empty-string code_challenge the same way", async () => {
		const { app } = await makeApp({
			oauth: { grants: { authorization_code: { pkce: { required: true } } } },
		});
		const res = await authorize(app, { ...baseQuery, code_challenge: "" });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
	});
});

describe("/authorize — nonce validation (IH-16)", () => {
	it("rejects a repeated nonce (array) as invalid_request at the boundary", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, nonce: ["a", "b"] });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("nonce must be a single string value");
	});
});

describe("/authorize — code_challenge_method resolution (B-7)", () => {
	it("falls back to the configured defaultMethod when the method is omitted", async () => {
		const { app, createCode } = await makeApp({
			oauth: {
				grants: {
					authorization_code: {
						pkce: { defaultMethod: "plain", supportedMethods: ["S256", "plain"] },
					},
				},
			},
		});
		const res = await authorize(app, { ...baseQuery, code_challenge: "abc" });
		const params = redirectParams(res);
		expect(params.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledWith(
			expect.objectContaining({ code_challenge: "abc", code_challenge_method: "plain" }),
		);
	});

	it("rejects a method outside supportedMethods", async () => {
		const { app } = await makeApp({
			oauth: {
				grants: { authorization_code: { pkce: { supportedMethods: ["plain"] } } },
			},
		});
		const res = await authorize(app, {
			...baseQuery,
			code_challenge: "abc",
			code_challenge_method: "S256",
		});
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe('code_challenge_method "S256" is not supported');
	});
});

describe("/authorize — policy evaluation edges (C-2)", () => {
	it("passes subject/requestedScope as undefined when the session user has no id and no scope was sent", async () => {
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const { app } = await makeApp({
			grantPolicy: { kind: "test", evaluate },
			session: { isAuthenticated: true, user: {} },
		});
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("code")).toBe("code-x");
		expect(evaluate).toHaveBeenCalledTimes(1);
		const evaluated = evaluate.mock.calls[0]?.[0] as unknown as Record<string, unknown>;
		expect(evaluated.subject).toBeUndefined();
		expect(evaluated.requestedScope).toBeUndefined();
	});

	it('redirects a deny without errorDescription as "policy denied"', async () => {
		const { app } = await makeApp({
			grantPolicy: {
				kind: "test",
				evaluate: async () => ({ outcome: "deny" as const, error: "access_denied" }),
			},
		});
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("access_denied");
		expect(params.get("error_description")).toBe("policy denied");
	});
});

describe("/authorize — resource indicator without allowedAudiences (RFC 8707)", () => {
	it("cannot derive an audience for a foreign resource and rejects invalid_target", async () => {
		// The client record predates `allowedAudiences`; the derivation bound
		// falls back to the client id alone, which cannot represent the
		// requested resource.
		const { app } = await makeApp({
			oauth: { resourceIndicator: { enabled: true } },
		});
		const res = await authorize(app, { ...baseQuery, resource: "https://api.example" });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_target");
		expect(params.get("error_description")).toBe(
			"requested_resources_not_in_audience: https://api.example",
		);
	});
});

describe("/authorize — code issuance failure", () => {
	it("redirects server_error when the code repository is down", async () => {
		const { app } = await makeApp({ createCodeThrows: true });
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("server_error");
		expect(params.get("error_description")).toBe("Failed to create authorization code");
		expect(params.get("code")).toBeNull();
	});
});

describe("/authorize — success audit subject (login.success)", () => {
	it("emits login.success with subject undefined when the session user has no string id", async () => {
		const record = vi.fn(async () => {});
		const { app } = await makeApp({
			auditSink: { record },
			session: { isAuthenticated: true, user: {} },
		});
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("code")).toBe("code-x");
		expect(record).toHaveBeenCalledWith(expect.objectContaining({ type: "login.success" }));
		const event = record.mock.calls.find(
			(c) => (c as unknown as [Record<string, unknown>])[0]?.type === "login.success",
		)?.[0] as unknown as Record<string, unknown>;
		expect(event.subject).toBeUndefined();
		expect(event.clientId).toBe(CLIENT_ID);
	});
});
