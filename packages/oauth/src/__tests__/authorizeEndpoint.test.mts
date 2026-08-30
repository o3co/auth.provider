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

import crypto from "node:crypto";
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

// #273: PKCE/S256 is mandatory for every client, so every request that is
// meant to get PAST the PKCE gate has to carry a challenge. `baseQuery`
// carries one; the PKCE suites below override or drop it deliberately.
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const makeConfig = (oauthOverrides: Record<string, unknown>, loginUrl = "/login"): AppConfig =>
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
		endpoints: { login: { url: loginUrl } },
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
	/** `endpoints.login.url`; default `/login`. */
	loginUrl?: string;
	grantPolicy?: GrantPolicyHook;
	auditSink?: AuditSink;
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		// #396: the old implicit omitted-scope grant, now declared.
		defaultScopes: ["read"],
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
		config: makeConfig(opts.oauth ?? {}, opts.loginUrl),
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
	code_challenge: S256_CHALLENGE,
	code_challenge_method: "S256",
};

/** `baseQuery` minus the PKCE pair, then `extra` — for the gate's own tests. */
const withoutPkce = (extra: Query = {}): Query => {
	const { code_challenge: _c, code_challenge_method: _m, ...rest } = baseQuery;
	return { ...rest, ...extra };
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
		const redirectTo = decodeURIComponent(location.split("redirect_to=")[1] as string);
		// #356: the target's origin is the configured issuer — a fixed value
		// the login page's redirect allowlist can pin exactly.
		expect(redirectTo.startsWith("https://issuer.example/oauth/authorize?")).toBe(true);
		expect(redirectTo).toContain(`client_id=${CLIENT_ID}`);
	});

	it("joins redirect_to with & when the login URL already carries a query", async () => {
		const { app } = await makeApp({
			session: { isAuthenticated: false },
			loginUrl: "/login?tenant=x",
		});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		const location = res.headers.location as string;
		expect(location.startsWith("/login?tenant=x&redirect_to=")).toBe(true);
	});

	it("builds redirect_to from the configured origin, not the Host header (#356)", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const res = await request(app)
			.get("/oauth/authorize")
			.set("Host", "evil.example")
			.query(baseQuery);
		expect(res.status).toBe(302);
		const redirectTo = decodeURIComponent(
			(res.headers.location as string).split("redirect_to=")[1] as string,
		);
		expect(new URL(redirectTo).origin).toBe("https://issuer.example");
	});

	it("ignores forwarded proto/host even under `trust proxy` (#356)", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		// The deployment shape the attack needs: Express trusting its proxy
		// hop, so `req.protocol` / `req.get("host")` follow whatever forwarded
		// headers the client sent. The fix never reads them.
		app.set("trust proxy", true);
		const res = await request(app)
			.get("/oauth/authorize")
			.set("X-Forwarded-Proto", "http")
			.set("X-Forwarded-Host", "evil.example")
			.query(baseQuery);
		expect(res.status).toBe(302);
		const redirectTo = decodeURIComponent(
			(res.headers.location as string).split("redirect_to=")[1] as string,
		);
		expect(new URL(redirectTo).origin).toBe("https://issuer.example");
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

describe("/authorize — scope semantics (#396)", () => {
	it("narrows an over-asking request and persists only the allowlisted scopes", async () => {
		// The narrowing half of the §3.3 contract; the echo half (the token
		// response naming what WAS granted) is pinned in authorization.test.mts.
		const { app, createCode } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, scope: "read bogus" });
		expect(res.status).toBe(302);
		expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ grantedScope: ["read"] }));
	});

	it("grants defaultScopes when scope is omitted and the client declares them", async () => {
		const { app, createCode } = await makeApp({});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ grantedScope: ["read"] }));
	});

	it("redirects invalid_scope when scope is omitted and no defaultScopes are declared", async () => {
		// #396 deny-by-absence: the old behavior granted the client's ENTIRE
		// allowlist, making "forgot to send scope" the maximum grant.
		const { app } = await makeApp({ client: { defaultScopes: undefined } });
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_scope");
		expect(params.get("error_description")).toContain("defaultScopes");
	});

	it("keeps the empty grant for a scope-less client (empty allowlist, no defaults)", async () => {
		// The carve-out: nothing to over-grant, so scope-less deployments work.
		const { app, createCode } = await makeApp({
			client: { allowedScopes: [], defaultScopes: undefined },
		});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ grantedScope: undefined }));
	});
});

describe("/authorize — response_type validation", () => {
	// #397: once the client and redirect_uri validate, the refusal travels via
	// redirect (RFC 6749 §4.1.2.1) — the user lands back in the app instead of
	// on a JSON wall. 400 JSON remains for the cases where no redirect target
	// could be validated (next test).
	it("redirects unsupported_response_type for a non-code response_type once the client validates", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, response_type: "token" });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("unsupported_response_type");
		expect(params.get("state")).toBe("xyz");
		expect(params.get("code")).toBeNull();
	});

	it("answers 400 invalid_client JSON when the client cannot be validated — the client refusal outranks response_type (A-1)", async () => {
		const { app } = await makeApp({ clientNotFound: true });
		const res = await authorize(app, { ...baseQuery, response_type: "token" });
		// No validated redirect target exists, so nothing redirects — the
		// refusal is about the client, which outranks the response_type.
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
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

describe("/authorize — PKCE required (#273)", () => {
	it("rejects a confidential-client request without code_challenge", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, withoutPkce());
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
	});

	it("rejects an empty-string code_challenge the same way", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, withoutPkce({ code_challenge: "" }));
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
	});

	it("rejects a repeated code_challenge (array) as a repeat, not as absence", async () => {
		// RFC 6749 §3.1 — see SINGLE_VALUED_QUERY_PARAMS. The message names the
		// actual defect rather than reporting the parameter as missing.
		const { app } = await makeApp({});
		const res = await authorize(app, withoutPkce({ code_challenge: ["a", "b"] }));
		expect(redirectParams(res).get("error_description")).toBe(
			"code_challenge must be a single string value",
		);
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

describe("/authorize — code_challenge_method resolution (#273)", () => {
	it("rejects an omitted method — RFC 7636 §4.3 reads absence as `plain`", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, withoutPkce({ code_challenge: S256_CHALLENGE }));
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe(
			'code_challenge_method is required and must be "S256"',
		);
	});

	it("rejects a repeated method (array) as a repeat — it must not resolve as absent", async () => {
		// Reading a repeat as absence meant falling through to RFC 7636 §4.3's
		// `plain`, which an `allowPlainPkce` client could then use to downgrade
		// its own S256 request. See SINGLE_VALUED_QUERY_PARAMS.
		const { app } = await makeApp({});
		const res = await authorize(app, {
			...baseQuery,
			code_challenge_method: ["S256", "S256"],
		});
		expect(redirectParams(res).get("error_description")).toBe(
			"code_challenge_method must be a single string value",
		);
	});

	it("rejects a method outside the client's list", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, code_challenge_method: "S512" });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe('code_challenge_method "S512" is not supported');
	});

	it("persists the resolved method on the code", async () => {
		const { app, createCode } = await makeApp({});
		expect(redirectParams(await authorize(app, baseQuery)).get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledWith(
			expect.objectContaining({
				code_challenge: S256_CHALLENGE,
				code_challenge_method: "S256",
			}),
		);
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

describe("/authorize — success audit subject (authorize.granted)", () => {
	it("emits authorize.granted with subject undefined when the session user has no string id", async () => {
		const record = vi.fn(async () => {});
		const { app } = await makeApp({
			auditSink: { record },
			session: { isAuthenticated: true, user: {} },
		});
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("code")).toBe("code-x");
		expect(record).toHaveBeenCalledWith(expect.objectContaining({ type: "authorize.granted" }));
		const event = record.mock.calls.find(
			(c) => (c as unknown as [Record<string, unknown>])[0]?.type === "authorize.granted",
		)?.[0] as unknown as Record<string, unknown>;
		expect(event.subject).toBeUndefined();
		expect(event.clientId).toBe(CLIENT_ID);
	});
});

describe("/authorize — rejection audit vocabulary (authorize.rejected, #329)", () => {
	it("emits authorize.rejected when the client is not registered for the code grant", async () => {
		// The rejection used to reuse the token endpoint's
		// `token.issued.failure`; /authorize rejections carry their own name
		// so the success/failure pair names one operation.
		const record = vi.fn(async () => {});
		const { app } = await makeApp({
			auditSink: { record },
			client: { allowedGrantTypes: ["client_credentials"] },
		});
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("error")).toBe("unauthorized_client");
		expect(record).toHaveBeenCalledWith(
			expect.objectContaining({
				type: "authorize.rejected",
				clientId: CLIENT_ID,
				details: expect.objectContaining({ reason: "grant_type_not_allowed" }),
			}),
		);
	});
});

/*
 * #284 — "the OIDC surface is narrower than the OIDC-provider claim".
 *
 * Three separate defects behind that sentence, and they are not the same kind:
 *
 *  - `request` / `request_uri` were silently ignored. That is the security one:
 *    a signed request object exists to make the parameters tamper-proof, so an
 *    AS that processes the query string instead hands an attacker exactly what
 *    the object was there to prevent, while the RP believes it was honoured.
 *  - The discovery document *claimed* `request_uri` support by omission — OIDC
 *    Discovery defaults `request_uri_parameter_supported` to `true`.
 *  - `prompt=none` returned the login page, so silent renewal in a hidden
 *    iframe timed out rather than receiving `login_required`.
 *
 * POST was a plain missing MUST (OIDC Core §3.1.2.1).
 */

const authorizePost = (app: express.Express, body: Query) =>
	request(app)
		.post("/oauth/authorize")
		.type("form")
		.send(body as Record<string, string>);

describe("/authorize — request objects are refused, not ignored (#284)", () => {
	it("answers request_not_supported for a request parameter", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, request: "ey.J.x" }));
		expect(params.get("error")).toBe("request_not_supported");
	});

	it("answers request_uri_not_supported for a request_uri parameter", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorize(app, { ...baseQuery, request_uri: "https://rp.example/req.jwt" }),
		);
		expect(params.get("error")).toBe("request_uri_not_supported");
	});

	it("refuses before minting anything", async () => {
		// The failure mode was issuing a code for the query parameters while
		// the RP believed its signed object had been used.
		const createCode = vi.fn();
		const { app } = await makeApp({ createCode });
		await authorize(app, { ...baseQuery, request_uri: "https://rp.example/req.jwt" });
		expect(createCode).not.toHaveBeenCalled();
	});

	it("preserves state on the refusal so the RP can correlate it", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorize(app, { ...baseQuery, state: "xyz", request: "ey.J.x" }),
		);
		expect(params.get("state")).toBe("xyz");
	});
});

describe("/authorize — prompt=none (#284)", () => {
	it("answers login_required by redirect when there is no session", async () => {
		// The point: a hidden iframe cannot act on a login page. This has to
		// reach the RP's own redirect_uri, which is why the request is allowed
		// past the session gate to have its redirect_uri validated first.
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("login_required");
	});

	it("proceeds silently when a session is present", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, prompt: "none" });
		const location = new URL(res.headers.location as string);
		expect(location.searchParams.get("error")).toBeNull();
		expect(location.searchParams.get("code")).not.toBeNull();
	});

	it("still sends an unauthenticated request without prompt=none to the login page", async () => {
		// The fall-through is scoped to prompt=none; every other
		// unauthenticated request must still answer before touching the
		// repository.
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(res.headers.location).toContain("/login");
	});

	it("refuses prompt=none combined with another value", async () => {
		// §3.1.2.1: "if this parameter contains none with any other value, an
		// error is returned".
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none login" }));
		expect(params.get("error")).toBe("invalid_request");
	});

	it("refuses consent and select_account rather than ignoring them", async () => {
		// Ignoring would hand back a token the RP believes was freshly
		// consented to. This AS is first-party only and has no consent step.
		const { app } = await makeApp({});
		// Collected then asserted as a set, so a failure names which value
		// behaved differently rather than stopping at the first.
		const outcomes: string[] = [];
		for (const prompt of ["consent", "select_account", "login"]) {
			const params = redirectParams(await authorize(app, { ...baseQuery, prompt }));
			const namesTheValue = (params.get("error_description") ?? "").includes(prompt);
			outcomes.push(`${prompt}:${params.get("error")}:names=${namesTheValue}`);
		}
		expect(outcomes).toEqual([
			"consent:invalid_request:names=true",
			"select_account:invalid_request:names=true",
			"login:invalid_request:names=true",
		]);
	});

	it("refuses a repeated prompt parameter instead of picking one", async () => {
		// `?prompt=none&prompt=login` parses to an array, not a string. Reading
		// one element of it would let an attacker who can append to the query
		// choose which directive the AS sees; taking the whole thing as a
		// single value would then reject a legitimate `prompt=none`. Neither
		// is a decision this endpoint should be making on the RP's behalf.
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorize(app, { ...baseQuery, prompt: ["none", "login"] }),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toContain("single string");
	});

	it("treats an absent prompt exactly as before", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, baseQuery);
		expect(new URL(res.headers.location as string).searchParams.get("code")).not.toBeNull();
	});
});

describe("/authorize — POST is supported (#284)", () => {
	it("accepts the same request as a form POST", async () => {
		// OIDC Core §3.1.2.1 makes this a MUST, and it is how an RP sends a
		// request too large for a URL.
		const { app } = await makeApp({});
		const res = await authorizePost(app, baseQuery);
		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string).searchParams.get("code")).not.toBeNull();
	});

	it("runs the same checks on POST — a refusal on GET is a refusal on POST", async () => {
		// One handler instance behind both methods, so a check cannot be
		// mounted on one and forgotten on the other.
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorizePost(app, { ...baseQuery, request_uri: "https://rp.example/r.jwt" }),
		);
		expect(params.get("error")).toBe("request_uri_not_supported");
	});

	it("answers login_required on POST too", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const params = redirectParams(await authorizePost(app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("login_required");
	});
});
