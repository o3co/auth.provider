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
 * `GET /authorize` — error and edge paths of the RFC 6749 §4.1 sequence. The
 * happy paths and per-invariant gates have their own suites
 * (firstPartyAuthorize, emailVerifiedGate, resourceIndicator.stage2, hooks);
 * this file pins the request-boundary failures they step over: the 400-JSON
 * phase before `redirect_uri` is trusted, the malformed-parameter rejects
 * (response_type, nonce, PKCE), the policy / repository failure modes, and
 * the unauthenticated login redirect.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type FederationProvider,
	type GrantPolicyHook,
	type Logger,
	type LoginEntry,
	type PublicClient,
	type SessionAuthentication,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	ACR_VALUE_UNSATISFIABLE,
	logUnsatisfiableAcrValues,
	vouchableAcrValues,
} from "#/acrValues.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";

// PKCE/S256 is mandatory for every client, so a request meant to get past
// the PKCE gate carries a challenge. `baseQuery` carries one; the PKCE suites
// below override or drop it deliberately.
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const makeConfig = (
	oauthOverrides: Record<string, unknown>,
	loginUrl = "/login",
	federations: Record<string, unknown> = {},
): AppConfig =>
	({
		federations,
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			// `dual` so requests without `openid` reach the branch under test
			// instead of tripping the `openid` scope gate first.
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
	/** Pass `false` to compose without an express-session store. */
	sessionStore?: false;
	/** Share one ask store between two apps. */
	sessionStoreRecords?: Map<string, unknown>;
	/** Make the ask store fail on one operation. */
	sessionStoreFail?: "set" | "get";
	/** Merged into `config.oauth`. */
	oauth?: Record<string, unknown>;
	/** `endpoints.login.url`; default `/login`. */
	loginUrl?: string;
	/** The `loginEntry` slot, when a module provides it. */
	loginEntry?: LoginEntry;
	grantPolicy?: GrantPolicyHook;
	auditSink?: AuditSink;
	/** The session store `/authorize` re-checks a live `sid` against. */
	userSessionStore?: UserSessionStore;
	logger?: Logger;
	/**
	 * Install one federation, as a federation module's contribution would —
	 * `"trusted"` with `federations.google.trustUpstreamAmr = true` (the MFA
	 * ADR's D13), `"untrusted"` with the switch absent.
	 */
	federation?: "trusted" | "untrusted";
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		// What an omitted `scope` grants: nothing is granted implicitly.
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
		requirements: resolverForTests([]),
		registry: new GrantRegistry(),
		config: makeConfig(
			opts.oauth ?? {},
			opts.loginUrl,
			opts.federation === "trusted"
				? { google: { enabled: true, trustUpstreamAmr: true } }
				: opts.federation === "untrusted"
					? { google: { enabled: true } }
					: {},
		),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.loginEntry ? { loginEntry: opts.loginEntry } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
		...(opts.federation
			? {
					getFederationProviders: () =>
						new Map([["google", { name: "google" } as unknown as FederationProvider]]),
				}
			: {}),
	});

	const app = express();
	// One session object per app, and the same one for every request that app
	// serves. Copied rather than shared, because the fixtures are module-level
	// constants and a test may mutate what it is handed.
	const state: { session: Record<string, unknown> } = {
		session: { ...(opts.session ?? { isAuthenticated: true, user: { id: "user-1" } }) },
	};
	// The express-session store the middleware would have mounted. The
	// re-authentication ask is a record in it, under a prefix of its own.
	const records = opts.sessionStoreRecords ?? new Map<string, unknown>();
	const storeDown = new Error("session store unavailable");
	const sessionStore = {
		get: (sid: string, cb: (err: unknown, rec?: unknown) => void) =>
			opts.sessionStoreFail === "get" ? cb(storeDown) : cb(null, records.get(sid)),
		set: (sid: string, rec: unknown, cb?: (err?: unknown) => void) => {
			if (opts.sessionStoreFail === "set") return cb?.(storeDown);
			records.set(sid, rec);
			cb?.();
		},
		destroy: (sid: string, cb?: (err?: unknown) => void) => {
			records.delete(sid);
			cb?.();
		},
	};
	// `regenerate`, as express-session's session has it: the refused session
	// is replaced by a fresh, unauthenticated one (ADR
	// 2026-09-28-session-admission, D8, change 6). Not enumerable, so a test
	// comparing the session object sees the fields alone.
	const withRegenerate = (holder: { session?: unknown }): Record<string, unknown> => {
		const session = state.session;
		Object.defineProperty(session, "regenerate", {
			enumerable: false,
			configurable: true,
			value: (cb: (err?: unknown) => void) => {
				state.session = {};
				holder.session = withRegenerate(holder);
				cb();
			},
		});
		return session;
	};
	app.use((req, _res, next) => {
		const holder = req as unknown as { session?: unknown; sessionStore?: unknown };
		holder.session = withRegenerate(holder);
		if (opts.sessionStore !== false) holder.sessionStore = sessionStore;
		next();
	});
	app.use("/oauth", router);
	return {
		app,
		createCode,
		get session() {
			return state.session;
		},
		/** Replace the session object wholesale, as `/session/login` does when it regenerates. */
		regenerate(next: Record<string, unknown>) {
			state.session = next;
		},
		records,
	};
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

/** Parses the error redirect this endpoint answers once `redirect_uri` is trusted. */
const redirectParams = (res: request.Response): URLSearchParams => {
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string);
	expect(location.origin + location.pathname).toBe(REDIRECT_URI);
	return location.searchParams;
};

/**
 * A `loginEntry` that records every target it is asked for and sends
 * the browser to `/sign-in`, under a parameter of its own — so a trip built
 * from it cannot be mistaken for one built from `endpoints.login.url`.
 */
const recordingLoginEntry = (): { readonly asked: string[]; readonly entry: LoginEntry } => {
	const asked: string[] = [];
	return {
		asked,
		entry: Object.freeze({
			url: "/sign-in",
			urlFor: (returnTo: string) => {
				asked.push(returnTo);
				return `/sign-in?back=${encodeURIComponent(returnTo)}`;
			},
		}),
	};
};

describe("/authorize — unauthenticated session", () => {
	it("sends the login trip through the loginEntry a module provides, to come back to the same request", async () => {
		const { asked, entry } = recordingLoginEntry();
		const { app } = await makeApp({ session: { isAuthenticated: false }, loginEntry: entry });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(asked).toHaveLength(1);
		const target = asked[0] as string;
		expect(res.headers.location).toBe(`/sign-in?back=${encodeURIComponent(target)}`);
		// The request to come back to is the one `endpoints.login.url`'s trip names.
		expect(target.startsWith("https://issuer.example/oauth/authorize?")).toBe(true);
		expect(target).toContain(`client_id=${CLIENT_ID}`);
	});

	it("redirects to the configured login page, round-tripping the original URL", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		const location = res.headers.location as string;
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
		const redirectTo = decodeURIComponent(location.split("redirect_to=")[1] as string);
		// The target's origin is the configured issuer — a fixed value the
		// login page's redirect allowlist can pin exactly.
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
		// One redirect_to, naming the request to come back to; the page's own
		// query kept as it was.
		const query = new URL(location, "https://login.invalid").searchParams;
		expect(query.getAll("tenant")).toEqual(["x"]);
		expect(query.getAll("redirect_to")).toHaveLength(1);
		expect(query.get("redirect_to")?.startsWith("https://issuer.example/oauth/authorize?")).toBe(
			true,
		);
	});

	it.each([
		["a fragment alone", "/login#x", /^\/login\?redirect_to=([^#]*)#x$/],
		["a query and a fragment", "/login?tenant=x#y", /^\/login\?tenant=x&redirect_to=([^#]*)#y$/],
		[
			"a question mark inside the fragment alone",
			"/login#a?b",
			/^\/login\?redirect_to=([^#]*)#a\?b$/,
		],
		[
			"an absolute URL with a query and a fragment",
			"https://login.example/signin?tenant=x#y",
			/^https:\/\/login\.example\/signin\?tenant=x&redirect_to=([^#]*)#y$/,
		],
	])(
		"adds redirect_to to the login URL's query, before its fragment, when it carries %s",
		async (_label, loginUrl, shape) => {
			const { app } = await makeApp({ session: { isAuthenticated: false }, loginUrl });
			const res = await authorize(app, baseQuery);
			expect(res.status).toBe(302);
			const location = res.headers.location as string;
			const encoded = shape.exec(location)?.[1];
			expect(encoded, location).toBeDefined();
			// The target encoded whole, as encodeURIComponent writes it — not as a
			// form, which would write a space as `+`.
			const target = decodeURIComponent(encoded as string);
			expect(encoded).toBe(encodeURIComponent(target));
			expect(target.startsWith("https://issuer.example/oauth/authorize?")).toBe(true);
			expect(new URL(location, "https://login.invalid").searchParams.getAll("redirect_to")).toEqual(
				[target],
			);
		},
	);

	it("builds redirect_to from the configured origin, not the Host header", async () => {
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

	it("ignores forwarded proto/host even under `trust proxy`", async () => {
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		// The deployment shape the attack needs: Express trusting its proxy
		// hop, so `req.protocol` / `req.get("host")` follow whatever forwarded
		// headers the client sent. The endpoint never reads them.
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

describe("/authorize — pre-redirect validation (400/500 JSON)", () => {
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

	it("answers 503 temporarily_unavailable when the client repository is down", async () => {
		const { app } = await makeApp({ findByIdThrows: true });
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
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

describe("/authorize — redirect_uri matching (RFC 8252 §7.3)", () => {
	// A native app receives the authorization response on a loopback listener
	// whose port the OS assigns at run time, so the registration cannot name
	// it. The port — and only the port — is therefore ignored when BOTH sides
	// are `http:` on a loopback IP literal. Everything else is an exact string
	// comparison.
	const attempt = async (registered: string, presented: string) => {
		const { app, createCode } = await makeApp({ client: { allowedRedirectUris: [registered] } });
		const res = await authorize(app, { ...baseQuery, redirect_uri: presented });
		return { res, createCode };
	};

	const expectAccepted = (res: request.Response, presented: string) => {
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		// The PRESENTED URI is where the response goes — the registration is an
		// allowlist entry, not a rewrite target.
		expect(location.origin + location.pathname).toBe(presented);
		expect(location.searchParams.get("code")).toBe("code-x");
	};

	const expectRefused = (res: request.Response) => {
		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "redirect_uri not allowed",
		});
	};

	it("accepts an ephemeral port against a portless 127.0.0.1 registration", async () => {
		const presented = "http://127.0.0.1:49152/cb";
		const { res, createCode } = await attempt("http://127.0.0.1/cb", presented);
		expectAccepted(res, presented);
		// The code record binds the URI actually used, so the token endpoint's
		// RFC 6749 §4.1.3 equality check still has something exact to compare.
		expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ redirect_uri: presented }));
	});

	it("accepts an ephemeral port against a portless [::1] registration", async () => {
		const presented = "http://[::1]:49152/cb";
		const { res } = await attempt("http://[::1]/cb", presented);
		expectAccepted(res, presented);
	});

	it("refuses a different path or host even when both are loopback", async () => {
		expectRefused((await attempt("http://127.0.0.1/cb", "http://127.0.0.1:49152/other")).res);
		expectRefused((await attempt("http://127.0.0.1/cb", "http://127.0.0.2:49152/cb")).res);
	});

	it("refuses a path that only a URL normalization would equate with the registration", async () => {
		// The carve-out is the port and nothing else: a comparison on
		// normalized URLs would have let these into the allowlist.
		expectRefused((await attempt("http://127.0.0.1/cb", "http://127.0.0.1:49152/a/../cb")).res);
		expectRefused((await attempt("http://127.0.0.1/cb", "http://127.0.0.1:49152/cb/")).res);
	});

	it("refuses a port difference on localhost — no carve-out (RFC 8252 §8.3)", async () => {
		expectRefused((await attempt("http://localhost/cb", "http://localhost:1234/cb")).res);
	});

	it("refuses a port difference on https", async () => {
		expectRefused((await attempt("https://app.example/cb", "https://app.example:8443/cb")).res);
	});
});

describe("/authorize — scope semantics", () => {
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
		// Deny by absence: "forgot to send scope" must not grant the client's
		// entire allowlist.
		const { app } = await makeApp({ client: { defaultScopes: undefined } });
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_scope");
		expect(params.get("error_description")).toContain("defaultScopes");
	});

	it("redirects invalid_scope for a scope that is not RFC 6749 §3.3's space-delimited list, rather than narrowing it", async () => {
		// Narrowing is for a scope this client may not have (§3.3). A malformed
		// one is a different answer (§4.1.2.1 invalid_scope: "malformed"):
		// "read\tbogus" is not the scope "read" with a typo beside it, and
		// narrowing it to nothing would issue a code for a request nobody made.
		const { app, createCode } = await makeApp({});
		for (const scope of ["read\tbogus", 'read "x"', "\t"]) {
			const params = redirectParams(await authorize(app, { ...baseQuery, scope }));
			expect(params.get("error"), JSON.stringify(scope)).toBe("invalid_scope");
			expect(params.get("error_description")).toBe(
				"scope is not a space-delimited list of scope-tokens",
			);
		}
		expect(createCode).not.toHaveBeenCalled();
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
	// Once the client and redirect_uri validate, the refusal travels via
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

	it("answers 400 invalid_client JSON when the client cannot be validated — the client refusal outranks response_type", async () => {
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

	// RFC 6749 §4.1.2.1 holds `error_description` to %x20-21 / %x23-5B /
	// %x5D-7E. The refusal names the value that arrived, so the redirect
	// replaces every other character with `?`.
	// `state` is the client's own value, returned exactly (RFC 6749
	// §4.1.2.1): URL-encoded in the redirect, never `?`-replaced like the
	// error text around it.
	it("returns state unchanged in an error redirect, whatever characters it carries", async () => {
		const { app } = await makeApp({});
		const state = 'a"b\\c d\u00e9\u{1F600}';
		const res = await authorize(app, { ...baseQuery, response_type: "token", state });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("unsupported_response_type");
		expect(params.get("state")).toBe(state);
	});

	it("names the refused response_type within RFC 6749's character set", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, response_type: 'a"b\\c\u0007d\u00e9' });
		expect(redirectParams(res).get("error_description")).toBe(
			"response_type 'a?b?c?d?' is not supported",
		);
	});
});

describe("/authorize — PKCE required", () => {
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

describe("/authorize — nonce validation", () => {
	it("rejects a repeated nonce (array) as invalid_request at the boundary", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, { ...baseQuery, nonce: ["a", "b"] });
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("nonce must be a single string value");
	});
});

describe("/authorize — code_challenge_method resolution", () => {
	it("rejects an omitted method — RFC 7636 §4.3 reads absence as `plain`", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, withoutPkce({ code_challenge: S256_CHALLENGE }));
		const params = redirectParams(res);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe(
			"code_challenge_method is required and must be 'S256'",
		);
	});

	it("rejects a repeated method (array) as a repeat — it must not resolve as absent", async () => {
		// Reading a repeat as absence would fall through to RFC 7636 §4.3's
		// `plain`, which an `allowPlainPkce` client could use to downgrade its
		// own S256 request. See SINGLE_VALUED_QUERY_PARAMS.
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
		expect(params.get("error_description")).toBe("code_challenge_method 'S512' is not supported");
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

describe("/authorize — policy evaluation edges", () => {
	it("never consults the policy for a session whose user has no id: such a cookie is not admitted, and the browser is sent to log in", async () => {
		// A cookie that says authenticated without a user is not a session this
		// provider wrote: admission refuses it before any read, and the browser
		// is sent to log in.
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const { app, createCode } = await makeApp({
			grantPolicy: { kind: "test", evaluate },
			session: { isAuthenticated: true, user: {} },
		});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(res.headers.location).toContain("/login");
		expect(evaluate).not.toHaveBeenCalled();
		expect(createCode).not.toHaveBeenCalled();
	});

	it("passes requestedScope as undefined when no scope was sent", async () => {
		const evaluate = vi.fn(async () => ({ outcome: "allow" as const }));
		const { app } = await makeApp({ grantPolicy: { kind: "test", evaluate } });
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("code")).toBe("code-x");
		expect(evaluate).toHaveBeenCalledTimes(1);
		const evaluated = evaluate.mock.calls[0]?.[0] as unknown as Record<string, unknown>;
		expect(evaluated.subject).toBe("user-1");
		expect(evaluated.requestedScope).toBeUndefined();
	});

	// RFC 6749 §4.1.2.1 makes `error` 1*NQSCHAR (printable ASCII without `"`
	// and `\`). A deny code outside it, or none, is answered `access_denied`
	// — the code for a request the authorization server refuses — and the
	// policy's code is logged, sanitised, for the operator who wrote it.
	it.each([
		["a double quote", 'bad "code"', "bad ?code?"],
		["non-ASCII", "d\u00e9ny", "d?ny"],
		["nothing", "", ""],
	])(
		"answers access_denied for a policy deny code with %s, and logs it sanitised",
		async (_label, code, logged) => {
			const logger = createMockLogger();
			const { app } = await makeApp({
				logger,
				grantPolicy: {
					kind: "test",
					evaluate: async () => ({ outcome: "deny", error: code, errorDescription: "no" }),
				},
			});
			const params = redirectParams(await authorize(app, baseQuery));
			expect(params.get("error")).toBe("access_denied");
			expect(params.get("error_description")).toBe("no");
			expect(logger.warn).toHaveBeenCalledWith(
				{ error: logged },
				"authorize_policy_deny_error_malformed",
			);
		},
	);

	it("logs a long malformed deny code capped", async () => {
		const logger = createMockLogger();
		const { app } = await makeApp({
			logger,
			grantPolicy: {
				kind: "test",
				evaluate: async () => ({
					outcome: "deny",
					error: `"${"x".repeat(300)}`,
					errorDescription: "no",
				}),
			},
		});
		await authorize(app, baseQuery);
		expect(logger.warn).toHaveBeenCalledWith(
			{ error: `?${"x".repeat(196)}...` },
			"authorize_policy_deny_error_malformed",
		);
	});

	// A JavaScript policy can return anything as its description. One that is
	// not a non-empty string is not sent — RFC 6749 A.8 makes the field
	// 1*NQSCHAR — and the redirect carries the default instead.
	it.each([
		["a number", 42],
		["the empty string", ""],
	])(
		"redirects with the default description for a deny description that is %s",
		async (_label, description) => {
			const { app } = await makeApp({
				grantPolicy: {
					kind: "test",
					evaluate: async () =>
						({
							outcome: "deny",
							error: "access_denied",
							errorDescription: description,
						}) as unknown as GrantPolicyDecision,
				},
			});
			const params = redirectParams(await authorize(app, baseQuery));
			expect(params.get("error")).toBe("access_denied");
			expect(params.get("error_description")).toBe("policy denied");
		},
	);

	it("refuses a policy that returns a non-array grantedScope or grantedAudience", async () => {
		// A JavaScript policy can return a string where the type says array.
		// `.filter` would throw on one, and an audience string persisted on the
		// code is read back as its first character at /token.
		const scopeString = await makeApp({
			grantPolicy: {
				kind: "test",
				evaluate: async () =>
					({ outcome: "allow", grantedScope: "read" }) as unknown as GrantPolicyDecision,
			},
		});
		const scopeRes = await authorize(scopeString.app, baseQuery);
		expect(redirectParams(scopeRes).get("error")).toBe("server_error");
		expect(redirectParams(scopeRes).get("error_description")).toMatch(/non-array grantedScope/);

		const audienceString = await makeApp({
			grantPolicy: {
				kind: "test",
				evaluate: async () =>
					({
						outcome: "allow",
						grantedAudience: "https://api.example.com",
					}) as unknown as GrantPolicyDecision,
			},
		});
		const audienceRes = await authorize(audienceString.app, baseQuery);
		expect(redirectParams(audienceRes).get("error")).toBe("server_error");
		expect(redirectParams(audienceRes).get("error_description")).toMatch(
			/non-array grantedAudience/,
		);

		// Falsy is still present: `""` and `null` are a malformed decision, not
		// the absence of one, and only `undefined` means the policy said nothing.
		for (const malformed of ["", null]) {
			const { app } = await makeApp({
				grantPolicy: {
					kind: "test",
					evaluate: async () =>
						({ outcome: "allow", grantedScope: malformed }) as unknown as GrantPolicyDecision,
				},
			});
			expect(redirectParams(await authorize(app, baseQuery)).get("error")).toBe("server_error");
		}
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
		// The client record has no `allowedAudiences`; the derivation bound
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
	it("redirects temporarily_unavailable when the code repository is down, and logs it once at error level", async () => {
		// RFC 6749 §4.1.2.1 defines `temporarily_unavailable` for exactly this:
		// the authorization server cannot handle the request because of a
		// temporary condition. `server_error` says the server is broken.
		const logger = createMockLogger();
		const { app } = await makeApp({ createCodeThrows: true, logger });
		const res = await authorize(app, baseQuery);
		const params = redirectParams(res);
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("authorization code store unavailable");
		expect(params.get("code")).toBeNull();
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "authorization_code",
				step: "create",
				clientId: CLIENT_ID,
				err: expect.objectContaining({ name: "Error" }),
			},
			"authorize_store_unavailable",
		);
		expect(logger.error.mock.calls[0]?.[0].err).not.toBeInstanceOf(Error);
	});
});

describe("/authorize — success audit subject (authorize.granted)", () => {
	it("emits no authorize.granted for a session whose user has no id: such a cookie is not admitted, and the browser is sent to log in", async () => {
		const record = vi.fn(async () => {});
		const { app, createCode } = await makeApp({
			auditSink: { record },
			session: { isAuthenticated: true, user: {} },
		});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(res.headers.location).toContain("/login");
		expect(createCode).not.toHaveBeenCalled();
		expect(record).not.toHaveBeenCalledWith(expect.objectContaining({ type: "authorize.granted" }));
	});

	it("emits authorize.granted with the admitted session's subject", async () => {
		const record = vi.fn(async () => {});
		const { app } = await makeApp({ auditSink: { record } });
		const res = await authorize(app, baseQuery);
		expect(redirectParams(res).get("code")).toBe("code-x");
		const event = record.mock.calls.find(
			(c) => (c as unknown as [Record<string, unknown>])[0]?.type === "authorize.granted",
		)?.[0] as unknown as Record<string, unknown>;
		expect(event.subject).toBe("user-1");
		expect(event.clientId).toBe(CLIENT_ID);
	});
});

describe("/authorize — rejection audit vocabulary (authorize.rejected)", () => {
	it("emits authorize.rejected when the client is not registered for the code grant", async () => {
		// /authorize rejections carry their own name, not the token endpoint's
		// `token.issued.failure`, so the success/failure pair names one operation.
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
 * OIDC parameters are honoured or refused, never ignored:
 *  - `request` / `request_uri` are refused. A signed request object makes the
 *    parameters tamper-proof; processing the query string instead hands an
 *    attacker what the object prevents, while the RP believes it was honoured.
 *  - `prompt=none` without a session answers `login_required` at the
 *    redirect_uri, so silent renewal in a hidden iframe does not time out.
 *  - POST is a MUST (OIDC Core §3.1.2.1).
 */

const authorizePost = (app: express.Express, body: Query) =>
	request(app)
		.post("/oauth/authorize")
		.type("form")
		.send(body as Record<string, string>);

describe("/authorize — request objects are refused, not ignored", () => {
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
		// No code is issued for the query parameters while the RP believes its
		// signed object was used.
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

describe("/authorize — prompt=none", () => {
	it("answers login_required by redirect when there is no session", async () => {
		// The point: a hidden iframe cannot act on a login page. This has to
		// reach the RP's own redirect_uri, which is why the request is allowed
		// past the session gate to have its redirect_uri validated first.
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("login_required");
	});

	it("answers a malformed prompt naming none at the redirect_uri, not with the login page", async () => {
		// The gate that lets a silent request past the login redirect reads
		// `prompt` tolerantly: a hidden iframe that sent `none` with a stray tab
		// is still a silent context, and a login page would hang it. Its
		// `invalid_request` belongs at the RP's redirect_uri, which the strict
		// reading in `resolvePrompt` delivers once that URI is validated.
		const { app } = await makeApp({ session: { isAuthenticated: false } });
		for (const prompt of ["none\t", "none\tlogin", "\tnone"]) {
			const res = await authorize(app, { ...baseQuery, prompt });
			expect(res.headers.location, JSON.stringify(prompt)).not.toMatch(/^\/login/);
			const params = redirectParams(res);
			expect(params.get("error"), JSON.stringify(prompt)).toBe("invalid_request");
			expect(params.get("error_description")).toBe(
				"prompt is not a space-delimited list of values",
			);
		}
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

	it("refuses select_account and login rather than ignoring them", async () => {
		// Ignoring would hand back a token the RP believes was freshly
		// re-authenticated or account-picked. There is no account picker, and
		// a forced re-authentication cannot yet be told apart from a loop.
		const { app } = await makeApp({});
		// Collected then asserted as a set, so a failure names which value
		// behaved differently rather than stopping at the first.
		const outcomes: string[] = [];
		for (const prompt of ["select_account", "login"]) {
			const params = redirectParams(await authorize(app, { ...baseQuery, prompt }));
			const namesTheValue = (params.get("error_description") ?? "").includes(prompt);
			outcomes.push(`${prompt}:${params.get("error")}:names=${namesTheValue}`);
		}
		expect(outcomes).toEqual([
			"select_account:invalid_request:names=true",
			"login:invalid_request:names=true",
		]);
	});

	it("describes an unsupported prompt value in plain ASCII (RFC 6749 §4.1.2.1)", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "select_account" }));
		expect(params.get("error_description")).toBe(
			"prompt values not supported: select_account; this authorization server has no account picker",
		);
	});

	it("honours prompt=consent — a no-op for a first-party client, which has nothing to consent to", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "consent" }));
		expect(params.get("error")).toBeNull();
		expect(params.get("code")).toBe("code-x");
	});

	it("refuses a prompt that is not a space-delimited list, saying so rather than naming a value", async () => {
		// OIDC Core §3.1.2.1: space-delimited. `none\tlogin` is not the value
		// "none<TAB>login" this server happens not to support; it is malformed.
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none\tlogin" }));
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("prompt is not a space-delimited list of values");
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

	it("issues a code when prompt is absent", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, baseQuery);
		expect(new URL(res.headers.location as string).searchParams.get("code")).not.toBeNull();
	});
});

describe("/authorize — POST is supported", () => {
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

/**
 * A session whose `sid` is dead (its `UserSession` deleted by logout's
 * cascade, a store restart or an out-of-band delete) is not an authenticated
 * session. A code carrying the dead `sid` is refused at `/token` with
 * `invalid_grant`, looping the browser without a login page, so `/authorize`
 * performs the same read `/token` does, where the answer can still be "log in
 * again".
 */
describe("/authorize — dead sid is unauthenticated", () => {
	const liveSid = "sid-live";
	const deadSid = "sid-dead";

	const makeStore = (impl: (sid: string) => Promise<unknown>): UserSessionStore =>
		({
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(impl),
			delete: vi.fn(async () => {}),
		}) as unknown as UserSessionStore;

	const liveStore = () =>
		makeStore(async (sid: string) =>
			sid === liveSid
				? {
						sid: liveSid,
						sub: "user-1",
						authTime: new Date(),
						createdAt: new Date(),
						expiresAt: new Date(Date.now() + 3_600_000),
						claims: {},
						amr: undefined,
						authentication: undefined,
					}
				: null,
		);

	it("sends a session whose sid no longer resolves to the login page", async () => {
		const createCode = vi.fn();
		const { app } = await makeApp({
			createCode,
			userSessionStore: liveStore(),
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: deadSid },
		});

		const res = await authorize(app, baseQuery);

		// Identical to the unauthenticated branch: same login URL, same
		// round-tripped `redirect_to`.
		expect(res.status).toBe(302);
		const location = res.headers.location as string;
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
		const redirectTo = decodeURIComponent(location.split("redirect_to=")[1] as string);
		expect(redirectTo.startsWith("https://issuer.example/oauth/authorize?")).toBe(true);
		expect(createCode).not.toHaveBeenCalled();
	});

	it("answers login_required for prompt=none when the sid no longer resolves", async () => {
		const createCode = vi.fn();
		const { app } = await makeApp({
			createCode,
			userSessionStore: liveStore(),
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: deadSid },
		});

		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none" }));

		expect(params.get("error")).toBe("login_required");
		expect(createCode).not.toHaveBeenCalled();
	});

	it("still mints for a session whose sid is live", async () => {
		const store = liveStore();
		const { app, createCode } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: liveSid },
		});

		const res = await authorize(app, baseQuery);

		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string).searchParams.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalled();
		expect(store.get).toHaveBeenCalledWith(liveSid);
	});

	it("sends a session that records no sid to the login page while a store is wired, without reading it", async () => {
		// The session-admission ADR's D8, change 1: with a store wired, a cookie
		// that names no record is not a live session. Nothing is read: no sid
		// names a record.
		const store = liveStore();
		const { app, createCode } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, user: { id: "user-1" } },
		});

		const res = await authorize(app, baseQuery);

		expect(res.status).toBe(302);
		expect(res.headers.location).toContain("/login");
		expect(createCode).not.toHaveBeenCalled();
		expect(store.get).not.toHaveBeenCalled();
	});

	it("sends a session that records no sid through the loginEntry a module provides", async () => {
		const { asked, entry } = recordingLoginEntry();
		const { app } = await makeApp({
			userSessionStore: liveStore(),
			session: { isAuthenticated: true, user: { id: "user-1" } },
			loginEntry: entry,
		});
		const res = await authorize(app, baseQuery);
		expect(res.status).toBe(302);
		expect(asked).toHaveLength(1);
		expect(res.headers.location).toBe(`/sign-in?back=${encodeURIComponent(asked[0] as string)}`);
	});

	it("does not read the store for a genuinely unauthenticated request", async () => {
		// An unauthenticated request answers before touching any repository,
		// so an unauthenticated endpoint cannot be turned into one lookup per
		// hit.
		const store = liveStore();
		const { app } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: false, sid: deadSid },
		});

		const res = await authorize(app, baseQuery);

		expect(res.status).toBe(302);
		expect(res.headers.location).toContain("/login");
		expect(store.get).not.toHaveBeenCalled();
	});

	it("fails closed with temporarily_unavailable on the redirect URI when the session store is unreachable", async () => {
		const logger = createMockLogger();
		const createCode = vi.fn();
		const { app } = await makeApp({
			createCode,
			logger,
			userSessionStore: makeStore(async () => {
				throw new Error("redis down");
			}),
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: liveSid },
		});

		const params = redirectParams(await authorize(app, baseQuery));

		// The session-admission ADR's D8, change 2: an outage is answered on the
		// validated redirect URI, never with the login page — whose forwarding
		// of signed-in users would loop on the flag the cookie keeps.
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("session store unavailable");
		expect(createCode).not.toHaveBeenCalled();
		// The outage is logged once, at error level, by admission (the
		// session-admission ADR's D10): the store and the action, the
		// projection — never the sid, not a warn.
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.authorize",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
		expect(logger.error.mock.calls[0]?.[0].err).not.toBeInstanceOf(Error);
	});

	it("answers prompt=none with temporarily_unavailable when the store is unreachable, not login_required", async () => {
		// `login_required` would tell the relying party the user is not signed
		// in — a verdict the outage cannot make. RFC 6749 §4.1.2.1's
		// `temporarily_unavailable` says what is true, and OIDC Core allows it
		// as an authentication error response.
		const logger = createMockLogger();
		const createCode = vi.fn();
		const { app } = await makeApp({
			createCode,
			logger,
			userSessionStore: makeStore(async () => {
				throw new Error("redis down");
			}),
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: liveSid },
		});

		const params = redirectParams(await authorize(app, { ...baseQuery, prompt: "none" }));

		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("session store unavailable");
		expect(createCode).not.toHaveBeenCalled();
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.authorize",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("mints unchanged when no session store is wired", async () => {
		const { app, createCode } = await makeApp({
			session: { isAuthenticated: true, user: { id: "user-1" }, sid: deadSid },
		});

		const res = await authorize(app, baseQuery);

		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string).searchParams.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalled();
	});
});

describe("/authorize — step-up and re-authentication", () => {
	const SID = "sid-1";
	const session = { isAuthenticated: true, sid: SID, user: { id: "user-1" } };
	// A `Date`, or a thunk when a test needs the authentication to change
	// between two requests — which is what a login round trip is.
	// `authentication` absent: a session written before the MFA ADR's D9,
	// which the readers split as they read it.
	const storeWith = (
		at: Date | (() => Date),
		amr?: readonly string[],
		authentication?: SessionAuthentication,
	): UserSessionStore =>
		({
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async (sid: string): Promise<UserSession | null> => {
				const authTime = typeof at === "function" ? at() : at;
				return sid === SID
					? {
							sid: SID,
							sub: "user-1",
							authTime,
							createdAt: authTime,
							expiresAt: new Date(Date.now() + 3_600_000),
							claims: {},
							amr,
							authentication,
						}
					: null;
			}),
			delete: vi.fn(async () => {}),
		}) as unknown as UserSessionStore;
	/** A federated session as the MFA ADR's D9 records it, for a federation that trusts its IdP's `amr`. */
	const TRUSTED_FEDERATION: SessionAuthentication = {
		primary: "fed",
		federation: "google",
		upstreamAmr: undefined,
		mfaAt: undefined,
	};
	const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);
	/**
	 * A re-authentication, which comes strictly after the ask: the ask is
	 * compared to the millisecond, and a test that reads the clock in the same
	 * millisecond as `/authorize` would be describing an authentication that
	 * happened before the ask was made.
	 */
	const reauthenticatedNow = async (): Promise<Date> => {
		await new Promise((resolve) => setTimeout(resolve, 2));
		return new Date();
	};
	const mintingCode = () =>
		vi.fn(async () => ({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }));
	/** The login-page redirect, with the round-tripped authorize URL parsed. */
	const loginRedirectTo = (res: request.Response): URL => {
		expect(res.status).toBe(302);
		const location = res.headers.location as string;
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
		return new URL(decodeURIComponent(location.split("redirect_to=")[1] as string));
	};

	describe("max_age", () => {
		it("passes a session younger than max_age straight through and mints a code", async () => {
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(5)),
				createCode,
			});
			const res = await authorize(app, { ...baseQuery, max_age: "3600" });
			expect(redirectParams(res).get("code")).toBe("code-x");
		});

		it("sends a session older than max_age back to the login page, naming an ask it recorded", async () => {
			const harness = await makeApp({ session, userSessionStore: storeWith(minutesAgo(5)) });
			const res = await authorize(harness.app, { ...baseQuery, max_age: "60" });
			const back = loginRedirectTo(res);
			expect(back.searchParams.get("max_age")).toBe("60");
			expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
			expect(back.searchParams.get("state")).toBe("xyz");
			// An opaque id naming a record in the session store — not a value the
			// caller could have written, and not a field on the session, which
			// the login itself regenerates away.
			const askId = back.searchParams.get("reauth_ask") as string;
			expect(askId.length).toBeGreaterThanOrEqual(43);
			expect([...harness.records.keys()]).toEqual([`reauth:${askId}`]);
			expect(harness.session).not.toHaveProperty("reauthAskedAt");
		});

		it("sends a session older than max_age through the loginEntry a module provides, naming the ask", async () => {
			const { asked, entry } = recordingLoginEntry();
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(5)),
				loginEntry: entry,
			});
			const res = await authorize(harness.app, { ...baseQuery, max_age: "60" });
			expect(res.status).toBe(302);
			expect(asked).toHaveLength(1);
			expect(res.headers.location).toBe(`/sign-in?back=${encodeURIComponent(asked[0] as string)}`);
			expect(new URL(asked[0] as string).searchParams.get("reauth_ask")).toBeTruthy();
		});

		it("max_age=0 always re-authenticates", async () => {
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(new Date(Date.now() - 2_000)),
			});
			const res = await authorize(harness.app, { ...baseQuery, max_age: "0" });
			expect(loginRedirectTo(res).searchParams.get("reauth_ask")).toBeTruthy();
		});

		it("refuses a max_age that is not a non-negative integer", async () => {
			const { app } = await makeApp({ session, userSessionStore: storeWith(minutesAgo(1)) });
			for (const bad of ["-1", "abc", "1.5", " "]) {
				const res = await authorize(app, { ...baseQuery, max_age: bad });
				expect(redirectParams(res).get("error"), bad).toBe("invalid_request");
			}
		});

		it("reads an empty max_age as omitted (RFC 6749 §3.1): no freshness asked for", async () => {
			// "Parameters sent without a value MUST be treated as if they were
			// omitted from the request." A session of any age proceeds, on GET and
			// POST alike, and no ask is recorded.
			const createCode = mintingCode();
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(600)),
				createCode,
			});
			expect(
				redirectParams(await authorize(harness.app, { ...baseQuery, max_age: "" })).get("code"),
			).toBe("code-x");
			expect(
				redirectParams(await authorizePost(harness.app, { ...baseQuery, max_age: "" })).get("code"),
			).toBe("code-x");
			expect(harness.records.size).toBe(0);
		});

		it("reads an empty max_age as omitted where no session store is wired, too", async () => {
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(1)),
				sessionStore: false,
			});
			expect(
				redirectParams(await authorize(harness.app, { ...baseQuery, max_age: "" })).get("code"),
			).toBe("code-x");
		});

		it("refuses a repeated max_age like every other single-valued parameter", async () => {
			const { app } = await makeApp({ session, userSessionStore: storeWith(minutesAgo(1)) });
			const res = await authorize(app, { ...baseQuery, max_age: ["60", "120"] });
			expect(redirectParams(res).get("error")).toBe("invalid_request");
		});

		it("ignores a marker the caller writes — the ask is a record only this server can name", async () => {
			// A marker read from the request would let `max_age=60&reauth_after=0`
			// satisfy "authenticated at or after the ask" for any live session and
			// skip the round trip the parameter exists to force. Neither
			// `reauth_after` nor an invented ask id decides anything.
			const harness = await makeApp({ session, userSessionStore: storeWith(minutesAgo(10)) });
			for (const forged of [
				{ max_age: "60", reauth_after: "0" },
				{ prompt: "login", reauth_after: "0" },
				{ max_age: "60", reauth_ask: "not-an-ask-this-server-minted" },
				{ prompt: "login", reauth_ask: "a".repeat(43) },
			]) {
				const res = await authorize(harness.app, { ...baseQuery, ...forged });
				// The login page, every time — never a code.
				loginRedirectTo(res);
			}
		});
	});

	describe("prompt=login", () => {
		it("re-authenticates even a fresh session, carrying prompt=login back and naming an ask", async () => {
			const harness = await makeApp({ session, userSessionStore: storeWith(new Date()) });
			const res = await authorize(harness.app, { ...baseQuery, prompt: "login" });
			const back = loginRedirectTo(res);
			expect(back.searchParams.get("prompt")).toBe("login");
			expect(back.searchParams.get("reauth_ask")).toBeTruthy();
			expect(harness.session).not.toHaveProperty("reauthAskedAt");
		});

		it("is satisfied once the session was authenticated after the ask, and mints a code", async () => {
			// The real round trip: ask, authenticate, return to the URL the login
			// page was handed.
			const createCode = mintingCode();
			const authTime = { at: minutesAgo(10) };
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(() => authTime.at),
				createCode,
			});
			const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
			authTime.at = await reauthenticatedNow();
			const res = await request(harness.app).get(back.pathname + back.search);
			expect(redirectParams(res).get("code")).toBe("code-x");
		});

		it("survives the session regeneration the login itself performs", async () => {
			// `/session/login` regenerates the session (session fixation) and
			// restores only `isAuthenticated`, `user`, `redirectTo` and `sid`. An
			// ask held on the session would be destroyed by the very
			// authentication that satisfies it, and `prompt=login` — whose
			// staleness test is unconditional — would ask again forever.
			const createCode = mintingCode();
			const authTime = { at: minutesAgo(10) };
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(() => authTime.at),
				createCode,
			});
			const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
			// What regeneration leaves behind: a brand-new session object.
			harness.regenerate({ isAuthenticated: true, user: { id: "user-1" }, sid: "sid-1" });
			authTime.at = await reauthenticatedNow();
			const res = await request(harness.app).get(back.pathname + back.search);
			expect(redirectParams(res).get("code")).toBe("code-x");
		});

		it("spends the ask, so replaying the returned URL asks again", async () => {
			const createCode = mintingCode();
			const authTime = { at: minutesAgo(10) };
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(() => authTime.at),
				createCode,
			});
			const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
			authTime.at = await reauthenticatedNow();
			const askId = back.searchParams.get("reauth_ask") as string;
			const path = back.pathname + back.search;
			expect(redirectParams(await request(harness.app).get(path)).get("code")).toBe("code-x");
			expect(harness.records.has(`reauth:${askId}`)).toBe(false);
			// Replayed: that record is gone, so this is a request with no ask, and
			// it earns a fresh one rather than a second code.
			const again = loginRedirectTo(await request(harness.app).get(path));
			expect(again.searchParams.get("reauth_ask")).not.toBe(askId);
		});

		it("does not let an ask for one request satisfy another", async () => {
			// An ask outstanding for request A must not answer B's freshness
			// requirement: B's authentication may be far older than B asked for.
			const createCode = mintingCode();
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(5)),
				createCode,
			});
			const back = loginRedirectTo(
				await authorize(harness.app, { ...baseQuery, prompt: "login", state: "request-a" }),
			);
			const askId = back.searchParams.get("reauth_ask") as string;
			// B is a different request — another `state` is enough — carrying A's ask.
			const res = await authorize(harness.app, {
				...baseQuery,
				max_age: "0",
				state: "request-b",
				reauth_ask: askId,
			});
			loginRedirectTo(res);
			expect(createCode).not.toHaveBeenCalled();
		});

		it("does not count an authentication earlier in the same second as the ask", async () => {
			// Compared in whole seconds with `>=`, a session authenticated at
			// …:00.200 would satisfy an ask made at …:00.800 — `prompt=login`
			// honoured without re-authenticating, within one wall-clock second.
			vi.useFakeTimers({ toFake: ["Date"] });
			try {
				vi.setSystemTime(new Date("2026-09-13T12:00:00.800Z"));
				const harness = await makeApp({
					session,
					userSessionStore: storeWith(new Date("2026-09-13T12:00:00.200Z")),
				});
				const back = loginRedirectTo(
					await authorize(harness.app, { ...baseQuery, prompt: "login" }),
				);
				const res = await request(harness.app).get(back.pathname + back.search);
				expect(redirectParams(res).get("error")).toBe("login_required");
			} finally {
				vi.useRealTimers();
			}
		});

		it("answers login_required — no second round trip — when the user came back without re-authenticating", async () => {
			const harness = await makeApp({ session, userSessionStore: storeWith(minutesAgo(10)) });
			const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
			// Same stale authentication: the user never logged in.
			const res = await request(harness.app).get(back.pathname + back.search);
			const params = redirectParams(res);
			expect(params.get("error")).toBe("login_required");
			expect(params.get("state")).toBe("xyz");
			expect(harness.records.size).toBe(0);
		});

		it("the ask satisfies max_age=0 on the way back too", async () => {
			const createCode = mintingCode();
			const authTime = { at: minutesAgo(10) };
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(() => authTime.at),
				createCode,
			});
			const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "0" }));
			authTime.at = await reauthenticatedNow();
			const res = await request(harness.app).get(back.pathname + back.search);
			expect(redirectParams(res).get("code")).toBe("code-x");
		});

		it("answers temporarily_unavailable when the ask cannot be recorded", async () => {
			// An outage is not a decision either way — the same rule the
			// session-liveness read applies. Asking for a re-authentication this
			// endpoint could not recognise on the way back would loop instead.
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(10)),
				sessionStoreFail: "set",
			});
			const params = redirectParams(await authorize(harness.app, { ...baseQuery, max_age: "60" }));
			expect(params.get("error")).toBe("temporarily_unavailable");
		});

		it("answers temporarily_unavailable when the ask cannot be read back", async () => {
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(10)),
				sessionStoreFail: "get",
			});
			const params = redirectParams(
				await authorize(harness.app, { ...baseQuery, max_age: "60", reauth_ask: "a".repeat(43) }),
			);
			expect(params.get("error")).toBe("temporarily_unavailable");
		});

		it("refuses max_age and prompt=login when the composition wires no session store", async () => {
			// There is nowhere to record an ask, and asking for a
			// re-authentication this endpoint could never recognise on the way
			// back is the loop the record exists to prevent.
			const harness = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(10)),
				sessionStore: false,
			});
			expect(
				redirectParams(await authorize(harness.app, { ...baseQuery, max_age: "60" })).get("error"),
			).toBe("invalid_request");
			expect(
				redirectParams(await authorize(harness.app, { ...baseQuery, prompt: "login" })).get(
					"error",
				),
			).toBe("invalid_request");
		});

		it("still refuses prompt=none combined with login", async () => {
			const { app } = await makeApp({ session, userSessionStore: storeWith(new Date()) });
			const res = await authorize(app, { ...baseQuery, prompt: "none login" });
			expect(redirectParams(res).get("error")).toBe("invalid_request");
		});
	});

	describe("prompt=none stays silent", () => {
		it("answers login_required for a stale session instead of a login redirect", async () => {
			const { app } = await makeApp({ session, userSessionStore: storeWith(minutesAgo(5)) });
			const res = await authorize(app, { ...baseQuery, prompt: "none", max_age: "60" });
			expect(redirectParams(res).get("error")).toBe("login_required");
		});

		it("still proceeds silently for a fresh one", async () => {
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(1)),
				createCode,
			});
			const res = await authorize(app, { ...baseQuery, prompt: "none", max_age: "3600" });
			expect(redirectParams(res).get("code")).toBe("code-x");
		});
	});

	describe("acr_values", () => {
		const acrValues = { "urn:example:pwd": ["pwd"], "urn:example:mfa": ["pwd", "mfa"] };

		it("records the first requested acr the session satisfies into the code", async () => {
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd"]),
				createCode,
			});
			const res = await authorize(app, {
				...baseQuery,
				acr_values: "urn:example:mfa urn:example:pwd",
			});
			expect(redirectParams(res).get("code")).toBe("code-x");
			expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ acr: "urn:example:pwd" }));
		});

		it("refuses with unmet_authentication_requirements when the session meets none of them", async () => {
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd"]),
			});
			const res = await authorize(app, { ...baseQuery, acr_values: "urn:example:mfa" });
			const params = redirectParams(res);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
			expect(params.get("error_description")).toMatch(/urn:example:mfa/);
		});

		it("meets no acr where no session store is wired: there is no amr to read", async () => {
			// The no-store composition is authenticated on the cookie alone
			// (`live: true, session: null`); nothing records how, so nothing is met.
			const { app } = await makeApp({ session, oauth: { authorize: { acrValues } } });
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:pwd" }),
			);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
		});

		it("refuses an acr this deployment has not configured rather than accepting it silently", async () => {
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa"]),
			});
			const res = await authorize(app, { ...baseQuery, acr_values: "urn:nope" });
			const params = redirectParams(res);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
			expect(params.get("error_description")).toMatch(/urn:nope/);
		});

		it("refuses a prototype key as an acr instead of crashing on Object.prototype", async () => {
			// `table[acr]` on a plain object resolves `constructor` to `Object`
			// — truthy, with no `.every` — so the request would throw and answer
			// 500, on a route whose contract is that a post-validation error
			// travels by redirect to the client.
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd"]),
			});
			for (const acr of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
				const params = redirectParams(await authorize(app, { ...baseQuery, acr_values: acr }));
				expect(params.get("error")).toBe("unmet_authentication_requirements");
				expect(params.get("error_description")).toContain(acr);
			}
		});

		it("refuses one with no acr table configured at all — `{}` still carries the prototype", async () => {
			const { app } = await makeApp({
				session,
				userSessionStore: storeWith(minutesAgo(1), ["pwd"]),
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "constructor" }),
			);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
		});

		it("does not let a prototype key satisfy an acr the session has not met", async () => {
			// The other half: `required?.every(...)` must not be reached at all,
			// so no crafted value can be answered with a minted code.
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa"]),
				createCode,
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "constructor urn:example:pwd" }),
			);
			// The real acr later in the list still decides; the prototype key is
			// simply not an entry.
			expect(params.get("code")).toBe("code-x");
			expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ acr: "urn:example:pwd" }));
		});

		it("refuses acr_values that are not a space-delimited list as invalid_request", async () => {
			// Malformed is the request's fault, not the session's: it is not an
			// acr the deployment lacks, which is what
			// unmet_authentication_requirements tells an RP.
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa"]),
				createCode,
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:pwd\turn:example:mfa" }),
			);
			expect(params.get("error")).toBe("invalid_request");
			expect(params.get("error_description")).toBe(
				"acr_values is not a space-delimited list of values",
			);
			expect(createCode).not.toHaveBeenCalled();
		});

		it("answers an entry nothing installed can satisfy unmet, even for a session that carries it", async () => {
			// The MFA ADR's D15: no login this composition can perform records
			// `mfa`, so the entry is dropped at boot — withheld from discovery and
			// answered as one never configured. A session that carries the value
			// anyway (a custom login path) does not revive it.
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa"]),
				createCode,
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:mfa" }),
			);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
			expect(params.get("error_description")).toMatch(/urn:example:mfa/);
			expect(createCode).not.toHaveBeenCalled();
		});

		it("keeps an entry only an upstream IdP can meet while an installed federation trusts its amr", async () => {
			// The MFA ADR's D13: a trusted federation's upstream `amr` is recorded
			// beside `fed` and counts, so such a composition can meet any entry.
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa", "fed"], TRUSTED_FEDERATION),
				createCode,
				federation: "trusted",
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:mfa" }),
			);
			expect(params.get("code")).toBe("code-x");
			expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ acr: "urn:example:mfa" }));
		});

		it("answers an entry only an upstream IdP can meet unmet while the installed federation does not trust its amr", async () => {
			// The MFA ADR's D13: an untrusted IdP's `amr` counts for no `acr`, so
			// the entry is dropped at boot — and a session that carries the value
			// does not revive it.
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "mfa", "fed"]),
				createCode,
				federation: "untrusted",
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:mfa" }),
			);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
			expect(createCode).not.toHaveBeenCalled();
		});

		it("meets an any-of entry through any one of its alternatives", async () => {
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: {
					authorize: { acrValues: { "urn:example:phr": [["hwk"], ["swk"]] } },
				},
				userSessionStore: storeWith(minutesAgo(1), ["swk", "fed"], TRUSTED_FEDERATION),
				createCode,
				federation: "trusted",
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:phr" }),
			);
			expect(params.get("code")).toBe("code-x");
			expect(createCode).toHaveBeenCalledWith(expect.objectContaining({ acr: "urn:example:phr" }));
		});

		it("answers an any-of entry none of whose alternatives the session holds unmet", async () => {
			const { app } = await makeApp({
				session,
				oauth: {
					authorize: { acrValues: { "urn:example:phr": [["hwk"], ["swk"]] } },
				},
				userSessionStore: storeWith(minutesAgo(1), ["pwd", "fed"], TRUSTED_FEDERATION),
				federation: "trusted",
			});
			const params = redirectParams(
				await authorize(app, { ...baseQuery, acr_values: "urn:example:phr" }),
			);
			expect(params.get("error")).toBe("unmet_authentication_requirements");
		});

		it("records no acr when none was requested", async () => {
			const createCode = mintingCode();
			const { app } = await makeApp({
				session,
				oauth: { authorize: { acrValues } },
				userSessionStore: storeWith(minutesAgo(1), ["pwd"]),
				createCode,
			});
			await authorize(app, baseQuery);
			// Named, holding `undefined`: the code record says "no acr"
			// rather than leaving the field out.
			expect(createCode.mock.calls[0]?.[0]).toHaveProperty("acr", undefined);
		});
	});
});

describe("/authorize — the acr table at boot", () => {
	const EVENT = "acr_value_unsatisfiable";
	const acrValues = {
		"urn:example:pwd": ["pwd"],
		"urn:example:mfa": ["pwd", "mfa"],
		"urn:example:phr": [["hwk"], ["swk"]],
		"urn:example:kba": ["kba"],
	};
	const linesFor = (fn: ReturnType<typeof vi.fn>) =>
		fn.mock.calls.filter((call) => call[1] === EVENT);

	it("says once, object-first, which entries it dropped: info when only a second factor is missing and no registered requirement reaches one", async () => {
		const logger = createMockLogger();
		await makeApp({ oauth: { authorize: { acrValues } }, logger });
		expect(linesFor(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, EVENT],
			[{ acr: "urn:example:phr", unproducible: ["hwk", "swk"] }, EVENT],
		]);
		expect(linesFor(logger.warn)).toEqual([
			[{ acr: "urn:example:kba", unproducible: ["kba"] }, EVENT],
		]);
		for (const level of [logger.trace, logger.debug, logger.error, logger.fatal]) {
			expect(linesFor(level)).toEqual([]);
		}
	});

	it("keeps what a registered requirement reaches, and warns for what is still unmet once one reaches a second factor", async () => {
		// The session-admission ADR's D6: the level is decided on what the
		// registered requirements reach, never on `mfa.mode`. A requirement
		// reaching `otp` and `mfa` meets the `mfa` entry; `phr` needs a key no
		// requirement reaches, which is a warning now that MFA is installed.
		const logger = createMockLogger();
		const { router } = await createOAuthRouter(express, {
			registry: new GrantRegistry(),
			config: makeConfig({ authorize: { acrValues } }),
			requirements: resolverForTests(
				[
					{
						name: "mfa",
						secondFactorAuthority: true,
						reach: new Set(["otp", "mfa"]),
						stepUpPage: { url: "/mfa", params: {} },
						remediations: ["mfa.step_up"],
						hintKeys: [],
						admit: async () => ({ outcome: "met" }),
					},
				],
				{ issuer: "https://issuer.example" },
			),
			clientRepository: { findById: async () => null, authenticate: async () => null },
			codeRepository: {
				createCode: async () => ({ code: "c", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
				findByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			},
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			logger,
		});
		expect(router).toBeDefined();
		expect(linesFor(logger.info)).toEqual([]);
		expect(linesFor(logger.warn).map((call) => (call[0] as { acr: string }).acr)).toEqual([
			"urn:example:phr",
			"urn:example:kba",
		]);
	});

	it("warns for an entry needing fed while no federation is installed, whatever the mode", async () => {
		// `fed` is no second factor: MFA installed would not meet the entry, so
		// the line is a warning even under `mfa.mode = "off"`.
		const logger = createMockLogger();
		await makeApp({
			oauth: { authorize: { acrValues: { "urn:example:fed": ["fed"] } } },
			logger,
		});
		expect(linesFor(logger.warn)).toEqual([
			[{ acr: "urn:example:fed", unproducible: ["fed"] }, EVENT],
		]);
		expect(linesFor(logger.info)).toEqual([]);
	});

	it("answers an entry needing fed unmet while no federation is installed", async () => {
		const createCode = vi.fn(async () => ({
			code: "code-x",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
		}));
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => ({
				sid: "sid-1",
				sub: "user-1",
				authTime: new Date(Date.now() - 60_000),
				createdAt: new Date(Date.now() - 60_000),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: {},
				amr: ["fed"],
				authentication: undefined,
			})),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const { app } = await makeApp({
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
			oauth: { authorize: { acrValues: { "urn:example:fed": ["fed"] } } },
			userSessionStore: store,
			createCode,
		});
		const params = redirectParams(
			await authorize(app, { ...baseQuery, acr_values: "urn:example:fed" }),
		);
		expect(params.get("error")).toBe("unmet_authentication_requirements");
		expect(createCode).not.toHaveBeenCalled();
	});

	it("says nothing when an installed federation trusts its upstream amr: every entry can be met", async () => {
		const logger = createMockLogger();
		await makeApp({ oauth: { authorize: { acrValues } }, logger, federation: "trusted" });
		for (const level of [logger.info, logger.warn, logger.error]) {
			expect(linesFor(level)).toEqual([]);
		}
	});

	it("drops what only an upstream IdP could meet when the installed federation does not trust it", async () => {
		// The MFA ADR's D13: the federation adds `fed` alone, so every entry
		// needing anything else is dropped as without one — an entry needing
		// `fed` stays.
		const logger = createMockLogger();
		await makeApp({
			oauth: { authorize: { acrValues: { ...acrValues, "urn:example:fed": ["fed"] } } },
			logger,
			federation: "untrusted",
		});
		expect(linesFor(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, EVENT],
			[{ acr: "urn:example:phr", unproducible: ["hwk", "swk"] }, EVENT],
		]);
		expect(linesFor(logger.warn)).toEqual([
			[{ acr: "urn:example:kba", unproducible: ["kba"] }, EVENT],
		]);
	});

	it("bounds what it logs of an entry", async () => {
		const logger = createMockLogger();
		const acr = `urn:example:${"x".repeat(300)}`;
		await makeApp({ oauth: { authorize: { acrValues: { [acr]: ["kba\nforged"] } } }, logger });
		const [fields] = linesFor(logger.warn)[0] as [{ acr: string; unproducible: string[] }];
		expect(fields.acr.length).toBeLessThanOrEqual(200);
		expect(fields.unproducible[0]).not.toContain("\n");
	});
});

describe("/authorize — the claims parameter", () => {
	const REFUSAL = "request acr through acr_values";
	const claims = (value: unknown) => JSON.stringify(value);

	it.each([
		["essential, for the id_token", { id_token: { acr: { essential: true, values: ["urn:x"] } } }],
		["voluntary, for the id_token", { id_token: { acr: null } }],
		["essential, for userinfo", { userinfo: { acr: { essential: true } } }],
		["with a value, for userinfo", { userinfo: { acr: { value: "urn:x" } }, id_token: {} }],
	])(
		"refuses a request naming acr %s: it would be vouched for through a door the table does not guard",
		async (_label, value) => {
			// OIDC Core §5.5.1.1 lets an RP ask for `acr` here, essential or not;
			// this server vouches for an acr only through `acr_values` and its
			// table. Ignoring the request would hand back a token the RP reads as
			// having honoured it; a security-relevant parameter is refused, never
			// ignored.
			const createCode = vi.fn(async () => ({
				code: "code-x",
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
			}));
			const { app } = await makeApp({ createCode });
			const params = redirectParams(await authorize(app, { ...baseQuery, claims: claims(value) }));
			expect(params.get("error")).toBe("invalid_request");
			expect(params.get("error_description")).toBe(REFUSAL);
			expect(params.get("state")).toBe("xyz");
			expect(createCode).not.toHaveBeenCalled();
		},
	);

	it("reads an empty claims as omitted (RFC 6749 §3.1), on GET and POST", async () => {
		const { app } = await makeApp({});
		expect(redirectParams(await authorize(app, { ...baseQuery, claims: "" })).get("code")).toBe(
			"code-x",
		);
		expect(redirectParams(await authorizePost(app, { ...baseQuery, claims: "" })).get("code")).toBe(
			"code-x",
		);
	});

	it("ignores other uses of claims and issues the code", async () => {
		const { app } = await makeApp({});
		const res = await authorize(app, {
			...baseQuery,
			claims: claims({
				id_token: { auth_time: { essential: true }, email: { acr: 1 } },
				userinfo: { name: { essential: true } },
				acr: { essential: true },
			}),
		});
		expect(redirectParams(res).get("code")).toBe("code-x");
	});

	it.each([
		["not JSON", "acr"],
		["a JSON array", "[]"],
		["a JSON string", '"acr"'],
		["JSON null", "null"],
		["a JSON number", "1"],
	])("refuses claims that is %s: whether it names acr cannot be told", async (_label, value) => {
		const { app } = await makeApp({});
		const params = redirectParams(await authorize(app, { ...baseQuery, claims: value }));
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("claims is not a JSON object");
	});

	it("refuses a repeated claims parameter", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorize(app, { ...baseQuery, claims: [claims({}), claims({})] }),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("claims must be a single string value");
	});

	it("refuses it on POST as on GET", async () => {
		const { app } = await makeApp({});
		const params = redirectParams(
			await authorizePost(app, { ...baseQuery, claims: claims({ id_token: { acr: null } }) }),
		);
		expect(params.get("error_description")).toBe(REFUSAL);
	});

	it("refuses before sending the browser to log in again", async () => {
		// `prompt=login` would otherwise send the user through a login, only to
		// refuse the request when they come back.
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => ({
				sid: "sid-1",
				sub: "user-1",
				authTime: new Date(Date.now() - 60_000),
				createdAt: new Date(Date.now() - 60_000),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: {},
				amr: ["pwd"],
				authentication: undefined,
			})),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const harness = await makeApp({
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
			userSessionStore: store,
		});
		const params = redirectParams(
			await authorize(harness.app, {
				...baseQuery,
				prompt: "login",
				claims: claims({ id_token: { acr: { essential: true } } }),
			}),
		);
		expect(params.get("error_description")).toBe(REFUSAL);
		expect(harness.records.size).toBe(0);
	});
});

describe("the acr drop's boot line for an entry with an empty alternative", () => {
	it("says the entry has an alternative that requires nothing, so an empty unproducible list is not the whole story", () => {
		// A table built by hand — `readAcrTable` and the schema never build
		// one — whose only alternative requires nothing: nothing is missing,
		// and it is still never met.
		const logger = createMockLogger();
		const { dropped } = vouchableAcrValues(
			{ "urn:example:any": [[]], "urn:example:kba": [["kba"]] },
			undefined,
			{},
			new Set(),
		);
		logUnsatisfiableAcrValues(dropped, new Set(), logger);
		expect(logger.warn.mock.calls).toEqual([
			[
				{ acr: "urn:example:any", unproducible: [], emptyAlternative: true },
				ACR_VALUE_UNSATISFIABLE,
			],
			[{ acr: "urn:example:kba", unproducible: ["kba"] }, ACR_VALUE_UNSATISFIABLE],
		]);
		for (const level of [logger.info, logger.error, logger.debug, logger.trace, logger.fatal]) {
			expect(level).not.toHaveBeenCalled();
		}
	});

	it("keeps the first ten values an entry lacks, and counts them all when it cut", () => {
		// Values an operator wrote; `auditErrorList` bounds the list the line
		// carries, and the count says how many there were.
		const lacked = Array.from({ length: 12 }, (_, i) => `x${i}`);
		const logger = createMockLogger();
		const { dropped } = vouchableAcrValues(
			{ "urn:example:many": [lacked] },
			undefined,
			{},
			new Set(),
		);
		logUnsatisfiableAcrValues(dropped, new Set(), logger);
		expect(logger.warn.mock.calls).toEqual([
			[
				{ acr: "urn:example:many", unproducible: lacked.slice(0, 10), unproducibleCount: 12 },
				ACR_VALUE_UNSATISFIABLE,
			],
		]);
	});
});
