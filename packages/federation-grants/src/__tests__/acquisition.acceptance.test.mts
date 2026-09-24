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

import { createServer as createNetServer } from "node:net";
import { inspect } from "node:util";
import type {
	BootstrapMap,
	ClientRepository,
	FederatedIdentityLookup,
	FederatedIdentityLookupResult,
	FederatedIdentityRegistration,
	Logger,
	SubjectRevocation,
	UserRepository,
	UserSession,
} from "@o3co/auth-provider-core";
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
import { HttpUserRepository } from "@o3co/auth-provider-foundation";
import type { Request, RequestHandler } from "express";
import express from "express";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import { ACQUISITION_ENDPOINTS, callbackUrlFor } from "./acquisitionFixture.mjs";

/**
 * The bundled repository, with a lookup that covers this deployment's one
 * registration — which the bundled one alone does not (#611). Both methods
 * read the instance's own fields, so a caller that takes either off the
 * object loses `this` and fails: the slice 6 bug every arrow-function stub
 * hid (Codex).
 */
class DirectoryRepository extends InMemoryUserRepository {
	private readonly covered = "upstream";
	private readonly owners = new Map<string, string>();
	/** What the callback asked, so a test can see the composed deployment asked at all. */
	readonly asked: FederatedIdentityLookup[] = [];

	/** Records that `sub` at the covered registration belongs to local user `owner`. */
	own(sub: string, owner: string): this {
		this.owners.set(sub, owner);
		return this;
	}

	override supportsFederatedIdentityLookup(registration: FederatedIdentityRegistration): boolean {
		return registration.provider === this.covered;
	}

	override async findSubjectByFederatedIdentity(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult> {
		if (identity.provider !== this.covered) {
			return { kind: "indeterminate", reason: "registration_not_covered" };
		}
		this.asked.push({ ...identity });
		const owner = this.owners.get(identity.sub);
		return owner === undefined ? { kind: "unlinked" } : { kind: "linked", subject: owner };
	}
}

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

/** Whose account the fake upstream's exchange verifies; a test may add claims. */
let exchangeUpstream: { issuer: string; subject: string; claims?: Record<string, string> } = {
	issuer: "https://issuer.example",
	subject: "00u-alice",
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
		upstream: { ...exchangeUpstream, claims: { ...(exchangeUpstream.claims ?? {}) } },
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

const directory = () =>
	new DirectoryRepository(new Map([["alice", { password: "unused", id: "alice" }]]));

/** The two stores a deployment reads its grants from, to hand a second deployment the first one's. */
interface GrantStores {
	readonly grants: ReturnType<typeof createMemoryFederationGrantStore>;
	readonly intents: ReturnType<typeof createMemoryFederationGrantIntentStore>;
}

const boot = async (
	subjectRevocation: SubjectRevocation = createInMemorySubjectRevocation(),
	userRepository: UserRepository = directory(),
	connections: Record<string, Record<string, unknown>> = {},
	stores: GrantStores = {
		grants: createMemoryFederationGrantStore(),
		intents: createMemoryFederationGrantIntentStore(),
	},
	logger?: Logger,
) => {
	const full = makeValidFullSections();
	const handle = await createApp({
		modules: [
			federationModule,
			...federationGrantsModules,
			defineModule({
				name: "test-stores",
				provides: {
					federationGrantStore: () => stores.grants,
					federationGrantIntentStore: () => stores.intents,
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
						...connections,
					},
				},
			},
			pathResolver: (s: string) => s,
			...(logger === undefined ? {} : { logger }),
			clientRepository,
			userRepository,
			userSessionStore: { get: async (sid: string) => durable.get(sid) ?? null },
			sessionRPRegistry: {},
			sessionFamilyIndex: {},
			sessionFederationIndex: {},
			federationTokenStore: {},
			refreshTokenFamilyRevocation: {},
			subjectRevocation,
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

	/** A browser signed in as alice at `authTime`, with its durable session. */
	const signIn = (browser: string, authTime: Date) => {
		const sid = `sid-${browser}`;
		browsers.set(browser, { isAuthenticated: true, user: { id: "alice" }, sid });
		durable.set(sid, {
			sid,
			sub: "alice",
			authTime,
			createdAt: authTime,
			expiresAt: new Date(Date.now() + 86_400_000),
			claims: {},
		} as UserSession);
	};

	it("asks the Store, through the composed deployment, and refuses an upstream account it places with another user (#611)", async () => {
		// The composition — not the router's options in a unit test — is what
		// decides whether check 5 runs: a module that handed the router
		// "unsupported" would boot, probe coverage, and then skip the check on
		// every callback.
		const repository = directory().own("00u-alice", "bob");
		const { handle, app } = await boot(undefined, repository);
		try {
			const connect = await lodgeFor(app);
			signIn("b-conflict", new Date());
			const started = await request(app)
				.get(`${connect.pathname}${connect.search}`)
				.set("x-browser", "b-conflict");
			const challenge =
				new URL(started.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
			const approved = await request(app)
				.post("/session/federation-grants/consent")
				.set("x-browser", "b-conflict")
				.send({ challenge, decision: "accept" });
			const state = new URL(approved.headers.location as string).searchParams.get("state") ?? "";
			const returned = await request(app)
				.get("/session/federation-grants/callback/calendar")
				.query({ state, code: "code-1" })
				.set("x-browser", "b-conflict");
			expect(returned.status).toBe(303);
			expect(new URL(returned.headers.location as string).searchParams.get("error")).toBe(
				"identity_conflict",
			);
			expect(repository.asked).toEqual([
				{
					provider: "upstream",
					issuer: "https://issuer.example",
					clientId: "provider-client",
					sub: "00u-alice",
					claims: {},
				},
			]);
		} finally {
			await handle.dispose();
		}
	});

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

	it("holds the browser to the subject's sessions boundary, as the revocation adapter records it", async () => {
		const revocation = createInMemorySubjectRevocation();
		const { handle, app } = await boot(revocation);
		try {
			const connect = await lodgeFor(app);
			// Signed in a minute before every one of alice's sessions was revoked.
			signIn("b-revoked", new Date(Date.now() - 60_000));
			await revocation.revokeBefore("alice", new Date(), new Date(Date.now() + 86_400_000));
			const refused = await request(app)
				.get(`${connect.pathname}${connect.search}`)
				.set("x-browser", "b-revoked");
			expect(refused.status).toBe(403);
			expect(refused.text).toMatch(/sign in again/i);
		} finally {
			await handle.dispose();
		}
	});

	it("fails closed on a revocation adapter that answers neither a date nor null", async () => {
		const broken = {
			...createInMemorySubjectRevocation(),
			revokedBefore: async () => "yesterday" as unknown as Date,
		};
		const { handle, app } = await boot(broken);
		try {
			const connect = await lodgeFor(app);
			signIn("b-broken", new Date());
			const refused = await request(app)
				.get(`${connect.pathname}${connect.search}`)
				.set("x-browser", "b-broken");
			expect(refused.status).toBe(503);
		} finally {
			await handle.dispose();
		}
	});
});

// #613: the identity lookup over HTTP, composed — a deployment on
// `HttpUserRepository` keeps `identityLookup = "required"` with a connection
// configured, given a Store that answers, and the callback reads the Store's
// answer as the port's.
describe("#613: the identity lookup over HTTP, composed", () => {
	const STORE = "http://localhost:18081";
	const LOOKUP = `${STORE}/identity/lookup`;
	const server = setupServer();
	/** What the Store answers, and what it was asked — and with which Authorization. */
	const store = {
		status: 200,
		headers: {} as Record<string, string>,
		body: { kind: "unlinked" } as unknown,
		asked: [] as unknown[],
		authorization: [] as (string | null)[],
	};
	beforeAll(() => {
		// Only the Store is mocked: supertest's own requests to the composed app
		// pass through, and anything else aimed at the Store's origin is an error.
		server.listen({
			onUnhandledRequest: (req, print) => {
				if (req.url.startsWith(STORE)) print.error();
			},
		});
		server.use(
			http.post(LOOKUP, async ({ request: req }) => {
				store.asked.push(await req.json());
				store.authorization.push(req.headers.get("authorization"));
				const init = { status: store.status, headers: store.headers };
				return store.body === undefined
					? new HttpResponse(null, init)
					: HttpResponse.json(store.body as never, init);
			}),
		);
	});
	afterEach(() => {
		store.status = 200;
		store.headers = {};
		store.body = { kind: "unlinked" };
		store.asked = [];
		store.authorization = [];
		exchangeUpstream = { issuer: "https://issuer.example", subject: "00u-alice" };
	});
	afterAll(() => server.close());

	const httpRepository = (credential: { bearerToken?: string } = {}) =>
		new HttpUserRepository({
			...credential,
			authenticateUrl: `${STORE}/authenticate`,
			authenticateByTokenUrl: `${STORE}/authenticate/token`,
			findSubjectByFederatedIdentityUrl: LOOKUP,
			federatedIdentityLookupCoverage: [
				{
					provider: "upstream",
					issuer: "https://issuer.example",
					clientId: "provider-client",
					requiredClaims: ["tid", "oid"],
				},
			],
			timeout: 5000,
		});
	const claimed = { calendar: { identityClaims: ["oid", "tid"] } };
	/** The `calendar` connection with the claims the Store's strategy needs. */
	const connections = () => ({
		calendar: {
			federation: "upstream",
			scopes: ["openid", "offline_access", "calendar.read"],
			boundary: "production",
			maxAccessTokenLifetime: 3600,
			callbackURL: callbackUrlFor("calendar"),
			...claimed.calendar,
		},
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

	/** A browser signed in as alice now, with its durable session. */
	const signIn = (browser: string) => {
		const sid = `sid-${browser}`;
		browsers.set(browser, { isAuthenticated: true, user: { id: "alice" }, sid });
		durable.set(sid, {
			sid,
			sub: "alice",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 86_400_000),
			claims: {},
		} as UserSession);
	};

	/** Lodge, sign in, consent, and come back from the upstream: the callback's redirect. */
	const connectAs = async (app: express.Express, browser: string) => {
		const connect = await lodgeFor(app);
		signIn(browser);
		const started = await request(app)
			.get(`${connect.pathname}${connect.search}`)
			.set("x-browser", browser);
		const challenge =
			new URL(started.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
		const approved = await request(app)
			.post("/session/federation-grants/consent")
			.set("x-browser", browser)
			.send({ challenge, decision: "accept" });
		const state = new URL(approved.headers.location as string).searchParams.get("state") ?? "";
		const returned = await request(app)
			.get("/session/federation-grants/callback/calendar")
			.query({ state, code: "code-1" })
			.set("x-browser", browser);
		expect(returned.status).toBe(303);
		return new URL(returned.headers.location as string).searchParams;
	};

	it("boots under required with a connection, asking the Store nothing at boot", async () => {
		const { handle } = await boot(undefined, httpRepository(), connections());
		try {
			expect(store.asked).toEqual([]);
		} finally {
			await handle.dispose();
		}
	});

	it("activates on the Store's unlinked, having sent it the registration, the sub and the claims", async () => {
		exchangeUpstream = { ...exchangeUpstream, claims: { oid: "O-ALICE", tid: "T-1" } };
		const { handle, app } = await boot(undefined, httpRepository(), connections());
		try {
			const back = await connectAs(app, "b-http-1");
			expect(back.has("error")).toBe(false);
			expect(store.asked).toEqual([
				{
					provider: "upstream",
					issuer: "https://issuer.example",
					clientId: "provider-client",
					sub: "00u-alice",
					claims: { oid: "O-ALICE", tid: "T-1" },
				},
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses on the Store's indeterminate, and reads its linked-to-another as a conflict", async () => {
		exchangeUpstream = { ...exchangeUpstream, claims: { oid: "O-BOB", tid: "T-1" } };
		const { handle, app } = await boot(undefined, httpRepository(), connections());
		try {
			store.body = { kind: "indeterminate", reason: "identity_not_resolvable" };
			expect((await connectAs(app, "b-http-2")).get("error")).toBe("identity_unverifiable");
			store.body = { kind: "linked", subject: "bob" };
			expect((await connectAs(app, "b-http-3")).get("error")).toBe("identity_conflict");
			expect(store.asked).toHaveLength(2);
		} finally {
			await handle.dispose();
		}
	});

	it("reads a Store that answers 404, or a body that is not an answer, as an outage — never as nobody", async () => {
		exchangeUpstream = { ...exchangeUpstream, claims: { oid: "O-ALICE", tid: "T-1" } };
		const { handle, app } = await boot(undefined, httpRepository(), connections());
		try {
			store.status = 404;
			store.body = { kind: "unlinked" };
			expect((await connectAs(app, "b-http-4")).get("error")).toBe("temporarily_unavailable");
			store.status = 200;
			store.body = { found: false };
			expect((await connectAs(app, "b-http-5")).get("error")).toBe("temporarily_unavailable");
		} finally {
			await handle.dispose();
		}
	});

	it("reports a Store that refuses this deployment's token as store_credential_refused — never the token — and answers temporarily_unavailable", async () => {
		// The lookup's only caller reports through the sanitized reporter,
		// which logs a classification and never the error: without one of its
		// own, a refused token would read as "unknown" here.
		const TOKEN = "0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a";
		const lines: unknown[][] = [];
		const record =
			(level: string) =>
			(...args: unknown[]): void => {
				lines.push([level, ...args]);
			};
		const logger = {
			trace: record("trace"),
			debug: record("debug"),
			info: record("info"),
			warn: record("warn"),
			error: record("error"),
			fatal: record("fatal"),
			child: () => logger,
		} as Logger;
		exchangeUpstream = { ...exchangeUpstream, claims: { oid: "O-ALICE", tid: "T-1" } };
		const { handle, app } = await boot(
			undefined,
			httpRepository({ bearerToken: TOKEN }),
			connections(),
			undefined,
			logger,
		);
		try {
			store.status = 401;
			store.headers = { "WWW-Authenticate": 'Bearer error="invalid_token"' };
			store.body = { error: "invalid_token" };
			expect((await connectAs(app, "b-http-6")).get("error")).toBe("temporarily_unavailable");
			expect(store.authorization).toEqual([`Bearer ${TOKEN}`]);
			const reports = lines.filter(
				([, first]) =>
					(first as { event?: unknown } | undefined)?.event === "federation_grant.failure",
			);
			expect(reports).toEqual([
				[
					"warn",
					expect.objectContaining({
						during: "callback_identity_lookup",
						classification: "store_credential_refused",
					}),
					"federation grant operation failed",
				],
			]);
			expect(
				lines.filter((line) =>
					inspect(line, { depth: Number.POSITIVE_INFINITY, showHidden: true }).includes(TOKEN),
				),
			).toEqual([]);
		} finally {
			await handle.dispose();
		}
	});

	it("reports a Store it cannot reach as store_transport_failed, and answers temporarily_unavailable", async () => {
		const lines: unknown[][] = [];
		const record =
			(level: string) =>
			(...args: unknown[]): void => {
				lines.push([level, ...args]);
			};
		const logger = {
			trace: record("trace"),
			debug: record("debug"),
			info: record("info"),
			warn: record("warn"),
			error: record("error"),
			fatal: record("fatal"),
			child: () => logger,
		} as Logger;
		// A loopback port nothing listens on — outside the mocked Store origin,
		// so the connection is really refused.
		const closed = await new Promise<number>((resolve) => {
			const probe = createNetServer();
			probe.listen(0, "127.0.0.1", () => {
				const { port } = probe.address() as { port: number };
				probe.close(() => resolve(port));
			});
		});
		const unreachable = new HttpUserRepository({
			authenticateUrl: `${STORE}/authenticate`,
			authenticateByTokenUrl: `${STORE}/authenticate/token`,
			findSubjectByFederatedIdentityUrl: `http://127.0.0.1:${closed}/identity/lookup`,
			federatedIdentityLookupCoverage: [
				{
					provider: "upstream",
					issuer: "https://issuer.example",
					clientId: "provider-client",
					requiredClaims: ["tid", "oid"],
				},
			],
			timeout: 5000,
		});
		exchangeUpstream = { ...exchangeUpstream, claims: { oid: "O-ALICE", tid: "T-1" } };
		const { handle, app } = await boot(undefined, unreachable, connections(), undefined, logger);
		try {
			expect((await connectAs(app, "b-http-7")).get("error")).toBe("temporarily_unavailable");
			const reports = lines.filter(
				([, first]) =>
					(first as { event?: unknown } | undefined)?.event === "federation_grant.failure",
			);
			expect(reports).toEqual([
				[
					"warn",
					expect.objectContaining({
						during: "callback_identity_lookup",
						classification: "store_transport_failed",
					}),
					"federation grant operation failed",
				],
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses at boot a connection that does not name a claim the Store's strategy needs", async () => {
		const mail = {
			...connections().calendar,
			callbackURL: callbackUrlFor("mail"),
			identityClaims: ["oid"],
		};
		await expect(boot(undefined, httpRepository(), { ...connections(), mail })).rejects.toThrow(
			/connections\.mail[\s\S]*identityClaims/,
		);
	});
});

describe("#593 AC1: a consented grant survives the initiating session's end and a restart", () => {
	/** The whole connect flow for alice, in the browser named, down to the grant it created. */
	const acquire = async (app: express.Express, browser: string): Promise<string> => {
		const lodged = await request(app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic)
			.send({ connection: "calendar", sub: "alice", redirect_uri: REDIRECT, state: "s" });
		expect(lodged.status).toBe(201);
		const connect = new URL(lodged.body.connect_uri as string);

		const started = await request(app)
			.get(`${connect.pathname}${connect.search}`)
			.set("x-browser", browser);
		expect(started.status).toBe(303);
		const challenge =
			new URL(started.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
		const approved = await request(app)
			.post("/session/federation-grants/consent")
			.set("x-browser", browser)
			.send({ challenge, decision: "accept" });
		expect(approved.status).toBe(303);
		const state = new URL(approved.headers.location as string).searchParams.get("state") ?? "";

		const returned = await request(app)
			.get("/session/federation-grants/callback/calendar")
			.query({ state, code: "code-1" })
			.set("x-browser", browser);
		expect(returned.status).toBe(303);
		const back = new URL(returned.headers.location as string);
		expect(back.searchParams.has("error")).toBe(false);
		return back.searchParams.get("grant_id") as string;
	};

	it("is spent by a fresh deployment after the session that agreed it is gone", async () => {
		// The row of the ADR's acceptance table reads "new client instance,
		// session deleted, token returned". The grant is agreed through the
		// real flow, so that what survives is what the flow wrote and not a
		// seed; then the browser session that agreed it ends, both halves —
		// the cookie's and the durable record's — and the process that saw the
		// consent is disposed of. The next process has only the stores.
		const stores: GrantStores = {
			grants: createMemoryFederationGrantStore(),
			intents: createMemoryFederationGrantIntentStore(),
		};
		const first = await boot(undefined, undefined, {}, stores);
		let grantId: string;
		try {
			const sid = "sid-ac1";
			browsers.set("b-ac1", { isAuthenticated: true, user: { id: "alice" }, sid });
			durable.set(sid, {
				sid,
				sub: "alice",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 86_400_000),
				claims: {},
			} as UserSession);
			grantId = await acquire(first.app, "b-ac1");

			// The session ends: the browser's half and the durable half.
			browsers.delete("b-ac1");
			durable.delete(sid);
		} finally {
			await first.handle.dispose();
		}

		const second = await boot(undefined, undefined, {}, stores);
		try {
			const status = await request(second.app)
				.post(`/oauth/federation-grants/${grantId}/status`)
				.set("Authorization", basic)
				.send({ sub: "alice" });
			expect(status.status).toBe(200);
			expect(status.body.status).toBe("active");

			const token = await request(second.app)
				.post(`/oauth/federation-grants/${grantId}/token`)
				.set("Authorization", basic)
				.send({ sub: "alice" });
			expect(token.status).toBe(200);
			expect(token.body).toMatchObject({
				access_token: "upstream-access-token",
				token_type: "bearer",
			});
		} finally {
			await second.handle.dispose();
		}
	});
});

describe("#616: a grant the upstream asked the user for, and one starved of scope, recover on the same grant id", () => {
	const codes = [
		"interaction_required",
		"login_required",
		"consent_required",
		"account_selection_required",
	] as const;
	const original = {
		refreshDelegatedToken: upstream.refreshDelegatedToken,
		exchangeDelegatedCode: upstream.exchangeDelegatedCode,
	};
	afterEach(() => {
		Object.assign(upstream, original);
		vi.useRealTimers();
	});

	/** A browser signed in as alice now, with its durable session. */
	const signIn = (browser: string): void => {
		const sid = `sid-${browser}`;
		browsers.set(browser, { isAuthenticated: true, user: { id: "alice" }, sid });
		durable.set(sid, {
			sid,
			sub: "alice",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 86_400_000),
			claims: {},
		} as UserSession);
	};

	/** The browser half of a lodged intent: connect, consent, callback; what came back to the client. */
	const walk = async (app: express.Express, browser: string, connectUri: string): Promise<URL> => {
		const connect = new URL(connectUri);
		const started = await request(app)
			.get(`${connect.pathname}${connect.search}`)
			.set("x-browser", browser);
		expect(started.status).toBe(303);
		const challenge =
			new URL(started.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
		const approved = await request(app)
			.post("/session/federation-grants/consent")
			.set("x-browser", browser)
			.send({ challenge, decision: "accept" });
		expect(approved.status).toBe(303);
		const state = new URL(approved.headers.location as string).searchParams.get("state") ?? "";
		const returned = await request(app)
			.get("/session/federation-grants/callback/calendar")
			.query({ state, code: "code-616" })
			.set("x-browser", browser);
		expect(returned.status).toBe(303);
		const back = new URL(returned.headers.location as string);
		expect(back.searchParams.get("error")).toBeNull();
		return back;
	};

	/** A grant agreed for alice through the real flow, lodged with `body` over the defaults. */
	const agree = async (
		app: express.Express,
		browser: string,
		body: Record<string, unknown> = {},
	): Promise<string> => {
		const lodged = await request(app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic)
			.send({ connection: "calendar", sub: "alice", redirect_uri: REDIRECT, state: "s", ...body });
		expect(lodged.status).toBe(201);
		signIn(browser);
		const back = await walk(app, browser, lodged.body.connect_uri as string);
		return back.searchParams.get("grant_id") as string;
	};

	const token = (app: express.Express, grantId: string) =>
		request(app)
			.post(`/oauth/federation-grants/${grantId}/token`)
			.set("Authorization", basic)
			.send({ sub: "alice" });
	const status = (app: express.Express, grantId: string) =>
		request(app)
			.post(`/oauth/federation-grants/${grantId}/status`)
			.set("Authorization", basic)
			.send({ sub: "alice" });
	const reauthorize = (app: express.Express, grantId: string, body: Record<string, unknown> = {}) =>
		request(app)
			.post(`/oauth/federation-grants/${grantId}/reauthorize`)
			.set("Authorization", basic)
			.send({ sub: "alice", redirect_uri: REDIRECT, state: "s2", ...body });

	/** An hour and a second on: the token the flow obtained has run out, and the next call refreshes. */
	const runDown = (): void => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date(Date.now() + 3_601_000));
	};

	for (const code of codes) {
		it(`recovers from ${code}: 410 by name and no wait, the status says the same, one renewal, then a token`, async () => {
			const { handle, app } = await boot();
			try {
				const grantId = await agree(app, `b-${code}`);
				// The job pauses; meanwhile the IdP's policy changes under it, and
				// the next refresh is answered with the user's absence.
				Object.assign(upstream, {
					refreshDelegatedToken: async () => {
						throw Object.assign(new Error("server responded with an error"), { error: code });
					},
				});
				runDown();
				const denied = await token(app, grantId);
				expect(denied.status).toBe(410);
				expect(denied.body).toEqual({
					error: "reauthorization_required",
					error_description: `upstream_${code}`,
				});
				expect(denied.headers["retry-after"]).toBeUndefined();
				expect((await status(app, grantId)).body).toMatchObject({
					status: "reauthorization_required",
					reason: `upstream_${code}`,
				});
				// Polling changes nothing: the record remembers, and the upstream is not asked.
				let asked = 0;
				Object.assign(upstream, {
					refreshDelegatedToken: async () => {
						asked += 1;
						throw new Error("must not be asked");
					},
				});
				expect((await token(app, grantId)).status).toBe(410);
				expect(asked).toBe(0);

				// The user comes back: one renewal, the browser through connect, consent
				// and the callback, and the same grant serves again.
				const renewed = await reauthorize(app, grantId);
				expect(renewed.status).toBe(201);
				expect(renewed.body).toMatchObject({
					grant_id: grantId,
					status: "reauthorization_required",
				});
				signIn(`b-${code}-2`);
				const back = await walk(app, `b-${code}-2`, renewed.body.connect_uri as string);
				expect(back.searchParams.get("grant_id")).toBe(grantId);
				const served = await token(app, grantId);
				expect(served.status).toBe(200);
				expect(served.body.access_token).toBe("upstream-access-token");
				expect((await status(app, grantId)).body).toMatchObject({ status: "active" });
			} finally {
				await handle.dispose();
			}
		});
	}

	it("recovers a grant starved of scope through a wider consent, on the same grant id", async () => {
		const { handle, app } = await boot();
		try {
			// A narrow first consent, which the upstream honours as asked.
			Object.assign(upstream, {
				exchangeDelegatedCode: async () => {
					const base = await original.exchangeDelegatedCode();
					return { ...base, tokens: { ...base.tokens, scope: "openid offline_access" } };
				},
			});
			const grantId = await agree(app, "b-narrow", { scope: "openid offline_access" });
			expect((await status(app, grantId)).body).toMatchObject({ scope: "openid offline_access" });

			// Later, a wider consent on the same registration: the IdP now answers
			// every refresh with the accumulated set (D19), and this grant is starved.
			Object.assign(upstream, {
				refreshDelegatedToken: async () => ({
					accessToken: "wide-token",
					refreshToken: "rt-wide",
					expiresIn: 3600,
					expiresAt: new Date(Date.now() + 3_600_000),
					tokenType: "bearer",
					scope: "openid offline_access calendar.read",
				}),
			});
			runDown();
			const starved = await token(app, grantId);
			expect(starved.status).toBe(502);
			expect(starved.body).toMatchObject({
				error: "upstream_token_ineligible",
				error_description: "scope_exceeded",
			});
			expect((await status(app, grantId)).body).toMatchObject({
				status: "upstream_token_ineligible",
				reason: "scope_exceeded",
			});

			// The way back: a renewal for the set the registration now returns,
			// consented to by the user, activated by the callback.
			Object.assign(upstream, { exchangeDelegatedCode: original.exchangeDelegatedCode });
			const renewed = await reauthorize(app, grantId, {
				scope: "openid offline_access calendar.read",
			});
			expect(renewed.status).toBe(201);
			expect(renewed.body).toMatchObject({
				grant_id: grantId,
				status: "upstream_token_ineligible",
			});
			signIn("b-wide");
			const back = await walk(app, "b-wide", renewed.body.connect_uri as string);
			expect(back.searchParams.get("grant_id")).toBe(grantId);
			const served = await token(app, grantId);
			expect(served.status).toBe(200);
			expect(served.body.access_token).toBe("upstream-access-token");
			expect((await status(app, grantId)).body).toMatchObject({
				status: "active",
				scope: "openid offline_access calendar.read",
			});
		} finally {
			await handle.dispose();
		}
	});
});
