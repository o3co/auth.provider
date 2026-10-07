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

import { createSecretKey } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	checkRedirectUri,
	createInMemorySessionLifecycleStore,
	createSessionLifecycle,
	createSymmetricKeyStore,
	type FederationProvider,
	type FederationTokenStore,
	type FederationTokens,
	type Logger,
	type RefreshTokenFamilyRevocation,
	type RegisteredRP,
	type SessionLifecycle,
	type SessionLifecycleOptions,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createSessionCloseNotifier } from "#/logout/sessionCloseNotifier.mjs";
import { createRouter } from "#/routes/logout.mjs";
import {
	hashSourceOf,
	iframeSrcsOf,
	parsePolicy,
	policyHeaderCount,
	scriptsOf,
} from "./_helpers/frontchannelPage.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	expectBestEffortWarn,
	expectOutageLine,
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";
import { outsideAnswer } from "./_helpers/sessionLifecycle.mjs";

/**
 * A federation that satisfies the `FederationProvider` contract, with whatever
 * capability the case under test adds: these routes read a provider the boot
 * planner could actually have handed them.
 */
const federationBase = (name: string) => ({
	name,
	scope: ["openid"] as readonly string[],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/auth`),
	exchangeCode: async () => ({
		issuer: `https://${name}.example`,
		sub: "sub-1",
		expiresAt: null,
	}),
});

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

/** Mint an id_token with the given claims. */
// Mints carry typ JWT. `typ` stays overridable so the suite can present a
// wrong spelling, `id+jwt` included.
async function mintIdToken(extra: Record<string, unknown> = {}, typ = "JWT"): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		aud: "client-1",
		sid: "sid-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

async function mintOldIdToken(): Promise<string> {
	const oldIat = Math.floor((Date.now() - 25 * 60 * 60 * 1000) / 1000);
	return new SignJWT({
		sub: "u-1",
		aud: "client-1",
		sid: "sid-1",
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
		.setExpirationTime("1h")
		.setIssuedAt(oldIat)
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

/**
 * Mint an access token (typ: at+jwt) for use with POST /oauth/federation/:name/logout.
 * Includes sid, sub, and family_id by default.
 */
async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({
		sub: "u-1",
		sid: "sid-1",
		family_id: "fam-1",
		...extra,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);
}

// A minimal valid UserSession (no derived fields)
const baseSession: UserSession = {
	sid: "sid-1",
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: { email: "alice@example.com" },
	amr: undefined,
	authentication: undefined,
};

function makeSessionStore(override?: Partial<UserSessionStore>): UserSessionStore {
	return {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn().mockResolvedValue(baseSession),
		delete: vi.fn(),
		...override,
	};
}

function makeFamilyRevocation(
	override?: Partial<RefreshTokenFamilyRevocation>,
): RefreshTokenFamilyRevocation {
	return {
		isFamilyRevoked: vi.fn().mockResolvedValue(false),
		revokeFamily: vi.fn().mockResolvedValue(undefined),
		...override,
	};
}

function makeFedTokenStore(override?: Partial<FederationTokenStore>): FederationTokenStore {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn().mockResolvedValue(null),
		getVersioned: vi.fn(),
		replaceIf: vi.fn(),
		removeIf: vi.fn(),
		removeBySid: vi.fn().mockResolvedValue(undefined),
		delete: vi.fn(),
		...override,
	};
}

function makeClientRepo(override?: Partial<ClientRepository>): ClientRepository {
	return {
		findById: vi.fn().mockResolvedValue(null),
		authenticate: vi.fn(),
		...override,
	};
}

interface BuildAppOpts {
	sessionStore?: UserSessionStore;
	/**
	 * What `sid-1` joined, written to its lifecycle record before the first
	 * request: relying parties (a client repository answers each one's
	 * registration as recorded, under what `clientRepo` answers), families
	 * (`fam-1` by default) and federations, in that order.
	 */
	joinedRps?: readonly RegisteredRP[];
	joinedFamilies?: readonly string[];
	joinedFederations?: readonly string[];
	refreshFamilyRevocation?: RefreshTokenFamilyRevocation;
	fedTokenStore?: FederationTokenStore;
	clientRepo?: ClientRepository;
	/** Getter for federation providers — evaluated at request time. */
	getFederationProviders?: () => ReadonlyMap<string, FederationProvider> | undefined;
	/** Override fetch for broadcast testing. Defaults to a no-op stub. */
	fetchImpl?: typeof fetch;
	logger?: Logger;
	auditSink?: AuditSink;
	/** A session lifecycle in place of core's over the stores above. */
	sessionLifecycle?: SessionLifecycle;
	/**
	 * The express-session bag the request carries. Absent by default, which is
	 * the shape the rest of this suite runs in (no session middleware mounted)
	 * and the one the browser-session destroy must not throw on.
	 */
	browserSession?: FakeBrowserSession;
}

/**
 * The slice of `express-session`'s request session logout touches: the `sid` it
 * recorded at login and the `destroy` callback. `destroyed` records whether
 * the route actually ended it, so a test can assert on scoping rather than on
 * a spy's call count alone.
 */
interface FakeBrowserSession extends Record<string, unknown> {
	destroy: (cb: (err: Error | null) => void) => void;
	destroyed?: boolean;
}

/**
 * Builds the session bag a logged-in browser carries. `sid` names the
 * UserSession this browser belongs to; `destroyFails` makes the store's
 * destroy reject the way a Redis outage would, and `destroyThrows` makes it
 * throw synchronously the way an adapter that validates its arguments before
 * reaching its own callback does — the path that never calls back at all.
 */
function makeBrowserSession(
	opts: { sid?: string; destroyFails?: boolean; destroyThrows?: boolean } = {},
): FakeBrowserSession {
	const session: FakeBrowserSession = {
		isAuthenticated: true,
		user: { id: "u-1" },
		destroyed: false,
		destroy(cb: (err: Error | null) => void) {
			if (opts.destroyThrows) {
				throw new Error("session store threw synchronously");
			}
			if (opts.destroyFails) {
				cb(new Error("session store down"));
				return;
			}
			session.destroyed = true;
			session.isAuthenticated = false;
			cb(null);
		},
	};
	if (opts.sid !== undefined) session.sid = opts.sid;
	return session;
}

/**
 * A session lifecycle whose `close` answers `answer`, over a live session
 * that joined `google`: for a case that drives the route's answer to a close.
 */
function closing(answer: Awaited<ReturnType<SessionLifecycle["close"]>>): SessionLifecycle {
	return {
		open: vi.fn(async () => ({ outcome: "opened" as const })),
		join: vi.fn(async () => ({ outcome: "joined" as const })),
		close: vi.fn(async () => answer),
		liveness: vi.fn(async () => ({ outcome: "live" as const, session: baseSession })),
		federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
		resumePending: vi.fn(async () => ({ done: 0, pending: 0, unavailable: 0 })),
	};
}

/**
 * A session lifecycle a host fills, whose `step` read rejects with `error`;
 * the session is otherwise live and joined `google`.
 */
function rejecting(step: "liveness" | "federations", error: unknown): SessionLifecycle {
	const lifecycle = closing({ outcome: "done", rps: [], federations: [] });
	return { ...lifecycle, [step]: vi.fn().mockRejectedValue(error) };
}

/**
 * Core's session lifecycle over the stores `buildApp` composes, with `sid-1`
 * opened for `baseSession` and `joined` written to its record before any
 * member answers: the session the suite logs out, as a login and its
 * exchanges would have left it, written to the record directly so that no
 * store a case spies on is read to set it up.
 */
function joinedLifecycle(
	stores: Pick<
		SessionLifecycleOptions,
		"userSessionStore" | "refreshTokenFamilyRevocation" | "federationTokenStore" | "notifier"
	> & { readonly logger: Logger | undefined },
	joined: {
		readonly rps: readonly string[];
		readonly families: readonly string[];
		readonly federations: readonly string[];
	},
): SessionLifecycle {
	const store = createInMemorySessionLifecycleStore();
	const lifecycle = createSessionLifecycle({
		...stores,
		store,
		retainMs: 3_600_000,
		logger: stores.logger ?? { warn: () => undefined, error: () => undefined },
	});
	const seeded = (async () => {
		await store.open("sid-1", baseSession.sub, baseSession.expiresAt);
		for (const [kind, ids] of [
			["rp", joined.rps],
			["family", joined.families],
			["federation", joined.federations],
		] as const) {
			for (const id of ids) await store.join("sid-1", { kind, id, data: "" });
		}
	})();
	const after =
		<A extends unknown[], R>(call: (...args: A) => Promise<R>) =>
		async (...args: A): Promise<R> => {
			await seeded;
			return call(...args);
		};
	return {
		open: after(lifecycle.open),
		join: after(lifecycle.join),
		close: after(lifecycle.close),
		liveness: after(lifecycle.liveness),
		federations: after(lifecycle.federations),
		resumePending: after(lifecycle.resumePending),
	};
}

function buildApp(opts: BuildAppOpts = {}) {
	const app = express();
	if (opts.browserSession) {
		app.use((req, _res, next) => {
			(req as unknown as { session: FakeBrowserSession }).session =
				opts.browserSession as FakeBrowserSession;
			next();
		});
	}
	const userSessionStore = opts.sessionStore ?? makeSessionStore();
	const refreshTokenFamilyRevocation = opts.refreshFamilyRevocation ?? makeFamilyRevocation();
	const federationTokenStore = opts.fedTokenStore ?? makeFedTokenStore();
	const joinedRps = opts.joinedRps ?? [];
	// A relying party the session joined is registered as a client: the close
	// answers its id, and the notifier and the front-channel page read its
	// registration. Its registration carries what was recorded of it at the
	// join, under what the case's repository answers; one the repository does
	// not know is the recorded one alone. Read once.
	let joined: ReadonlyMap<string, object> | undefined;
	const joinedClients = () => {
		joined ??= new Map(joinedRps.map((rp) => [rp.clientId, rp]));
		return joined;
	};
	const baseClients = opts.clientRepo ?? makeClientRepo();
	const clientRepository: ClientRepository = {
		...baseClients,
		findById: async (clientId) => {
			const registered = await baseClients.findById(clientId);
			const recorded = joinedClients().get(clientId);
			if (recorded === undefined) return registered ?? null;
			if (registered === null || registered === undefined) {
				return recorded as Awaited<ReturnType<ClientRepository["findById"]>>;
			}
			return { ...recorded, ...registered } as Awaited<ReturnType<ClientRepository["findById"]>>;
		},
	};
	// Stub fetchImpl so back-channel notices never make real network calls.
	const fetchImpl = opts.fetchImpl ?? vi.fn().mockResolvedValue({ ok: true, status: 200 });
	// Core's session lifecycle over the same stores, its notifier oauth's own.
	const notifier = createSessionCloseNotifier({
		clientRepository,
		keyStore,
		issuer: "https://auth.example.com",
		fetchImpl: fetchImpl as typeof fetch,
	});
	const sessionLifecycle =
		opts.sessionLifecycle ??
		joinedLifecycle(
			{
				userSessionStore,
				refreshTokenFamilyRevocation,
				federationTokenStore,
				notifier: () => notifier,
				logger: opts.logger,
			},
			{
				rps: joinedRps.map((rp) => rp.clientId),
				families: opts.joinedFamilies ?? ["fam-1"],
				federations: opts.joinedFederations ?? [],
			},
		);
	const router = createRouter(express, {
		keyStore,
		issuer: "https://auth.example.com",
		userSessionStore,
		sessionLifecycle,
		refreshTokenFamilyRevocation,
		federationTokenStore,
		clientRepository,
		getFederationProviders: opts.getFederationProviders ?? (() => undefined),
		logger: opts.logger,
		auditSink: opts.auditSink,
	});
	app.use("/oauth", router);
	return app;
}

async function postLogout(
	app: ReturnType<typeof express>,
	body: Record<string, string | undefined>,
	headers: Record<string, string> = {},
) {
	const req = request(app).post("/oauth/logout").type("form");
	for (const [k, v] of Object.entries(headers)) {
		req.set(k, v);
	}
	// Only send defined values
	const filteredBody = Object.fromEntries(
		Object.entries(body).filter(([, v]) => v !== undefined),
	) as Record<string, string>;
	return req.send(filteredBody);
}

function getLogout(app: ReturnType<typeof express>, query: Record<string, string | undefined>) {
	const filteredQuery = Object.fromEntries(
		Object.entries(query).filter(([, v]) => v !== undefined),
	) as Record<string, string>;
	return request(app).get("/oauth/logout").query(filteredQuery);
}

function expectLogoutConfirmation(res: Awaited<ReturnType<typeof getLogout>>) {
	expect(res.status).toBe(200);
	expect(res.headers["content-type"]).toMatch(/^text\/html/);
	expect(res.text).toContain("<form");
	expect(res.text).toContain('method="POST"');
	// action="" submits to the current URL — avoids the relative-URL trap
	// where action="logout" on /oauth/logout/ resolves to /oauth/logout/logout.
	expect(res.text).toContain('action=""');
}

describe("POST /oauth/logout", () => {
	describe("happy path", () => {
		it("valid id_token_hint + session → the session is closed, returns JSON { logged_out: true }", async () => {
			const sessionStore = makeSessionStore();
			const refreshFamilyRevocation = makeFamilyRevocation();
			const fedTokenStore = makeFedTokenStore();
			const app = buildApp({ sessionStore, refreshFamilyRevocation, fedTokenStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			// The close revokes each family, deletes the session and clears its
			// federation tokens.
			expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
			expect(fedTokenStore.removeBySid).toHaveBeenCalledWith("sid-1");
		});

		it("confirmed=1 form-submission shape (hint + confirmed + state) completes hint-based logout, not 400", async () => {
			// The GET confirmation page posts `confirmed=1` plus the
			// id_token_hint as a hidden input; that shape must reach the
			// hint-based logout path, or "Sign out" always fails.
			const sessionStore = makeSessionStore();
			const refreshFamilyRevocation = makeFamilyRevocation();
			const app = buildApp({ sessionStore, refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				confirmed: "1",
				state: "round-trip",
			});

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		});
	});

	describe("id_token_hint typ — only the standard spelling is accepted", () => {
		it("refuses an id_token_hint carrying typ id+jwt", async () => {
			// Logout is where an already-issued id_token would lose its hint
			// value once the spelling is refused; none carrying `id+jwt` exist.
			const sessionStore = makeSessionStore();
			const app = buildApp({ sessionStore });
			const token = await mintIdToken({}, "id+jwt");

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
			expect(sessionStore.delete).not.toHaveBeenCalled();
		});

		it("accepts the standard spelling", async () => {
			const sessionStore = makeSessionStore();
			const app = buildApp({ sessionStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
		});

		it("refuses at+jwt, as it always did", async () => {
			// The accepted set is exactly one value: no cross-type confusion.
			const app = buildApp({});
			const token = await mintIdToken({}, "at+jwt");

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
		});
	});

	describe("session missing (defensive no-op)", () => {
		it("userSessionStore.get → null → 200 JSON, nothing closed", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(null) });
			const refreshFamilyRevocation = makeFamilyRevocation();
			const app = buildApp({ sessionStore, refreshFamilyRevocation });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
			expect(sessionStore.delete).not.toHaveBeenCalled();
		});
	});

	describe("id_token_hint invalid signature", () => {
		it("returns 400 invalid_token", async () => {
			const app = buildApp();

			const res = await postLogout(app, { id_token_hint: "not.a.valid.jwt" });

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("id_token_hint missing sid claim", () => {
		it("returns 400 invalid_request", async () => {
			const app = buildApp();
			// Mint a token without sid
			const token = await new SignJWT({ sub: "u-1", aud: "client-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
				.setIssuer("https://auth.example.com")
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
			expect(res.body.error_description).toMatch(/sid/);
		});

		// A hint that names no session can log nothing out, on GET or POST, and
		// that is known before anything else is asked: neither the client
		// repository (for post_logout_redirect_uri) nor, on a stale GET, the
		// confirmation page — whose "Sign out" would only post the same hint
		// back to this 400.
		const hintWithoutSid = (iat?: number) => {
			const jwt = new SignJWT({ sub: "u-1", aud: "client-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
				.setIssuer("https://auth.example.com")
				.setExpirationTime("1h");
			return (iat === undefined ? jwt.setIssuedAt() : jwt.setIssuedAt(iat)).sign(secretKey);
		};

		it("answers 400 without asking the client repository for post_logout_redirect_uri", async () => {
			const findById = vi.fn().mockRejectedValue(storeReplyError());
			const app = buildApp({ clientRepo: makeClientRepo({ findById }) });

			const res = await postLogout(app, {
				id_token_hint: await hintWithoutSid(),
				post_logout_redirect_uri: "https://rp.example/logged-out",
			});

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
			expect(findById).not.toHaveBeenCalled();
		});

		it("answers a stale GET 400, not with a confirmation page that can only fail", async () => {
			const app = buildApp();
			const stale = Math.floor((Date.now() - 25 * 60 * 60 * 1000) / 1000);

			const res = await getLogout(app, { id_token_hint: await hintWithoutSid(stale) });

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
		});
	});

	describe("backchannelLogoutSessionRequired:false omits sid from logout_token", () => {
		it("RP with backchannelLogoutSessionRequired:false → fetch called without sid in logout_token", async () => {
			const capturedBodies: string[] = [];
			const fetchSpy = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
				if (init?.body) capturedBodies.push(String(init.body));
				return { ok: true };
			});
			const rpData = [
				{
					clientId: "rp-no-sid",
					backchannelLogoutUri: "https://rp.example.com/back-logout",
					backchannelLogoutSessionRequired: false,
					registeredAt: new Date(),
					frontchannelLogoutUri: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, fetchImpl: fetchSpy });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(fetchSpy).toHaveBeenCalledOnce();
			// The logout_token body is URL-encoded; extract and decode it
			expect(capturedBodies).toHaveLength(1);
			const params = new URLSearchParams(capturedBodies[0]);
			const logoutToken = params.get("logout_token");
			expect(logoutToken).toBeTruthy();
			if (!logoutToken) throw new Error("logout_token missing from broadcast request body");
			// Decode JWT payload (no signature verification needed — we minted it)
			const payloadBase64 = logoutToken.split(".")[1];
			const payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
			// backchannelLogoutSessionRequired:false → sid MUST be absent
			expect(payload.sid).toBeUndefined();
		});
	});

	describe("front-channel HTML response", () => {
		it("Accept: text/html + session has frontchannelLogoutUri RP → 200 text/html with <iframe>", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			expect(res.text).toContain("<iframe");
			expect(res.text).toContain("rp1.example.com");
		});

		it("sends the page under its own Content-Security-Policy, replacing the one a host set", async () => {
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
				{
					clientId: "rp-2",
					frontchannelLogoutUri: "https://rp2.example.com:8443/fc",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			// A host's global policy, set ahead of the route as helmet sets it.
			const host = express();
			host.use((_req, res, next) => {
				res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'");
				next();
			});
			host.use(buildApp({ joinedRps: rpData, clientRepo }));

			const res = await postLogout(
				host,
				{
					id_token_hint: await mintIdToken(),
					post_logout_redirect_uri: "https://trusted.example.com/logged-out",
					state: "s-1",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(policyHeaderCount(res)).toBe(1);
			const policy = parsePolicy(res.headers["content-security-policy"] as string);
			expect([...(policy.get("frame-src") ?? [])].sort()).toEqual([
				"https://rp1.example.com",
				"https://rp2.example.com:8443",
			]);
			expect(
				iframeSrcsOf(res.text)
					.map((src) => new URL(src).origin)
					.sort(),
			).toEqual(["https://rp1.example.com", "https://rp2.example.com:8443"]);
			const [script] = scriptsOf(res.text);
			expect(script?.attributes["data-target"]).toBe(
				"https://trusted.example.com/logged-out?state=s-1",
			);
			expect(policy.get("script-src")).toEqual([hashSourceOf(script?.text ?? "")]);
			// The page's other headers are as they were.
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
			expect(res.headers["content-type"]).toBe("text/html; charset=utf-8");
		});

		it("leaves the host's policy on an answer that is not the page", async () => {
			const host = express();
			host.use((_req, res, next) => {
				res.setHeader("Content-Security-Policy", "default-src 'none'");
				next();
			});
			host.use(buildApp());

			const res = await postLogout(host, { id_token_hint: await mintIdToken() });

			expect(res.status).toBe(200);
			expect(res.headers["content-security-policy"]).toBe("default-src 'none'");
		});

		const storedRP = (clientId: string, frontchannelLogoutUri: string) => ({
			clientId,
			frontchannelLogoutUri,
			registeredAt: new Date(),
			backchannelLogoutUri: undefined,
			backchannelLogoutSessionRequired: undefined,
			frontchannelLogoutSessionRequired: undefined,
		});
		const NON_HTTP_URIS = [
			"javascript:void(0)",
			"JAVASCRIPT:void(0)",
			"java\tscript:void(0)",
			"data:text/plain,signed-out",
			"blob:https://rp.example/x",
			"com.example.app:/x",
		];

		it("renders only http(s) front-channel URIs, and warns once for each RP it skips", async () => {
			const logger = createMockLogger();
			const rpData = [
				storedRP("rp-1", "https://rp1.example.com/fc-logout"),
				...NON_HTTP_URIS.map((uri, i) => storedRP(`rp-skipped-${i}`, uri)),
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, logger });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			const srcs = [...res.text.matchAll(/<iframe src="([^"]*)"/g)].map((m) => m[1] ?? "");
			expect(srcs).toHaveLength(1);
			for (const src of srcs) expect(src).toMatch(/^https?:\/\//);
			const refused = logger.warn.mock.calls.filter(
				([, name]) => name === "logout_frontchannel_uri_refused",
			);
			expect(refused).toHaveLength(NON_HTTP_URIS.length);
			for (const [line] of refused) {
				expect(line).toMatchObject({ site: "logout", reason: "not-http" });
			}
		});

		it("renders exactly the RPs it accepts, reading each registry field once", async () => {
			const reads = new Map<string, number>();
			const counted = (clientId: string, uri: string, sessionRequired?: boolean) => {
				const count = (field: string) =>
					reads.set(`${clientId}.${field}`, (reads.get(`${clientId}.${field}`) ?? 0) + 1);
				return {
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					get clientId(): string {
						count("clientId");
						return clientId;
					},
					get frontchannelLogoutUri(): string {
						count("frontchannelLogoutUri");
						return uri;
					},
					get frontchannelLogoutSessionRequired(): boolean | undefined {
						count("frontchannelLogoutSessionRequired");
						return sessionRequired;
					},
				};
			};
			const rpData = [
				counted("rp-1", "https://rp1.example.com/fc"),
				counted("rp-2", "https://rp2.example.com/fc", false),
				counted("rp-skipped", "com.example.app:/x"),
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, logger: createMockLogger() });

			const res = await postLogout(
				app,
				{ id_token_hint: await mintIdToken() },
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			const srcs = [...res.text.matchAll(/<iframe src="([^"]*)"/g)].map((m) => m[1] ?? "");
			expect(srcs).toEqual([
				"https://rp1.example.com/fc?iss=https%3A%2F%2Fauth.example.com&amp;sid=sid-1",
				"https://rp2.example.com/fc?iss=https%3A%2F%2Fauth.example.com",
			]);
			for (const [field, count] of reads) {
				if (
					field.endsWith(".frontchannelLogoutUri") ||
					field.endsWith(".frontchannelLogoutSessionRequired")
				) {
					expect(count, field).toBe(1);
				}
			}
			expect(reads.get("rp-1.frontchannelLogoutUri")).toBe(1);
			expect(reads.get("rp-skipped.frontchannelLogoutSessionRequired")).toBeUndefined();
		});

		it("warns through the route's console fallback for an RP it skips when no logger is wired", async () => {
			const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const rpData = [storedRP("rp-skipped", "com.example.app:/x")];
				const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
				const joinedRps = rpData;
				const app = buildApp({ sessionStore, joinedRps });
				const token = await mintIdToken();

				const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

				expect(res.status).toBe(200);
				const refused = warn.mock.calls.filter(
					([, name]) => name === "logout_frontchannel_uri_refused",
				);
				expect(refused).toHaveLength(1);
				expect(refused[0]?.[0]).toMatchObject({
					site: "logout",
					clientId: "rp-skipped",
					reason: "not-http",
				});
			} finally {
				warn.mockRestore();
			}
		});

		it("answers the JSON fallback when no RP's front-channel URI is http(s) and nothing else redirects", async () => {
			const logger = createMockLogger();
			const rpData = NON_HTTP_URIS.map((uri, i) => storedRP(`rp-skipped-${i}`, uri));
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, logger });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
			expect(res.text).not.toContain("<iframe");
			expect(
				logger.warn.mock.calls.filter(([, name]) => name === "logout_frontchannel_uri_refused"),
			).toHaveLength(NON_HTTP_URIS.length);
		});

		it("redirects to the registered post_logout_redirect_uri when no RP's front-channel URI is http(s)", async () => {
			const rpData = NON_HTTP_URIS.map((uri, i) => storedRP(`rp-skipped-${i}`, uri));
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://app.example.com/logged-out"],
				}),
			});
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({
				sessionStore,
				joinedRps,
				clientRepo,
				logger: createMockLogger(),
			});

			const res = await postLogout(
				app,
				{
					id_token_hint: await mintIdToken(),
					post_logout_redirect_uri: "https://app.example.com/logged-out",
					state: "s-1",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe("https://app.example.com/logged-out?state=s-1");
		});

		it.each([
			["text/html", /text\/html/],
			["application/json", /application\/json/],
		])(
			"a registered RP whose frontchannelLogoutUri read throws does not fail the logout (Accept: %s)",
			async (accept, contentType) => {
				const logger = createMockLogger();
				const rpData = [
					{
						clientId: "rp-throws",
						registeredAt: new Date(),
						backchannelLogoutUri: undefined,
						backchannelLogoutSessionRequired: undefined,
						get frontchannelLogoutUri(): string | undefined {
							throw new Error("field unavailable");
						},
						frontchannelLogoutSessionRequired: undefined,
					},
					{
						clientId: "rp-1",
						frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
						registeredAt: new Date(),
						backchannelLogoutUri: undefined,
						backchannelLogoutSessionRequired: undefined,
						frontchannelLogoutSessionRequired: undefined,
					},
				];
				const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
				const joinedRps = rpData;
				const app = buildApp({ sessionStore, joinedRps, logger });
				const token = await mintIdToken();

				const res = await postLogout(app, { id_token_hint: token }, { Accept: accept });

				expect(res.status).toBe(200);
				expect(res.headers["content-type"]).toMatch(contentType);
				if (accept === "text/html") {
					expect(res.text).toContain("rp1.example.com");
					expectBestEffortWarn(
						logger,
						"logout_frontchannel_uri_refused",
						{ site: "logout", clientId: "rp-throws", reason: "unreadable" },
						null,
					);
				}
			},
		);
	});

	describe("HTML branch open-redirect defense", () => {
		it("unregistered post_logout_redirect_uri is NOT embedded in redirect script (open redirect defense)", async () => {
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			// Client does NOT include evil.example in postLogoutRedirectUris
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{
					id_token_hint: token,
					post_logout_redirect_uri: "https://evil.example/steal",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			// Body MUST NOT contain the attacker-controlled URL
			expect(res.text).not.toContain("evil.example");
		});

		it("registered post_logout_redirect_uri IS embedded in HTML redirect script", async () => {
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps, clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{
					id_token_hint: token,
					post_logout_redirect_uri: "https://trusted.example.com/logged-out",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			// The validated URI MUST appear in the page
			expect(res.text).toContain("trusted.example.com");
		});

		it("carries state on the page's redirect, as the 303 does", async () => {
			// OIDC RP-Initiated Logout 1.0 §3: `state` is passed back to the RP
			// on the post_logout_redirect_uri, whichever way the browser gets there.
			const rpData = [
				{
					clientId: "client-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const joinedRps = rpData;
			const app = buildApp({ joinedRps, clientRepo });

			const res = await postLogout(
				app,
				{
					id_token_hint: await mintIdToken(),
					post_logout_redirect_uri: "https://trusted.example.com/logged-out",
					state: "s-1",
				},
				{ Accept: "text/html" },
			);

			expect(res.status).toBe(200);
			expect(res.text).toContain('"https://trusted.example.com/logged-out?state=s-1"');
		});
	});

	describe("post_logout_redirect_uri in allowlist", () => {
		it("returns 303 redirect to post_logout_redirect_uri with state appended", async () => {
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://app.example.com/logged-out"],
				}),
			});
			const app = buildApp({ clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				post_logout_redirect_uri: "https://app.example.com/logged-out",
				state: "csrf-abc",
			});

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("https://app.example.com/logged-out");
			expect(res.headers.location).toContain("state=csrf-abc");
		});
	});

	describe("post_logout_redirect_uri NOT in allowlist", () => {
		it("falls back to 200 JSON (no redirect)", async () => {
			const clientRepo = makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					allowedRedirectUris: [],
					allowedScopes: [],
					postLogoutRedirectUris: ["https://trusted.example.com/logged-out"],
				}),
			});
			const app = buildApp({ clientRepo });
			const token = await mintIdToken();

			const res = await postLogout(app, {
				id_token_hint: token,
				post_logout_redirect_uri: "https://evil.example.com/steal",
			});

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
		});
	});

	describe("federation end-session redirect", () => {
		it("session.federations has provider with endSession → 303 to mock endSession URL", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedFederations = ["google"];

			const mockEndSessionUrl = new URL("https://accounts.google.com/logout?id_token_hint=x");
			const mockProvider: FederationProvider & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				...federationBase("google"),
				endSession: vi.fn().mockResolvedValue({ url: mockEndSessionUrl, method: "GET" }),
			};
			const federationProviders = new Map<string, FederationProvider>([["google", mockProvider]]);

			const app = buildApp({
				sessionStore,
				joinedFederations,
				getFederationProviders: () => federationProviders,
			});
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("accounts.google.com");
			expect(mockProvider.endSession).toHaveBeenCalledOnce();
		});

		it("goes to the upstream without the id_token hint when the token record cannot be read, and says so once", async () => {
			// Best effort: the logout proceeds, and the upstream end-session call
			// goes without `id_token_hint`, so the IdP may ask the user to
			// confirm, or pick the account itself.
			const endSession = vi.fn().mockResolvedValue({
				url: new URL("https://accounts.google.com/logout"),
				method: "GET",
			});
			const provider = { ...federationBase("google"), endSession } as unknown as FederationProvider;
			const logger = createMockLogger();
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
				joinedFederations: ["google"],
				fedTokenStore: makeFedTokenStore({ get: vi.fn().mockRejectedValue(storeReplyError()) }),
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				logger,
			});

			const res = await postLogout(app, { id_token_hint: await mintIdToken() });

			expect(res.status).toBe(303);
			expect(endSession).toHaveBeenCalledWith(expect.objectContaining({ idTokenHint: undefined }));
			expectBestEffortWarn(logger, "logout_federation_token_read_failed", {
				federation: "google",
				store: "federation_token",
				step: "get",
			});
		});
	});

	describe("the front-channel page of a session whose federation ends sessions upstream", () => {
		const REGISTERED = "https://trusted.example.com/logged-out";
		const FRONTCHANNEL_RP = {
			clientId: "client-1",
			frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
			registeredAt: new Date(),
			backchannelLogoutUri: undefined,
			backchannelLogoutSessionRequired: undefined,
			frontchannelLogoutSessionRequired: undefined,
		};

		/** An upstream that ends at its end-session endpoint with what it is handed. */
		const upstreamEndSession = vi.fn(
			async (req: { postLogoutRedirectUri?: string; state?: string }) => {
				const url = new URL("https://idp.example/end-session");
				url.searchParams.set("id_token_hint", "upstream-hint");
				if (req.postLogoutRedirectUri !== undefined) {
					url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
				}
				if (req.state !== undefined) url.searchParams.set("state", req.state);
				return { url, method: "GET" as const };
			},
		);

		function build(provider: FederationProvider) {
			return buildApp({
				joinedRps: [FRONTCHANNEL_RP],
				joinedFederations: ["upstream"],
				getFederationProviders: () => new Map<string, FederationProvider>([["upstream", provider]]),
				clientRepo: makeClientRepo({
					findById: vi.fn().mockResolvedValue({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						postLogoutRedirectUris: [REGISTERED],
						frontchannelLogoutUri: FRONTCHANNEL_RP.frontchannelLogoutUri,
					}),
				}),
			});
		}
		const withEndSession = () =>
			({
				...federationBase("upstream"),
				endSession: upstreamEndSession,
			}) as unknown as FederationProvider;
		const body = async () => ({
			id_token_hint: await mintIdToken(),
			post_logout_redirect_uri: REGISTERED,
			state: "s-1",
		});

		it("ends at the upstream end-session URL, which carries post_logout_redirect_uri and state", async () => {
			const res = await postLogout(build(withEndSession()), await body(), {
				Accept: "text/html",
			});

			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toBe("text/html; charset=utf-8");
			expect(iframeSrcsOf(res.text).map((src) => new URL(src).origin)).toEqual([
				"https://rp1.example.com",
			]);
			const [script] = scriptsOf(res.text);
			const target = new URL(script?.attributes["data-target"] ?? "");
			expect(target.origin + target.pathname).toBe("https://idp.example/end-session");
			expect(target.searchParams.get("post_logout_redirect_uri")).toBe(REGISTERED);
			expect(target.searchParams.get("state")).toBe("s-1");
			expect(target.searchParams.get("id_token_hint")).toBe("upstream-hint");
		});

		it("sends the page under its one policy, which allows the same script by hash and frames the same origins", async () => {
			const res = await postLogout(build(withEndSession()), await body(), {
				Accept: "text/html",
			});

			expect(policyHeaderCount(res)).toBe(1);
			const policy = parsePolicy(res.headers["content-security-policy"] as string);
			const [script] = scriptsOf(res.text);
			expect(policy.get("script-src")).toEqual([hashSourceOf(script?.text ?? "")]);
			expect(policy.get("frame-src")).toEqual(["https://rp1.example.com"]);
			expect(policy.get("default-src")).toEqual(["'none'"]);
			expect(policy.get("form-action")).toEqual(["'none'"]);
		});

		it("ends at the post_logout_redirect_uri with state when the federation does not end sessions upstream", async () => {
			const res = await postLogout(build(federationBase("upstream")), await body(), {
				Accept: "text/html",
			});

			expect(res.status).toBe(200);
			expect(scriptsOf(res.text)[0]?.attributes["data-target"]).toBe(`${REGISTERED}?state=s-1`);
		});

		it("answers a request that does not prefer HTML with the 303 to the upstream end-session URL", async () => {
			const res = await postLogout(build(withEndSession()), await body());

			expect(res.status).toBe(303);
			const location = new URL(res.headers.location as string);
			expect(location.origin + location.pathname).toBe("https://idp.example/end-session");
			expect(location.searchParams.get("post_logout_redirect_uri")).toBe(REGISTERED);
			expect(location.searchParams.get("state")).toBe("s-1");
		});
	});

	// The upstream end-session call is handed the caller's
	// post_logout_redirect_uri only once it matched the client's registered
	// list: an adapter for an IdP that publishes no end-session endpoint
	// (Google, GitHub, Apple) redirects straight to what it is handed.
	describe("the post_logout_redirect_uri the upstream end-session call is handed", () => {
		const REGISTERED = "https://rp.example/logged-out";

		function buildWithUpstream(opts: BuildAppOpts = {}) {
			const endSession = vi.fn().mockResolvedValue({
				url: new URL("https://accounts.google.com/Logout"),
				method: "GET",
			});
			const provider = { ...federationBase("google"), endSession } as unknown as FederationProvider;
			const app = buildApp({
				joinedFederations: ["google"],
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				clientRepo: makeClientRepo({
					findById: vi.fn().mockResolvedValue({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						postLogoutRedirectUris: [REGISTERED],
					}),
				}),
				...opts,
			});
			return { app, endSession };
		}

		it("is none when the client has not registered it", async () => {
			const { app, endSession } = buildWithUpstream();

			const res = await postLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: "https://evil.example/landing",
				state: "s-1",
			});

			expect(res.status).toBe(303);
			expect(endSession).toHaveBeenCalledOnce();
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("is none when the client is not known", async () => {
			const { app, endSession } = buildWithUpstream({
				clientRepo: makeClientRepo({ findById: vi.fn().mockResolvedValue(null) }),
			});

			await postLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: REGISTERED,
			});

			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("is the registered one when it matches exactly", async () => {
			const { app, endSession } = buildWithUpstream();

			await postLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: REGISTERED,
				state: "s-1",
			});

			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: REGISTERED, state: "s-1" }),
			);
		});

		it("asks the client repository nothing when the request names no post_logout_redirect_uri", async () => {
			const findById = vi.fn().mockRejectedValue(storeReplyError());
			const { app, endSession } = buildWithUpstream({
				clientRepo: makeClientRepo({ findById }),
			});

			const res = await postLogout(app, { id_token_hint: await mintIdToken() });

			expect(res.status).toBe(303);
			expect(findById).not.toHaveBeenCalled();
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("completes the logout without the redirect when the client repository cannot answer", async () => {
			// An outage says nothing about whether the URI is registered, so it is
			// not used; but refusing the logout for it would keep the session, its
			// refresh-token families and the relying parties' sessions alive to
			// protect a redirect. The logout runs as if no URI had been sent.
			const logger = createMockLogger();
			const sessionStore = makeSessionStore();
			const refreshFamilyRevocation = makeFamilyRevocation();
			const joinedRps = [
				{
					clientId: "rp-1",
					backchannelLogoutUri: "https://rp-1.example/backchannel",
					backchannelLogoutSessionRequired: true,
					frontchannelLogoutUri: undefined,
					frontchannelLogoutSessionRequired: undefined,
					registeredAt: new Date(),
				},
			];
			const fetchImpl = vi.fn().mockResolvedValue({ ok: true });
			const browserSession = makeBrowserSession({ sid: "sid-1" });
			const { app, endSession } = buildWithUpstream({
				sessionStore,
				refreshFamilyRevocation,
				joinedRps,
				fetchImpl,
				browserSession,
				// The registration read for the redirect fails; the relying party's,
				// read later by the lifecycle's notifier, answers.
				clientRepo: makeClientRepo({
					findById: vi.fn().mockRejectedValueOnce(storeReplyError()).mockResolvedValue(null),
				}),
				logger,
			});

			const res = await postLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: REGISTERED,
			});

			// The answer a logout that named no URI gets: the upstream's own page.
			expect(res.status).toBe(303);
			expect(res.headers.location).toBe("https://accounts.google.com/Logout");
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
			expectOutageLine(logger, "client_repository_unavailable", {
				site: "logout",
				step: "find",
				clientId: "client-1",
			});
			// Everything a logout does, done.
			expect(fetchImpl).toHaveBeenCalledOnce();
			expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
			expect(browserSession.destroyed).toBe(true);
		});

		// OIDC RP-Initiated Logout 1.0 §3: the URI must match a registered one
		// exactly. Each of these is one character or one convention away.
		it.each([
			["a trailing slash", `${REGISTERED}/`],
			["a different case in the path", "https://rp.example/Logged-Out"],
			["a different case in the host", "https://RP.example/logged-out"],
			["a query appended", `${REGISTERED}?next=%2F`],
			["a path segment appended", `${REGISTERED}/more`],
			["a fragment appended", `${REGISTERED}#top`],
			["a prefix of it", "https://rp.example/logged"],
			["another scheme", "http://rp.example/logged-out"],
		])("is none for a near miss: %s", async (_label, nearMiss) => {
			const { app, endSession } = buildWithUpstream();
			await postLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: nearMiss,
			});
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);

			// And with no federation to hand it to, no redirect at all.
			const plain = buildApp({
				clientRepo: makeClientRepo({
					findById: vi.fn().mockResolvedValue({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						postLogoutRedirectUris: [REGISTERED],
					}),
				}),
			});
			const res = await postLogout(plain, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: nearMiss,
			});
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ logged_out: true });
		});

		// A custom ClientRepository bypasses ClientEntrySchema, so an entry
		// `checkRedirectUri` would refuse at boot can reach this route: one the
		// URL parser cannot read, one in an executable scheme, or one whose
		// query carries a name the response appends. Matching it exactly does
		// not make it a place to send a browser: `new URL()` on the first would
		// end a finished logout in a 500, the second would reach
		// `window.location.href` on the front-channel page, which is script on
		// this origin, and the third would hand the RP a `state` it never sent.
		// Each is dropped with one warn, and the logout completes as if no URI
		// had been sent.
		describe("a registered entry this server would not redirect to", () => {
			const UNPARSABLE = "::not a url";
			const EXECUTABLE = "javascript:alert(document.domain)";
			const RESERVED = "https://rp.example/bye?state=registered";
			const cases = [
				["one the URL parser cannot read", UNPARSABLE, "unparsable"],
				["one in an executable scheme", EXECUTABLE, "executable-scheme"],
				["one whose query carries a response parameter", RESERVED, "reserved-parameter"],
			] as const;

			const registering = (entry: string) =>
				makeClientRepo({
					findById: vi.fn().mockResolvedValue({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						postLogoutRedirectUris: [entry],
					}),
				});

			const expectRefusedOnce = (logger: MockLogger, reason: string) => {
				expectBestEffortWarn(
					logger,
					"logout_registered_redirect_uri_refused",
					{ site: "logout", clientId: "client-1", reason },
					null,
				);
				expect(logger.error).not.toHaveBeenCalled();
			};

			it.each(cases)("is not the redirect (7c): %s", async (_label, entry, reason) => {
				const logger = createMockLogger();
				const sessionStore = makeSessionStore();
				const app = buildApp({ sessionStore, clientRepo: registering(entry), logger });

				const res = await postLogout(app, {
					id_token_hint: await mintIdToken(),
					post_logout_redirect_uri: entry,
					state: "s-1",
				});

				expect(res.status).toBe(200);
				expect(res.body).toEqual({ logged_out: true });
				expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
				expectRefusedOnce(logger, reason);
			});

			it.each(cases)(
				"is not handed to the upstream end-session call (7b): %s",
				async (_label, entry, reason) => {
					const logger = createMockLogger();
					const { app, endSession } = buildWithUpstream({
						clientRepo: registering(entry),
						logger,
					});

					const res = await postLogout(app, {
						id_token_hint: await mintIdToken(),
						post_logout_redirect_uri: entry,
					});

					expect(res.status).toBe(303);
					expect(res.headers.location).toBe("https://accounts.google.com/Logout");
					expect(endSession).toHaveBeenCalledWith(
						expect.objectContaining({ postLogoutRedirectUri: undefined }),
					);
					expectRefusedOnce(logger, reason);
				},
			);

			it.each(cases)(
				"is not where the front-channel page sends the browser (7a): %s",
				async (_label, entry, reason) => {
					const logger = createMockLogger();
					const joinedRps = [
						{
							clientId: "client-1",
							frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
							registeredAt: new Date(),
							backchannelLogoutUri: undefined,
							backchannelLogoutSessionRequired: undefined,
							frontchannelLogoutSessionRequired: undefined,
						},
					];
					const app = buildApp({ joinedRps, clientRepo: registering(entry), logger });

					const res = await postLogout(
						app,
						{ id_token_hint: await mintIdToken(), post_logout_redirect_uri: entry },
						{ Accept: "text/html" },
					);

					expect(res.status).toBe(200);
					expect(res.headers["content-type"]).toMatch(/text\/html/);
					expect(res.text).toContain("<iframe");
					expect(res.text).not.toContain("<script>");
					expect(res.text).not.toContain("javascript:");
					expect(res.text).not.toContain("not a url");
					expect(res.text).not.toContain("state=registered");
					expectRefusedOnce(logger, reason);
				},
			);
		});

		describe("which client's list the URI is held to", () => {
			/** Only `client-1` is registered, with the one URI. */
			const onlyClient1 = () =>
				vi.fn<ClientRepository["findById"]>(async (clientId) =>
					clientId === "client-1"
						? {
								clientId: "client-1",
								tokenEndpointAuthMethod: "client_secret_basic",
								allowedRedirectUris: [],
								allowedScopes: [],
								postLogoutRedirectUris: [REGISTERED],
							}
						: null,
				);

			it("is the azp's when the hint names one among its audiences", async () => {
				const findById = onlyClient1();
				const { app, endSession } = buildWithUpstream({
					clientRepo: makeClientRepo({ findById }),
				});

				await postLogout(app, {
					id_token_hint: await mintIdToken({ aud: ["other-client", "client-1"], azp: "client-1" }),
					post_logout_redirect_uri: REGISTERED,
				});

				expect(findById).toHaveBeenCalledWith("client-1");
				expect(endSession).toHaveBeenCalledWith(
					expect.objectContaining({ postLogoutRedirectUri: REGISTERED }),
				);
			});

			it("is nobody's for several audiences and no azp: the URI is dropped", async () => {
				const findById = onlyClient1();
				const { app, endSession } = buildWithUpstream({
					clientRepo: makeClientRepo({ findById }),
				});

				await postLogout(app, {
					id_token_hint: await mintIdToken({ aud: ["client-1", "other-client"] }),
					post_logout_redirect_uri: REGISTERED,
				});

				expect(findById).not.toHaveBeenCalled();
				expect(endSession).toHaveBeenCalledWith(
					expect.objectContaining({ postLogoutRedirectUri: undefined }),
				);
			});

			it("is the one audience's, as a string or a one-element list", async () => {
				for (const aud of ["client-1", ["client-1"]]) {
					const findById = onlyClient1();
					const { app, endSession } = buildWithUpstream({
						clientRepo: makeClientRepo({ findById }),
					});

					await postLogout(app, {
						id_token_hint: await mintIdToken({ aud }),
						post_logout_redirect_uri: REGISTERED,
					});

					expect(findById, JSON.stringify(aud)).toHaveBeenCalledWith("client-1");
					expect(endSession).toHaveBeenCalledWith(
						expect.objectContaining({ postLogoutRedirectUri: REGISTERED }),
					);
				}
			});

			it("is the one audience's when azp names a client outside it", async () => {
				const findById = onlyClient1();
				const { app, endSession } = buildWithUpstream({
					clientRepo: makeClientRepo({ findById }),
				});

				await postLogout(app, {
					id_token_hint: await mintIdToken({ aud: "client-1", azp: "other-client" }),
					post_logout_redirect_uri: REGISTERED,
				});

				expect(findById).toHaveBeenCalledWith("client-1");
				expect(findById).not.toHaveBeenCalledWith("other-client");
				expect(endSession).toHaveBeenCalledWith(
					expect.objectContaining({ postLogoutRedirectUri: REGISTERED }),
				);
			});
		});
	});

	describe("id_token_hint missing entirely", () => {
		it("returns 400 invalid_request", async () => {
			const app = buildApp();

			const res = await postLogout(app, {});

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
		});
	});

	describe("userSessionStore.get throws (fail-closed)", () => {
		it("returns 503 temporarily_unavailable when userSessionStore.get throws", async () => {
			const throwingStore = makeSessionStore({
				get: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildApp({ sessionStore: throwingStore });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
		});

		it("logs it once, at error level, as logout_store_unavailable", async () => {
			const logger = createMockLogger();
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockRejectedValue(storeReplyError()) }),
				logger,
			});
			const res = await postLogout(app, { id_token_hint: await mintIdToken() });
			expect(res.status).toBe(503);
			expectOutageLine(logger, "logout_store_unavailable", { store: "user_session", step: "get" });
		});
	});

	describe("Cache-Control / Pragma headers", () => {
		it("200 JSON success path sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildApp();
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("503 on a close that cannot commit sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildApp({ sessionLifecycle: closing(outsideAnswer<never>()) });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(503);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("400 invalid id_token_hint sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildApp();

			const res = await postLogout(app, { id_token_hint: "not.a.valid.jwt" });

			expect(res.status).toBe(400);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("200 HTML front-channel response sets Cache-Control: no-store and Pragma: no-cache", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

			expect(res.status).toBe(200);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});
	});

	describe("q-weighted Accept header content negotiation", () => {
		it("application/json > text/html returns JSON (not HTML)", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps });
			const token = await mintIdToken();

			const res = await postLogout(
				app,
				{ id_token_hint: token },
				{ Accept: "application/json, text/html;q=0.1" },
			);

			expect(res.headers["content-type"]).toMatch(/json/);
			expect(res.body.logged_out).toBe(true);
		});

		it("Accept: */* falls back to JSON (not HTML)", async () => {
			const rpData = [
				{
					clientId: "rp-1",
					frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
					registeredAt: new Date(),
					backchannelLogoutUri: undefined,
					backchannelLogoutSessionRequired: undefined,
					frontchannelLogoutSessionRequired: undefined,
				},
			];
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedRps = rpData;
			const app = buildApp({ sessionStore, joinedRps });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token }, { Accept: "*/*" });

			expect(res.headers["content-type"]).toMatch(/json/);
			expect(res.body.logged_out).toBe(true);
		});
	});

	describe("logger routing for handler-level warnings", () => {
		it("routes federation endSession failure warning to opts.logger (not console)", async () => {
			const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) });
			const joinedFederations = ["google"];
			const throwingProvider: FederationProvider & {
				endSession: () => Promise<never>;
			} = {
				...federationBase("google"),
				endSession: vi.fn().mockRejectedValue(new Error("IdP down")),
			};
			const logger = createMockLogger();
			const warnSpy = logger.warn;
			const app = buildApp({
				sessionStore,
				joinedFederations,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", throwingProvider]]),
				logger,
			});
			const token = await mintIdToken();

			const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const res = await postLogout(app, { id_token_hint: token });
				// Logout still succeeds (best-effort federation end-session)
				expect(res.status).toBe(200);
				expect(warnSpy).toHaveBeenCalled();
				expect(consoleWarnSpy).not.toHaveBeenCalled();
				expectBestEffortWarn(
					logger,
					"logout_federation_end_session_failed",
					{ federation: "google" },
					"Error",
				);
			} finally {
				consoleWarnSpy.mockRestore();
			}
		});
	});
});

describe("GET /oauth/logout", () => {
	it("logs out and redirects to a registered post_logout_redirect_uri with state", async () => {
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const fedTokenStore = makeFedTokenStore();
		const app = buildApp({
			sessionStore,
			refreshFamilyRevocation,
			fedTokenStore,
			clientRepo: makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: ["https://example.test/cb"],
					allowedScopes: ["openid"],
					postLogoutRedirectUris: ["https://rp.example/logged-out"],
				}),
			}),
		});
		const token = await mintIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "bye",
		});

		expect(res.status).toBe(303);
		expect(res.headers.location).toBe("https://rp.example/logged-out?state=bye");
		expect(refreshFamilyRevocation.revokeFamily).toHaveBeenCalledWith("fam-1");
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(fedTokenStore.removeBySid).toHaveBeenCalledWith("sid-1");
	});

	it("appends to a post-logout redirect only names checkRedirectUri refuses in a registered query", async () => {
		const app = buildApp({
			clientRepo: makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: ["https://example.test/cb"],
					allowedScopes: ["openid"],
					postLogoutRedirectUris: ["https://rp.example/logged-out"],
				}),
			}),
		});

		const res = await getLogout(app, {
			id_token_hint: await mintIdToken(),
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "bye",
		});

		expect(res.status).toBe(303);
		const appended = [...new URL(res.headers.location as string).searchParams.keys()];
		expect(appended).toContain("state");
		for (const name of appended) {
			expect(checkRedirectUri(`https://rp.example/logged-out?${name}=x`), name).toEqual({
				reason: "reserved-parameter",
				parameter: name,
			});
		}
	});

	it("returns 400 invalid_request when id_token_hint is missing (no hint to pass through)", async () => {
		// With no id_token_hint, a confirmation page would render a "Sign out"
		// button whose POST cannot satisfy the hint requirement, so reject
		// directly rather than show a confirmation that always fails.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });

		const res = await getLogout(app, {
			post_logout_redirect_uri: "https://rp.example/logged-out",
		});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("returns 400 invalid_token when id_token_hint signature is invalid (no confirm page)", async () => {
		// Invalid-signature / iss / typ id_token_hint: the POST verifier uses
		// identical options to GET, so passing the same hint through hidden
		// inputs would render a "Sign out" button that the confirmed POST
		// can only re-fail with 400 invalid_token. Reject directly for GET
		// as well as POST.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });

		const res = await getLogout(app, { id_token_hint: "not.a.valid.jwt" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_token");
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("renders confirmation HTML and does not log out when id_token_hint iat is stale", async () => {
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		// Allowlist the redirect URI we will pass — exercises the round-trip
		// path and confirms the value reaches the hidden input.
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://rp.example/logged-out"],
			}),
		});
		const app = buildApp({ sessionStore, refreshFamilyRevocation, clientRepo });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "xyz",
		});

		expectLogoutConfirmation(res);
		// All three params must round-trip into the form so a confirmed POST
		// completes the standard hint-based logout (verification on POST has
		// no staleness check, so the same hint will succeed there).
		expect(res.text).toContain(`value="${token}"`);
		expect(res.text).toContain('name="id_token_hint"');
		expect(res.text).toContain('name="post_logout_redirect_uri"');
		expect(res.text).toContain('value="https://rp.example/logged-out"');
		expect(res.text).toContain('name="state"');
		expect(res.text).toContain('value="xyz"');
		expect(refreshFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("drops post_logout_redirect_uri from the stale-iat confirm page when not allowlisted", async () => {
		// Even though the post-cascade allowlist gate prevents an actual
		// redirect to an attacker URL, reflecting the URL into the confirm
		// page on the auth-provider origin weakens the invariant. Only
		// allowlisted URIs round-trip into the form.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://rp.example/logged-out"],
			}),
		});
		const app = buildApp({ sessionStore, refreshFamilyRevocation, clientRepo });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://attacker.example/steal",
			state: "xyz",
		});

		expectLogoutConfirmation(res);
		expect(res.text).not.toContain("attacker.example");
		expect(res.text).not.toContain('name="post_logout_redirect_uri"');
		// The hint and state must still round-trip — only the redirect URI
		// is dropped.
		expect(res.text).toContain('name="id_token_hint"');
		expect(res.text).toContain('name="state"');
	});

	it("renders a stale-iat confirm page without the URI when the client repository cannot answer", async () => {
		// The page may carry the URI only once it is known to be registered;
		// an outage leaves it unknown, so the page goes without it, as a logout
		// that named none would.
		const logger = createMockLogger();
		const sessionStore = makeSessionStore();
		const clientRepo = makeClientRepo({ findById: vi.fn().mockRejectedValue(storeReplyError()) });
		const app = buildApp({ sessionStore, clientRepo, logger });

		const res = await getLogout(app, {
			id_token_hint: await mintOldIdToken(),
			post_logout_redirect_uri: "https://rp.example/logged-out",
			state: "xyz",
		});

		expectLogoutConfirmation(res);
		expect(res.text).not.toContain('name="post_logout_redirect_uri"');
		expect(res.text).toContain('name="state"');
		expectOutageLine(logger, "client_repository_unavailable", {
			site: "logout",
			step: "find",
			clientId: "client-1",
		});
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("HTML-escapes hidden input values to prevent attribute injection", async () => {
		// state may carry attacker-influenced characters in the worst case;
		// the GET-confirm path echoes it into an HTML attribute so it must
		// be escaped (an unescaped `"` would break out of the value attr).
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			state: 'evil"><script>alert(1)</script>',
		});

		expectLogoutConfirmation(res);
		expect(res.text).not.toContain('"><script>');
		expect(res.text).toContain("&quot;");
	});

	it("HTML-escapes ampersands in hidden input values (& → &amp;)", async () => {
		// The previous test covers only the `"` escape. State values commonly
		// contain `&` in query-encoded round-tripping, so the entity escape
		// gets its own case.
		const sessionStore = makeSessionStore();
		const refreshFamilyRevocation = makeFamilyRevocation();
		const app = buildApp({ sessionStore, refreshFamilyRevocation });
		const token = await mintOldIdToken();

		const res = await getLogout(app, {
			id_token_hint: token,
			state: "a&b=1",
		});

		expectLogoutConfirmation(res);
		expect(res.text).toContain("a&amp;b=1");
		// Raw `a&b=1` must NOT appear unescaped — a regex-bounded check
		// avoids matching the escaped form's substring.
		expect(res.text).not.toMatch(/value="a&b=1"/);
	});

	// `postLogoutRedirectUris` accepts RFC 8252 §7.1 reverse-domain custom
	// schemes, so a native app can be sent back to itself after logout. The
	// allowlist stays an EXACT match, and the value is never rendered into
	// HTML unescaped.
	describe("custom-scheme post_logout_redirect_uri", () => {
		const NATIVE_URI = "com.example.app:/signout";

		const nativeClientRepo = () =>
			makeClientRepo({
				findById: vi.fn().mockResolvedValue({
					clientId: "client-1",
					tokenEndpointAuthMethod: "none",
					allowedRedirectUris: [NATIVE_URI],
					allowedScopes: ["openid"],
					postLogoutRedirectUris: [NATIVE_URI],
				}),
			});

		it("redirects to a registered custom-scheme target, with state", async () => {
			const sessionStore = makeSessionStore();
			const app = buildApp({ sessionStore, clientRepo: nativeClientRepo() });

			const res = await getLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: NATIVE_URI,
				state: "bye",
			});

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe("com.example.app:/signout?state=bye");
			expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		});

		it("redirects to a registered custom-scheme target with no state", async () => {
			// No `state` means the value is emitted without a query, so this
			// catches a serializer that would mangle the opaque form.
			const app = buildApp({ clientRepo: nativeClientRepo() });

			const res = await getLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: NATIVE_URI,
			});

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe("com.example.app:/signout");
		});

		it("matches the allowlist exactly — a different path on the same scheme is refused", async () => {
			// The comparison is string equality, and stays so for custom
			// schemes: nothing about `com.example.app:` makes a sibling path
			// the same target.
			const app = buildApp({ clientRepo: nativeClientRepo() });

			const res = await getLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: "com.example.app:/signout/../elsewhere",
			});

			expect(res.status).toBe(200);
			expect(res.headers.location).toBeUndefined();
			// The JSON fallback, which a native app is spared only when the
			// target IS registered.
			expect(res.body).toEqual({ logged_out: true });
		});

		it("refuses an unregistered app's scheme", async () => {
			const app = buildApp({ clientRepo: nativeClientRepo() });

			const res = await getLogout(app, {
				id_token_hint: await mintIdToken(),
				post_logout_redirect_uri: "com.attacker.app:/steal",
			});

			expect(res.status).toBe(200);
			expect(res.headers.location).toBeUndefined();
		});

		it("escapes the custom-scheme URI in the stale-iat confirmation page", async () => {
			// The confirm page echoes the allowlisted value into an HTML
			// attribute; a custom scheme must go through the same escape as
			// every other value there.
			const app = buildApp({ clientRepo: nativeClientRepo() });

			const res = await getLogout(app, {
				id_token_hint: await mintOldIdToken(),
				post_logout_redirect_uri: NATIVE_URI,
			});

			expectLogoutConfirmation(res);
			expect(res.text).toContain('name="post_logout_redirect_uri"');
			expect(res.text).toContain(`value="${NATIVE_URI}"`);
			expect(res.text).not.toMatch(/<script>/);
		});
	});
});

// ---------------------------------------------------------------------------
// POST /oauth/federation/:name/logout
// ---------------------------------------------------------------------------

/** Session that has google linked (no derived fields) */
const sessionWithGoogle: UserSession = { ...baseSession };
const googleFederations = ["google"];

function buildFedLogoutApp(opts: BuildAppOpts = {}) {
	return buildApp({
		sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(sessionWithGoogle) }),
		joinedFederations: googleFederations,
		...opts,
	});
}

async function postFedLogout(
	app: ReturnType<typeof express>,
	name: string,
	token: string,
	body: Record<string, string> = {},
	headers: Record<string, string> = {},
) {
	const req = request(app)
		.post(`/oauth/federation/${name}/logout`)
		.type("form")
		.set("Authorization", `Bearer ${token}`);
	for (const [k, v] of Object.entries(headers)) {
		req.set(k, v);
	}
	return req.send(body);
}

describe("POST /oauth/federation/:name/logout", () => {
	describe("happy path WITH endSession capability", () => {
		it("returns 303 redirect to provider end-session URL", async () => {
			const endSessionUrl = new URL("https://accounts.google.com/o/oauth2/revoke?token=id-hint");
			const mockProvider: FederationProvider & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				...federationBase("google"),
				endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
			};
			const app = buildFedLogoutApp({
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", mockProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(303);
			expect(res.headers.location).toContain("accounts.google.com");
			expect(mockProvider.endSession).toHaveBeenCalledOnce();
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	// The same rule as RP-initiated logout, for the client the access token
	// was issued to (`azp`): the upstream is handed the caller's
	// post_logout_redirect_uri only once that client has registered it.
	describe("the post_logout_redirect_uri the upstream end-session call is handed", () => {
		const REGISTERED = "https://rp.example/logged-out";

		function buildWithUpstream(opts: BuildAppOpts = {}) {
			const endSession = vi.fn().mockResolvedValue({
				url: new URL("https://accounts.google.com/Logout"),
				method: "GET",
			});
			const provider = { ...federationBase("google"), endSession } as unknown as FederationProvider;
			const fedTokenStore = makeFedTokenStore({ delete: vi.fn().mockResolvedValue(undefined) });
			const app = buildFedLogoutApp({
				fedTokenStore,
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				clientRepo: makeClientRepo({
					findById: vi.fn().mockResolvedValue({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						postLogoutRedirectUris: [REGISTERED],
					}),
				}),
				...opts,
			});
			return { app, endSession, fedTokenStore };
		}

		it("is none when the token's client has not registered it", async () => {
			const { app, endSession } = buildWithUpstream();

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
				{
					post_logout_redirect_uri: "https://evil.example/landing",
					state: "s-1",
				},
			);

			expect(res.status).toBe(303);
			expect(endSession).toHaveBeenCalledOnce();
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("is none when the token's client is not known", async () => {
			const { app, endSession } = buildWithUpstream({
				clientRepo: makeClientRepo({ findById: vi.fn().mockResolvedValue(null) }),
			});

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
				{
					post_logout_redirect_uri: REGISTERED,
				},
			);

			expect(res.status).toBe(303);
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("asks the client repository nothing when the request names no post_logout_redirect_uri", async () => {
			const findById = vi.fn().mockRejectedValue(storeReplyError());
			const { app, endSession } = buildWithUpstream({ clientRepo: makeClientRepo({ findById }) });

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
			);

			expect(res.status).toBe(303);
			expect(findById).not.toHaveBeenCalled();
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("is none when the token names no client", async () => {
			const findById = vi.fn();
			const { app, endSession } = buildWithUpstream({ clientRepo: makeClientRepo({ findById }) });

			await postFedLogout(app, "google", await mintAccessToken(), {
				post_logout_redirect_uri: REGISTERED,
			});

			expect(findById).not.toHaveBeenCalled();
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
		});

		it("is the registered one when it matches exactly", async () => {
			const { app, endSession } = buildWithUpstream();

			await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
				{
					post_logout_redirect_uri: REGISTERED,
					state: "s-1",
				},
			);

			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: REGISTERED, state: "s-1" }),
			);
		});

		it("disconnects without the redirect when the client repository cannot answer", async () => {
			const logger = createMockLogger();
			const { app, endSession, fedTokenStore } = buildWithUpstream({
				clientRepo: makeClientRepo({ findById: vi.fn().mockRejectedValue(storeReplyError()) }),
				logger,
			});

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
				{
					post_logout_redirect_uri: REGISTERED,
				},
			);

			expect(res.status).toBe(303);
			expect(res.headers.location).toBe("https://accounts.google.com/Logout");
			expect(endSession).toHaveBeenCalledWith(
				expect.objectContaining({ postLogoutRedirectUri: undefined }),
			);
			expectOutageLine(logger, "client_repository_unavailable", {
				site: "federation_logout",
				step: "find",
				clientId: "client-1",
			});
			expect(fedTokenStore.delete).toHaveBeenCalledWith("sid-1", "google");
		});

		// The same gap on this route: an entry a custom ClientRepository holds
		// that `checkRedirectUri` would refuse is not handed to the adapter.
		it.each([
			["one the URL parser cannot read", "::not a url", "unparsable"],
			["one in an executable scheme", "javascript:alert(document.domain)", "executable-scheme"],
			[
				"one whose query carries a response parameter",
				"https://rp.example/bye?state=registered",
				"reserved-parameter",
			],
		] as const)(
			"is none for a registered entry this server would not redirect to: %s",
			async (_label, entry, reason) => {
				const logger = createMockLogger();
				const { app, endSession, fedTokenStore } = buildWithUpstream({
					clientRepo: makeClientRepo({
						findById: vi.fn().mockResolvedValue({
							clientId: "client-1",
							allowedRedirectUris: [],
							allowedScopes: [],
							postLogoutRedirectUris: [entry],
						}),
					}),
					logger,
				});

				const res = await postFedLogout(
					app,
					"google",
					await mintAccessToken({ azp: "client-1", aud: "client-1" }),
					{
						post_logout_redirect_uri: entry,
					},
				);

				expect(res.status).toBe(303);
				expect(res.headers.location).toBe("https://accounts.google.com/Logout");
				expect(endSession).toHaveBeenCalledWith(
					expect.objectContaining({ postLogoutRedirectUri: undefined }),
				);
				expect(fedTokenStore.delete).toHaveBeenCalledWith("sid-1", "google");
				expectBestEffortWarn(
					logger,
					"logout_registered_redirect_uri_refused",
					{ site: "federation_logout", clientId: "client-1", reason },
					null,
				);
				expect(logger.error).not.toHaveBeenCalled();
			},
		);
	});

	describe("a POST that carries no body", () => {
		it("is a disconnect that names no post_logout_redirect_uri, not a 500", async () => {
			// No Content-Type, no body: the form parser leaves `req.body` unset.
			const app = buildFedLogoutApp();

			const res = await request(app)
				.post("/oauth/federation/google/logout")
				.set("Authorization", `Bearer ${await mintAccessToken()}`);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});
	});

	// A token that names its client (`azp`) must have been issued for that
	// client itself: its `aud` must contain the same id.
	describe("the audience of a token that names its client", () => {
		const RESOURCE = "https://rs.example/api";

		it("refuses a token issued for a resource server, and disconnects nothing", async () => {
			const fedTokenStore = makeFedTokenStore({ delete: vi.fn().mockResolvedValue(undefined) });
			const logger = createMockLogger();
			const app = buildFedLogoutApp({ fedTokenStore, logger });

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: RESOURCE }),
			);

			expect(res.status).toBe(401);
			expect(res.body).toEqual({ error: "invalid_token", error_description: "invalid token" });
			expect(res.headers["www-authenticate"]).toBe(
				'Bearer error="invalid_token", error_description="invalid token"',
			);
			expect(fedTokenStore.get).not.toHaveBeenCalled();
			expect(fedTokenStore.delete).not.toHaveBeenCalled();
			expect(logger.warn).toHaveBeenCalledWith(
				{ federation: "google", reason: "aud" },
				"federation_logout_jwt_verify_failed",
			);
		});

		it("refuses a token that names its client and no audience", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: undefined }),
			);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});

		it("disconnects with a token whose audience is its own client", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: "client-1" }),
			);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});

		it("disconnects with a token whose several audiences include its own client", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: [RESOURCE, "client-1"] }),
			);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});

		/** `token` with its payload's claims changed after signing, its signature kept. */
		const withClaimsChanged = (token: string, change: Record<string, unknown>): string => {
			const [header, payload, signature] = token.split(".");
			const claims = JSON.parse(Buffer.from(payload ?? "", "base64url").toString("utf8"));
			const changed = Buffer.from(JSON.stringify({ ...claims, ...change })).toString("base64url");
			return `${header}.${changed}.${signature}`;
		};

		it("refuses a token whose several audiences exclude its client, and disconnects nothing", async () => {
			const fedTokenStore = makeFedTokenStore({ delete: vi.fn().mockResolvedValue(undefined) });
			const app = buildFedLogoutApp({ fedTokenStore });

			const res = await postFedLogout(
				app,
				"google",
				await mintAccessToken({ azp: "client-1", aud: [RESOURCE, "client-2"] }),
			);

			expect(res.status).toBe(401);
			expect(res.body).toEqual({ error: "invalid_token", error_description: "invalid token" });
			expect(fedTokenStore.delete).not.toHaveBeenCalled();
		});

		it("refuses a token whose azp was changed after signing to the client its aud names", async () => {
			const fedTokenStore = makeFedTokenStore({ delete: vi.fn().mockResolvedValue(undefined) });
			const logger = createMockLogger();
			const app = buildFedLogoutApp({ fedTokenStore, logger });
			const token = withClaimsChanged(await mintAccessToken({ azp: "client-2", aud: "client-1" }), {
				azp: "client-1",
			});

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body).toEqual({ error: "invalid_token", error_description: "invalid token" });
			expect(logger.warn).toHaveBeenCalledWith(
				{ federation: "google", reason: "signature" },
				"federation_logout_jwt_verify_failed",
			);
			expect(fedTokenStore.delete).not.toHaveBeenCalled();
		});

		it("refuses a token that names no client once its azp is changed after signing", async () => {
			const fedTokenStore = makeFedTokenStore({ delete: vi.fn().mockResolvedValue(undefined) });
			const app = buildFedLogoutApp({ fedTokenStore });
			const token = withClaimsChanged(await mintAccessToken({ azp: "client-1", aud: RESOURCE }), {
				azp: undefined,
			});

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
			expect(fedTokenStore.delete).not.toHaveBeenCalled();
		});

		// An `azp` that is not a non-empty string names no client to pin to: the
		// token is answered as one with no `azp`, its audience unchecked (the
		// route's rule for a token that names no client).
		it.each([
			["a number", 123],
			["an array naming the client", ["client-1"]],
			["an empty string", ""],
		])("answers a token whose azp is %s as one that names no client", async (_label, azp) => {
			const logger = createMockLogger();
			const app = buildFedLogoutApp({ logger });

			const res = await postFedLogout(app, "google", await mintAccessToken({ azp, aud: RESOURCE }));

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
			expect(logger.warn.mock.calls.map(([, event]) => event)).toContain("jwt_verify_aud_skipped");
		});

		it("checks the audience, so the verifier logs no jwt_verify_aud_skipped", async () => {
			for (const aud of ["client-1", RESOURCE]) {
				// A fresh logger each time: the verifier logs the gap once per logger.
				const logger = createMockLogger();
				const app = buildFedLogoutApp({ logger });

				await postFedLogout(app, "google", await mintAccessToken({ azp: "client-1", aud }));

				const events = [...logger.warn.mock.calls, ...logger.info.mock.calls].map(
					([, event]) => event,
				);
				expect(events, aud).not.toContain("jwt_verify_aud_skipped");
			}
		});

		it("still disconnects with a token that names no client, its audience unchecked", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(app, "google", await mintAccessToken({ aud: RESOURCE }));

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});
	});

	describe("happy path WITHOUT endSession capability", () => {
		it("returns 200 JSON { disconnected: true } when provider has no endSession method", async () => {
			const bareProvider = federationBase("github");
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
				joinedFederations: ["github"],
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["github", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("missing Authorization header", () => {
		it("returns 401 invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("wrong token type (rt+jwt)", () => {
		it("returns 401 invalid_token when typ is not at+jwt", async () => {
			const refreshToken = await new SignJWT({ sub: "u-1", sid: "sid-1", family_id: "fam-1" })
				.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
				.setExpirationTime("1h")
				.setIssuedAt()
				.sign(secretKey);
			const app = buildFedLogoutApp();

			const res = await postFedLogout(app, "google", refreshToken);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("invalid signature", () => {
		it("returns 401 invalid_token", async () => {
			const app = buildFedLogoutApp();

			const res = await postFedLogout(app, "google", "not.a.valid.jwt");

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("family revoked", () => {
		it("returns 401 invalid_token when isFamilyRevoked returns true", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
			});
			const app = buildFedLogoutApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("session null", () => {
		it("returns 401 invalid_token when session is not found", async () => {
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(null) }),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_token");
		});
	});

	describe("federation not linked", () => {
		it("returns 404 federation_not_linked when federation is absent from session", async () => {
			// sessionWithGoogle only has google, so 'github' is not linked
			const app = buildFedLogoutApp();
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(404);
			expect(res.body.error).toBe("federation_not_linked");
			expect(res.body.error_description).toBe("federation 'github' is not linked to this session");
		});

		it("quotes the requested name within RFC 6749's characters", async () => {
			// The name is the client's path segment: `'` for the quotes, `?` for
			// any character Appendix A.8 does not allow.
			const app = buildFedLogoutApp();
			const token = await mintAccessToken();

			const res = await postFedLogout(app, encodeURIComponent('git"h\\ub\u00e9'), token);

			expect(res.status).toBe(404);
			expect(res.body.error_description).toBe(
				"federation 'git?h?ub?' is not linked to this session",
			);
		});
	});

	describe("federationTokenStore.delete throws", () => {
		it("returns 503 when delete fails after local state was partially cleared", async () => {
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildFedLogoutApp({ fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
			expect(res.headers["cache-control"]).toBe("no-store");
		});
	});

	describe("provider.endSession throws (soft-fail)", () => {
		it("returns 200 { disconnected: true } when endSession throws (local state already cleared)", async () => {
			const throwingProvider: FederationProvider & {
				endSession: () => Promise<never>;
			} = {
				...federationBase("google"),
				endSession: vi.fn().mockRejectedValue(new Error("IdP unreachable")),
			};
			const app = buildFedLogoutApp({
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", throwingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			// Local state cleared before endSession call; soft-fail returns 200
			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
			expect(res.headers["cache-control"]).toBe("no-store");
		});

		it("logs the orphan IdP session once, structured, with the error's projection", async () => {
			const provider = {
				...federationBase("google"),
				endSession: vi.fn().mockRejectedValue(new Error("IdP unreachable")),
			} as unknown as FederationProvider;
			const logger = createMockLogger();
			const app = buildFedLogoutApp({
				getFederationProviders: () => new Map<string, FederationProvider>([["google", provider]]),
				logger,
			});

			const res = await postFedLogout(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expectBestEffortWarn(
				logger,
				"federation_logout_end_session_failed",
				{ federation: "google" },
				"Error",
			);
		});
	});

	describe("a refused access token is logged by the verifier's reason", () => {
		it("logs the reason alone, nothing the token carries", async () => {
			const logger = createMockLogger();
			const res = await postFedLogout(
				buildFedLogoutApp({ logger }),
				"google",
				await mintTypMarkerToken(),
			);
			expect(res.status).toBe(401);
			const line = expectBestEffortWarn(
				logger,
				"federation_logout_jwt_verify_failed",
				{ federation: "google" },
				null,
			);
			expect(line).toEqual({ federation: "google", reason: "typ" });
		});
	});

	describe("getFederationProviders returns undefined (no federation configured)", () => {
		it("returns 200 { disconnected: true } when providers map is undefined", async () => {
			const app = buildFedLogoutApp({ getFederationProviders: () => undefined });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ disconnected: true });
		});
	});

	describe("WWW-Authenticate header on 401 paths", () => {
		it("missing Authorization header returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("invalid signature returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildFedLogoutApp();
			const res = await postFedLogout(app, "google", "not.a.valid.jwt");

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("family revoked returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
			});
			const app = buildFedLogoutApp({ refreshFamilyRevocation });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});

		it("session not found returns WWW-Authenticate: Bearer error=invalid_token", async () => {
			const app = buildApp({
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(null) }),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/Bearer/);
			expect(res.headers["www-authenticate"]).toMatch(/error="invalid_token"/);
		});
	});

	describe("Cache-Control / Pragma headers", () => {
		it("401 missing Bearer sets both Cache-Control: no-store and Pragma: no-cache", async () => {
			const app = buildFedLogoutApp();
			const res = await request(app).post("/oauth/federation/google/logout").type("form").send({});

			expect(res.status).toBe(401);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});

		it("503 federationTokenStore.delete throw sets both Cache-Control: no-store and Pragma: no-cache", async () => {
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("redis down")),
			});
			const app = buildFedLogoutApp({ fedTokenStore });
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(503);
			expect(res.headers["cache-control"]).toBe("no-store");
			expect(res.headers.pragma).toBe("no-cache");
		});
	});

	describe("every store failure it logs reaches the logger as a projection, never as the error", () => {
		it("the family revocation check", async () => {
			const logger = createMockLogger();
			const refreshFamilyRevocation = makeFamilyRevocation({
				isFamilyRevoked: vi.fn().mockRejectedValue(storeReplyError()),
			});
			const res = await postFedLogout(
				buildFedLogoutApp({ refreshFamilyRevocation, logger }),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expect(res.body.error_description).toBe("refresh token store unavailable");
			// An outage line like every other: error level, object-first, the
			// store error's projection and never the error.
			expect(logger.error).toHaveBeenCalledWith(
				{
					federation: "google",
					store: "refresh_token_family",
					err: expect.objectContaining({ name: "ReplyError" }),
				},
				"federation_logout_store_unavailable",
			);
			const line = logger.error.mock.calls.find(
				([, event]) => event === "federation_logout_store_unavailable",
			);
			expect(line?.[0].err).not.toBeInstanceOf(Error);
			expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
		});

		for (const [label, raw] of [
			["a control character", "goo\u0007gle"],
			["more than 200 characters", "g".repeat(300)],
		] as const) {
			it(`records a federation name carrying ${label} sanitised and capped`, async () => {
				const logger = createMockLogger();
				const res = await postFedLogout(
					buildFedLogoutApp({
						sessionLifecycle: rejecting("liveness", storeReplyError()),
						logger,
					}),
					encodeURIComponent(raw),
					await mintAccessToken(),
				);
				expect(res.status).toBe(503);
				const line = expectOutageLine(logger, "federation_logout_store_unavailable", {
					store: "session_lifecycle",
				});
				const logged = String(line.federation);
				expect(logged.length).toBeLessThanOrEqual(200);
				// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
				expect(logged).not.toMatch(/[\u0000-\u001f\u007f]/);
			});
		}

		for (const step of ["liveness", "federations"] as const) {
			it(`the session lifecycle's ${step} read`, async () => {
				const logger = createMockLogger();
				const res = await postFedLogout(
					buildFedLogoutApp({ sessionLifecycle: rejecting(step, storeReplyError()), logger }),
					"google",
					await mintAccessToken(),
				);
				expect(res.status).toBe(503);
				expectOutageLine(logger, "federation_logout_store_unavailable", {
					federation: "google",
					store: "session_lifecycle",
					step,
				});
			});
		}

		it("the token store's read", async () => {
			const logger = createMockLogger();
			const res = await postFedLogout(
				buildFedLogoutApp({
					fedTokenStore: makeFedTokenStore({ get: vi.fn().mockRejectedValue(storeReplyError()) }),
					logger,
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expectOutageLine(logger, "federation_logout_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "get",
			});
		});

		it("the token store's delete", async () => {
			const logger = createMockLogger();
			const res = await postFedLogout(
				buildFedLogoutApp({
					fedTokenStore: makeFedTokenStore({
						delete: vi.fn().mockRejectedValue(storeReplyError()),
					}),
					logger,
				}),
				"google",
				await mintAccessToken(),
			);
			expect(res.status).toBe(503);
			expectOutageLine(logger, "federation_logout_store_unavailable", {
				federation: "google",
				store: "federation_token",
				step: "delete",
			});
		});
	});

	describe("logger routing", () => {
		it("routes /federation/:name/logout failures to opts.logger (not console)", async () => {
			const logger = createMockLogger();
			const warnSpy = logger.warn;
			const fedTokenStore = makeFedTokenStore({
				delete: vi.fn().mockRejectedValue(new Error("boom")),
			});
			const app = buildFedLogoutApp({ fedTokenStore, logger });
			const token = await mintAccessToken();

			const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			try {
				const res = await postFedLogout(app, "google", token);
				expect(res.status).toBe(503);
				expect(warnSpy).toHaveBeenCalled();
				expect(consoleWarnSpy).not.toHaveBeenCalled();
			} finally {
				consoleWarnSpy.mockRestore();
			}
		});
	});
});

// ---------------------------------------------------------------------------
// Audit event observability
// ---------------------------------------------------------------------------

describe("audit events", () => {
	describe("federation.logout.idp_unreachable", () => {
		it("emits when provider.endSession throws (orphan IdP session)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const throwingProvider: FederationProvider & { endSession: () => Promise<never> } = {
				...federationBase("google"),
				endSession: vi.fn().mockRejectedValue(new Error("IdP down")),
			};
			const app = buildFedLogoutApp({
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", throwingProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.idp_unreachable",
					details: { federation: "google", cause: { name: "Error" } },
				}),
			);
		});

		it("keeps the IdP's own words out of the event", async () => {
			// An IdP's refusal, as its client library carries it: the upstream's
			// description and the body it answered with, in the message too.
			const leaked = "id-token-hint-SECRET";
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const refusal = Object.assign(
				new Error(`server responded with an error in the response body: {"hint":"${leaked}"}`),
				{
					name: "ResponseBodyError",
					code: "OAUTH_RESPONSE_BODY_ERROR",
					error: "invalid_request",
					error_description: `id_token_hint ${leaked} is not valid`,
				},
			);
			const throwingProvider: FederationProvider & { endSession: () => Promise<never> } = {
				...federationBase("google"),
				endSession: vi.fn().mockRejectedValue(refusal),
			};
			const app = buildFedLogoutApp({
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", throwingProvider]]),
			});

			const res = await postFedLogout(app, "google", await mintAccessToken());

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.idp_unreachable",
					details: {
						federation: "google",
						cause: { name: "ResponseBodyError", code: "OAUTH_RESPONSE_BODY_ERROR" },
					},
				}),
			);
			expect(JSON.stringify(vi.mocked(auditSink.record).mock.calls)).not.toContain(leaked);
		});
	});

	describe("federation.logout.success", () => {
		it("emits with redirected_to_idp: true when endSession succeeds (303 path)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const endSessionUrl = new URL("https://accounts.google.com/logout");
			const mockProvider: FederationProvider & {
				endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
			} = {
				...federationBase("google"),
				endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
			};
			const app = buildFedLogoutApp({
				auditSink,
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["google", mockProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "google", token);

			expect(res.status).toBe(303);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.success",
					details: expect.objectContaining({ federation: "google", redirected_to_idp: true }),
				}),
			);
		});

		it("emits with redirected_to_idp: false when provider has no endSession (200 path)", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const bareProvider = federationBase("github");
			const app = buildApp({
				auditSink,
				sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
				joinedFederations: ["github"],
				getFederationProviders: () =>
					new Map<string, FederationProvider>([["github", bareProvider]]),
			});
			const token = await mintAccessToken();

			const res = await postFedLogout(app, "github", token);

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "federation.logout.success",
					details: expect.objectContaining({ federation: "github", redirected_to_idp: false }),
				}),
			);
		});

		for (const [label, raw] of [
			["a control character", "goo\u0007gle"],
			["more than 200 characters", "g".repeat(300)],
		] as const) {
			it(`audits a federation name carrying ${label} sanitised and capped`, async () => {
				// The linked-federation check compares the path's name with the
				// session's; what the audit event records is the log lines' form of it.
				const auditSink: AuditSink = {
					kind: "mock",
					record: vi.fn().mockResolvedValue(undefined),
				};
				const app = buildApp({
					auditSink,
					sessionStore: makeSessionStore({ get: vi.fn().mockResolvedValue(baseSession) }),
					joinedFederations: [raw],
					getFederationProviders: () => new Map<string, FederationProvider>(),
				});
				const res = await postFedLogout(app, encodeURIComponent(raw), await mintAccessToken());
				expect(res.status).toBe(200);
				const event = vi
					.mocked(auditSink.record)
					.mock.calls.map(([recorded]) => recorded)
					.find((recorded) => recorded.type === "federation.logout.success");
				const audited = String(event?.details?.federation);
				expect(audited.length).toBeLessThanOrEqual(200);
				// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
				expect(audited).not.toMatch(/[\u0000-\u001f\u007f]/);
			});
		}
	});

	describe("logout.success", () => {
		it("emits on POST /oauth/logout happy path", async () => {
			const auditSink: AuditSink = {
				kind: "mock",
				record: vi.fn().mockResolvedValue(undefined),
			};
			const app = buildApp({ auditSink });
			const token = await mintIdToken();

			const res = await postLogout(app, { id_token_hint: token });

			expect(res.status).toBe(200);
			expect(auditSink.record).toHaveBeenCalledWith(
				expect.objectContaining({
					type: "logout.success",
					details: expect.objectContaining({ sid: "sid-1" }),
				}),
			);
		});
	});
});

/**
 * `/oauth/logout` must end the browser session too. The close deletes the
 * `UserSession` record; a surviving express-session would keep satisfying
 * `req.session.isAuthenticated` at `/authorize`, minting codes carrying the
 * dead `sid` that `/token` refuses: a login loop for up to `session.maxAge`.
 *
 * Scoping is the substance of these tests: the destroy is owed to the browser
 * that OWNS the session being logged out, and to no other. An RP-initiated
 * logout arriving on some third party's cookie must leave that cookie alone.
 */
describe("POST /oauth/logout — browser session", () => {
	it("destroys the express-session whose sid is the one being logged out", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(browserSession.destroyed).toBe(true);
		expect(browserSession.isAuthenticated).toBe(false);
	});

	it("leaves a browser session belonging to a DIFFERENT sid untouched", async () => {
		// RP-initiated logout for someone else's session, arriving on this
		// browser's cookie. Destroying it would log out an unrelated user.
		const browserSession = makeBrowserSession({ sid: "sid-other" });
		const app = buildApp({ browserSession });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(browserSession.destroyed).toBe(false);
		expect(browserSession.isAuthenticated).toBe(true);
	});

	it("leaves a browser session that recorded no sid untouched", async () => {
		// Without a recorded `sid` there is no evidence this cookie belongs to
		// the session being logged out, so the conservative read wins.
		const browserSession = makeBrowserSession();
		const app = buildApp({ browserSession });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(browserSession.destroyed).toBe(false);
	});

	it("completes normally when no session middleware is mounted at all", async () => {
		// A back-channel-only deployment carries no cookie; the destroy must be
		// a no-op rather than a TypeError on `req.session`.
		const app = buildApp();
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
	});

	it("destroys on the front-channel HTML response branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const joinedRps = [
			{
				clientId: "client-1",
				frontchannelLogoutUri: "https://rp1.example.com/fc-logout",
				registeredAt: new Date(),
				backchannelLogoutUri: undefined,
				backchannelLogoutSessionRequired: undefined,
				frontchannelLogoutSessionRequired: undefined,
			},
		];
		const app = buildApp({ browserSession, joinedRps });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token }, { Accept: "text/html" });

		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toMatch(/text\/html/);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys on the IdP end-session 303 branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const mockProvider = {
			kind: "oidc",
			endSession: vi
				.fn()
				.mockResolvedValue({ url: new URL("https://idp.example/end"), method: "GET" }),
		} as unknown as FederationProvider;
		const joinedFederations = ["google"];
		const app = buildApp({
			browserSession,
			joinedFederations,
			getFederationProviders: () => new Map([["google", mockProvider]]),
		});
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(303);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys on the post_logout_redirect_uri 303 branch", async () => {
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const clientRepo = makeClientRepo({
			findById: vi.fn().mockResolvedValue({
				clientId: "client-1",
				allowedRedirectUris: [],
				allowedScopes: [],
				postLogoutRedirectUris: ["https://app.example.com/logged-out"],
			}),
		});
		const app = buildApp({ browserSession, clientRepo });
		const token = await mintIdToken();

		const res = await postLogout(app, {
			id_token_hint: token,
			post_logout_redirect_uri: "https://app.example.com/logged-out",
		});

		expect(res.status).toBe(303);
		expect(browserSession.destroyed).toBe(true);
	});

	it("destroys the browser session when the UserSession record is already gone", async () => {
		// The no-op branch is exactly the broken-loop state: the store entry has
		// expired or was deleted out of band while the cookie still claims to be
		// authenticated. Ending the cookie here is what unsticks the browser.
		const browserSession = makeBrowserSession({ sid: "sid-1" });
		const sessionStore = makeSessionStore({ get: vi.fn().mockResolvedValue(null) });
		const app = buildApp({ browserSession, sessionStore });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(browserSession.destroyed).toBe(true);
	});

	it("a failing destroy is logged, and does not turn a successful cascade into a 5xx", async () => {
		const logger = createMockLogger();
		const browserSession = makeBrowserSession({ sid: "sid-1", destroyFails: true });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore, logger });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		// The cascade succeeded — the stores are clean and the RPs were told.
		// A cookie the store could not delete is a weaker failure than
		// reporting the whole logout as failed, which would invite a retry of
		// a cascade that already ran.
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(logger.warn).toHaveBeenCalled();
	});

	it("a destroy that throws synchronously is logged, and the request still answers", async () => {
		// An adapter that validates before reaching its own callback throws
		// instead of calling back, so the promise the route awaits would never
		// settle and the request would hang. The synchronous guard is what
		// turns that into the same logged, non-fatal outcome as a callback
		// error.
		const logger = createMockLogger();
		const browserSession = makeBrowserSession({ sid: "sid-1", destroyThrows: true });
		const sessionStore = makeSessionStore();
		const app = buildApp({ browserSession, sessionStore, logger });
		const token = await mintIdToken();

		const res = await postLogout(app, { id_token_hint: token });

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(sessionStore.delete).toHaveBeenCalledWith("sid-1");
		expect(logger.warn).toHaveBeenCalled();
		expect(browserSession.destroyed).toBe(false);
	});
});

/**
 * A token whose `typ` header is text the verifier reads before the signature
 * and quotes in its refusal's message. A route's own line about the refusal
 * carries the verifier's reason and nothing of the token.
 */
const TYP_MARKER = "typ-must-never-reach-a-route-line";
const mintTypMarkerToken = (): Promise<string> =>
	new SignJWT({ sub: "u-1", sid: "sid-1", azp: "client-1", family_id: "fam-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: TYP_MARKER })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(secretKey);

/**
 * A federation logout over core's real session lifecycle, as `buildApp`
 * composes it: the federation's tokens go, the lifecycle keeps it listed as
 * having joined, and the session's later close ends it upstream again with
 * no hint left to send.
 */
describe("a federation logout, then RP-initiated logout, over core's session lifecycle", () => {
	it("leaves the federation listed with no tokens, answers a repeat the same, and the close ends it upstream without a hint", async () => {
		const sessions = new Map<string, UserSession>([["sid-1", baseSession]]);
		const userSessionStore: UserSessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn(async (sid: string) => sessions.get(sid) ?? null),
			delete: vi.fn(async (sid: string) => {
				sessions.delete(sid);
			}),
		};
		const tokens = new Map<string, { idToken: string }>([
			["sid-1:google", { idToken: "upstream-id-token" }],
		]);
		const fedTokenStore = makeFedTokenStore({
			get: vi.fn(
				async (sid: string, name: string) =>
					(tokens.get(`${sid}:${name}`) ?? null) as FederationTokens | null,
			),
			delete: vi.fn(async (sid: string, name: string) => {
				tokens.delete(`${sid}:${name}`);
			}),
			removeBySid: vi.fn(async (sid: string) => {
				for (const key of [...tokens.keys()]) if (key.startsWith(`${sid}:`)) tokens.delete(key);
			}),
		});
		const refreshFamilyRevocation = makeFamilyRevocation();
		const sessionLifecycle = createSessionLifecycle({
			store: createInMemorySessionLifecycleStore(),
			userSessionStore,
			refreshTokenFamilyRevocation: refreshFamilyRevocation,
			federationTokenStore: fedTokenStore,
			retainMs: 3_600_000,
			logger: { warn: () => undefined, error: () => undefined },
		});
		expect(
			await sessionLifecycle.open("sid-1", {
				sub: baseSession.sub,
				expiresAt: baseSession.expiresAt,
			}),
		).toEqual({ outcome: "opened" });
		expect(await sessionLifecycle.join("sid-1", { federation: "google" })).toEqual({
			outcome: "joined",
		});
		const close = vi.spyOn(sessionLifecycle, "close");
		const endSession = vi.fn(async (request: { idTokenHint?: string }) => ({
			url: new URL(
				`https://accounts.google.com/Logout${request.idTokenHint === undefined ? "" : "?hinted=1"}`,
			),
			method: "GET" as const,
		}));
		const app = buildApp({
			sessionStore: userSessionStore,
			fedTokenStore,
			refreshFamilyRevocation,
			sessionLifecycle,
			getFederationProviders: () =>
				new Map([["google", { ...federationBase("google"), endSession } as FederationProvider]]),
		});

		const first = await postFedLogout(app, "google", await mintAccessToken());
		expect(first.status).toBe(303);
		expect(first.headers.location).toBe("https://accounts.google.com/Logout?hinted=1");
		expect(tokens.get("sid-1:google")).toBeUndefined();
		expect(await sessionLifecycle.federations("sid-1")).toEqual({
			outcome: "listed",
			federations: ["google"],
		});

		// The federation is still listed: a repeat is the same disconnect, now
		// with no token to hand upstream.
		const repeat = await postFedLogout(app, "google", await mintAccessToken());
		expect(repeat.status).toBe(303);
		expect(repeat.headers.location).toBe("https://accounts.google.com/Logout");

		const logout = await postLogout(app, { id_token_hint: await mintIdToken() });
		expect(logout.status).toBe(303);
		expect(logout.headers.location).toBe("https://accounts.google.com/Logout");
		expect(endSession).toHaveBeenLastCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(await close.mock.results[0]?.value).toMatchObject({ federations: ["google"] });
	});
});
