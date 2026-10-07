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
 * The federation routes over core's session lifecycle, on core's in-process
 * stores: a federated login and a link callback attach the federation's
 * tokens, then join the federation to the session through the lifecycle. A
 * session closed before the join commits is refused, and no federation
 * tokens are left for it; an outage at the join is a `503` that undoes the
 * tokens.
 */

import {
	codeChallenge,
	createFederationTokenStoreFactory,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createSessionLifecycle,
	type FederationProvider,
	type FederationTokenStore,
	type Logger,
	loggableError,
	readVersionedSessionLifecycle,
	registerBuiltinFederationTokenStores,
	type SessionLifecycle,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { createTestFederationSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { createRouter } from "#/routes/Federation.mjs";
import {
	HARNESS_ISSUER,
	HARNESS_SESSION_COOKIE_NAME,
	type HarnessSessionStore,
	makePermissivePolicy,
	makeSessionApp,
} from "./federation-harness.mjs";

const CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";
const SUBJECT = "user-1";
const LINKED_SID = "s-linked";
const silent = { warn: () => undefined, error: () => undefined };
const silentLogger: Logger = {
	trace: () => undefined,
	debug: () => undefined,
	info: () => undefined,
	warn: () => undefined,
	error: () => undefined,
	fatal: () => undefined,
	child: () => silentLogger,
};

const provider: FederationProvider = {
	name: "test",
	scope: ["openid"],
	buildAuthorizationUrl: ({ state, codeVerifier }) => {
		const url = new URL("https://idp.example.com/authorize");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
		return url;
	},
	exchangeCode: vi.fn(async () => ({
		issuer: "https://idp.example.com",
		sub: "external-42",
		accessToken: "upstream-at",
		expiresAt: new Date(Date.now() + 3_600_000),
		scope: "openid",
	})),
};

interface WorldOptions {
	/** Runs inside the lifecycle's `join`, before it: where a test lands a close or an outage. */
	readonly beforeJoin?: (lifecycle: SessionLifecycle, sid: string) => Promise<void>;
	/** Runs inside the token store's `attach`, before it. */
	readonly beforeAttach?: (lifecycle: SessionLifecycle, sid: string) => Promise<void>;
	/** The cookie session's save fails, once it has been regenerated. */
	readonly saveFails?: boolean;
	/** The router's logger: silent by default. */
	readonly logger?: Logger;
	/** Answers the lifecycle's `federations` in place of the service. */
	readonly federations?: SessionLifecycle["federations"];
}

async function world(options: WorldOptions = {}) {
	const userSessionStore = createInMemoryUserSessionStore();
	const tokens = createFederationTokenStoreFactory();
	registerBuiltinFederationTokenStores(tokens, silentLogger);
	const tokenStore = (await tokens.create({ type: "memory" })) as FederationTokenStore;
	const federationTokenStore: FederationTokenStore = Object.assign(Object.create(tokenStore), {
		attach: async (...args: Parameters<FederationTokenStore["attach"]>) => {
			await options.beforeAttach?.(service, args[0]);
			return tokenStore.attach(...args);
		},
	});
	const lifecycleStore = createInMemorySessionLifecycleStore();
	const service = createSessionLifecycle({
		store: lifecycleStore,
		userSessionStore,
		refreshTokenFamilyRevocation: {
			revokeFamily: async () => {},
			isFamilyRevoked: async () => false,
		},
		federationTokenStore,
		retainMs: 0,
		logger: silent,
	});
	const join = vi.fn<SessionLifecycle["join"]>(async (sid, joining) => {
		await options.beforeJoin?.(service, sid);
		return service.join(sid, joining);
	});
	const federations = vi.fn<SessionLifecycle["federations"]>(
		options.federations ?? ((sid) => service.federations(sid)),
	);
	const sessionLifecycle: SessionLifecycle = { ...service, join, federations };

	const store: HarnessSessionStore = new Map();
	const app = makeSessionApp(store);
	if (options.saveFails) {
		// The regenerated session's save fails, as a cookie store gone down
		// between the regeneration and the save does.
		app.use((req, _res, next) => {
			const held = req.session as unknown as {
				regenerate(cb: (err: unknown) => void): unknown;
			};
			const regenerate = held.regenerate.bind(held);
			held.regenerate = (cb) =>
				regenerate((err) => {
					const fresh = req.session as unknown as { save(cb: (err: unknown) => void): unknown };
					fresh.save = (done) => done(new Error("cookie store down"));
					cb(err);
				});
			next();
		});
	}
	const userRepository = {
		authenticate: vi.fn(async () => null),
		authenticateByToken: vi.fn(async () => ({ id: SUBJECT, username: "alice" })),
		linkFederatedIdentity: vi.fn(async () => ({ ok: true, user: { id: SUBJECT } })),
	} as unknown as UserRepository;
	app.use(
		createRouter(express, {
			federationSettings: createTestFederationSettings(),
			federationProviders: new Map([["test", provider]]),
			federationRedirectPolicyResolver: new Map([["test", makePermissivePolicy()]]) as never,
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			userRepository,
			userSessionStore,
			federationTokenStore,
			sessionLifecycleStore: lifecycleStore,
			sessionLifecycle,
			sessionCookieName: HARNESS_SESSION_COOKIE_NAME,
			requirements: resolverForTests([], {
				issuer: HARNESS_ISSUER,
				actions: SESSION_ADMISSION_ACTIONS,
			}),
			logger: options.logger ?? silentLogger,
		}),
	);
	return {
		app,
		store,
		userSessionStore,
		federationTokenStore,
		lifecycleStore,
		service,
		join,
		federations,
	};
}

type World = Awaited<ReturnType<typeof world>>;

/** A federated login's callback, on a browser whose start recorded `federation`. */
async function login(w: World) {
	w.store.set("browser", {
		data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
		cookie: { sameSite: "lax", secure: false, httpOnly: true },
	});
	return request(w.app)
		.get("/oauth/federation/test/callback?state=st-1&code=c-1")
		.set("Cookie", "sid=browser");
}

/** Tokens the session held for `test` before the link callback. */
const EARLIER_TOKENS = {
	accessToken: "earlier-at",
	refreshToken: undefined,
	idToken: undefined,
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: undefined,
	scope: "openid",
	grantedScope: "openid",
	obtainedAt: undefined,
};

interface LinkOptions {
	/** Whether the session's lifecycle record is opened; one established before the lifecycle was installed has none. */
	readonly open?: boolean;
	/** The session already carries `test`: in the per-session index, with tokens. */
	readonly carrying?: boolean;
}

/** A link callback for the live session `LINKED_SID`. */
async function link(w: World, { open = true, carrying = false }: LinkOptions = {}) {
	const expiresAt = new Date(Date.now() + 3_600_000);
	await w.userSessionStore.create({
		sid: LINKED_SID,
		sub: SUBJECT,
		authTime: new Date(),
		expiresAt,
		claims: {},
		amr: ["pwd"],
		authentication: undefined,
	});
	if (open) {
		expect(await w.service.open(LINKED_SID, { sub: SUBJECT, expiresAt })).toEqual({
			outcome: "opened",
		});
	}
	if (carrying) {
		// A session with no record carries the federation's tokens alone.
		if (open) {
			expect(await w.service.join(LINKED_SID, { federation: "test" })).toEqual({
				outcome: "joined",
			});
		}
		await w.federationTokenStore.attach(LINKED_SID, "test", EARLIER_TOKENS);
	}
	w.store.set("browser", {
		data: {
			sid: LINKED_SID,
			isAuthenticated: true,
			user: { id: SUBJECT },
			federation: {
				name: "test",
				state: "st-1",
				codeVerifier: "cv-1",
				link: { sid: LINKED_SID, subject: SUBJECT },
			},
		},
		cookie: { sameSite: "lax", secure: false, httpOnly: true },
	});
	return request(w.app)
		.get("/oauth/federation/test/callback?state=st-1&code=c-1")
		.set("Cookie", "sid=browser");
}

const participantsOf = async (w: World, sid: string) =>
	readVersionedSessionLifecycle(await w.lifecycleStore.read(sid))?.value.participants.map(
		(p) => `${p.kind}:${p.id}`,
	);

/** The sid of the one user session a login created. */
const loginSid = (w: World): string => String(w.join.mock.calls[0]?.[0]);

/** A join answering an outcome the lifecycle's types do not declare: anything but a success is acted on as an outage. */
const UNDECLARED_JOIN = (async () => ({
	outcome: "undeclared",
})) as unknown as SessionLifecycle["join"];

/** A logger whose `error` and `warn` are spies; `child` answers the same logger. */
function spiedLogger() {
	const error = vi.fn();
	const warn = vi.fn();
	const logger: Logger = { ...silentLogger, error, warn, child: () => logger };
	return { logger, error, warn };
}

describe("a federated login over the session lifecycle", () => {
	it("attaches the federation's tokens, then joins the federation to the session", async () => {
		const w = await world();

		const res = await login(w);

		expect(res.status).toBe(302);
		const sid = loginSid(w);
		expect(w.join).toHaveBeenCalledExactlyOnceWith(sid, { federation: "test" });
		expect(await participantsOf(w, sid)).toEqual(["federation:test"]);
		expect((await w.federationTokenStore.get(sid, "test"))?.accessToken).toBe("upstream-at");
		expect(w.store.get("browser")?.data).toMatchObject({ isAuthenticated: true, sid });
	});

	it("is refused when the session closes before the join, leaving no federation tokens and no signed-in session", async () => {
		const w = await world({
			beforeJoin: async (lifecycle, sid) => {
				expect((await lifecycle.close(sid, "subject_revocation")).outcome).toBe("done");
			},
		});

		const res = await login(w);

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		const sid = loginSid(w);
		expect(await w.federationTokenStore.get(sid, "test")).toBeNull();
		expect(await w.userSessionStore.get(sid)).toBeNull();
		expect(w.store.get("browser")?.data ?? {}).not.toHaveProperty("isAuthenticated");
	});

	it("leaves no federation tokens when the session closed before they were attached", async () => {
		const w = await world({
			beforeAttach: async (lifecycle, sid) => {
				expect((await lifecycle.close(sid, "subject_revocation")).outcome).toBe("done");
			},
		});

		const res = await login(w);

		expect(res.status).toBe(401);
		expect(await w.federationTokenStore.get(loginSid(w), "test")).toBeNull();
	});

	it("logs nothing for a refused join: the session's close, not an outage", async () => {
		const error = vi.fn();
		const logger: Logger = { ...silentLogger, error, child: () => logger };
		const w = await world({
			logger,
			beforeJoin: async (lifecycle, sid) => {
				expect((await lifecycle.close(sid, "subject_revocation")).outcome).toBe("done");
			},
		});

		const res = await login(w);

		expect(res.status).toBe(401);
		expect(error).not.toHaveBeenCalled();
	});

	it("closes the record it opened when the cookie session cannot be saved after the join", async () => {
		const w = await world({ saveFails: true });

		const res = await login(w);

		expect(res.status).toBe(503);
		const sid = loginSid(w);
		expect(w.join).toHaveBeenCalledOnce();
		expect(readVersionedSessionLifecycle(await w.lifecycleStore.read(sid))?.value.state).toBe(
			"closed",
		);
		expect(await w.service.join(sid, { federation: "test" })).toEqual({ outcome: "refused" });
		expect(await w.federationTokenStore.get(sid, "test")).toBeNull();
		expect(await w.userSessionStore.get(sid)).toBeNull();
		expect(w.store.get("browser")?.data ?? {}).not.toHaveProperty("isAuthenticated");
	});

	it("answers 503 when the lifecycle rejects the join, logged once at error with the rejection's projection, undoing the tokens it attached", async () => {
		const thrown = new Error("lifecycle store down");
		const { logger, error, warn } = spiedLogger();
		const w = await world({ logger });
		w.join.mockImplementationOnce(async () => {
			throw thrown;
		});

		const res = await login(w);

		expect(res.status).toBe(503);
		expect(error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				store: "session_lifecycle",
				step: "join",
				err: loggableError(thrown),
			}),
			"federation_callback_store_unavailable",
		);
		expect(warn).not.toHaveBeenCalled();
		const sid = loginSid(w);
		expect(await w.federationTokenStore.get(sid, "test")).toBeNull();
		expect(await w.userSessionStore.get(sid)).toBeNull();
		expect(w.store.get("browser")?.data ?? {}).not.toHaveProperty("isAuthenticated");
	});

	it("answers 503 when the lifecycle answers an outcome it does not declare to the join, undoing the tokens it attached", async () => {
		const w = await world();
		w.join.mockImplementationOnce(UNDECLARED_JOIN);

		const res = await login(w);

		expect(res.status).toBe(503);
		const sid = loginSid(w);
		expect(await w.federationTokenStore.get(sid, "test")).toBeNull();
		expect(await w.userSessionStore.get(sid)).toBeNull();
		expect(w.store.get("browser")?.data ?? {}).not.toHaveProperty("isAuthenticated");
	});
});

describe("the federation routes require core's session lifecycle beside the user-session store", () => {
	it("refuses to build the router without a sessionLifecycle, naming both slots", () => {
		expect(() =>
			createRouter(express, {
				federationSettings: createTestFederationSettings(),
				federationProviders: new Map([["test", provider]]),
				federationRedirectPolicyResolver: new Map([["test", makePermissivePolicy()]]) as never,
				providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
				userRepository: { authenticate: vi.fn(), authenticateByToken: vi.fn() } as never,
				userSessionStore: createInMemoryUserSessionStore(),
				federationTokenStore: {} as FederationTokenStore,
				sessionCookieName: HARNESS_SESSION_COOKIE_NAME,
				requirements: resolverForTests([], {
					issuer: HARNESS_ISSUER,
					actions: SESSION_ADMISSION_ACTIONS,
				}),
				logger: silentLogger,
			}),
		).toThrow(/userSessionStore is wired, but sessionLifecycle is not/);
	});

	it("refuses to build the router with a sessionLifecycle and no sessionLifecycleStore, naming the slot", () => {
		expect(() =>
			createRouter(express, {
				federationSettings: createTestFederationSettings(),
				federationProviders: new Map([["test", provider]]),
				federationRedirectPolicyResolver: new Map([["test", makePermissivePolicy()]]) as never,
				providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
				userRepository: { authenticate: vi.fn(), authenticateByToken: vi.fn() } as never,
				userSessionStore: createInMemoryUserSessionStore(),
				sessionLifecycle: {} as SessionLifecycle,
				federationTokenStore: {} as FederationTokenStore,
				sessionCookieName: HARNESS_SESSION_COOKIE_NAME,
				requirements: resolverForTests([], {
					issuer: HARNESS_ISSUER,
					actions: SESSION_ADMISSION_ACTIONS,
				}),
				logger: silentLogger,
			}),
		).toThrow(
			/^federation routes: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*sessionLifecycleModule\.$/,
		);
	});
});

describe("a link callback over the session lifecycle", () => {
	it("attaches the federation's tokens, then joins the federation to the live session", async () => {
		const w = await world();

		const res = await link(w);

		expect(res.status).toBe(302);
		expect(w.join).toHaveBeenCalledExactlyOnceWith(LINKED_SID, { federation: "test" });
		expect(await participantsOf(w, LINKED_SID)).toEqual(["federation:test"]);
		expect((await w.federationTokenStore.get(LINKED_SID, "test"))?.accessToken).toBe("upstream-at");
	});

	it("is refused when the session closes between its admission and the join, leaving no federation tokens", async () => {
		const w = await world({
			beforeJoin: async (lifecycle, sid) => {
				expect((await lifecycle.close(sid, "session_logout")).outcome).toBe("done");
			},
		});

		const res = await link(w);

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
	});

	it("re-links a federation the session already carries: joined again, its tokens replaced", async () => {
		const w = await world();

		const res = await link(w, { carrying: true });

		expect(res.status).toBe(302);
		expect(await participantsOf(w, LINKED_SID)).toEqual(["federation:test"]);
		expect((await w.federationTokenStore.get(LINKED_SID, "test"))?.accessToken).toBe("upstream-at");
	});

	it("refuses a session with no lifecycle record before it attaches or joins anything: an absent record reads as closed", async () => {
		const w = await world();

		const res = await link(w, { open: false, carrying: true });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(w.join).not.toHaveBeenCalled();
		expect((await w.federationTokenStore.get(LINKED_SID, "test"))?.accessToken).toBe("earlier-at");
		expect(readVersionedSessionLifecycle(await w.lifecycleStore.read(LINKED_SID))).toBeNull();
	});

	it("leaves no federation tokens when the session closed before they were attached", async () => {
		const w = await world({
			beforeAttach: async (lifecycle, sid) => {
				expect((await lifecycle.close(sid, "session_logout")).outcome).toBe("done");
			},
		});

		const res = await link(w);

		expect(res.status).toBe(401);
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
	});

	it("answers 503 when the lifecycle rejects the join, logged once at error with the rejection's projection, undoing the tokens it attached", async () => {
		const thrown = new Error("lifecycle store down");
		const { logger, error, warn } = spiedLogger();
		const w = await world({ logger });
		w.join.mockImplementationOnce(async () => {
			throw thrown;
		});

		const res = await link(w);

		expect(res.status).toBe(503);
		expect(error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				store: "session_lifecycle",
				step: "join",
				err: loggableError(thrown),
			}),
			"federation_link_store_unavailable",
		);
		expect(warn).not.toHaveBeenCalled();
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
		expect(await participantsOf(w, LINKED_SID)).toEqual([]);
	});

	it("answers 503 when the lifecycle answers an outcome it does not declare to the join, undoing the tokens it attached", async () => {
		const w = await world();
		w.join.mockImplementationOnce(UNDECLARED_JOIN);

		const res = await link(w);

		expect(res.status).toBe(503);
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
		expect(await participantsOf(w, LINKED_SID)).toEqual([]);
	});

	it("reads whether the session carries the federation from the lifecycle, with no per-session index wired", async () => {
		const w = await world();

		const res = await link(w);

		expect(res.status).toBe(302);
		expect(w.federations).toHaveBeenCalledExactlyOnceWith(LINKED_SID);
	});

	it("keeps the re-link's newly attached tokens on a federation the lifecycle lists when the join rejects", async () => {
		// The session joined `test` earlier through the lifecycle, which lists it.
		const w = await world();
		w.join.mockImplementationOnce(async () => {
			throw new Error("lifecycle store down");
		});

		const res = await link(w, { carrying: true });

		expect(res.status).toBe(503);
		expect((await w.federationTokenStore.get(LINKED_SID, "test"))?.accessToken).toBe("upstream-at");
	});

	it("answers 503 when the lifecycle rejects the federations read, logged once at error with its projection, nothing attached", async () => {
		const thrown = new Error("lifecycle store down");
		const { logger, error, warn } = spiedLogger();
		const w = await world({
			logger,
			federations: async () => {
				throw thrown;
			},
		});

		const res = await link(w);

		expect(res.status).toBe(503);
		expect(error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				store: "session_lifecycle",
				step: "federations",
				err: loggableError(thrown),
			}),
			"federation_link_store_unavailable",
		);
		expect(warn).not.toHaveBeenCalled();
		expect(w.join).not.toHaveBeenCalled();
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
	});

	it("answers 503 when the lifecycle answers the federations read outside its outcomes, nothing attached", async () => {
		const w = await world({
			federations: (async () => ({
				outcome: "undeclared",
				federations: [],
			})) as unknown as SessionLifecycle["federations"],
		});

		const res = await link(w);

		expect(res.status).toBe(503);
		expect(w.join).not.toHaveBeenCalled();
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
	});
});
