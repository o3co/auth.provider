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
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionLifecycleStore,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createSessionLifecycle,
	type FederationProvider,
	type FederationTokenStore,
	type Logger,
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
	HARNESS_TRANSACTION_COOKIE_NAME,
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
	const sessionFederationIndex = createInMemorySessionFederationIndex();
	const lifecycleStore = createInMemorySessionLifecycleStore();
	const service = createSessionLifecycle({
		store: lifecycleStore,
		userSessionStore,
		refreshTokenFamilyRevocation: {
			revokeFamily: async () => {},
			isFamilyRevoked: async () => false,
		},
		federationTokenStore,
		sessionRPRegistry: createInMemorySessionRPRegistry(),
		sessionFamilyIndex: createInMemorySessionFamilyIndex(),
		sessionFederationIndex,
		retainMs: 0,
		logger: silent,
	});
	const join = vi.fn<SessionLifecycle["join"]>(async (sid, joining) => {
		await options.beforeJoin?.(service, sid);
		return service.join(sid, joining);
	});
	const sessionLifecycle: SessionLifecycle = { ...service, join };

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
			sessionFederationIndex,
			federationTokenStore,
			sessionLifecycleStore: lifecycleStore,
			sessionLifecycle,
			federationTransactionCookieName: HARNESS_TRANSACTION_COOKIE_NAME,
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
		sessionFederationIndex,
		lifecycleStore,
		service,
		join,
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
		if (open) {
			expect(await w.service.join(LINKED_SID, { federation: "test" })).toEqual({
				outcome: "joined",
			});
		} else {
			await w.sessionFederationIndex.addFederation(LINKED_SID, "test", expiresAt);
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

	it("answers 503 when the lifecycle cannot answer the join, undoing the tokens it attached", async () => {
		const w = await world();
		w.join.mockImplementationOnce(async () => ({ outcome: "unavailable" }));

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
				sessionFederationIndex: createInMemorySessionFederationIndex(),
				federationTokenStore: {} as FederationTokenStore,
				federationTransactionCookieName: HARNESS_TRANSACTION_COOKIE_NAME,
				requirements: resolverForTests([], {
					issuer: HARNESS_ISSUER,
					actions: SESSION_ADMISSION_ACTIONS,
				}),
				logger: silentLogger,
			}),
		).toThrow(/userSessionStore is wired, but sessionLifecycle is not/);
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

	it("refuses a session with no lifecycle record: a federation alone cannot adopt it, and a re-link removes that federation's tokens", async () => {
		const w = await world();

		const res = await link(w, { open: false, carrying: true });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
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

	it("answers 503 when the lifecycle cannot answer the join, undoing the tokens it attached", async () => {
		const w = await world();
		w.join.mockImplementationOnce(async () => ({ outcome: "unavailable" }));

		const res = await link(w);

		expect(res.status).toBe(503);
		expect(await w.federationTokenStore.get(LINKED_SID, "test")).toBeNull();
		expect(await participantsOf(w, LINKED_SID)).toEqual([]);
	});
});
