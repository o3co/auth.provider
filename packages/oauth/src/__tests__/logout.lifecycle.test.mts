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
 * `/oauth/logout` where core's session lifecycle is installed: the route
 * closes the session through `sessionLifecycle.close`, reads the upstream
 * `id_token_hint` before it, and answers from the close's answer. The
 * relying parties are told back-channel by the lifecycle's notifier, never
 * by the route.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createSessionLifecycle,
	createSymmetricKeyStore,
	type FederationProvider,
	type FederationTokenStore,
	type Logger,
	readVersionedSessionLifecycle,
	type SessionLifecycle,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { createSessionCloseNotifier } from "#/logout/sessionCloseNotifier.mjs";
import { createRouter, type LogoutRouterOptions } from "#/routes/logout.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import {
	expectOutageLine,
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";
import { outsideAnswer } from "./_helpers/sessionLifecycle.mjs";

const ISSUER = "https://auth.example.com";
const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));
const SID = "sid-1";
const HOUR = 3_600_000;

async function mintIdToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u-1", aud: "client-1", sid: SID, ...extra })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer(ISSUER)
		.sign(secretKey);
}

const baseSession: UserSession = {
	sid: SID,
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + HOUR),
	claims: {},
	amr: undefined,
	authentication: undefined,
};

/** A federation whose provider ends the upstream session. */
function endingFederation(name: string) {
	const endSession = vi.fn(async (_request: { idTokenHint?: string }) => ({
		url: new URL(`https://${name}.example/logout`),
		method: "GET" as const,
	}));
	const provider = {
		name,
		scope: ["openid"] as readonly string[],
		buildAuthorizationUrl: () => new URL(`https://${name}.example/auth`),
		exchangeCode: async () => ({ issuer: `https://${name}.example`, sub: "s", expiresAt: null }),
		endSession,
	} as unknown as FederationProvider;
	return { provider, endSession };
}

/** A lifecycle whose answers the case sets; every member a spy. */
function fakeLifecycle(over: Partial<SessionLifecycle> = {}) {
	return {
		open: vi.fn<SessionLifecycle["open"]>(over.open ?? (async () => ({ outcome: "opened" }))),
		join: vi.fn<SessionLifecycle["join"]>(over.join ?? (async () => ({ outcome: "joined" }))),
		close: vi.fn<SessionLifecycle["close"]>(
			over.close ?? (async () => ({ outcome: "done", rps: [], federations: [] })),
		),
		liveness: vi.fn<SessionLifecycle["liveness"]>(
			over.liveness ?? (async () => ({ outcome: "not_live" })),
		),
		federations: vi.fn<SessionLifecycle["federations"]>(
			over.federations ?? (async () => ({ outcome: "listed", federations: [] })),
		),
		resumePending: vi.fn<SessionLifecycle["resumePending"]>(
			over.resumePending ?? (async () => ({ done: 0, pending: 0, unavailable: 0 })),
		),
	} satisfies SessionLifecycle;
}

/** A family revocation whose every member is a spy: the route must not use it to end the session. */
function untouchedStores() {
	return {
		refreshTokenFamilyRevocation: {
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(async () => undefined),
		},
	};
}

function fedTokenStore(tokens: Record<string, string> = {}): FederationTokenStore {
	return {
		kind: "memory",
		attach: vi.fn(),
		get: vi.fn(async (_sid: string, federation: string) =>
			tokens[federation] === undefined ? null : { idToken: tokens[federation] },
		),
		getVersioned: vi.fn(),
		replaceIf: vi.fn(),
		removeIf: vi.fn(),
		removeBySid: vi.fn(async () => undefined),
		delete: vi.fn(async () => undefined),
	} as unknown as FederationTokenStore;
}

interface AppOptions {
	readonly lifecycle: SessionLifecycle;
	readonly sessionStore?: UserSessionStore;
	readonly stores?: ReturnType<typeof untouchedStores>;
	readonly federationTokenStore?: FederationTokenStore;
	readonly clientRepository?: ClientRepository;
	readonly providers?: ReadonlyMap<string, FederationProvider>;
	readonly fetchImpl?: typeof fetch;
	readonly logger?: Logger;
	readonly auditSink?: AuditSink;
	readonly browserSession?: { sid?: string; destroyed?: boolean };
}

function buildApp(opts: AppOptions) {
	const app = express();
	if (opts.browserSession) {
		const session = opts.browserSession;
		app.use((req, _res, next) => {
			(req as unknown as { session: unknown }).session = Object.assign(session, {
				destroy(cb: (err: Error | null) => void) {
					session.destroyed = true;
					cb(null);
				},
			});
			next();
		});
	}
	const stores = opts.stores ?? untouchedStores();
	app.use(
		"/oauth",
		createRouter(express, {
			keyStore,
			issuer: ISSUER,
			userSessionStore:
				opts.sessionStore ??
				({
					kind: "memory",
					create: vi.fn(),
					get: vi.fn(async () => baseSession),
					delete: vi.fn(),
				} as unknown as UserSessionStore),
			...stores,
			federationTokenStore: opts.federationTokenStore ?? fedTokenStore(),
			clientRepository: opts.clientRepository ?? {
				findById: vi.fn(async () => null),
				authenticate: vi.fn(),
			},
			getFederationProviders: () => opts.providers,
			fetchImpl: opts.fetchImpl ?? (vi.fn(async () => new Response(null)) as typeof fetch),
			logger: opts.logger ?? createMockLogger(),
			auditSink: opts.auditSink,
			sessionLifecycle: opts.lifecycle,
		}),
	);
	return app;
}

function recordingSink() {
	const events: AuditEvent[] = [];
	const sink: AuditSink = {
		kind: "memory",
		record: async (event) => {
			events.push(event);
		},
	};
	return { sink, events };
}

const typesOf = (events: readonly AuditEvent[]): string[] => events.map((e) => e.type);

async function postLogout(
	app: express.Express,
	headers: Record<string, string> = {},
): Promise<request.Response> {
	const req = request(app).post("/oauth/logout").type("form");
	for (const [k, v] of Object.entries(headers)) req.set(k, v);
	return req.send({ id_token_hint: await mintIdToken() });
}

describe("/oauth/logout through the session lifecycle: the close's answer", () => {
	it("done: closes the session for an RP-initiated logout and answers success, through nothing but the lifecycle", async () => {
		const lifecycle = fakeLifecycle();
		const stores = untouchedStores();
		const sessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn(async () => baseSession),
			delete: vi.fn(),
		} as unknown as UserSessionStore;
		const federationTokenStore = fedTokenStore();
		const { sink, events } = recordingSink();
		const browserSession = { sid: SID, destroyed: false };
		const app = buildApp({
			lifecycle,
			stores,
			sessionStore,
			federationTokenStore,
			auditSink: sink,
			browserSession,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(lifecycle.close).toHaveBeenCalledExactlyOnceWith(SID, "rp_logout");
		expect(typesOf(events)).toEqual(["logout.success"]);
		expect(events[0]?.details).toEqual({ sid: SID, federations: [] });
		expect(browserSession.destroyed).toBe(true);
		// The lifecycle runs the close work; the route runs none of its own.
		expect(stores.refreshTokenFamilyRevocation.revokeFamily).not.toHaveBeenCalled();
		expect(federationTokenStore.removeBySid).not.toHaveBeenCalled();
		expect(sessionStore.delete).not.toHaveBeenCalled();
	});

	it("pending: the close committed with work outstanding; success, audited as logout.close_pending", async () => {
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({ outcome: "pending" as const, rps: [], federations: [] })),
		});
		const { sink, events } = recordingSink();
		const browserSession = { sid: SID, destroyed: false };
		const app = buildApp({ lifecycle, auditSink: sink, browserSession });

		const res = await postLogout(app);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(typesOf(events)).toEqual(["logout.close_pending", "logout.success"]);
		expect(events[0]).toMatchObject({ subject: "u-1", details: { sid: SID } });
		expect(browserSession.destroyed).toBe(true);
	});

	it("an answer outside the close's outcomes: 503, audited as logout.cascade_failed, one error line, and the browser session kept for a retry", async () => {
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => outsideAnswer<never>()),
		});
		const { sink, events } = recordingSink();
		const logger = createMockLogger();
		const browserSession = { sid: SID, destroyed: false };
		const app = buildApp({ lifecycle, auditSink: sink, logger, browserSession });

		const res = await postLogout(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(typesOf(events)).toEqual(["logout.cascade_failed"]);
		expect(events[0]).toMatchObject({
			subject: "u-1",
			details: { sid: SID, store: "session_lifecycle" },
		});
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ store: "session_lifecycle", step: "close" },
			"logout_store_unavailable",
		);
		expect(browserSession.destroyed).toBe(false);
	});

	it("a close that rejects with its store's error: 503, audited as logout.cascade_failed, one error line with the error's projection, and the browser session kept", async () => {
		const google = endingFederation("google");
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
			close: vi.fn(async () => {
				throw storeReplyError();
			}),
		});
		const { sink, events } = recordingSink();
		const logger = createMockLogger();
		const browserSession = { sid: SID, destroyed: false };
		const app = buildApp({
			lifecycle,
			auditSink: sink,
			logger,
			browserSession,
			providers: new Map([["google", google.provider]]),
		});

		const res = await postLogout(app);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(typesOf(events)).toEqual(["logout.cascade_failed"]);
		expect(events[0]).toMatchObject({
			subject: "u-1",
			details: { sid: SID, store: "session_lifecycle" },
		});
		expectOutageLine(logger, "logout_store_unavailable", {
			store: "session_lifecycle",
			step: "close",
		});
		expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
		expect(browserSession.destroyed).toBe(false);
		expect(google.endSession).not.toHaveBeenCalled();
	});

	for (const [label, rejection] of [
		[
			"a store-style RangeError",
			() =>
				Object.assign(new RangeError("Invalid array length"), {
					command: { name: "hset", args: [REFUSED_COMMAND_MARKER] },
				}),
		],
		["a generic rejection", () => new Error("connection reset")],
	] as const) {
		it(`a close that rejects with ${label}: 503, never a false logout, one error line, audited, the browser session kept`, async () => {
			const lifecycle = fakeLifecycle({
				close: async () => {
					throw rejection();
				},
			});
			const { sink, events } = recordingSink();
			const logger = createMockLogger();
			const browserSession = { sid: SID, destroyed: false };
			const app = buildApp({ lifecycle, auditSink: sink, logger, browserSession });

			const res = await postLogout(app);

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
			expect(typesOf(events)).toEqual(["logout.cascade_failed"]);
			expect(logger.error).toHaveBeenCalledExactlyOnceWith(
				expect.objectContaining({
					store: "session_lifecycle",
					step: "close",
					err: expect.objectContaining({ name: rejection().name }),
				}),
				"logout_store_unavailable",
			);
			expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
			expect(browserSession.destroyed).toBe(false);
		});
	}

	it("a session already gone: the no-op answer, and nothing is closed", async () => {
		const lifecycle = fakeLifecycle();
		const { sink, events } = recordingSink();
		const app = buildApp({
			lifecycle,
			auditSink: sink,
			sessionStore: {
				kind: "memory",
				create: vi.fn(),
				get: vi.fn(async () => null),
				delete: vi.fn(),
			} as unknown as UserSessionStore,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ logged_out: true });
		expect(lifecycle.close).not.toHaveBeenCalled();
		expect(lifecycle.federations).not.toHaveBeenCalled();
		expect(events).toEqual([]);
	});
});

describe("/oauth/logout through the session lifecycle: back-channel", () => {
	it("the route posts no logout token: the lifecycle's notifier tells the relying parties", async () => {
		const fetchImpl = vi.fn(async () => new Response(null)) as unknown as typeof fetch;
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({
				outcome: "done" as const,
				rps: ["rp-registry"],
				federations: [],
			})),
		});
		const app = buildApp({ lifecycle, fetchImpl });

		expect((await postLogout(app)).status).toBe(200);
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("a relying party that joined is told once, by the notifier, over a real lifecycle", async () => {
		const fetchImpl = vi.fn(async () => new Response(null, { status: 200 }));
		const clientRepository: ClientRepository = {
			findById: vi.fn(async (id: string) =>
				id === "rp-bc"
					? ({
							clientId: "rp-bc",
							backchannelLogoutUri: "https://rp-bc.example/logout",
						} as unknown as Awaited<ReturnType<ClientRepository["findById"]>>)
					: null,
			),
			authenticate: vi.fn(),
		};
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({ ...baseSession });
		const familyStore = createMemoryRefreshTokenFamilyStore();
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: familyStore,
			accessTokenHorizonMs: HOUR,
		});
		const federationTokenStore = fedTokenStore();
		const lifecycleStore = createInMemorySessionLifecycleStore();
		const notifier = createSessionCloseNotifier({
			clientRepository,
			keyStore,
			issuer: ISSUER,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		const lifecycle = createSessionLifecycle({
			store: lifecycleStore,
			userSessionStore,
			refreshTokenFamilyRevocation: revocation,
			federationTokenStore,
			notifier: () => notifier,
			retainMs: HOUR,
			logger: { warn: () => undefined, error: () => undefined },
		});
		const rp = {
			clientId: "rp-bc",
			backchannelLogoutUri: "https://rp-bc.example/logout",
			backchannelLogoutSessionRequired: true,
			frontchannelLogoutUri: undefined,
			frontchannelLogoutSessionRequired: undefined,
			registeredAt: new Date(),
		};
		expect(
			await lifecycle.open(SID, { sub: baseSession.sub, expiresAt: baseSession.expiresAt }),
		).toEqual({ outcome: "opened" });
		expect(await lifecycle.join(SID, { rp, familyId: "fam-bc" })).toEqual({ outcome: "joined" });
		const app = buildApp({
			lifecycle,
			sessionStore: userSessionStore,
			stores: {
				...untouchedStores(),
				refreshTokenFamilyRevocation: revocation,
			} as unknown as ReturnType<typeof untouchedStores>,
			federationTokenStore,
			clientRepository,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(200);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
		expect((fetchImpl.mock.calls[0] as unknown[])[0]).toBe("https://rp-bc.example/logout");
		expect(readVersionedSessionLifecycle(await lifecycleStore.read(SID))?.value.state).toBe(
			"closed",
		);
		expect(await userSessionStore.get(SID)).toBeNull();
		expect(await revocation.isFamilyRevoked("fam-bc")).toBe(true);
	});
});

describe("/oauth/logout through the session lifecycle: a pending close", () => {
	it("a second logout resumes it: the notice is sent again and the session closes", async () => {
		const fetchImpl = vi
			.fn(async () => new Response(null, { status: 200 }))
			.mockResolvedValueOnce(new Response(null, { status: 503 }));
		const clientRepository: ClientRepository = {
			findById: vi.fn(async (id: string) =>
				id === "rp-bc"
					? ({
							clientId: "rp-bc",
							backchannelLogoutUri: "https://rp-bc.example/logout",
						} as unknown as Awaited<ReturnType<ClientRepository["findById"]>>)
					: null,
			),
			authenticate: vi.fn(),
		};
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({ ...baseSession });
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: HOUR,
		});
		const federationTokenStore = fedTokenStore();
		const lifecycleStore = createInMemorySessionLifecycleStore();
		const notifier = createSessionCloseNotifier({
			clientRepository,
			keyStore,
			issuer: ISSUER,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		const lifecycle = createSessionLifecycle({
			store: lifecycleStore,
			userSessionStore,
			refreshTokenFamilyRevocation: revocation,
			federationTokenStore,
			notifier: () => notifier,
			retainMs: HOUR,
			logger: { warn: () => undefined, error: () => undefined },
		});
		const rp = {
			clientId: "rp-bc",
			backchannelLogoutUri: "https://rp-bc.example/logout",
			backchannelLogoutSessionRequired: true,
			frontchannelLogoutUri: undefined,
			frontchannelLogoutSessionRequired: undefined,
			registeredAt: new Date(),
		};
		expect(
			await lifecycle.open(SID, { sub: baseSession.sub, expiresAt: baseSession.expiresAt }),
		).toEqual({ outcome: "opened" });
		expect(await lifecycle.join(SID, { rp, familyId: "fam-bc" })).toEqual({ outcome: "joined" });
		const { sink, events } = recordingSink();
		const app = buildApp({
			lifecycle,
			sessionStore: userSessionStore,
			stores: {
				...untouchedStores(),
				refreshTokenFamilyRevocation: revocation,
			} as unknown as ReturnType<typeof untouchedStores>,
			federationTokenStore,
			clientRepository,
			auditSink: sink,
		});

		const first = await postLogout(app);
		expect(first.status).toBe(200);
		expect(typesOf(events)).toEqual(["logout.close_pending", "logout.success"]);
		expect(readVersionedSessionLifecycle(await lifecycleStore.read(SID))?.value.state).toBe(
			"closing",
		);
		expect(await userSessionStore.get(SID)).not.toBeNull();

		const second = await postLogout(app);
		expect(second.status).toBe(200);
		expect(second.body).toEqual({ logged_out: true });
		expect(fetchImpl).toHaveBeenCalledTimes(2);
		expect(readVersionedSessionLifecycle(await lifecycleStore.read(SID))?.value.state).toBe(
			"closed",
		);
		expect(await userSessionStore.get(SID)).toBeNull();
		expect(typesOf(events)).toEqual(["logout.close_pending", "logout.success", "logout.success"]);
	});
});

describe("/oauth/logout through the session lifecycle: front-channel", () => {
	const record = (fields: Record<string, unknown>) =>
		fields as unknown as Awaited<ReturnType<ClientRepository["findById"]>>;

	it("an iframe for each relying party the close answers, read from its client registration", async () => {
		const clientRepository: ClientRepository = {
			findById: vi.fn(async (id: string) =>
				id === "rp-a"
					? record({ clientId: "rp-a", frontchannelLogoutUri: "https://rp-a.example/fc" })
					: id === "rp-b"
						? record({ clientId: "rp-b" })
						: null,
			),
			authenticate: vi.fn(),
		};
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({
				outcome: "done" as const,
				rps: ["rp-a", "rp-b", "rp-gone"],
				federations: [],
			})),
		});
		const stores = untouchedStores();
		const app = buildApp({ lifecycle, clientRepository, stores });

		const res = await postLogout(app, { Accept: "text/html" });

		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toMatch(/text\/html/);
		expect(res.text).toContain("rp-a.example/fc");
		expect(clientRepository.findById).toHaveBeenCalledWith("rp-a");
		expect(clientRepository.findById).toHaveBeenCalledWith("rp-b");
		expect(clientRepository.findById).toHaveBeenCalledWith("rp-gone");
	});

	it("a client registration that cannot be read drops that iframe alone, logged once", async () => {
		const logger = createMockLogger();
		const clientRepository: ClientRepository = {
			findById: vi.fn(async (id: string) => {
				if (id === "rp-down") throw new Error("client store down");
				return record({ clientId: id, frontchannelLogoutUri: `https://${id}.example/fc` });
			}),
			authenticate: vi.fn(),
		};
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({
				outcome: "done" as const,
				rps: ["rp-down", "rp-up"],
				federations: [],
			})),
		});
		const app = buildApp({ lifecycle, clientRepository, logger });

		const res = await postLogout(app, { Accept: "text/html" });

		expect(res.status).toBe(200);
		expect(res.text).toContain("rp-up.example/fc");
		expect(res.text).not.toContain("rp-down.example");
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({ site: "logout", step: "find", clientId: "rp-down" }),
			"client_repository_unavailable",
		);
	});

	it("a registration whose front-channel field cannot be read drops that iframe alone", async () => {
		const logger = createMockLogger();
		const clientRepository: ClientRepository = {
			findById: vi.fn(async (id: string) =>
				id === "rp-bad"
					? record({
							clientId: "rp-bad",
							get frontchannelLogoutUri(): string {
								throw new Error("unreadable");
							},
						})
					: record({ clientId: id, frontchannelLogoutUri: `https://${id}.example/fc` }),
			),
			authenticate: vi.fn(),
		};
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({
				outcome: "done" as const,
				rps: ["rp-bad", "rp-good"],
				federations: [],
			})),
		});
		const app = buildApp({ lifecycle, clientRepository, logger });

		const res = await postLogout(app, { Accept: "text/html" });

		expect(res.status).toBe(200);
		expect(res.text).toContain("rp-good.example/fc");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: "rp-bad", reason: "unreadable" }),
			"logout_frontchannel_uri_refused",
		);
	});

	it("a JSON answer reads no client registration", async () => {
		const clientRepository: ClientRepository = {
			findById: vi.fn(async () => null),
			authenticate: vi.fn(),
		};
		const lifecycle = fakeLifecycle({
			close: vi.fn(async () => ({ outcome: "done" as const, rps: ["rp-a"], federations: [] })),
		});
		const app = buildApp({ lifecycle, clientRepository });

		expect((await postLogout(app)).status).toBe(200);
		expect(clientRepository.findById).not.toHaveBeenCalled();
	});
});

describe("/oauth/logout through the session lifecycle: the upstream end-session", () => {
	it("reads the first federation's id_token before the close, and ends that federation upstream with it", async () => {
		const google = endingFederation("google");
		const federationTokenStore = fedTokenStore({ google: "upstream-id-token" });
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const { sink, events } = recordingSink();
		const app = buildApp({
			lifecycle,
			federationTokenStore,
			providers: new Map([["google", google.provider]]),
			auditSink: sink,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(res.headers.location).toBe("https://google.example/logout");
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: "upstream-id-token" }),
		);
		const read = vi.mocked(federationTokenStore.get).mock.invocationCallOrder[0] as number;
		expect(vi.mocked(federationTokenStore.get).mock.calls).toEqual([[SID, "google"]]);
		expect(lifecycle.federations.mock.invocationCallOrder[0]).toBeLessThan(read);
		expect(read).toBeLessThan(lifecycle.close.mock.invocationCallOrder[0] as number);
		expect(events.at(-1)?.details).toEqual({ sid: SID, federations: ["google"] });
	});

	it("sends the hint read before the close only to the federation it was read for", async () => {
		const google = endingFederation("google");
		const github = endingFederation("github");
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["github"] })),
			close: vi.fn(async () => ({
				outcome: "done" as const,
				rps: [],
				federations: ["google", "github"],
			})),
		});
		const app = buildApp({
			lifecycle,
			federationTokenStore: fedTokenStore({ github: "github-id-token" }),
			providers: new Map([
				["google", google.provider],
				["github", github.provider],
			]),
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(res.headers.location).toBe("https://google.example/logout");
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(github.endSession).not.toHaveBeenCalled();
	});

	it("a federation that joined between the read and the close loses only its hint", async () => {
		const google = endingFederation("google");
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({ ...baseSession });
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: HOUR,
		});
		const federationTokenStore = fedTokenStore({ google: "google-id-token" });
		const lifecycleStore = createInMemorySessionLifecycleStore();
		const real = createSessionLifecycle({
			store: lifecycleStore,
			userSessionStore,
			refreshTokenFamilyRevocation: revocation,
			federationTokenStore,
			retainMs: HOUR,
			logger: { warn: () => undefined, error: () => undefined },
		});
		// The session holds a lifecycle record; the federation joins it right
		// after the logout read the session's federations, and before the close.
		expect(
			await real.open(SID, { sub: baseSession.sub, expiresAt: baseSession.expiresAt }),
		).toEqual({ outcome: "opened" });
		expect(await real.join(SID, { familyId: "fam-0" })).toEqual({ outcome: "joined" });
		const lifecycle: SessionLifecycle = {
			...real,
			federations: async (sid) => {
				const listed = await real.federations(sid);
				expect(await real.join(sid, { federation: "google" })).toEqual({ outcome: "joined" });
				return listed;
			},
		};
		const app = buildApp({
			lifecycle,
			sessionStore: userSessionStore,
			stores: {
				...untouchedStores(),
				refreshTokenFamilyRevocation: revocation,
			} as unknown as ReturnType<typeof untouchedStores>,
			federationTokenStore,
			providers: new Map([["google", google.provider]]),
		});

		const res = await postLogout(app);

		// Ended upstream all the same, without the hint the close removed.
		expect(res.status).toBe(303);
		expect(res.headers.location).toBe("https://google.example/logout");
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(federationTokenStore.get).not.toHaveBeenCalled();
		expect(federationTokenStore.removeBySid).toHaveBeenCalledWith(SID);
		expect(readVersionedSessionLifecycle(await lifecycleStore.read(SID))?.value.state).toBe(
			"closed",
		);
	});

	it("federations that cannot be read leave the logout without the hint", async () => {
		const google = endingFederation("google");
		const federationTokenStore = fedTokenStore({ google: "upstream-id-token" });
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => outsideAnswer<never>()),
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const app = buildApp({
			lifecycle,
			federationTokenStore,
			providers: new Map([["google", google.provider]]),
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(federationTokenStore.get).not.toHaveBeenCalled();
	});

	it("federations that reject with their store's error leave the logout without the hint, and say nothing", async () => {
		const google = endingFederation("google");
		const federationTokenStore = fedTokenStore({ google: "upstream-id-token" });
		const logger = createMockLogger();
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => {
				throw storeReplyError();
			}),
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const app = buildApp({
			lifecycle,
			federationTokenStore,
			providers: new Map([["google", google.provider]]),
			logger,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(lifecycle.close).toHaveBeenCalledExactlyOnceWith(SID, "rp_logout");
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(federationTokenStore.get).not.toHaveBeenCalled();
		expect(logger.error).not.toHaveBeenCalled();
		// The verifier's own audience note aside, nothing is said.
		expect(
			logger.warn.mock.calls.filter(([, event]) => event !== "jwt_verify_aud_skipped"),
		).toEqual([]);
	});

	it("a federation listing that throws before it answers leaves the logout without the hint, and says nothing", async () => {
		const google = endingFederation("google");
		const logger = createMockLogger();
		const lifecycle = fakeLifecycle({
			federations: vi.fn(() => {
				throw storeReplyError();
			}) as unknown as SessionLifecycle["federations"],
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const app = buildApp({
			lifecycle,
			providers: new Map([["google", google.provider]]),
			logger,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("a token record that cannot be read leaves the logout without the hint, said once at warn", async () => {
		const google = endingFederation("google");
		const logger = createMockLogger();
		const federationTokenStore = fedTokenStore();
		vi.mocked(federationTokenStore.get).mockRejectedValueOnce(new Error("token store down"));
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const app = buildApp({
			lifecycle,
			federationTokenStore,
			providers: new Map([["google", google.provider]]),
			logger,
		});

		const res = await postLogout(app);

		expect(res.status).toBe(303);
		expect(google.endSession).toHaveBeenCalledWith(
			expect.objectContaining({ idTokenHint: undefined }),
		);
		const lines = logger.warn.mock.calls.filter(
			([, event]) => event === "logout_federation_token_read_failed",
		);
		expect(lines).toEqual([
			[
				expect.objectContaining({ federation: "google", store: "federation_token", step: "get" }),
				"logout_federation_token_read_failed",
			],
		]);
	});

	it("a federation whose provider cannot end the session upstream: no token is read", async () => {
		const federationTokenStore = fedTokenStore({ google: "upstream-id-token" });
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
			close: vi.fn(async () => ({ outcome: "done" as const, rps: [], federations: ["google"] })),
		});
		const app = buildApp({ lifecycle, federationTokenStore, providers: new Map() });

		const res = await postLogout(app);

		expect(res.status).toBe(200);
		expect(federationTokenStore.get).not.toHaveBeenCalled();
	});

	it("the close that cannot commit ends nothing upstream", async () => {
		const google = endingFederation("google");
		const lifecycle = fakeLifecycle({
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations: ["google"] })),
			close: vi.fn(async () => outsideAnswer<never>()),
		});
		const app = buildApp({
			lifecycle,
			federationTokenStore: fedTokenStore({ google: "upstream-id-token" }),
			providers: new Map([["google", google.provider]]),
		});

		expect((await postLogout(app)).status).toBe(503);
		expect(google.endSession).not.toHaveBeenCalled();
	});
});

describe("POST /oauth/federation/:name/logout through the session lifecycle", () => {
	async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
		return new SignJWT({ sub: "u-1", sid: SID, azp: "client-1", ...extra })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
			.setExpirationTime("1h")
			.setIssuedAt()
			.setIssuer(ISSUER)
			.sign(secretKey);
	}

	const federationLogout = async (app: express.Express, token?: string) =>
		request(app)
			.post("/oauth/federation/google/logout")
			.set("Authorization", `Bearer ${token ?? (await mintAccessToken())}`)
			.send();

	const liveLifecycle = (federations: readonly string[] = ["google"]) =>
		fakeLifecycle({
			liveness: vi.fn(async () => ({ outcome: "live" as const, session: baseSession })),
			federations: vi.fn(async () => ({ outcome: "listed" as const, federations })),
		});

	it("reads the session's liveness and its federations from the lifecycle, never the per-session stores", async () => {
		const lifecycle = liveLifecycle();
		const stores = untouchedStores();
		const sessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn(async () => baseSession),
			delete: vi.fn(),
		} as unknown as UserSessionStore;
		const app = buildApp({ lifecycle, stores, sessionStore });

		const res = await federationLogout(app);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ disconnected: true });
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith(SID);
		expect(lifecycle.federations).toHaveBeenCalledExactlyOnceWith(SID);
		expect(sessionStore.get).not.toHaveBeenCalled();
	});

	it("removes the federation's tokens and leaves it listed as having joined the session", async () => {
		const federationTokenStore = fedTokenStore({ google: "upstream-id-token" });
		const lifecycle = liveLifecycle();
		const app = buildApp({ lifecycle, federationTokenStore });

		const res = await federationLogout(app);

		expect(res.status).toBe(200);
		expect(federationTokenStore.delete).toHaveBeenCalledExactlyOnceWith(SID, "google");
		expect(lifecycle.close).not.toHaveBeenCalled();
		expect(lifecycle.join).not.toHaveBeenCalled();
	});

	it("a session the lifecycle answers not live: 401 session not found", async () => {
		const app = buildApp({ lifecycle: fakeLifecycle() });

		const res = await federationLogout(app);

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "invalid_token", error_description: "session not found" });
	});

	it("a live session of another subject: 401 session not found", async () => {
		const lifecycle = fakeLifecycle({
			liveness: vi.fn(async () => ({
				outcome: "live" as const,
				session: { ...baseSession, sub: "someone-else" },
			})),
		});

		const res = await federationLogout(buildApp({ lifecycle }));

		expect(res.status).toBe(401);
	});

	it("a federation the session did not join: 404 federation_not_linked", async () => {
		const res = await federationLogout(buildApp({ lifecycle: liveLifecycle(["github"]) }));

		expect(res.status).toBe(404);
		expect(res.body.error).toBe("federation_not_linked");
	});

	it("a lifecycle that cannot answer: 503, one error line naming its step", async () => {
		for (const [step, lifecycle] of [
			["liveness", fakeLifecycle({ liveness: vi.fn(async () => outsideAnswer<never>()) })],
			[
				"federations",
				fakeLifecycle({
					liveness: vi.fn(async () => ({ outcome: "live" as const, session: baseSession })),
					federations: vi.fn(async () => outsideAnswer<never>()),
				}),
			],
		] as const) {
			const logger = createMockLogger();
			const res = await federationLogout(buildApp({ lifecycle, logger }));

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
			expect(logger.error).toHaveBeenCalledExactlyOnceWith(
				{ federation: "google", store: "session_lifecycle", step },
				"federation_logout_store_unavailable",
			);
		}
	});

	it("a lifecycle that throws: 503, logged with the error's projection", async () => {
		const logger = createMockLogger();
		const lifecycle = fakeLifecycle({
			liveness: vi.fn(async () => {
				throw new Error("lifecycle down");
			}),
		});

		const res = await federationLogout(buildApp({ lifecycle, logger }));

		expect(res.status).toBe(503);
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				federation: "google",
				store: "session_lifecycle",
				step: "liveness",
				err: expect.objectContaining({ name: "Error" }),
			}),
			"federation_logout_store_unavailable",
		);
	});
});

describe("the logout router's options", () => {
	it("take no per-session store: the session lifecycle ends and reads sessions", () => {
		expectTypeOf<LogoutRouterOptions>().not.toHaveProperty("sessionRPRegistry");
		expectTypeOf<LogoutRouterOptions>().not.toHaveProperty("sessionFamilyIndex");
		expectTypeOf<LogoutRouterOptions>().not.toHaveProperty("sessionFederationIndex");
		expectTypeOf<LogoutRouterOptions["sessionLifecycle"]>().toEqualTypeOf<SessionLifecycle>();
	});
});
