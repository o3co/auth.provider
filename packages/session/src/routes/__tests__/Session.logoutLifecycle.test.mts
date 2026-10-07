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
 * `POST /session/logout` where core's session lifecycle is installed: it
 * closes the session with `close(sid, "session_logout")`, which revokes its
 * families and tells its relying parties, instead of deleting the records the
 * session module owns.
 */

import {
	type AuditEvent,
	type AuditSink,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createSessionLifecycle,
	type FederationTokenStore,
	type Logger,
	loggableError,
	newRenewalNonce,
	readVersionedSessionLifecycle,
	type SessionCloseNotice,
	type SessionCookiePolicy,
	type SessionLifecycle,
	type SubjectSessionIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestCsrfTokenSigner, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createCsrfProtection } from "#/csrf.mjs";
import { createRouter } from "#/routes/Session.mjs";

const SID = "sid-1";
const HOUR = 3_600_000;
const SIGNER = createTestCsrfTokenSigner();
const csrf = createCsrfProtection({ signer: SIGNER, cookieName: "auth.session.csrf" });
const csrfToken = csrf.mint();

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

function mockLogger() {
	return {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	} as unknown as Logger & { error: ReturnType<typeof vi.fn> };
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

/** A user session store holding the live session, its writes spied. */
async function liveSessionStore(): Promise<UserSessionStore> {
	const store = createInMemoryUserSessionStore();
	await store.create({
		sid: SID,
		sub: "u-1",
		authTime: new Date(),
		expiresAt: new Date(Date.now() + HOUR),
		claims: {},
		amr: ["pwd"],
		authentication: undefined,
	});
	vi.spyOn(store, "delete");
	return store;
}

function spiedSubjectIndex(): SubjectSessionIndex {
	return {
		kind: "memory",
		addSid: vi.fn(),
		listSids: vi.fn(),
		removeSid: vi.fn(async () => undefined),
		removeBySubject: vi.fn(),
	} as unknown as SubjectSessionIndex;
}

interface Bag extends Record<string, unknown> {
	destroyed: boolean;
}

function buildApp(opts: {
	/** Absent: none is handed to the router. */
	readonly sessionLifecycle?: SessionLifecycle;
	readonly userSessionStore?: UserSessionStore;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	readonly federationTokenStore?: FederationTokenStore;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
	readonly bag?: Record<string, unknown>;
	/** The cookie store's destroy fails with it. */
	readonly destroyError?: Error;
	/** The session cookie's attributes; absent: a host-only, non-secure `auth.session`. */
	readonly sessionCookie?: Pick<SessionCookiePolicy, "name" | "secure" | "sameSite" | "domain">;
}) {
	const bag: Bag = {
		isAuthenticated: true,
		sid: SID,
		user: { id: "u-1", username: "alice" },
		...opts.bag,
		destroyed: false,
	};
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			...bag,
			destroy(cb: (err: Error | null) => void) {
				if (opts.destroyError) {
					cb(opts.destroyError);
					return;
				}
				bag.destroyed = true;
				cb(null);
			},
		};
		next();
	});
	app.use(
		"/session",
		createRouter(express, {
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			section: { rateLimit: { login: { windowMs: 60_000, limit: 100 } } },
			sessionCookie: opts.sessionCookie ?? {
				name: "auth.session",
				secure: false,
				sameSite: "lax",
				domain: undefined,
			},
			deploymentMode: "single",
			...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
			...(opts.federationTokenStore ? { federationTokenStore: opts.federationTokenStore } : {}),
			...(opts.subjectSessionIndex ? { subjectSessionIndex: opts.subjectSessionIndex } : {}),
			...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
			...(opts.sessionLifecycle ? { sessionLifecycle: opts.sessionLifecycle } : {}),
			logger: opts.logger ?? mockLogger(),
			csrfTokenSigner: SIGNER,
			requirements: resolverForTests([]),
		}),
	);
	return { app, bag };
}

/** A logout carrying the CSRF pair; its cookie is named after the session cookie, `sessionCookieName`. */
const logout = (app: express.Express, sessionCookieName = "auth.session") =>
	request(app)
		.post("/session/logout")
		.set("Cookie", `${sessionCookieName}.csrf=${csrfToken}`)
		.set(csrf.headerName, csrfToken);

describe("POST /session/logout through the session lifecycle: the close's answer", () => {
	it("done: closes the session for a session logout, through nothing but the lifecycle, and ends the cookie", async () => {
		const sessionLifecycle = fakeLifecycle();
		const federationTokenStore = {
			kind: "memory",
			removeBySid: vi.fn(async () => undefined),
		} as unknown as FederationTokenStore;
		const userSessionStore = await liveSessionStore();
		const subjectSessionIndex = spiedSubjectIndex();
		const { sink, events } = recordingSink();
		const { app, bag } = buildApp({
			sessionLifecycle,
			federationTokenStore,
			userSessionStore,
			subjectSessionIndex,
			auditSink: sink,
		});

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ message: "Logged out successfully" });
		expect(sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith(SID, "session_logout");
		// The close runs the work; the route's own deletes do not run.
		expect(federationTokenStore.removeBySid).not.toHaveBeenCalled();
		expect(userSessionStore.delete).not.toHaveBeenCalled();
		expect(subjectSessionIndex.removeSid).not.toHaveBeenCalled();
		expect(events).toEqual([]);
		expect(bag.destroyed).toBe(true);
	});

	it("pending: the close committed with work left; the logout succeeds and ends the cookie", async () => {
		const sessionLifecycle = fakeLifecycle({
			close: async () => ({ outcome: "pending", rps: [], federations: [] }),
		});
		const { sink, events } = recordingSink();
		const { app, bag } = buildApp({ sessionLifecycle, auditSink: sink });

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(bag.destroyed).toBe(true);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "logout.close_pending",
			subject: "u-1",
			details: { sid: SID },
		});
	});

	it("an outcome the lifecycle does not declare: the outage, 503, one error line, and the cookie kept for a retry", async () => {
		const logger = mockLogger();
		const { app, bag } = buildApp({
			sessionLifecycle: fakeLifecycle({
				close: (async () => ({ outcome: "undeclared" })) as unknown as SessionLifecycle["close"],
			}),
			logger,
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ sid: SID, store: "session_lifecycle", step: "close" },
			"session_logout_store_unavailable",
		);
		expect(bag.destroyed).toBe(false);
	});

	it("a lifecycle that rejects: the same 503, logged once at error with the rejection's projection, the cookie kept", async () => {
		const thrown = new Error("lifecycle exploded");
		const logger = mockLogger();
		const { app, bag } = buildApp({
			sessionLifecycle: fakeLifecycle({
				close: async () => {
					throw thrown;
				},
			}),
			logger,
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				sid: SID,
				store: "session_lifecycle",
				step: "close",
				err: loggableError(thrown),
			}),
			"session_logout_store_unavailable",
		);
		expect(logger.warn).not.toHaveBeenCalled();
		expect(bag.destroyed).toBe(false);
	});

	it("a close that rejects with a RangeError is the same outage: 503, logged once at error with its projection, the cookie kept", async () => {
		const thrown = new RangeError("Invalid array length");
		const logger = mockLogger();
		const { app, bag } = buildApp({
			sessionLifecycle: fakeLifecycle({
				close: async () => {
					throw thrown;
				},
			}),
			logger,
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ sid: SID, store: "session_lifecycle", step: "close", err: loggableError(thrown) },
			"session_logout_store_unavailable",
		);
		expect(logger.warn).not.toHaveBeenCalled();
		expect(bag.destroyed).toBe(false);
	});

	it("a cookie store that cannot destroy after a committed close: 503, the close not run again", async () => {
		const sessionLifecycle = fakeLifecycle();
		const logger = mockLogger();
		const { app } = buildApp({
			sessionLifecycle,
			logger,
			destroyError: new Error("cookie store down"),
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(sessionLifecycle.close).toHaveBeenCalledOnce();
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({ sid: SID, store: "cookie_session", step: "destroy" }),
			"session_logout_store_unavailable",
		);
	});

	it("a cookie with no sid closes nothing", async () => {
		const sessionLifecycle = fakeLifecycle();
		const { app, bag } = buildApp({ sessionLifecycle, bag: { sid: undefined } });

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(sessionLifecycle.close).not.toHaveBeenCalled();
		expect(bag.destroyed).toBe(true);
	});

	it("a cookie session the record was renewed away from closes nothing: the record is the renewed session's", async () => {
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({
			sid: SID,
			sub: "u-1",
			authTime: new Date(Date.now() - 60_000),
			expiresAt: new Date(Date.now() + HOUR),
			claims: {},
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
		// A step-up renewed the cookie session: the record carries the renewed one's nonce.
		await userSessionStore.recordSecondFactor(SID, {
			amr: ["otp", "mfa"],
			at: new Date(),
			renewalNonce: newRenewalNonce(),
		});
		const sessionLifecycle = fakeLifecycle();
		const { app, bag } = buildApp({
			sessionLifecycle,
			userSessionStore,
			bag: { renewalNonce: newRenewalNonce() },
		});

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(sessionLifecycle.close).not.toHaveBeenCalled();
		expect(bag.destroyed).toBe(true);
	});
});

describe("POST /session/logout through the session lifecycle: what the close runs", () => {
	it("revokes the session's families, tells its relying parties and deletes its user session", async () => {
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({
			sid: SID,
			sub: "u-1",
			authTime: new Date(),
			expiresAt: new Date(Date.now() + HOUR),
			claims: {},
			amr: ["pwd"],
			authentication: undefined,
		});
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: HOUR,
		});
		const notices: SessionCloseNotice[] = [];
		const store = createInMemorySessionLifecycleStore();
		const sessionLifecycle = createSessionLifecycle({
			store,
			userSessionStore,
			refreshTokenFamilyRevocation: revocation,
			federationTokenStore: {
				kind: "memory",
				removeBySid: vi.fn(async () => undefined),
				delete: vi.fn(async () => undefined),
			} as unknown as FederationTokenStore,
			notifier: () => ({
				notify: async (notice) => {
					notices.push(notice);
				},
			}),
			retainMs: HOUR,
			logger: { warn: () => undefined, error: () => undefined },
		});
		const rp = {
			clientId: "rp-1",
			backchannelLogoutUri: "https://rp-1.example/logout",
			backchannelLogoutSessionRequired: true,
			frontchannelLogoutUri: undefined,
			frontchannelLogoutSessionRequired: undefined,
			registeredAt: new Date(),
		};
		const established = await userSessionStore.get(SID);
		expect(
			await sessionLifecycle.open(SID, {
				sub: "u-1",
				expiresAt: established?.expiresAt ?? new Date(0),
			}),
		).toEqual({ outcome: "opened" });
		expect(await sessionLifecycle.join(SID, { rp, familyId: "fam-1" })).toEqual({
			outcome: "joined",
		});
		const { app, bag } = buildApp({ sessionLifecycle, userSessionStore });

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);
		expect(notices).toEqual([{ sid: SID, sub: "u-1", clientId: "rp-1", cause: "session_logout" }]);
		expect(await userSessionStore.get(SID)).toBeNull();
		expect(readVersionedSessionLifecycle(await store.read(SID))?.value.state).toBe("closed");
		expect(bag.destroyed).toBe(true);
	});
});

describe("where a user-session store is wired, core's session lifecycle is required", () => {
	it("refuses to build the router with a userSessionStore and no sessionLifecycle, naming both", async () => {
		const userSessionStore = await liveSessionStore();
		expect(() => buildApp({ userSessionStore })).toThrow(
			/userSessionStore is wired, but sessionLifecycle is not/,
		);
	});

	it("builds a sessionless router, with neither: its logout ends the cookie session alone", async () => {
		const { app, bag } = buildApp({});

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(bag.destroyed).toBe(true);
	});
});

/** The `Set-Cookie` lines of `res` that name the cookie `name`. */
const setCookiesNamed = (res: request.Response, name: string): string[] => {
	const raw = res.headers["set-cookie"] as unknown as string[] | string | undefined;
	const lines = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
	return lines.filter((line) => line.startsWith(`${name}=`));
};

/**
 * The session cookie is the session store module's: it expires the cookie of
 * a session destroyed during the request, whichever route destroyed it
 * (`src/__tests__/cookieSessionStore.test.mts`). The router sets no session
 * cookie of its own, so a router used without that module leaves the cookie
 * as it is.
 */
describe("POST /session/logout and the session cookie", () => {
	it("a logout that destroyed the cookie session sets no session cookie of its own", async () => {
		const { app, bag } = buildApp({ sessionLifecycle: fakeLifecycle() });

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(bag.destroyed).toBe(true);
		expect(setCookiesNamed(res, "auth.session")).toEqual([]);
	});

	it("nor under a configured name, domain, Secure and SameSite", async () => {
		const { app, bag } = buildApp({
			sessionLifecycle: fakeLifecycle(),
			sessionCookie: {
				name: "__Secure-app.sid",
				secure: true,
				sameSite: "none",
				domain: "auth.example.com",
			},
		});

		const res = await logout(app, "__Secure-app.sid");

		expect(res.status).toBe(200);
		expect(bag.destroyed).toBe(true);
		expect(setCookiesNamed(res, "__Secure-app.sid")).toEqual([]);
	});

	it("nor does a sessionless router's logout", async () => {
		const { app, bag } = buildApp({});

		const res = await logout(app);

		expect(res.status).toBe(200);
		expect(bag.destroyed).toBe(true);
		expect(setCookiesNamed(res, "auth.session")).toEqual([]);
	});

	it("a cookie store that cannot destroy leaves the session cookie as it is", async () => {
		const { app } = buildApp({
			sessionLifecycle: fakeLifecycle(),
			destroyError: new Error("cookie store down"),
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(setCookiesNamed(res, "auth.session")).toEqual([]);
	});

	it("a close that did not commit leaves the session cookie as it is", async () => {
		const { app } = buildApp({
			sessionLifecycle: fakeLifecycle({
				close: async () => {
					throw new Error("lifecycle down");
				},
			}),
		});

		const res = await logout(app);

		expect(res.status).toBe(503);
		expect(setCookiesNamed(res, "auth.session")).toEqual([]);
	});
});
