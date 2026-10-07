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
 * The federation token route over core's session lifecycle: a refreshed token
 * is handed on only to a session that is still live once the refresh is
 * written. A close whose commit lands during the upstream refresh is answered
 * as a session that is not live, and its close work removes the stored tokens.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	createInMemorySessionLifecycleStore,
	createSymmetricKeyStore,
	type FederationProvider,
	type FederationTokenStore,
	type FederationTokens,
	memoryFederationTokenStoreModule,
	type SessionLifecycle,
	type SessionLiveness,
	type SupportsLock,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/federationToken.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import { expectOutageLine, storeReplyError } from "./_helpers/projectedLog.mjs";
import { lifecycleOver } from "./_helpers/sessionLifecycle.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const SID = "sid-1";
const SUB = "u-1";
const NAME = "google";

const mintAccessToken = (): Promise<string> =>
	new SignJWT({ sub: SUB, sid: SID, azp: "client-1", aud: "client-1", family_id: "fam-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(createSecretKey(Buffer.from(SECRET)));

/** The stored connection: due unless `expiresAt` says otherwise. */
const link = (expiresAt: Date | null = new Date(Date.now() - 1000)): FederationTokens => ({
	accessToken: "old-at",
	refreshToken: "old-rt",
	idToken: "old-id",
	expiresAt,
	tokenType: "Bearer",
	scope: "openid email",
	grantedScope: "openid email",
	obtainedAt: undefined,
});

type Store = FederationTokenStore & SupportsLock;

const memoryStore = (): Store => {
	const store = memoryFederationTokenStoreModule.provides?.federationTokenStore?.({} as never) as
		| Store
		| undefined;
	if (store === undefined) throw new Error("core's memory module provides no store");
	return store;
};

/** Resolves once `open()` is called; `wait` is what callers await. */
const latch = () => {
	let open!: () => void;
	const wait = new Promise<void>((resolve) => {
		open = resolve;
	});
	return { open, wait };
};

interface Route {
	readonly store: Store;
	readonly lifecycle: SessionLifecycle;
	/** Core's lifecycle, whose `liveness` the route's answers by default. */
	readonly real: SessionLifecycle;
	readonly liveness: ReturnType<typeof vi.fn<(sid: string) => Promise<SessionLiveness>>>;
	readonly logger: MockLogger;
	readonly auditSink: AuditSink & { record: ReturnType<typeof vi.fn> };
	readonly refreshToken: ReturnType<typeof vi.fn>;
	/** Lets the close's removal of the federation tokens run. */
	readonly releaseRemoval: () => void;
	/** Resolves once the close's removal of the federation tokens has begun. */
	readonly removalBegun: Promise<void>;
	readonly post: () => Promise<request.Response>;
}

/**
 * The route over core's lifecycle and in-memory stores, the session opened
 * for `SUB` and joined by the federation, its record seeded with `seed`. The
 * close's removal of the federation tokens waits for `releaseRemoval`, so a
 * close can commit while its work is still outstanding. The provider's
 * refresh runs `refresh` with the lifecycle and the store, and answers what it
 * returns, or a token with an hour's life when it returns nothing.
 */
const route = async (opts: {
	seed: FederationTokens;
	refresh?: (
		lifecycle: SessionLifecycle,
		removalBegun: Promise<void>,
		store: Store,
	) => Promise<unknown>;
}): Promise<Route> => {
	const store = memoryStore();
	await store.attach(SID, NAME, opts.seed);

	const removal = latch();
	const begun = latch();
	const heldRemoval = new Proxy(store, {
		get(target, property) {
			if (property === "removeBySid") {
				return async (sid: string) => {
					begun.open();
					await removal.wait;
					return target.removeBySid(sid);
				};
			}
			const value = Reflect.get(target, property, target);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});

	const session: UserSession = {
		sid: SID,
		sub: SUB,
		authTime: new Date(),
		createdAt: new Date(),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: {},
		amr: undefined,
		authentication: undefined,
	};
	const sessionStore: UserSessionStore = {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn(async () => session),
		delete: vi.fn(async () => {}),
	};
	const lifecycleStore = createInMemorySessionLifecycleStore();
	expect((await lifecycleStore.open(SID, SUB, session.expiresAt)).outcome).toBe("opened");
	const real = lifecycleOver({
		userSessionStore: sessionStore,
		refreshTokenFamilyRevocation: { isFamilyRevoked: vi.fn(), revokeFamily: vi.fn() },
		federationTokenStore: heldRemoval,
		store: lifecycleStore,
	});
	expect(await real.join(SID, { federation: NAME })).toEqual({ outcome: "joined" });
	const liveness = vi.fn((sid: string) => real.liveness(sid));
	const lifecycle: SessionLifecycle = { ...real, liveness };

	const clientRepository: ClientRepository = {
		findById: vi.fn().mockResolvedValue({
			clientId: "client-1",
			allowedRedirectUris: [],
			allowedScopes: [],
			allowedAzpForFederationToken: true,
		}),
		authenticate: vi.fn(),
	};
	const logger = createMockLogger();
	const auditSink = { kind: "mock", record: vi.fn().mockResolvedValue(undefined) };
	const refreshToken = vi.fn(async () => {
		const answer = await opts.refresh?.(lifecycle, begun.wait, store);
		return answer ?? { accessToken: "new-at", expiresIn: 3600, refreshToken: "new-rt" };
	});
	const provider = {
		name: NAME,
		scope: ["openid"],
		buildAuthorizationUrl: () => new URL("https://google.example/auth"),
		exchangeCode: async () => ({ issuer: "https://google.example", sub: "s", expiresAt: null }),
		refreshToken,
	} as unknown as FederationProvider;
	const app = express();
	app.use(
		"/oauth",
		createRouter(express, {
			keyStore,
			sessionLifecycle: lifecycle,
			refreshTokenFamilyRevocation: {
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				revokeFamily: vi.fn(),
			},
			federationTokenStore: store,
			clientRepository,
			getFederationProviders: () => new Map([[NAME, provider]]),
			logger,
			auditSink,
		}),
	);
	const post = async () =>
		request(app)
			.post(`/oauth/federation/${NAME}/token`)
			.set("Authorization", `Bearer ${await mintAccessToken()}`)
			.send();
	return {
		store,
		lifecycle,
		real,
		liveness,
		logger,
		auditSink,
		refreshToken,
		releaseRemoval: removal.open,
		removalBegun: begun.wait,
		post,
	};
};

/** A relink of the federation in the session: a new connection, not due. */
const relink = (): FederationTokens => ({
	accessToken: "relinked-at",
	refreshToken: "relinked-rt",
	idToken: "relinked-id",
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: "Bearer",
	scope: "openid",
	grantedScope: "openid",
	obtainedAt: undefined,
});

const invalidGrant = (): Error =>
	Object.assign(new Error("server responded with an error in the response body"), {
		name: "ResponseBodyError",
		error: "invalid_grant",
		status: 400,
	});

const audited = (r: Route, type: string): unknown[] =>
	r.auditSink.record.mock.calls.filter(([event]) => (event as { type: string }).type === type);

const expectSessionNotLive = (res: request.Response): void => {
	expect(res.status).toBe(401);
	expect(res.body).toEqual({ error: "invalid_token", error_description: "session not found" });
	expect(res.headers["www-authenticate"]).toBe(
		'Bearer error="invalid_token", error_description="session not found"',
	);
	expect(res.body.access_token).toBeUndefined();
};

describe("federation token route — a refreshed token is handed on only to a session still live", () => {
	it("answers a close that commits during the upstream refresh as a session that is not live", async () => {
		let closed: Promise<unknown> | undefined;
		const r = await route({
			seed: link(),
			refresh: async (lifecycle, removalBegun) => {
				closed = lifecycle.close(SID, "rp_logout");
				// The closing commit has landed; the removal of the tokens has not run.
				await removalBegun;
			},
		});

		const res = await r.post();

		expectSessionNotLive(res);
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(audited(r, "federation.token.success")).toEqual([]);
		expect(r.logger.error).not.toHaveBeenCalled();

		r.releaseRemoval();
		await closed;
		expect(await r.store.get(SID, NAME)).toBeNull();
	});

	it("answers a session the read after the refresh finds live for another subject as one that is not live", async () => {
		const r = await route({ seed: link() });
		r.releaseRemoval();
		// The first read, before the refresh, is the lifecycle's own.
		r.liveness
			.mockImplementationOnce((sid) => r.real.liveness(sid))
			.mockImplementationOnce(async () => ({
				outcome: "live",
				session: {
					sid: SID,
					sub: "someone-else",
					authTime: new Date(),
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + 3_600_000),
					claims: {},
					amr: undefined,
					authentication: undefined,
				},
			}));

		const res = await r.post();

		expectSessionNotLive(res);
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(audited(r, "federation.token.success")).toEqual([]);
	});

	it("answers 503 when the liveness read after the refresh rejects", async () => {
		const r = await route({ seed: link() });
		r.releaseRemoval();
		r.liveness
			.mockImplementationOnce((sid) => r.real.liveness(sid))
			.mockImplementationOnce(async () => Promise.reject(storeReplyError()));

		const res = await r.post();

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(audited(r, "federation.token.success")).toEqual([]);
		expectOutageLine(r.logger, "federation_token_store_unavailable", {
			federation: NAME,
			store: "session_lifecycle",
			step: "liveness",
		});
	});

	it("answers a live session's refresh as before, reading its liveness once more after the write", async () => {
		const r = await route({ seed: link() });
		r.releaseRemoval();

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("new-at");
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(r.liveness).toHaveBeenCalledTimes(2);
		expect(r.liveness).toHaveBeenNthCalledWith(2, SID);
		expect((await r.store.get(SID, NAME))?.accessToken).toBe("new-at");
		expect(audited(r, "federation.token.success")).toEqual([
			[expect.objectContaining({ details: { federation: NAME, refreshed: true } })],
		]);
	});

	it("reads liveness once for a stored token that is not due", async () => {
		const r = await route({ seed: link(new Date(Date.now() + 3_600_000)) });
		r.releaseRemoval();

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("old-at");
		expect(r.refreshToken).not.toHaveBeenCalled();
		expect(r.liveness).toHaveBeenCalledTimes(1);
	});
});

describe("federation token route — a stored token is handed on after an upstream refresh only to a session still live", () => {
	it.each([
		["no refresh token", {}],
		["a rotated refresh token", { refreshToken: "new-rt" }],
	])(
		"answers a close that commits during a refresh answering a refused lifetime and %s as a session that is not live",
		async (_label, rotation) => {
			let closed: Promise<unknown> | undefined;
			const r = await route({
				seed: link(null),
				refresh: async (lifecycle, removalBegun) => {
					closed = lifecycle.close(SID, "rp_logout");
					await removalBegun;
					return { accessToken: "new-at", expiresIn: Number.NaN, ...rotation };
				},
			});

			const res = await r.post();

			expectSessionNotLive(res);
			expect(r.refreshToken).toHaveBeenCalledTimes(1);
			expect(audited(r, "federation.token.success")).toEqual([]);
			expect(r.liveness).toHaveBeenCalledTimes(2);

			r.releaseRemoval();
			await closed;
			expect(await r.store.get(SID, NAME)).toBeNull();
		},
	);

	it("answers a live session's refresh answering a refused lifetime with the stored token, reading liveness once more", async () => {
		const r = await route({
			seed: link(null),
			refresh: async () => ({ accessToken: "new-at", expiresIn: Number.NaN }),
		});
		r.releaseRemoval();

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("old-at");
		expect(r.liveness).toHaveBeenCalledTimes(2);
	});

	it.each([
		["answers a token", async () => undefined],
		[
			"refuses the refresh token",
			async () => {
				throw invalidGrant();
			},
		],
	])(
		"answers a relink and a close that both land while the upstream %s as a session that is not live",
		async (_label, answer) => {
			let closed: Promise<unknown> | undefined;
			const r = await route({
				seed: link(),
				refresh: async (lifecycle, removalBegun, store) => {
					await store.attach(SID, NAME, relink());
					closed = lifecycle.close(SID, "rp_logout");
					await removalBegun;
					return answer();
				},
			});

			const res = await r.post();

			expectSessionNotLive(res);
			expect(r.refreshToken).toHaveBeenCalledTimes(1);
			expect(audited(r, "federation.token.success")).toEqual([]);
			expect(r.liveness).toHaveBeenCalledTimes(2);

			r.releaseRemoval();
			await closed;
			expect(await r.store.get(SID, NAME)).toBeNull();
		},
	);

	it("answers a relink that lands during a live session's refresh with the relink's token, reading liveness once more", async () => {
		const r = await route({
			seed: link(),
			refresh: async (_lifecycle, _removalBegun, store) => {
				await store.attach(SID, NAME, relink());
				return undefined;
			},
		});
		r.releaseRemoval();

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("relinked-at");
		expect(r.liveness).toHaveBeenCalledTimes(2);
	});

	it("answers 503 when the liveness read before serving the relink rejects", async () => {
		const r = await route({
			seed: link(),
			refresh: async (_lifecycle, _removalBegun, store) => {
				await store.attach(SID, NAME, relink());
				return undefined;
			},
		});
		r.releaseRemoval();
		r.liveness
			.mockImplementationOnce((sid) => r.real.liveness(sid))
			.mockImplementationOnce(async () => Promise.reject(storeReplyError()));

		const res = await r.post();

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(audited(r, "federation.token.success")).toEqual([]);
		expect(r.logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ federation: NAME, store: "session_lifecycle", step: "liveness" }),
			"federation_token_store_unavailable",
		);
	});
});

describe("federation token route — a liveness reply outside the lifecycle's contract is the outage", () => {
	const malformed: ReadonlyArray<readonly [string, unknown]> = [
		["null", null],
		["undefined", undefined],
		["a string", "live"],
		["live with a null session", { outcome: "live", session: null }],
		["live with no session", { outcome: "live" }],
		["live with a session that is not an object", { outcome: "live", session: "u-1" }],
		["an unknown outcome", { outcome: "unrecognised" }],
	];

	const expectOutage = (r: Route, res: request.Response): void => {
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(audited(r, "federation.token.success")).toEqual([]);
		expect(r.logger.error).toHaveBeenCalledTimes(1);
		expect(r.logger.error).toHaveBeenCalledWith(
			{ federation: NAME, store: "session_lifecycle", step: "liveness" },
			"federation_token_store_unavailable",
		);
	};

	it.each(malformed)(
		"answers 503 when the read after the refresh answers %s",
		async (_label, reply) => {
			const r = await route({ seed: link() });
			r.releaseRemoval();
			r.liveness
				.mockImplementationOnce((sid) => r.real.liveness(sid))
				.mockImplementationOnce(async () => reply as SessionLiveness);

			const res = await r.post();

			expectOutage(r, res);
			expect(r.refreshToken).toHaveBeenCalledTimes(1);
		},
	);

	it.each(malformed)("answers 503 when the first read answers %s", async (_label, reply) => {
		const r = await route({ seed: link() });
		r.releaseRemoval();
		r.liveness.mockImplementationOnce(async () => reply as SessionLiveness);

		const res = await r.post();

		expectOutage(r, res);
		expect(r.refreshToken).not.toHaveBeenCalled();
	});
});

describe("federation token route — a token another request refreshed during the lock wait is handed on only to a session still live", () => {
	/** A sibling's refresh lands while this request waits for the lock: the record is fresh. */
	const siblingRefreshed = (): FederationTokens => ({
		...link(new Date(Date.now() + 3_600_000)),
		accessToken: "sibling-at",
		refreshToken: "sibling-rt",
	});

	/** Runs `during` with the store before this request's lock is acquired. */
	const waitForLock = (r: Route, during: () => Promise<void>): void => {
		const acquire = r.store.acquireLock.bind(r.store);
		r.store.acquireLock = async (...args) => {
			await during();
			return acquire(...args);
		};
	};

	it("answers a close that commits during the lock wait as a session that is not live", async () => {
		const r = await route({ seed: link() });
		let closed: Promise<unknown> | undefined;
		waitForLock(r, async () => {
			await r.store.attach(SID, NAME, siblingRefreshed());
			closed = r.lifecycle.close(SID, "rp_logout");
			await r.removalBegun;
		});

		const res = await r.post();

		expectSessionNotLive(res);
		expect(r.refreshToken).not.toHaveBeenCalled();
		expect(audited(r, "federation.token.success")).toEqual([]);
		expect(r.liveness).toHaveBeenCalledTimes(2);

		r.releaseRemoval();
		await closed;
		expect(await r.store.get(SID, NAME)).toBeNull();
	});

	it("answers a live session with the token refreshed during the lock wait, reading liveness once more", async () => {
		const r = await route({ seed: link() });
		r.releaseRemoval();
		waitForLock(r, async () => {
			await r.store.attach(SID, NAME, siblingRefreshed());
		});

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("sibling-at");
		expect(r.refreshToken).not.toHaveBeenCalled();
		expect(r.liveness).toHaveBeenCalledTimes(2);
	});

	it("answers 503 when the liveness read after the lock wait rejects", async () => {
		const r = await route({ seed: link() });
		r.releaseRemoval();
		waitForLock(r, async () => {
			await r.store.attach(SID, NAME, siblingRefreshed());
		});
		r.liveness
			.mockImplementationOnce((sid) => r.real.liveness(sid))
			.mockImplementationOnce(async () => Promise.reject(storeReplyError()));

		const res = await r.post();

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(r.refreshToken).not.toHaveBeenCalled();
		expect(audited(r, "federation.token.success")).toEqual([]);
		expectOutageLine(r.logger, "federation_token_store_unavailable", {
			federation: NAME,
			store: "session_lifecycle",
			step: "liveness",
		});
	});
});
