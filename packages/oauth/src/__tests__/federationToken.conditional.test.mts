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
 * The federation token route over core's in-memory store: it writes only the
 * record it read. A logout, an unlink or a relink landing while a refresh is
 * in flight is never undone or overwritten, and the route never removes a
 * link from the session's index itself.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuditSink,
	type ClientRepository,
	createSymmetricKeyStore,
	type FederationProvider,
	type FederationTokenStore,
	type FederationTokens,
	memoryFederationTokenStoreModule,
	type SessionFederationIndex,
	type SupportsLock,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/federationToken.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	expectBestEffortWarn,
	expectOutageLine,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const SID = "sid-1";
const NAME = "google";

const mintAccessToken = (): Promise<string> =>
	new SignJWT({ sub: "u-1", sid: SID, azp: "client-1", family_id: "fam-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.setIssuer("https://auth.example.com")
		.sign(createSecretKey(Buffer.from(SECRET)));

/** The connection the refresh starts from: due, with every field named. */
const linkA = (): FederationTokens => ({
	accessToken: "a-at",
	refreshToken: "a-rt",
	idToken: "a-id",
	expiresAt: new Date(Date.now() - 1000),
	tokenType: "Bearer",
	scope: "openid email",
	grantedScope: "openid email",
});

/** A relink of the same federation in the same session: a new, narrower connection, not due. */
const linkB = (): FederationTokens => ({
	accessToken: "b-at",
	refreshToken: "b-rt",
	idToken: "b-id",
	expiresAt: new Date(Date.now() + 3_600_000),
	tokenType: "Bearer",
	scope: "openid",
	grantedScope: "openid",
});

const invalidGrant = (): Error =>
	Object.assign(new Error("server responded with an error in the response body"), {
		name: "ResponseBodyError",
		error: "invalid_grant",
		status: 400,
	});

type Store = FederationTokenStore & SupportsLock;

const memoryStore = (): Store => {
	const store = memoryFederationTokenStoreModule.provides?.federationTokenStore?.({} as never) as
		| Store
		| undefined;
	if (store === undefined) throw new Error("core's memory module provides no store");
	return store;
};

interface Route {
	readonly store: Store;
	readonly index: SessionFederationIndex;
	readonly logger: MockLogger;
	readonly auditSink: AuditSink & { record: ReturnType<typeof vi.fn> };
	readonly refreshToken: ReturnType<typeof vi.fn>;
	readonly post: () => Promise<request.Response>;
}

/**
 * The route over `store`, seeded with `seed` unless it is `null`; the
 * provider's refresh runs `refresh` with the store, which is where a
 * concurrent logout or relink lands.
 */
const route = async (opts: {
	seed: FederationTokens | null;
	refresh?: (store: Store) => Promise<unknown>;
	store?: Store;
}): Promise<Route> => {
	const store = opts.store ?? memoryStore();
	if (opts.seed !== null) await store.attach(SID, NAME, opts.seed);
	const index: SessionFederationIndex = {
		kind: "memory",
		addFederation: vi.fn(async () => {}),
		listFederations: vi.fn(async () => [NAME]),
		removeFederation: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
	} as SessionFederationIndex;
	const sessionStore: UserSessionStore = {
		kind: "memory",
		create: vi.fn(),
		get: vi.fn().mockResolvedValue({
			sid: SID,
			sub: "u-1",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			amr: undefined,
			authentication: undefined,
		}),
		delete: vi.fn(),
	};
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
	const refreshToken = vi.fn(async () =>
		opts.refresh === undefined
			? { accessToken: "new-at", expiresIn: 3600, refreshToken: "rotated-rt" }
			: opts.refresh(store),
	);
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
			userSessionStore: sessionStore,
			sessionFederationIndex: index,
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
	return { store, index, logger, auditSink, refreshToken, post };
};

const audited = (r: Route, type: string): unknown[] =>
	r.auditSink.record.mock.calls.filter(([event]) => (event as { type: string }).type === type);

describe("federation token route — a refresh never restores a record removed while it was in flight", () => {
	it("answers 404 and leaves the record removed when a logout lands during the upstream call", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.delete(SID, NAME);
				return { accessToken: "new-at", expiresIn: 3600, refreshToken: "rotated-rt" };
			},
		});

		const res = await r.post();

		expect(res.status).toBe(404);
		expect(res.body.error).toBe("federation_not_linked");
		expect(await r.store.get(SID, NAME)).toBeNull();
		expect(r.index.removeFederation).not.toHaveBeenCalled();
		expect(audited(r, "federation.token.success")).toEqual([]);
		expectBestEffortWarn(
			r.logger,
			"federation_token_refresh_discarded",
			{ federation: NAME, reason: "record_gone" },
			null,
		);
	});
});

describe("federation token route — a refresh never overwrites a relink that landed while it was in flight", () => {
	it("keeps a logout plus relink whole, and answers the relink's token", async () => {
		const b = linkB();
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.delete(SID, NAME);
				await store.attach(SID, NAME, b);
				return { accessToken: "new-at", expiresIn: 3600, refreshToken: "rotated-rt" };
			},
		});

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("b-at");
		expect(res.body.scope).toBe("openid");
		expect(await r.store.get(SID, NAME)).toEqual(b);
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(audited(r, "federation.token.success")).toEqual([
			[expect.objectContaining({ details: { federation: NAME, refreshed: false } })],
		]);
		expectBestEffortWarn(
			r.logger,
			"federation_token_refresh_discarded",
			{ federation: NAME, reason: "record_replaced" },
			null,
		);
	});

	it("answers 503 with no second upstream call when the record that won is itself due", async () => {
		const due = { ...linkB(), expiresAt: new Date(Date.now() - 1000) };
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.attach(SID, NAME, due);
				return { accessToken: "new-at", expiresIn: 3600, refreshToken: "rotated-rt" };
			},
		});

		const res = await r.post();

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.body.error_description).toBe(
			"the federation token was replaced concurrently; retry",
		);
		expect(r.refreshToken).toHaveBeenCalledTimes(1);
		expect(await r.store.get(SID, NAME)).toEqual(due);
	});

	it("answers 404 when the record that won is gone by the time it is read again", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.attach(SID, NAME, linkB());
				return { accessToken: "new-at", expiresIn: 3600 };
			},
		});
		const replaceIf = r.store.replaceIf.bind(r.store);
		r.store.replaceIf = async (...args) => {
			const answer = await replaceIf(...args);
			await r.store.delete(SID, NAME);
			return answer;
		};

		const res = await r.post();

		expect(res.status).toBe(404);
		expect(res.body.error).toBe("federation_not_linked");
		expect(await r.store.get(SID, NAME)).toBeNull();
	});

	it("keeps a relink that lands before the upstream refuses the refresh token, and serves it", async () => {
		const b = linkB();
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.attach(SID, NAME, b);
				throw invalidGrant();
			},
		});

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("b-at");
		expect(await r.store.get(SID, NAME)).toEqual(b);
		expect(audited(r, "federation.token.reauthentication_required")).toEqual([]);
		expect(r.index.removeFederation).not.toHaveBeenCalled();
	});

	it("keeps a relink that lands during a refused refresh, and does not keep the rotated token on it", async () => {
		const b = linkB();
		const r = await route({
			seed: linkA(),
			// No access token: refused, with the rotated refresh token kept if it can be.
			refresh: async (store) => {
				await store.attach(SID, NAME, b);
				return { refreshToken: "rotated-rt" };
			},
		});

		const res = await r.post();

		expect(res.status).toBe(500);
		expect(res.body.error).toBe("refresh_failed");
		expect(await r.store.get(SID, NAME)).toEqual(b);
		expectBestEffortWarn(
			r.logger,
			"federation_token_keep_rotated_skipped",
			{ federation: NAME, reason: "replaced_concurrently" },
			null,
		);
	});

	it("keeps a relink that reuses the refresh token the refresh was made from, with its own id_token", async () => {
		// Equal refresh tokens are not one connection: the relink's record stays as linked.
		const b = { ...linkB(), refreshToken: "a-rt" };
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.attach(SID, NAME, b);
				return { refreshToken: "rotated-rt", idToken: "rotated-id" };
			},
		});

		const res = await r.post();

		expect(res.status).toBe(500);
		expect(await r.store.get(SID, NAME)).toEqual(b);
	});

	it("keeps the rotated refresh token on the record it was made from when nothing replaced it", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async () => ({ refreshToken: "rotated-rt", idToken: "rotated-id" }),
		});

		const res = await r.post();

		expect(res.status).toBe(500);
		expect(await r.store.get(SID, NAME)).toEqual({
			...linkA(),
			expiresAt: expect.any(Date),
			refreshToken: "rotated-rt",
			idToken: "rotated-id",
		});
	});
});

describe("federation token route — it never removes a link from the session's index itself", () => {
	it("answers a link with no record 404, leaving the index alone", async () => {
		const r = await route({ seed: null });

		const res = await r.post();

		expect(res.status).toBe(404);
		expect(res.body.error).toBe("federation_not_linked");
		expect(r.index.removeFederation).not.toHaveBeenCalled();
	});

	it("removes the record on an upstream invalid_grant, leaving the index alone", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async () => {
				throw invalidGrant();
			},
		});

		const res = await r.post();

		expect(res.status).toBe(410);
		expect(res.body.error).toBe("re_authentication_required");
		expect(await r.store.get(SID, NAME)).toBeNull();
		expect(r.index.removeFederation).not.toHaveBeenCalled();
		expect(audited(r, "federation.token.reauthentication_required")).toHaveLength(1);
	});

	it("still answers 410 when the record is gone before the clean-up", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async (store) => {
				await store.delete(SID, NAME);
				throw invalidGrant();
			},
		});

		const res = await r.post();

		expect(res.status).toBe(410);
		expect(audited(r, "federation.token.reauthentication_required")).toHaveLength(1);
	});

	it("still answers 410 when the clean-up cannot reach the store, logging it", async () => {
		const r = await route({
			seed: linkA(),
			refresh: async () => {
				throw invalidGrant();
			},
		});
		r.store.removeIf = vi.fn().mockRejectedValue(storeReplyError());

		const res = await r.post();

		expect(res.status).toBe(410);
		expectBestEffortWarn(r.logger, "federation_token_cleanup_failed", {
			federation: NAME,
			store: "federation_token",
			step: "remove_if",
		});
	});
});

describe("federation token route — a stored record holding no usable access token", () => {
	const unusable = (): FederationTokens => ({
		...linkB(),
		accessToken: "",
	});

	it("is removed from the store, not only unlisted, and answered 404", async () => {
		const r = await route({ seed: unusable() });

		const res = await r.post();

		expect(res.status).toBe(404);
		expect(res.body.error).toBe("federation_not_linked");
		expect(await r.store.get(SID, NAME)).toBeNull();
		expect(r.index.removeFederation).not.toHaveBeenCalled();
		expectBestEffortWarn(r.logger, "federation_token_record_unusable", { federation: NAME }, null);
	});

	it("is removed only as it was read: a relink landing before the removal is kept", async () => {
		const b = linkB();
		const r = await route({ seed: unusable() });
		const removeIf = r.store.removeIf.bind(r.store);
		r.store.removeIf = async (...args) => {
			await r.store.attach(SID, NAME, b);
			return removeIf(...args);
		};

		const res = await r.post();

		expect(res.status).toBe(404);
		expect(await r.store.get(SID, NAME)).toEqual(b);
	});

	it("is still refreshed from its refresh token when it is due", async () => {
		const r = await route({ seed: { ...linkA(), accessToken: "" } });

		const res = await r.post();

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("new-at");
		expect((await r.store.get(SID, NAME))?.accessToken).toBe("new-at");
	});
});

describe("federation token route — a write the store answers outside its contract is an outage", () => {
	it.each([
		["a malformed answer", async () => ({ outcome: "updated" })],
		[
			"a rejection",
			async () => {
				throw storeReplyError();
			},
		],
	])("answers 503 for %s, and hands nothing on", async (_label, answer) => {
		const r = await route({ seed: linkA() });
		r.store.replaceIf = vi.fn(answer) as unknown as Store["replaceIf"];

		const res = await r.post();

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.body.error_description).toBe("federation token store unavailable");
		expect(audited(r, "federation.token.success")).toEqual([]);
		expectOutageLine(
			r.logger,
			"federation_token_store_unavailable",
			{ federation: NAME, store: "federation_token", step: "replace_if" },
			_label === "a rejection" ? "ReplyError" : "TypeError",
		);
	});
});
