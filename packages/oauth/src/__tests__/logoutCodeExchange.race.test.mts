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
 * A logout and an authorization-code exchange on the same session, in each
 * order they can interleave: either the logout revokes the family the
 * exchange opened, or the exchange serves no token and revokes it itself.
 * The exchange joins the session through core's session lifecycle.
 *
 * Driven through the lifecycle's close and the real
 * grant, over core's memory stores. A checkpoint holds one side at a store
 * call while the other runs to its answer.
 */

import crypto from "node:crypto";
import {
	type CodeRepository,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	createSessionLifecycle,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type GrantHandler,
	type GrantResult,
	type RefreshTokenFamilyRevocation,
	readVersionedSessionLifecycle,
	type SessionJoinOutcome,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	expectOutageLine,
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";
import { outsideAnswer } from "./_helpers/sessionLifecycle.mjs";

const HOUR = 3_600_000;
const SID = "sid-race";
const SUBJECT = "u-1";
const CLIENT_ID = "client1";
const RP_URI = "https://rp.example/cb";
const CODE_VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(CODE_VERIFIER).digest("base64url");

const config = { ...makeValidAppConfig(), ...oauthConfigForTests() };

/**
 * One store call held open: `arrived` settles when the call reaches it, and
 * the call goes on once `release` is called.
 */
function checkpoint() {
	let arrive!: () => void;
	let release!: () => void;
	const arrived = new Promise<void>((resolve) => {
		arrive = resolve;
	});
	const released = new Promise<void>((resolve) => {
		release = resolve;
	});
	return {
		arrived,
		release,
		async pass(): Promise<void> {
			arrive();
			await released;
		},
	};
}

type Checkpoint = ReturnType<typeof checkpoint>;

/**
 * `store` with `method` held at `at` on its `nth` call (1-based), before the
 * call runs or after it answers. The other methods are the store's own.
 */
function holding<T extends object, K extends keyof T>(
	store: T,
	method: K,
	at: Checkpoint,
	opts: { readonly when: "before" | "after"; readonly nth?: number },
): T {
	const original = store[method] as unknown as (...args: unknown[]) => Promise<unknown>;
	let calls = 0;
	return {
		...store,
		[method]: async (...args: unknown[]) => {
			calls += 1;
			const held = calls === (opts.nth ?? 1);
			if (held && opts.when === "before") await at.pass();
			const answer = await original(...args);
			if (held && opts.when === "after") await at.pass();
			return answer;
		},
	};
}

/**
 * One session, opened in core's session lifecycle as a login opens it, and
 * every store both sides use. The grant and the logout each get their own
 * view of the stores (`grantStores`, `logoutStores`), so a checkpoint on one
 * side does not hold the other.
 */
async function world() {
	const userSessionStore = createInMemoryUserSessionStore();
	const expiresAt = new Date(Date.now() + HOUR);
	await userSessionStore.create({
		sid: SID,
		sub: SUBJECT,
		authTime: new Date(),
		expiresAt,
		claims: {},
		amr: undefined,
		authentication: undefined,
	});
	const familyStore = createMemoryRefreshTokenFamilyStore();
	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore: familyStore,
		accessTokenHorizonMs: HOUR,
	});
	const revocation = createRefreshTokenFamilyRevocation({
		refreshTokenFamilyStore: familyStore,
		accessTokenHorizonMs: HOUR,
	});
	const register = vi.fn(rotation.register);
	const logoutRevocation: RefreshTokenFamilyRevocation = {
		...revocation,
		revokeFamily: vi.fn(revocation.revokeFamily),
	};
	const federationTokenStore = {
		kind: "memory",
		removeBySid: vi.fn(async () => undefined),
	} as unknown as FederationTokenStore;

	const lifecycleStore: SessionLifecycleStore = createInMemorySessionLifecycleStore();
	const lifecycle: SessionLifecycle = createSessionLifecycle({
		store: lifecycleStore,
		userSessionStore,
		refreshTokenFamilyRevocation: revocation,
		federationTokenStore,
		retainMs: HOUR,
		logger: { warn: () => undefined, error: () => undefined },
	});
	expect(await lifecycle.open(SID, { sub: SUBJECT, expiresAt })).toEqual({ outcome: "opened" });

	const grantStores = {
		userSessionStore: userSessionStore as UserSessionStore,
		refreshTokenFamilyRotation: { ...rotation, register },
		refreshTokenFamilyRevocation: revocation as RefreshTokenFamilyRevocation,
		sessionLifecycle: lifecycle,
	};
	const logoutStores = {
		userSessionStore: userSessionStore as UserSessionStore,
		federationTokenStore,
		refreshTokenFamilyRevocation: logoutRevocation,
	};

	const exchange = async (
		stores: typeof grantStores = grantStores,
		logger: MockLogger = createMockLogger(),
	): Promise<GrantResult> => {
		const grant: GrantHandler = createAuthorizationGrant({
			sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
			...grantSettingsFrom(config),
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			clientRepository: { findById: async () => null, authenticate: async () => null },
			codeRepository: {
				consumeByCode: async () =>
					codeRecord({
						code: "the-code",
						client_id: CLIENT_ID,
						redirect_uri: RP_URI,
						code_challenge: S256_CHALLENGE,
						code_challenge_method: "S256",
						grantedScope: ["read"],
						sid: SID,
						// What /authorize records over this record, whose primary cannot be told.
						authentication: { primary: undefined, mfaAt: undefined },
					}),
				createCode: vi.fn(),
				findByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			logger,
			...stores,
		});
		const { result } = await grant.handle({
			body: {
				code: "the-code",
				client_id: CLIENT_ID,
				redirect_uri: RP_URI,
				code_verifier: CODE_VERIFIER,
			},
			session: { user: { id: SUBJECT } },
			issuer: "https://auth.example",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
		});
		return result;
	};

	/** The family the exchange registered. */
	const familyId = (): string => {
		expect(register).toHaveBeenCalledTimes(1);
		return register.mock.calls[0]?.[1] as string;
	};

	return {
		expiresAt,
		grantStores,
		logoutStores,
		exchange,
		familyId,
		revocation,
		logoutRevocation,
		userSessionStore,
		lifecycle,
		lifecycleStore,
	};
}

/** The refusal a session that ended during the exchange gets, with no token in it. */
function expectSessionInvalidated(result: GrantResult): void {
	expect(result).toMatchObject({
		status: 400,
		error: "invalid_grant",
		errorDescription: "session_invalidated",
	});
	expect(result).not.toHaveProperty("tokens");
}

describe("a code exchange that joins through the session lifecycle", () => {
	it("joins the relying party and its family to the session's lifecycle record", async () => {
		const w = await world();

		const result = await w.exchange();

		expect(result.status).toBe(200);
		const record = readVersionedSessionLifecycle(await w.lifecycleStore.read(SID));
		expect(record?.value.participants.map((p) => `${p.kind}:${p.id}`)).toEqual([
			`rp:${CLIENT_ID}`,
			`family:${w.familyId()}`,
		]);
	});

	it("a close through the lifecycle committed first: the join is refused, the exchange serves nothing, and the family is revoked", async () => {
		const w = await world();
		const lifecycle = w.lifecycle;
		// The session joined once before; its close commits and stays
		// pending, the user session still there.
		await lifecycle.join(SID, { familyId: "earlier-family" });
		vi.mocked(w.logoutStores.federationTokenStore.removeBySid).mockRejectedValueOnce(
			new Error("federation token store down"),
		);
		expect((await lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(await w.userSessionStore.get(SID)).not.toBeNull();

		const result = await w.exchange();

		expectSessionInvalidated(result);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a session gone before the join: the exchange serves nothing, and the family is revoked", async () => {
		const w = await world();
		const held = checkpoint();
		const exchange = w.exchange({
			...w.grantStores,
			userSessionStore: holding(w.grantStores.userSessionStore, "get", held, {
				when: "after",
				nth: 2,
			}),
		});
		await held.arrived;
		await w.userSessionStore.delete(SID);
		held.release();

		expectSessionInvalidated(await exchange);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a lifecycle that cannot answer: 503, and no token", async () => {
		const w = await world();
		const result = await w.exchange({
			...w.grantStores,
			sessionLifecycle: {
				...w.lifecycle,
				join: async () => outsideAnswer<SessionJoinOutcome>(),
			},
		});

		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(result).not.toHaveProperty("tokens");
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a lifecycle that cannot answer: one error line at the grant, beside the lifecycle's own", async () => {
		const w = await world();
		const logger = createMockLogger();
		await w.exchange(
			{
				...w.grantStores,
				sessionLifecycle: {
					...w.lifecycle,
					join: async () => outsideAnswer<SessionJoinOutcome>(),
				},
			},
			logger,
		);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{ store: "session_lifecycle", step: "join", clientId: CLIENT_ID },
			"authorization_grant_store_unavailable",
		);
	});

	it("a lifecycle join that rejects with its store's error: 503, no token, the family revoked", async () => {
		const w = await world();
		const result = await w.exchange({
			...w.grantStores,
			sessionLifecycle: {
				...w.lifecycle,
				join: async () => {
					throw storeReplyError();
				},
			},
		});

		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(result).not.toHaveProperty("tokens");
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a lifecycle join that rejects with its store's error: one error line at the grant, carrying the error's projection", async () => {
		const w = await world();
		const logger = createMockLogger();
		await w.exchange(
			{
				...w.grantStores,
				sessionLifecycle: {
					...w.lifecycle,
					join: async () => {
						throw storeReplyError();
					},
				},
			},
			logger,
		);
		expectOutageLine(logger, "authorization_grant_store_unavailable", {
			store: "session_lifecycle",
			step: "join",
			clientId: CLIENT_ID,
		});
		expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
	});

	it("a lifecycle join that rejects, and a revocation of its family that rejects too: 503, no token, the outage's line and then the revocation's", async () => {
		const w = await world();
		const logger = createMockLogger();
		const result = await w.exchange(
			{
				...w.grantStores,
				refreshTokenFamilyRevocation: {
					...w.grantStores.refreshTokenFamilyRevocation,
					revokeFamily: async () => {
						throw storeReplyError();
					},
				},
				sessionLifecycle: {
					...w.lifecycle,
					join: async () => {
						throw storeReplyError();
					},
				},
			},
			logger,
		);

		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(result).not.toHaveProperty("tokens");
		expect(logger.error.mock.calls.map(([, event]) => event)).toEqual([
			"authorization_grant_store_unavailable",
			"authorization_grant_refused_family_revocation_failed",
		]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			store: "session_lifecycle",
			step: "join",
			err: expect.objectContaining({ name: "ReplyError" }),
		});
		expect(logger.error.mock.calls[1]?.[0]).toMatchObject({
			familyId: w.familyId(),
			err: expect.objectContaining({ name: "ReplyError" }),
		});
		expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
	});

	it("a lifecycle join that rejects with a store-style RangeError: 503, no token, one error line with the projection, the family revoked", async () => {
		const w = await world();
		const logger = createMockLogger();
		const result = await w.exchange(
			{
				...w.grantStores,
				sessionLifecycle: {
					...w.lifecycle,
					join: async () => {
						throw Object.assign(new RangeError("Invalid array length"), {
							command: { name: "hset", args: [REFUSED_COMMAND_MARKER] },
						});
					},
				},
			},
			logger,
		);

		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(result).not.toHaveProperty("tokens");
		expectOutageLine(
			logger,
			"authorization_grant_store_unavailable",
			{ store: "session_lifecycle", step: "join", clientId: CLIENT_ID },
			"RangeError",
		);
		expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});
});
