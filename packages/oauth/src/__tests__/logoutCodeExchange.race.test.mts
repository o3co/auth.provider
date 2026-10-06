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
 * Driven through `cascadeLogout` or the lifecycle's close, and the real
 * grant, over core's memory stores. A checkpoint holds one side at a store
 * call while the other runs to its answer.
 */

import crypto from "node:crypto";
import {
	type CodeRepository,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionLifecycleStore,
	createInMemorySessionRPRegistry,
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
	type SessionFamilyIndex,
	type SessionLifecycle,
	type SessionLifecycleStore,
	type SupportsSessionEnd,
	supportsSessionEnd,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { cascadeLogout } from "#/logout/cascadeLogout.mjs";
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

/** An index with only the port's three methods: no session-end capability. */
function withoutSessionEnd(index: SessionFamilyIndex): SessionFamilyIndex {
	return {
		kind: index.kind,
		addFamilyId: vi.fn(index.addFamilyId),
		listFamilyIds: vi.fn(index.listFamilyIds),
		removeBySid: vi.fn(index.removeBySid),
	};
}

/**
 * One session and every store both sides use. The grant and the logout each
 * get their own view of the stores (`grantStores`, `logoutStores`), so a
 * checkpoint on one side does not hold the other.
 */
async function world(
	opts: { readonly index?: SessionFamilyIndex; readonly lifecycle?: boolean } = {},
) {
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
	const memoryIndex = createInMemorySessionFamilyIndex();
	const index = opts.index ?? memoryIndex;
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
	/** What each guarded add answered, in order. */
	const answers: Array<"added" | "ended"> = [];
	const recording = (
		capable: SessionFamilyIndex & SupportsSessionEnd,
	): SessionFamilyIndex & SupportsSessionEnd => ({
		...capable,
		addFamilyIdUnlessEnded: async (sid, familyId, until) => {
			const answer = await capable.addFamilyIdUnlessEnded(sid, familyId, until);
			answers.push(answer);
			return answer;
		},
	});
	const recordingIndex: SessionFamilyIndex = supportsSessionEnd(index) ? recording(index) : index;
	const logoutRevocation: RefreshTokenFamilyRevocation = {
		...revocation,
		revokeFamily: vi.fn(revocation.revokeFamily),
	};
	const federationTokenStore = {
		kind: "memory",
		removeBySid: vi.fn(async () => undefined),
	} as unknown as FederationTokenStore;
	const sessionRPRegistry = createInMemorySessionRPRegistry();
	const sessionFederationIndex = createInMemorySessionFederationIndex();

	// Core's session lifecycle over the same stores, written beside the
	// per-session ones (its bridge), when the composition installs it.
	const lifecycleStore: SessionLifecycleStore = createInMemorySessionLifecycleStore();
	const lifecycle: SessionLifecycle | undefined = opts.lifecycle
		? createSessionLifecycle({
				store: lifecycleStore,
				userSessionStore,
				refreshTokenFamilyRevocation: revocation,
				federationTokenStore,
				sessionRPRegistry,
				sessionFamilyIndex: recordingIndex,
				sessionFederationIndex,
				retainMs: HOUR,
				logger: { warn: () => undefined, error: () => undefined },
			})
		: undefined;

	const grantStores = {
		userSessionStore: userSessionStore as UserSessionStore,
		sessionFamilyIndex: recordingIndex,
		sessionRPRegistry,
		refreshTokenFamilyRotation: { ...rotation, register },
		refreshTokenFamilyRevocation: revocation as RefreshTokenFamilyRevocation,
		...(lifecycle === undefined ? {} : { sessionLifecycle: lifecycle }),
	};
	const logoutStores = {
		userSessionStore: userSessionStore as UserSessionStore,
		sessionFamilyIndex: index,
		sessionRPRegistry,
		sessionFederationIndex,
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

	const logout = (stores: typeof logoutStores = logoutStores) =>
		cascadeLogout({ sid: SID, expiresAt, ...stores });

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
		logout,
		familyId,
		answers,
		revocation,
		logoutRevocation,
		index,
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
	it("joins the relying party and its family to the session's lifecycle record, and the per-session stores beside it", async () => {
		const w = await world({ lifecycle: true });

		const result = await w.exchange();

		expect(result.status).toBe(200);
		expect(w.answers).toEqual(["added"]);
		const record = readVersionedSessionLifecycle(await w.lifecycleStore.read(SID));
		expect(record?.value.participants.map((p) => `${p.kind}:${p.id}`)).toEqual([
			`rp:${CLIENT_ID}`,
			`family:${w.familyId()}`,
		]);
		expect((await w.grantStores.sessionRPRegistry.listRPs(SID)).map((rp) => rp.clientId)).toEqual([
			CLIENT_ID,
		]);
	});

	it("add before end: the logout through the per-session stores lists the family and revokes it", async () => {
		const w = await world({ lifecycle: true });

		expect((await w.exchange()).status).toBe(200);
		expect(await w.logout()).toEqual({ outcome: "done" });

		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("end before add: the old end mark refuses the join, the exchange serves nothing, and the family is revoked", async () => {
		const w = await world({ lifecycle: true });
		const held = checkpoint();
		const logout = w.logout({
			...w.logoutStores,
			federationTokenStore: holding(w.logoutStores.federationTokenStore, "removeBySid", held, {
				when: "before",
			}),
		});
		await held.arrived;

		const result = await w.exchange();
		held.release();

		expectSessionInvalidated(result);
		expect(w.answers).toEqual(["ended"]);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
		expect(await w.lifecycleStore.read(SID)).toBeNull();
		expect(await logout).toEqual({ outcome: "done" });
	});

	it("a close through the lifecycle committed first: the join is refused, the exchange serves nothing, and the family is revoked", async () => {
		const w = await world({ lifecycle: true });
		const lifecycle = w.lifecycle as SessionLifecycle;
		// The session joined once before, so it has a lifecycle record; its
		// close commits and stays pending, the user session still there.
		await lifecycle.join(SID, { familyId: "earlier-family" });
		vi.mocked(w.logoutStores.federationTokenStore.removeBySid).mockRejectedValueOnce(
			new Error("federation token store down"),
		);
		expect((await lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		expect(await w.userSessionStore.get(SID)).not.toBeNull();
		w.answers.length = 0;

		const result = await w.exchange();

		expectSessionInvalidated(result);
		// Refused by the record before the per-session stores are written.
		expect(w.answers).toEqual([]);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a close through the lifecycle committed first, over an index that keeps no end mark: the record alone refuses the join", async () => {
		const index = withoutSessionEnd(createInMemorySessionFamilyIndex());
		const w = await world({ index, lifecycle: true });
		const lifecycle = w.lifecycle as SessionLifecycle;
		await lifecycle.join(SID, { familyId: "earlier-family" });
		vi.mocked(w.logoutStores.federationTokenStore.removeBySid).mockRejectedValueOnce(
			new Error("federation token store down"),
		);
		expect((await lifecycle.close(SID, "rp_logout")).outcome).toBe("pending");
		vi.mocked(index.addFamilyId).mockClear();

		const result = await w.exchange();

		expectSessionInvalidated(result);
		expect(index.addFamilyId).not.toHaveBeenCalled();
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("a session gone before the join: the exchange serves nothing, and the family is revoked", async () => {
		const w = await world({ lifecycle: true });
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
		const w = await world({ lifecycle: true });
		const result = await w.exchange({
			...w.grantStores,
			sessionLifecycle: {
				...(w.lifecycle as SessionLifecycle),
				join: async () => ({ outcome: "unavailable" }),
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
		const w = await world({ lifecycle: true });
		const logger = createMockLogger();
		await w.exchange(
			{
				...w.grantStores,
				sessionLifecycle: {
					...(w.lifecycle as SessionLifecycle),
					join: async () => ({ outcome: "unavailable" }),
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
		const w = await world({ lifecycle: true });
		const result = await w.exchange({
			...w.grantStores,
			sessionLifecycle: {
				...(w.lifecycle as SessionLifecycle),
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
		const w = await world({ lifecycle: true });
		const logger = createMockLogger();
		await w.exchange(
			{
				...w.grantStores,
				sessionLifecycle: {
					...(w.lifecycle as SessionLifecycle),
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

	it("a lifecycle join that throws: the family is revoked before the throw leaves", async () => {
		const w = await world({ lifecycle: true });
		await expect(
			w.exchange({
				...w.grantStores,
				sessionLifecycle: {
					...(w.lifecycle as SessionLifecycle),
					join: async () => {
						throw new RangeError("session lifecycle: sid must be 1 to 512 characters");
					},
				},
			}),
		).rejects.toThrow(RangeError);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});
});
