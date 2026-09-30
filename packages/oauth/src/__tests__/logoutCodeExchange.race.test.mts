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
 *
 * Driven through `cascadeLogout` and the real grant over core's memory
 * stores. A checkpoint holds one side at a store call while the other runs
 * to its answer.
 */

import crypto from "node:crypto";
import {
	type CodeRepository,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
	type FederationTokenStore,
	type GrantDependencies,
	type GrantHandler,
	type GrantResult,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SupportsSessionEnd,
	supportsSessionEnd,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { cascadeLogout } from "#/logout/cascadeLogout.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import { capturing, withGrants } from "./_helpers/sections.mjs";

const HOUR = 3_600_000;
const SID = "sid-race";
const SUBJECT = "u-1";
const CLIENT_ID = "client1";
const RP_URI = "https://rp.example/cb";
const CODE_VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(CODE_VERIFIER).digest("base64url");

const config = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86_400 },
	},
} as unknown as GrantDependencies["config"];

/** The line the grant logs when the session ended while it was issuing. */
const INVALIDATED_LINE = "authorization_grant_rejected_session_invalidated_during_token_issuance";
/** The line the grant logs when it could not revoke the family of a refused exchange. */
const REVOCATION_FAILED_LINE = "authorization_grant_refused_family_revocation_failed";
/** The boot line for a family index without the session-end capability. */
const NO_SESSION_END_LINE = "session_family_index_without_session_end";

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
async function world(opts: { readonly index?: SessionFamilyIndex } = {}) {
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

	const grantStores = {
		userSessionStore: userSessionStore as UserSessionStore,
		sessionFamilyIndex: recordingIndex,
		sessionRPRegistry,
		refreshTokenFamilyRotation: { ...rotation, register },
		refreshTokenFamilyRevocation: revocation as RefreshTokenFamilyRevocation,
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
			config,
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

describe("a logout and a code exchange on the same session", () => {
	it("add before end: the logout lists the family and revokes it, and the exchange answers 200", async () => {
		const w = await world();

		const result = await w.exchange();
		const cascade = await w.logout();

		expect(result.status).toBe(200);
		expect(w.answers).toEqual(["added"]);
		expect(cascade).toEqual({ outcome: "done" });
		expect(w.logoutRevocation.revokeFamily).toHaveBeenCalledWith(w.familyId());
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("end before add: the add answers ended, the exchange refuses with no tokens, and the family is revoked", async () => {
		const w = await world();
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
		expect(await logout).toEqual({ outcome: "done" });
	});

	it("an add between the listing and the clean-up: the add answers ended", async () => {
		const w = await world();
		const held = checkpoint();
		const logout = w.logout({
			...w.logoutStores,
			sessionFamilyIndex: holding(w.logoutStores.sessionFamilyIndex, "removeBySid", held, {
				when: "before",
			}),
		});
		await held.arrived;

		const result = await w.exchange();
		held.release();

		expectSessionInvalidated(result);
		expect(w.answers).toEqual(["ended"]);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
		expect(await logout).toEqual({ outcome: "done" });
	});

	it("an add between the clean-up and the delete: the add answers ended", async () => {
		const w = await world();
		const held = checkpoint();
		const logout = w.logout({
			...w.logoutStores,
			userSessionStore: holding(w.logoutStores.userSessionStore, "delete", held, {
				when: "before",
			}),
		});
		await held.arrived;

		const result = await w.exchange();
		held.release();

		expectSessionInvalidated(result);
		expect(w.answers).toEqual(["ended"]);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
		expect(await logout).toEqual({ outcome: "done" });
	});

	it("admission before the delete and the add after it: the add answers ended", async () => {
		const w = await world();
		const held = checkpoint();
		// The exchange reads the session twice; the second read is the one
		// that admits it right before the add.
		const exchange = w.exchange({
			...w.grantStores,
			userSessionStore: holding(w.grantStores.userSessionStore, "get", held, {
				when: "after",
				nth: 2,
			}),
		});
		await held.arrived;

		expect(await w.logout()).toEqual({ outcome: "done" });
		expect(await w.userSessionStore.get(SID)).toBeNull();
		held.release();
		const result = await exchange;

		expectSessionInvalidated(result);
		expect(w.answers).toEqual(["ended"]);
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});

	it("says why it refused, once at warn, naming the session and the client", async () => {
		const w = await world();
		const logger = createMockLogger();
		const held = checkpoint();
		const logout = w.logout({
			...w.logoutStores,
			userSessionStore: holding(w.logoutStores.userSessionStore, "delete", held, {
				when: "before",
			}),
		});
		await held.arrived;

		await w.exchange(w.grantStores, logger);
		held.release();
		await logout;

		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith({ sid: SID, clientId: CLIENT_ID }, INVALIDATED_LINE);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("a failed revocation on ended: one error line, and the answer unchanged", async () => {
		const w = await world();
		const outage = new Error("family store is down");
		const logger = createMockLogger();
		const held = checkpoint();
		const logout = w.logout({
			...w.logoutStores,
			userSessionStore: holding(w.logoutStores.userSessionStore, "delete", held, {
				when: "before",
			}),
		});
		await held.arrived;

		const result = await w.exchange(
			{
				...w.grantStores,
				refreshTokenFamilyRevocation: {
					...w.revocation,
					revokeFamily: vi.fn(async () => {
						throw outage;
					}),
				},
			},
			logger,
		);
		held.release();
		await logout;

		expectSessionInvalidated(result);
		expect(w.answers).toEqual(["ended"]);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				sid: SID,
				clientId: CLIENT_ID,
				familyId: w.familyId(),
				err: expect.objectContaining({ message: outage.message }),
			}),
			REVOCATION_FAILED_LINE,
		);
	});

	it("an index without the capability: the exchange adds with addFamilyId and the logout lists with listFamilyIds", async () => {
		const index = withoutSessionEnd(createInMemorySessionFamilyIndex());
		const w = await world({ index });

		const result = await w.exchange();
		const cascade = await w.logout();

		expect(result.status).toBe(200);
		expect(index.addFamilyId).toHaveBeenCalledWith(SID, w.familyId(), w.expiresAt);
		expect(index.listFamilyIds).toHaveBeenCalledWith(SID);
		expect(cascade).toEqual({ outcome: "done" });
		expect(await w.revocation.isFamilyRevoked(w.familyId())).toBe(true);
	});
});

describe("the composition's family index", () => {
	const keyStoreModule = defineModule({
		name: "test:key-store",
		provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
	});
	const clientRepositoryModule = defineModule({
		name: "test:client-repository",
		provides: {
			clientRepository: () => ({ findById: async () => null, authenticate: async () => null }),
		},
	});
	const codeRepositoryModule = defineModule({
		name: "test:code-repository",
		provides: {
			codeRepository: () =>
				({
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
					createCode: async () => {
						throw new Error("not used");
					},
					findByCode: async () => null,
					removeByCode: async () => undefined,
				}) satisfies CodeRepository,
		},
	});

	const boot = async (overrideComponents: Record<string, unknown> = {}) => {
		const appConfig = withGrants(makeValidAppConfig(), { authorizationCode: true });
		const logger = createMockLogger();
		const handle = await createTestApp({
			modules: [
				oauthAuthorizationModule({ config: appConfig }),
				memorySessionStoresModule,
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				keyStoreModule,
				clientRepositoryModule,
				codeRepositoryModule,
			],
			bootstrapComponents: {
				config: capturing(appConfig, [oauthAuthorizationModule({ config: appConfig })]),
				pathResolver: (s: string) => s,
				logger,
			},
			overrideComponents: overrideComponents as never,
		});
		const expiresAt = new Date(Date.now() + HOUR);
		await handle.components.userSessionStore?.create({
			sid: SID,
			sub: SUBJECT,
			authTime: new Date(),
			expiresAt,
			claims: {},
			amr: undefined,
			authentication: undefined,
		});
		const exchange = async () => {
			const grant = handle.inspect.grants.get("authorization_code") as GrantHandler;
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
				authenticatedClient: {
					clientId: CLIENT_ID,
					tokenEndpointAuthMethod: "client_secret_basic",
				},
			});
			return result;
		};
		const lines = logger.warn.mock.calls.filter((call) => call[1] === NO_SESSION_END_LINE);
		return { handle, expiresAt, exchange, lines };
	};

	it("the memory index: the exchange refuses a session the index marked ended, and boot says nothing", async () => {
		const { handle, expiresAt, exchange, lines } = await boot();
		try {
			const index = handle.components.sessionFamilyIndex;
			if (!supportsSessionEnd(index)) throw new Error("the memory index has the capability");
			await index.endSession(SID, expiresAt);

			expectSessionInvalidated(await exchange());
			expect(lines).toEqual([]);
		} finally {
			await handle.dispose();
		}
	});

	it("an index without the capability: the exchange answers 200, and boot warns once", async () => {
		const index = withoutSessionEnd(createInMemorySessionFamilyIndex());
		const { handle, exchange, lines } = await boot({ sessionFamilyIndex: index });
		try {
			expect((await exchange()).status).toBe(200);
			expect(index.addFamilyId).toHaveBeenCalledTimes(1);
			expect(lines).toEqual([[{ slot: "sessionFamilyIndex", kind: "memory" }, NO_SESSION_END_LINE]]);
		} finally {
			await handle.dispose();
		}
	});
});
