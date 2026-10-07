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
 * The webauthn grant under `oauth.requireEmailVerified`, read from the
 * `oauthTokenSettings` slot. With the setting on, the grant reads the user
 * behind the credential through `userRepository.findBySubject` after the
 * assertion and the sign-count update, and before the scope, the grant
 * policy, the family registration and signing: a user the Store does not
 * hold, or whose email is not verified (`isEmailVerified`), is
 * `invalid_grant` "email address is not verified", as the session grant
 * answers; a lookup that throws is a 503. A grant built with the setting on
 * and no repository that can look a user up is refused. With the setting
 * off, nothing is read.
 *
 * `verifyWebAuthnAssertion` is mocked, as in grant.test.mts: its contract is
 * covered by internal.verification.test.mts.
 */

import {
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryRefreshTokenFamilyStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantHandler,
	type User,
	type UserRepository,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	createTestUserRepository,
	type TestUserRepositoryOptions,
} from "@o3co/auth-provider-core/testing";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAttestation: vi.fn(),
}));

import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { verifyWebAuthnAssertion } from "#/internal/verification.mjs";
import { webauthnModule } from "#/module.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);

const ISSUER = "https://test.example";
const USER_ID = "user-alice-123";
const CLIENT_ID = "native-app-client";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk";
const CHALLENGE = "email-gate-challenge";
const SCOPE = "webauthn:authentication";
const TTL_MS = 120_000;

const NOT_VERIFIED = {
	status: 400,
	error: "invalid_grant",
	errorDescription: "email address is not verified",
} as const;

const verified: User = { id: USER_ID, username: "alice", emailVerified: true };

function assertion(): AuthenticationResponseJSON {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.get", challenge: CHALLENGE, origin: ISSUER }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: {
			clientDataJSON,
			authenticatorData: "stub",
			signature: "stub",
			userHandle: Buffer.from(USER_ID, "utf8").toString("base64url"),
		},
		clientExtensionResults: {},
		type: "public-key",
	};
}

function ctx(): GrantContext {
	return {
		body: { grant_type: WEBAUTHN_GRANT_TYPE, assertion: assertion() },
		session: {},
		issuer: ISSUER,
		metadata: {},
		authenticatedClient: {
			clientId: CLIENT_ID,
			tokenEndpointAuthMethod: "none",
			allowedGrantTypes: [WEBAUTHN_GRANT_TYPE, "refresh_token"],
			allowedScopes: [],
			allowedAudiences: [],
		},
	};
}

/** A logger whose every level is a spy; `child` answers the same logger. */
function spyLogger() {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	return logger;
}

interface Arrangement {
	readonly requireEmailVerified: boolean;
	/** The repository in the deps; `null` leaves the slot unfilled. */
	readonly userRepository?: TestUserRepositoryOptions | null;
}

/** The stores, the challenge and the spies a run reads; the grant is built by `build`. */
async function arrange(a: Arrangement) {
	const challengeStore = createMemoryChallengeStore();
	await challengeStore.issue(SCOPE, CHALLENGE, Date.now() + TTL_MS, Date.now());
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential({
		userId: USER_ID,
		credentialId: CREDENTIAL_ID,
		publicKey: new Uint8Array(64),
		signCount: 5,
		backedUp: false,
		createdAt: new Date("2026-01-01"),
	});
	const updateSignCount = vi.fn(credentialStore.updateSignCount.bind(credentialStore));
	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
		accessTokenHorizonMs: 3_600_000,
	});
	const register = vi.fn(rotation.register.bind(rotation));
	const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
	const sign = vi.spyOn(keyStore, "sign");
	const evaluate = vi.fn(async () => ({ outcome: "allow" }) as const);
	const userRepository =
		a.userRepository === null
			? undefined
			: createTestUserRepository(a.userRepository ?? { users: [verified] });
	const findBySubject = userRepository?.findBySubject;
	const lookup =
		findBySubject === undefined
			? undefined
			: vi.fn(async (subject: string) => {
					// The sign-count update has answered before the user is read.
					expect(updateSignCount).toHaveBeenCalledTimes(1);
					return findBySubject(subject);
				});
	const logger = spyLogger();
	const deps = {
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		webauthnCredentialStore: { ...credentialStore, updateSignCount },
		challengeCeremony: createChallengeCeremony({
			challengeStore,
			replaySeenSet: createMemoryReplaySeenSet(),
		}),
		oauthTokenSettings: createTestOAuthTokenSettings({
			issuer: ISSUER,
			requireEmailVerified: a.requireEmailVerified,
		}),
		webauthnConfig: createTestWebAuthnConfig({ origin: [ISSUER], challengeTtlMs: TTL_MS }),
		grantPolicy: { kind: "test-allow", evaluate },
		refreshTokenFamilyRotation: { ...rotation, register },
		logger,
		...(userRepository === undefined
			? {}
			: {
					userRepository: {
						...userRepository,
						...(lookup === undefined ? {} : { findBySubject: lookup }),
					} satisfies UserRepository,
				}),
	};
	return {
		deps,
		register,
		sign,
		evaluate,
		logger,
		lookups: () => userRepository?.lookups ?? [],
		build: () => createWebAuthnGrant(deps),
		run: async () => (await createWebAuthnGrant(deps).handle(ctx())).result,
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });
});

describe("createWebAuthnGrant — oauth.requireEmailVerified on", () => {
	for (const [label, users] of [
		["whose email is not verified", [{ ...verified, emailVerified: false }]],
		["whose Store publishes no verification state", [{ id: USER_ID, username: "alice" }]],
		[
			"whose verification state is a truthy non-boolean",
			[{ ...verified, emailVerified: "true" as unknown as boolean }],
		],
		["the Store does not hold", []],
	] as const) {
		it(`refuses a user ${label}, with nothing scoped, registered or signed`, async () => {
			const h = await arrange({ requireEmailVerified: true, userRepository: { users } });

			const result = await h.run();

			expect(result).toEqual(NOT_VERIFIED);
			expect(result).not.toHaveProperty("tokens");
			expect(h.lookups()).toEqual([USER_ID]);
			expect(h.evaluate).not.toHaveBeenCalled();
			expect(h.register).not.toHaveBeenCalled();
			expect(h.sign).not.toHaveBeenCalled();
		});
	}

	it("mints for a verified user, after reading the user behind the credential", async () => {
		const h = await arrange({ requireEmailVerified: true });

		const result = await h.run();

		expect(result).toMatchObject({ status: 200 });
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(typeof result.tokens.access_token).toBe("string");
		expect(typeof result.tokens.refresh_token).toBe("string");
		expect(h.lookups()).toEqual([USER_ID]);
		expect(h.register).toHaveBeenCalledTimes(1);
	});

	it("answers 503 when the lookup throws, logged as a store outage, with nothing registered or signed", async () => {
		const h = await arrange({
			requireEmailVerified: true,
			userRepository: { users: [verified], unavailable: new Error("store down: secret") },
		});

		const result = await h.run();

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "identity resolution unavailable",
		});
		expect(h.evaluate).not.toHaveBeenCalled();
		expect(h.register).not.toHaveBeenCalled();
		expect(h.sign).not.toHaveBeenCalled();
		expect(h.logger.error).toHaveBeenCalledTimes(1);
		const [fields, event] = h.logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("webauthn_grant_store_unavailable");
		expect(fields).toMatchObject({ store: "user_repository", step: "read", clientId: CLIENT_ID });
		expect(fields.err).not.toBeInstanceOf(Error);
	});

	it("reads no user when the sign-count update fails", async () => {
		const h = await arrange({ requireEmailVerified: true });
		h.deps.webauthnCredentialStore.updateSignCount.mockResolvedValueOnce(false);

		const result = await h.run();

		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(h.lookups()).toEqual([]);
	});

	it("refuses to build without a userRepository", async () => {
		const h = await arrange({ requireEmailVerified: true, userRepository: null });

		expect(() => h.build()).toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});

	it("refuses to build over a userRepository without findBySubject", async () => {
		const h = await arrange({
			requireEmailVerified: true,
			userRepository: { users: [verified], subjectLookup: false },
		});

		expect(() => h.build()).toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});
});

describe("createWebAuthnGrant — oauth.requireEmailVerified off", () => {
	for (const [label, userRepository] of [
		["reads no user from a repository that can look one up", { users: [] }],
		["builds and mints without a userRepository", null],
		["builds and mints over a userRepository without findBySubject", { subjectLookup: false }],
	] as const) {
		it(label, async () => {
			const h = await arrange({ requireEmailVerified: false, userRepository });

			const result = await h.run();

			expect(result).toMatchObject({ status: 200 });
			expect(h.lookups()).toEqual([]);
		});
	}
});

describe("webauthnModule — the userRepository slot", () => {
	it("declares it optional, with no absence policy, and hands it to the grant", async () => {
		expect(webauthnModule.optional).toContain("userRepository");
		expect(webauthnModule.requires).not.toContain("userRepository");
		expect(Object.keys(webauthnModule.absencePolicies ?? {})).not.toContain("userRepository");

		const h = await arrange({
			requireEmailVerified: true,
			userRepository: { users: [{ ...verified, emailVerified: false }] },
		});
		const factory = webauthnModule.contributes?.grants?.[WEBAUTHN_GRANT_TYPE];
		if (!factory) throw new Error("webauthnModule contributes no webauthn grant");
		const { webauthnConfig, ...slots } = h.deps;
		const grant = (await factory({ ...slots, section: webauthnConfig } as never)) as GrantHandler;

		const { result } = await grant.handle(ctx());

		expect(result).toEqual(NOT_VERIFIED);
		expect(h.lookups()).toEqual([USER_ID]);
	});
});
