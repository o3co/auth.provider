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
 * The webauthn grant's answer when a store it needs cannot answer.
 *
 * The credential lookup, the challenge ceremony and the sign-count update
 * used to reach the token route's terminal handler unwrapped — a `500` logged
 * as an unhandled error, never as the outage it was — and a family store that
 * could not register the refresh token's family was a `503` nobody logged. A
 * store that cannot answer is the server's outage: `503
 * temporarily_unavailable`, logged once at error level as
 * `webauthn_grant_store_unavailable` with `store`, `step` and the error's
 * projection — never a verdict on the passkey, and never a token.
 *
 * Driven through the grant `webauthnModule` contributes, over core's memory
 * credential store, challenge store, replay seen-set and ceremony, with one
 * method replaced by one that throws. `verifyWebAuthnAssertion` is mocked as
 * in `grant.test.mts`: the assertion check has its own tests, and a real
 * ceremony fixture adds nothing to what a store outage does.
 */

import {
	type ChallengeStore,
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryRefreshTokenFamilyStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantHandler,
	type Logger,
	type RefreshTokenFamilyRotation,
	type ReplaySeenSet,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAttestation: vi.fn(),
}));

import { WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { verifyWebAuthnAssertion } from "#/internal/verification.mjs";
import { webauthnModule } from "#/module.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);

const ISSUER = "https://test.example";
const USER_ID = "user-alice-123";
const CLIENT_ID = "native-app-client";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk";
const CHALLENGE = "outage-challenge";
const SCOPE = "webauthn:authentication";

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

type SpyLogger = ReturnType<typeof spyLogger>;

/**
 * Exactly one line, at error, object-first, named `event`, carrying `fields`
 * and the error's projection — a plain object, never the `Error` — and
 * nothing at any other level.
 */
function expectOneOutageLine(
	logger: SpyLogger,
	event: string,
	fields: Record<string, unknown>,
	message: string,
): void {
	expect(logger.error).toHaveBeenCalledTimes(1);
	const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
	expect(name).toBe(event);
	expect(context).toMatchObject(fields);
	expect(context.err).not.toBeInstanceOf(Error);
	expect(context.err).toMatchObject({ name: "Error", message });
	for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
		expect(logger[level]).not.toHaveBeenCalled();
	}
}

function assertion(challenge = CHALLENGE): AuthenticationResponseJSON {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.get", challenge, origin: ISSUER }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: { clientDataJSON, authenticatorData: "stub", signature: "stub" },
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

const down = (what: string) => async (): Promise<never> => {
	throw new Error(`${what} is down`);
};

type Stores = {
	readonly credentialStore: WebAuthnCredentialStore;
	readonly challengeStore: ChallengeStore;
	readonly replaySeenSet: ReplaySeenSet;
	readonly rotation: RefreshTokenFamilyRotation;
};

/** Core's memory stores, with one registered credential and one live challenge. */
async function makeStores(): Promise<Stores> {
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential({
		userId: USER_ID,
		credentialId: CREDENTIAL_ID,
		publicKey: new Uint8Array(64),
		signCount: 5,
		backedUp: false,
		createdAt: new Date("2026-01-01"),
	});
	const challengeStore = createMemoryChallengeStore();
	await challengeStore.issue(SCOPE, CHALLENGE, Date.now() + 60_000);
	return {
		credentialStore,
		challengeStore,
		replaySeenSet: createMemoryReplaySeenSet(),
		rotation: createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: 3_600_000,
		}),
	};
}

/** The grant `webauthnModule` contributes, as the boot planner builds it. */
async function contributedGrant(stores: Stores, logger: Logger): Promise<GrantHandler> {
	const factory = webauthnModule.contributes?.grants?.[WEBAUTHN_GRANT_TYPE];
	if (!factory) throw new Error("webauthnModule contributes no webauthn grant");
	return factory({
		config: {
			oauth: {
				jwt: { issuer: ISSUER },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86_400 },
			},
		},
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		webauthnCredentialStore: stores.credentialStore,
		challengeCeremony: createChallengeCeremony({
			challengeStore: stores.challengeStore,
			replaySeenSet: stores.replaySeenSet,
		}),
		webauthnConfig: {
			rpId: "test.example",
			rpName: "Test",
			origin: [ISSUER],
			challengeTtlMs: 120_000,
			attestationPreference: "none",
			userVerification: "preferred",
			allowCredentialsForKnownUser: false,
			rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
		},
		grantPolicy: { kind: "test-noop", evaluate: async () => ({ outcome: "allow" }) as const },
		refreshTokenFamilyRotation: stores.rotation,
		logger,
	} as never) as Promise<GrantHandler>;
}

beforeEach(() => {
	vi.clearAllMocks();
	mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });
});

describe("the webauthn grant answers a store that cannot answer as an outage", () => {
	it("the credential lookup: 503, one error line, and nothing of the ceremony spent", async () => {
		const stores = await makeStores();
		const logger = spyLogger();
		const grant = await contributedGrant(
			{
				...stores,
				credentialStore: {
					...stores.credentialStore,
					findByCredentialId: down("the credential store"),
				},
			},
			logger,
		);

		const { result } = await grant.handle(ctx());

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "credential store unavailable",
		});
		expectOneOutageLine(
			logger,
			"webauthn_grant_store_unavailable",
			{ store: "webauthn_credential", step: "find", clientId: CLIENT_ID },
			"the credential store is down",
		);
		// The challenge was never reached, so the same assertion can be
		// presented again once the store is back.
		expect(await stores.challengeStore.find(SCOPE, CHALLENGE)).not.toBeNull();
	});

	it("the challenge ceremony: 503 and one error line — and a challenge it consumed stays spent", async () => {
		const stores = await makeStores();
		const logger = spyLogger();
		// The seen-set write comes after the atomic delete: the outage lands
		// once the challenge is already gone.
		const grant = await contributedGrant(
			{
				...stores,
				replaySeenSet: { ...stores.replaySeenSet, markSeen: down("the replay seen-set") },
			},
			logger,
		);

		const { result } = await grant.handle(ctx());

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "challenge store unavailable",
		});
		expectOneOutageLine(
			logger,
			"webauthn_grant_store_unavailable",
			{ store: "challenge_ceremony", step: "consume", clientId: CLIENT_ID },
			"the replay seen-set is down",
		);
		expect(mockVerifyAssertion).not.toHaveBeenCalled();
		expect(await stores.challengeStore.find(SCOPE, CHALLENGE)).toBeNull();
	});

	it("the sign-count update: 503 and one error line, and no token", async () => {
		const stores = await makeStores();
		const logger = spyLogger();
		const grant = await contributedGrant(
			{
				...stores,
				credentialStore: {
					...stores.credentialStore,
					updateSignCount: down("the credential store"),
				},
			},
			logger,
		);

		const { result } = await grant.handle(ctx());

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "credential store unavailable",
		});
		expectOneOutageLine(
			logger,
			"webauthn_grant_store_unavailable",
			{ store: "webauthn_credential", step: "update_sign_count", clientId: CLIENT_ID },
			"the credential store is down",
		);
	});

	it("the refresh-token family: 503 and one error line, and neither token is served", async () => {
		const stores = await makeStores();
		const logger = spyLogger();
		const grant = await contributedGrant(
			{ ...stores, rotation: { ...stores.rotation, register: down("the family store") } },
			logger,
		);

		const { result } = await grant.handle(ctx());

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "refresh token store unavailable",
		});
		expectOneOutageLine(
			logger,
			"webauthn_grant_store_unavailable",
			{ store: "refresh_token_family", step: "register", clientId: CLIENT_ID },
			"the family store is down",
		);
	});

	it("still issues, and logs nothing, when every store answers", async () => {
		const stores = await makeStores();
		const logger = spyLogger();
		const grant = await contributedGrant(stores, logger);

		const { result } = await grant.handle(ctx());

		expect(result.status).toBe(200);
		expect("tokens" in result && typeof result.tokens.refresh_token).toBe("string");
		for (const level of ["trace", "debug", "info", "warn", "error", "fatal"] as const) {
			expect(logger[level]).not.toHaveBeenCalled();
		}
	});
});
