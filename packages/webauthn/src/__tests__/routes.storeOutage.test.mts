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
 * The three ceremony routes answer a store that cannot answer as an outage.
 *
 * Every store call they make — the credential list behind `excludeCredentials`
 * and `allowCredentials`, the challenge write, the ceremony's consume, the
 * credential insert — used to reach the terminal handler unwrapped: a `500`
 * logged as an unhandled error, never as the outage it was. Each is now `503
 * temporarily_unavailable`, logged once at error level as
 * `webauthn_ceremony_store_unavailable` with the route's `site`, the `store`,
 * the `step` and the error's projection. A duplicate credential is still the
 * client's `400 credential_id_conflict`.
 *
 * Booted through `createApp`, as a composition is: `webauthnModule`, core's
 * memory stores and default ceremony, and the deployment's logger as the
 * `logger` component — with one store method replaced by one that throws.
 */

import {
	createApp,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Logger,
	WebAuthnCredentialStorageError,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import supertest from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAttestation: vi.fn(),
	verifyWebAuthnAssertion: vi.fn(),
}));

import type { WebAuthnConfig } from "#/config.mjs";
import { verifyWebAuthnAttestation } from "#/internal/verification.mjs";
import { webauthnModule } from "#/module.mjs";

const mockVerifyAttestation = vi.mocked(verifyWebAuthnAttestation);

const USER_ID = "user-alice-123";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk";

const webauthnConfig: WebAuthnConfig = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	// On, so the authentication options route reads the credential store.
	allowCredentialsForKnownUser: true,
	rateLimit: { authenticationOptions: { limit: 100, windowSeconds: 60 } },
};

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

const down = (what: string) => async (): Promise<never> => {
	throw new Error(`${what} is down`);
};

type Stores = {
	readonly credentialStore: ReturnType<typeof createMemoryWebAuthnCredentialStore>;
	readonly challengeStore: ReturnType<typeof createMemoryChallengeStore>;
	readonly replaySeenSet: ReturnType<typeof createMemoryReplaySeenSet>;
};

const memoryStores = (): Stores => ({
	credentialStore: createMemoryWebAuthnCredentialStore(),
	challengeStore: createMemoryChallengeStore(),
	replaySeenSet: createMemoryReplaySeenSet(),
});

let dispose: (() => Promise<void>) | undefined;
afterEach(async () => {
	await dispose?.();
	dispose = undefined;
});

beforeEach(() => {
	vi.clearAllMocks();
});

/**
 * `webauthnModule` over `stores`, booted by `createApp` with `logger` as the
 * deployment's logger; the subject middleware a deployment writes sets
 * `req.webauthnSubject`. The logger's boot-time lines are cleared, so what it
 * holds afterwards is what the request logged.
 */
async function boot(stores: Stores, logger: SpyLogger): Promise<express.Express> {
	const base = makeValidAppConfig();
	const config = {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
		deployment: { mode: "single" },
	};
	const handle = await createApp({
		modules: [
			webauthnModule,
			defineModule({
				name: "test:webauthn-outage-config",
				provides: { webauthnConfig: () => webauthnConfig },
			}),
			defineModule({
				name: "test:webauthn-outage-key-store",
				provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
			}),
			defineModule({
				name: "test:webauthn-outage-stores",
				provides: {
					webauthnCredentialStore: () => stores.credentialStore,
					challengeStore: () => stores.challengeStore,
					replaySeenSet: () => stores.replaySeenSet,
				},
			}),
			defaultChallengeCeremonyModule,
			defineModule({
				name: "test:webauthn-outage-grant-policy",
				provides: {
					grantPolicy: (): GrantPolicyHook => ({
						kind: "test-noop",
						evaluate: async () => ({ outcome: "allow" }) as const,
					}),
				},
			}),
		],
		bootstrapComponents: {
			config,
			pathResolver: (p: string) => p,
			logger: logger as unknown as Logger,
		} as never,
	});
	dispose = () => handle.dispose();
	const app = express();
	app.use((req, _res, next) => {
		req.webauthnSubject = { userId: USER_ID };
		next();
	});
	app.use(handle.router);
	for (const level of Object.values(logger)) level.mockClear();
	logger.child.mockReturnValue(logger);
	return app;
}

/**
 * Exactly one line, at error, object-first, named
 * `webauthn_ceremony_store_unavailable`, carrying `fields` and the error's
 * projection — a plain object, never the `Error` — and nothing at any other
 * level.
 */
function expectOneOutageLine(
	logger: SpyLogger,
	fields: Record<string, unknown>,
	message: string,
): void {
	expect(logger.error).toHaveBeenCalledTimes(1);
	const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
	expect(name).toBe("webauthn_ceremony_store_unavailable");
	expect(context).toMatchObject(fields);
	expect(context.err).not.toBeInstanceOf(Error);
	expect(context.err).toMatchObject({ name: "Error", message });
	for (const level of ["trace", "debug", "info", "warn", "fatal"] as const) {
		expect(logger[level]).not.toHaveBeenCalled();
	}
}

/** A registration response whose clientDataJSON carries `challenge`. */
function registrationResponse(challenge: string) {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.create", challenge, origin: "https://example.com" }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: { clientDataJSON, attestationObject: "stub" },
		clientExtensionResults: {},
		type: "public-key",
	};
}

const REGISTRATION_SCOPE = `webauthn:registration:${USER_ID}`;

describe("POST /oauth/webauthn/registration/options", () => {
	it.each([
		["the credential list", "listByUserId", "webauthn_credential", "list", "credential store"],
		["the challenge write", "issue", "challenge", "issue", "challenge store"],
	] as const)(
		"answers 503 and logs once when %s cannot be done",
		async (_label, method, store, step, name) => {
			const stores = memoryStores();
			const logger = spyLogger();
			const broken: Stores =
				method === "listByUserId"
					? {
							...stores,
							credentialStore: { ...stores.credentialStore, listByUserId: down(`the ${name}`) },
						}
					: { ...stores, challengeStore: { ...stores.challengeStore, issue: down(`the ${name}`) } };
			const app = await boot(broken, logger);

			const res = await supertest(app).post("/oauth/webauthn/registration/options").send({});

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: `${name} unavailable`,
			});
			expectOneOutageLine(
				logger,
				{ site: "registration_options", store, step },
				`the ${name} is down`,
			);
		},
	);
});

describe("POST /oauth/webauthn/registration/verify", () => {
	it("answers 503 and logs once when the ceremony cannot consume the challenge", async () => {
		const stores = memoryStores();
		await stores.challengeStore.issue(REGISTRATION_SCOPE, "reg-challenge", Date.now() + 60_000);
		const logger = spyLogger();
		const app = await boot(
			{ ...stores, replaySeenSet: { ...stores.replaySeenSet, markSeen: down("the replay seen-set") } },
			logger,
		);

		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: registrationResponse("reg-challenge") });

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "challenge store unavailable",
		});
		expectOneOutageLine(
			logger,
			{ site: "registration_verify", store: "challenge_ceremony", step: "consume" },
			"the replay seen-set is down",
		);
		expect(mockVerifyAttestation).not.toHaveBeenCalled();
	});

	it("answers 503 and logs once when the credential cannot be stored", async () => {
		const stores = memoryStores();
		await stores.challengeStore.issue(REGISTRATION_SCOPE, "reg-challenge", Date.now() + 60_000);
		mockVerifyAttestation.mockResolvedValue({
			ok: true,
			material: {
				credentialId: CREDENTIAL_ID,
				publicKey: new Uint8Array([1, 2, 3, 4]),
				signCount: 0,
				transports: ["internal"],
				backedUp: false,
			},
		});
		const logger = spyLogger();
		const app = await boot(
			{
				...stores,
				credentialStore: {
					...stores.credentialStore,
					registerCredential: down("the credential store"),
				},
			},
			logger,
		);

		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: registrationResponse("reg-challenge") });

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "credential store unavailable",
		});
		expectOneOutageLine(
			logger,
			{ site: "registration_verify", store: "webauthn_credential", step: "register" },
			"the credential store is down",
		);
	});

	it("still answers a duplicate credential as the client's 400, and logs nothing", async () => {
		const stores = memoryStores();
		await stores.challengeStore.issue(REGISTRATION_SCOPE, "reg-challenge", Date.now() + 60_000);
		mockVerifyAttestation.mockResolvedValue({
			ok: true,
			material: {
				credentialId: CREDENTIAL_ID,
				publicKey: new Uint8Array([1, 2, 3, 4]),
				signCount: 0,
				transports: ["internal"],
				backedUp: false,
			},
		});
		const logger = spyLogger();
		const app = await boot(
			{
				...stores,
				credentialStore: {
					...stores.credentialStore,
					registerCredential: async () => {
						throw new WebAuthnCredentialStorageError({ reason: "duplicate-credential" });
					},
				},
			},
			logger,
		);

		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: registrationResponse("reg-challenge") });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("credential_id_conflict");
		expect(logger.error).not.toHaveBeenCalled();
		expect(logger.warn).not.toHaveBeenCalled();
	});
});

describe("POST /oauth/webauthn/authentication/options", () => {
	it.each([
		["the credential list", "listByUserId", "webauthn_credential", "list", "credential store"],
		["the challenge write", "issue", "challenge", "issue", "challenge store"],
	] as const)(
		"answers 503 and logs once when %s cannot be done",
		async (_label, method, store, step, name) => {
			const stores = memoryStores();
			const logger = spyLogger();
			const broken: Stores =
				method === "listByUserId"
					? {
							...stores,
							credentialStore: { ...stores.credentialStore, listByUserId: down(`the ${name}`) },
						}
					: { ...stores, challengeStore: { ...stores.challengeStore, issue: down(`the ${name}`) } };
			const app = await boot(broken, logger);

			const res = await supertest(app)
				.post("/oauth/webauthn/authentication/options")
				.send({ userId: USER_ID });

			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: `${name} unavailable`,
			});
			expectOneOutageLine(
				logger,
				{ site: "authentication_options", store, step },
				`the ${name} is down`,
			);
		},
	);
});
