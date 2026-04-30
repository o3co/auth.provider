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
import type { Router } from "express";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/app.mjs";
import type { AppConfig } from "#/config/application.schema.mjs";
import { createInMemoryFederationTokenStore } from "#/federation-tokens/adapters/memory.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "#/mfa/types.mjs";
import type { GrantPolicyHookBase } from "#/policy/types.mjs";
import { createInMemoryUserSessionStore } from "#/user-sessions/memory/userSessionStore.mjs";
import { createInMemorySessionFamilyIndex } from "#/user-sessions/memory/sessionFamilyIndex.mjs";
import { createInMemorySessionFederationIndex } from "#/user-sessions/memory/sessionFederationIndex.mjs";
import { createInMemorySessionRPRegistry } from "#/user-sessions/memory/sessionRPRegistry.mjs";

const mockExpress = {
	Router: () =>
		({
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn().mockReturnThis(),
		}) as unknown as Router,
	json: () => vi.fn(),
	urlencoded: () => vi.fn(),
};

const mockConfig = {
	http: { port: 3000, trustProxy: false },
	oauth: {
		jwt: {
			signingKey: {
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

const mockMfaCoordinator: MfaCoordinator = {
	async listEnrolled() {
		return [];
	},
};

const mockMfaProviderFactory: MfaProviderFactory = {
	register() {},
	async create() {
		throw new Error("not implemented");
	},
	registeredTypes() {
		return [];
	},
};

const mockMfaTransactionStore: MfaTransactionStore = {
	async save() {},
	async load() {
		return null;
	},
	async delete() {},
};

describe("createApp — MFA config guard", () => {
	it("throws when mfaCoordinator is set without mfaProviderFactory", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: mockConfig,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				mfaCoordinator: mockMfaCoordinator,
				mfaTransactionStore: mockMfaTransactionStore,
			}),
		).toThrow(/mfaProviderFactory is required/);
	});

	it("throws when mfaCoordinator is set without mfaTransactionStore", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: mockConfig,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				mfaCoordinator: mockMfaCoordinator,
				mfaProviderFactory: mockMfaProviderFactory,
			}),
		).toThrow(/mfaTransactionStore is required/);
	});

	it("accepts no MFA at all (current baseline)", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: mockConfig,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).not.toThrow();
	});
});

describe("createApp — grantPolicy / jwt.issuer consistency guard (CP-20)", () => {
	const noopPolicy: GrantPolicyHookBase = {
		kind: "noop",
		async evaluate() {
			return { outcome: "allow" };
		},
	};

	it("throws when grantPolicy is set but config.oauth.jwt.issuer is missing", () => {
		const configWithoutIssuer = {
			http: { port: 3000, trustProxy: false },
			oauth: {
				jwt: {
					// issuer intentionally omitted
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
					},
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
		} as unknown as AppConfig;

		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithoutIssuer,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				grantPolicy: noopPolicy,
			}),
		).toThrow(/config\.oauth\.jwt\.issuer must be set when grantPolicy/);
	});

	it("throws when grantPolicy is set and jwt.issuer is an empty string", () => {
		const configEmptyIssuer = {
			http: { port: 3000, trustProxy: false },
			oauth: {
				jwt: {
					issuer: "",
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
					},
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
		} as unknown as AppConfig;

		expect(() =>
			createApp({
				express: mockExpress,
				config: configEmptyIssuer,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				grantPolicy: noopPolicy,
			}),
		).toThrow(/config\.oauth\.jwt\.issuer must be set when grantPolicy/);
	});

	it("accepts grantPolicy when jwt.issuer is set", () => {
		const configWithIssuer = {
			http: { port: 3000, trustProxy: false },
			oauth: {
				jwt: {
					issuer: "https://auth.example",
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
					},
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
		} as unknown as AppConfig;

		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithIssuer,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				grantPolicy: noopPolicy,
			}),
		).not.toThrow();
	});

	it("does NOT require jwt.issuer when grantPolicy is absent", () => {
		// Same "no issuer" config passes without grantPolicy — the guard fires
		// only when grantPolicy depends on a trusted issuer.
		const configWithoutIssuer = {
			http: { port: 3000, trustProxy: false },
			oauth: {
				jwt: {
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
					},
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
		} as unknown as AppConfig;

		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithoutIssuer,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).not.toThrow();
	});
});

describe("createApp — TODO-F-1 federation store plumbing", () => {
	const configWithFederations = {
		...mockConfig,
		federations: {
			google: { enabled: true, clientId: "x", clientSecret: "y", callbackURL: "z" },
		},
	} as unknown as AppConfig;

	const configWithoutFederations = {
		...mockConfig,
		federations: {},
	} as unknown as AppConfig;

	it("throws when federations configured without federationTokenStore", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				userSessionStore: createInMemoryUserSessionStore(),
			}),
		).toThrow(/federationTokenStore/);
	});

	it("throws when federations configured without userSessionStore", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				federationTokenStore: createInMemoryFederationTokenStore(),
			}),
		).toThrow(/userSessionStore/);
	});

	it("throws when federations configured without sessionRPRegistry", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				userSessionStore: createInMemoryUserSessionStore(),
				federationTokenStore: createInMemoryFederationTokenStore(),
				// sessionRPRegistry deliberately omitted
			}),
		).toThrow(/sessionRPRegistry/);
	});

	it("throws when federations configured without sessionFamilyIndex", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				userSessionStore: createInMemoryUserSessionStore(),
				federationTokenStore: createInMemoryFederationTokenStore(),
				sessionRPRegistry: createInMemorySessionRPRegistry(),
				// sessionFamilyIndex deliberately omitted
			}),
		).toThrow(/sessionFamilyIndex/);
	});

	it("throws when federations configured without sessionFederationIndex", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				userSessionStore: createInMemoryUserSessionStore(),
				federationTokenStore: createInMemoryFederationTokenStore(),
				sessionRPRegistry: createInMemorySessionRPRegistry(),
				sessionFamilyIndex: createInMemorySessionFamilyIndex(),
				// sessionFederationIndex deliberately omitted
			}),
		).toThrow(/sessionFederationIndex/);
	});

	it("accepts federation config when all sibling stores are wired", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				userSessionStore: createInMemoryUserSessionStore(),
				federationTokenStore: createInMemoryFederationTokenStore(),
				sessionRPRegistry: createInMemorySessionRPRegistry(),
				sessionFamilyIndex: createInMemorySessionFamilyIndex(),
				sessionFederationIndex: createInMemorySessionFederationIndex(),
			}),
		).not.toThrow();
	});

	it("accepts no stores when no federations are configured", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithoutFederations,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).not.toThrow();
	});

	it("accepts no stores when federations config is entirely absent", () => {
		expect(() =>
			createApp({
				express: mockExpress,
				config: mockConfig,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).not.toThrow();
	});

	it('treats env-var string "true" as enabled and requires stores (pre-zod-coerce robustness)', () => {
		const configWithEnvString = {
			...mockConfig,
			federations: {
				google: { enabled: "true", clientId: "x", clientSecret: "y", callbackURL: "z" },
			},
		} as unknown as AppConfig;
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithEnvString,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				// Both stores omitted — should throw.
			}),
		).toThrow(/federationTokenStore|userSessionStore/);
	});

	it('treats env-var string "1" as enabled', () => {
		const configWithEnvOne = {
			...mockConfig,
			federations: { google: { enabled: "1", clientId: "x", clientSecret: "y", callbackURL: "z" } },
		} as unknown as AppConfig;
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithEnvOne,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).toThrow();
	});

	it('treats env-var string "false" as disabled (no stores required)', () => {
		const configWithEnvFalse = {
			...mockConfig,
			federations: {
				google: { enabled: "false", clientId: "x", clientSecret: "y", callbackURL: "z" },
			},
		} as unknown as AppConfig;
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithEnvFalse,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
			}),
		).not.toThrow();
	});

	it('does NOT treat non-schema strings like "yes" as enabled (schema-alignment, Copilot round 3 #6)', () => {
		// Schema coerces only "true"/"1" to true; "yes" is rejected at parse.
		// The pre-parse check must NOT fire the stores-missing error on "yes"
		// or it would mask the real schema validation error that the user
		// needs to see.
		const configWithYes = {
			...mockConfig,
			federations: {
				google: { enabled: "yes", clientId: "x", clientSecret: "y", callbackURL: "z" },
			},
		} as unknown as AppConfig;
		expect(() =>
			createApp({
				express: mockExpress,
				config: configWithYes,
				keyStore: createSymmetricKeyStore("test-secret"),
				modules: [],
				// Stores omitted — should NOT throw here; schema parse at init() will flag it.
			}),
		).not.toThrow();
	});
});
