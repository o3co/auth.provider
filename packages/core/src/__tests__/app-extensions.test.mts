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
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "#/mfa/types.mjs";

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
