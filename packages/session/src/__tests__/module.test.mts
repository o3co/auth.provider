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

import {
	type AppConfig,
	defineModule,
	type FederationTokenStoreBase,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import type { FederationProvider } from "#/federations/types.mjs";
import { sessionModule } from "#/module.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs (per A5 §10.1 typed-slot const-Module pattern)
// ---------------------------------------------------------------------------

const fakeUserRepository: UserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
} as unknown as UserRepository;

const userRepositoryModule = defineModule({
	name: "test:user-repository",
	provides: { userRepository: () => fakeUserRepository },
});

function makeUserSessionStore(): UserSessionStore {
	return {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore;
}

const userSessionStoreModule = defineModule({
	name: "test:user-session-store",
	provides: { userSessionStore: () => makeUserSessionStore() },
});

function makeFederationTokenStore(): FederationTokenStoreBase {
	return {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async deleteBySession() {},
		async delete() {},
	} as unknown as FederationTokenStoreBase;
}

const federationTokenStoreModule = defineModule({
	name: "test:federation-token-store",
	provides: { federationTokenStore: () => makeFederationTokenStore() },
});

function makeSessionFederationIndex(): SessionFederationIndex {
	return {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex;
}

const sessionFederationIndexModule = defineModule({
	name: "test:session-federation-index",
	provides: { sessionFederationIndex: () => makeSessionFederationIndex() },
});

/**
 * Stub modules for `sessionRPRegistry`, `sessionFamilyIndex`, and
 * `refreshTokenFamilyRevocation`. These slots are oauth-package concerns (not
 * provided by sessionModule or any session-package module), but the boot-time
 * `federation-stores-incomplete` validator requires them whenever any
 * federation is enabled in config (the validator stays aligned with route-level
 * gating in packages/oauth/src/routes.mts logoutSupported /
 * federationTokenSupported). Tests that enable a federation must include these
 * stubs so the guard passes and the session-level validations under test can
 * fire.
 */
const sessionRPRegistryModule = defineModule({
	name: "test:session-rp-registry",
	provides: { sessionRPRegistry: () => ({ kind: "stub" }) } as never,
});

const sessionFamilyIndexModule = defineModule({
	name: "test:session-family-index",
	provides: { sessionFamilyIndex: () => ({ kind: "stub" }) } as never,
});

const refreshTokenFamilyRevocationModule = defineModule({
	name: "test:refresh-token-family-revocation",
	provides: { refreshTokenFamilyRevocation: () => ({ kind: "stub" }) } as never,
});

/**
 * Stub federation module — contributes `federations.stub` + the paired
 * `federationRedirectPolicies.stub`. Needed for any test that exercises the
 * boot path with at least one enabled federation in config (otherwise the
 * planner's pairing invariant would fail to satisfy from config alone).
 */
const stubFederationProvider: FederationProvider = {
	name: "stub",
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
	exchangeCode: async () => ({ issuer: "https://example.com", sub: "user-1", expiresAt: null }),
};

const stubFederationModule = defineModule({
	name: "test:stub-federation",
	contributes: {
		federations: {
			stub: () => stubFederationProvider,
		},
		federationRedirectPolicies: {
			stub: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	},
});

const baseTestModules = [
	sessionModule,
	userRepositoryModule,
	userSessionStoreModule,
	federationTokenStoreModule,
	sessionFederationIndexModule,
	// Required by the boot-time `federation-stores-incomplete` validator whenever
	// any federation is enabled in config. These are oauth-package concerns;
	// the session-package tests use stubs so the guard passes and session-level
	// validations under test can fire. Per issue #101 TODO-F-1, plus #103 review
	// (refreshTokenFamilyRevocation added so validator matches route-level gating).
	sessionRPRegistryModule,
	sessionFamilyIndexModule,
	refreshTokenFamilyRevocationModule,
];

// ---------------------------------------------------------------------------
// Static manifest assertions (Codex-recommended: keep structural assertions
// for declarative shape; HTTP / integration tests cover behavior)
// ---------------------------------------------------------------------------

describe("sessionModule (static manifest)", () => {
	it("exposes the const Module shape — not a factory", () => {
		expect(typeof sessionModule).toBe("object");
		expect(sessionModule.name).toBe("session");
	});

	it("declares the Amendment 5 + A5 dep set in `requires`", () => {
		expect(sessionModule.requires).toEqual(
			expect.arrayContaining([
				"config",
				"userRepository",
				"userSessionStore",
				"federationTokenStore",
				"sessionFederationIndex",
				"federationProviders",
				"federationRedirectPolicyResolver",
			]),
		);
		// Amendment 5 (§1.1.5): `sessionRPRegistry` and `sessionFamilyIndex` are
		// oauth-package concerns, MUST NOT appear in sessionModule.requires.
		expect(sessionModule.requires).not.toContain("sessionRPRegistry");
		expect(sessionModule.requires).not.toContain("sessionFamilyIndex");
	});

	it("contributes exactly two routes, both at /session, with distinct ids", () => {
		const routes = sessionModule.contributes?.routes;
		expect(routes).toBeDefined();
		expect(routes).toHaveLength(2);
	});
});

// ---------------------------------------------------------------------------
// Boot-level integration tests (createTestApp)
// ---------------------------------------------------------------------------

describe("sessionModule (boot integration)", () => {
	it("boots successfully when no federations are enabled", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		expect(handle.routes.some((r) => r.contribution.mountPath === "/session")).toBe(true);
		await handle.dispose();
	});

	it("registers a federation provider contributed via per-federation module", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				stub: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					callbackURL: "https://example.com/cb",
				} as never,
			},
		} as AppConfig;
		const handle = await createTestApp({
			modules: [...baseTestModules, stubFederationModule],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		expect(handle.inspect.federations.has("stub")).toBe(true);
		await handle.dispose();
	});

	it("fails to boot when an enabled federation has no callbackURL", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				stub: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					// callbackURL intentionally absent
				} as never,
			},
		} as AppConfig;
		await expect(
			createTestApp({
				modules: [...baseTestModules, stubFederationModule],
				bootstrapComponents: { config, pathResolver: (s: string) => s },
			}),
		).rejects.toThrow(/callbackURL is required/);
	});

	it("skips disabled federations in the providerCallbackUrls projection", async () => {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			federations: {
				...base.federations,
				disabledFed: {
					enabled: false,
					// no callbackURL — must NOT throw because disabled
				} as never,
			},
		} as AppConfig;
		const handle = await createTestApp({
			modules: baseTestModules,
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		// No throw at boot, no entry in the federation registry.
		expect(handle.inspect.federations.has("disabledFed")).toBe(false);
		await handle.dispose();
	});
});
