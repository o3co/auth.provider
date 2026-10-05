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
 * Integration tests for the federation-stores-incomplete boot validator.
 *
 * When `core.federations.<name>.enabled === true` for any federation, all
 * six session/federation/refresh-family slots MUST be wired in the planned
 * component set: userSessionStore, sessionRPRegistry, sessionFamilyIndex,
 * sessionFederationIndex, federationTokenStore and
 * refreshTokenFamilyRevocation. Without one of the first five, federation
 * routes answer 503 at runtime with an opaque error; without
 * refreshTokenFamilyRevocation they never mount (see the logoutSupported /
 * federationTokenSupported gates in packages/oauth/src/routes.mts). The
 * validator catches both at boot.
 */
import { describe, expect, it, vi } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { federationTypeForTests } from "../../testing/fixtures/federationType.mjs";
import { coreConfigForTests, makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/** A bootstrap map with google federation enabled but no stores wired. */
function makeBootWithFederationEnabled() {
	return {
		config: {
			...makeValidAppConfig(),
			...coreConfigForTests({
				declaredAbsent: ["auditSink"],
				federations: {
					google: {
						enabled: true,
						type: "google",
						callbackURL: "https://auth.example/session/federation/google/callback",
					},
				},
			}),
		},
		pathResolver: (p: string) => p,
	} as never;
}

/** A bootstrap map with no federations enabled (empty federations map). */
function makeBootWithNoFederations() {
	return {
		config: makeValidAppConfig(),
		pathResolver: (p: string) => p,
	} as never;
}

/** The module that handles the enabled federation: it registers its type, `google`. */
const googleFederationModule = federationTypeForTests("google");

/** A module that provides all 6 required session/federation/refresh-family stores. */
const allStoresModule = defineModule({
	name: "test:all-federation-stores",
	provides: {
		userSessionStore: () => ({ kind: "stub" }),
		sessionRPRegistry: () => ({ kind: "stub" }),
		sessionFamilyIndex: () => ({ kind: "stub" }),
		sessionFederationIndex: () => ({ kind: "stub" }),
		federationTokenStore: () => ({ kind: "stub" }),
		refreshTokenFamilyRevocation: () => ({ kind: "stub" }),
	} as never,
});

describe("checkFederationStoresWiring", () => {
	it("throws when federation is enabled but stores are missing", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).rejects.toThrow(BootError);

		await expect(
			createApp({
				modules: [],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).rejects.toMatchObject({
			details: {
				reason: "federation-stores-incomplete",
				federationName: "google",
				missing: expect.arrayContaining([
					"userSessionStore",
					"sessionRPRegistry",
					"sessionFamilyIndex",
					"sessionFederationIndex",
					"federationTokenStore",
					"refreshTokenFamilyRevocation",
				]),
			},
		});
	});

	it("does not throw when no federations are enabled", async () => {
		await expect(
			createApp({
				modules: [],
				bootstrapComponents: makeBootWithNoFederations(),
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when federation is enabled and all 6 stores are wired", async () => {
		await expect(
			createApp({
				modules: [allStoresModule, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).resolves.toBeDefined();
	});

	// The validator consults `bootstrapComponents` and `overrideComponents` as
	// well as module `provides`, so a composition root that wires stores
	// through bootstrap/override is not falsely rejected.

	it("does not throw when all 6 stores are supplied via bootstrapComponents", async () => {
		const bootstrapWithStores = {
			...(makeBootWithFederationEnabled() as Record<string, unknown>),
			userSessionStore: { kind: "stub" },
			sessionRPRegistry: { kind: "stub" },
			sessionFamilyIndex: { kind: "stub" },
			sessionFederationIndex: { kind: "stub" },
			federationTokenStore: { kind: "stub" },
			refreshTokenFamilyRevocation: { kind: "stub" },
		} as never;
		await expect(
			createApp({
				modules: [googleFederationModule],
				bootstrapComponents: bootstrapWithStores,
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when stores come via overrideComponents", async () => {
		await expect(
			createApp({
				modules: [googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
				overrideComponents: {
					userSessionStore: { kind: "stub" },
					sessionRPRegistry: { kind: "stub" },
					sessionFamilyIndex: { kind: "stub" },
					sessionFederationIndex: { kind: "stub" },
					federationTokenStore: { kind: "stub" },
					refreshTokenFamilyRevocation: { kind: "stub" },
				} as never,
			}),
		).resolves.toBeDefined();
	});
});

const STORE_KEYS = [
	"userSessionStore",
	"sessionRPRegistry",
	"sessionFamilyIndex",
	"sessionFederationIndex",
	"federationTokenStore",
	"refreshTokenFamilyRevocation",
] as const;

/**
 * A module providing the six stores, no module reading them: each factory a
 * spy answering a stub, or what `answers` gives for its key.
 */
function storesModule(answers: Partial<Record<(typeof STORE_KEYS)[number], () => unknown>> = {}) {
	const factories = Object.fromEntries(
		STORE_KEYS.map((key) => [key, vi.fn(answers[key] ?? (() => ({ kind: "stub" })))]),
	) as Record<(typeof STORE_KEYS)[number], ReturnType<typeof vi.fn>>;
	return {
		factories,
		module: defineModule({ name: "test:unread-federation-stores", provides: factories as never }),
	};
}

describe("an enabled federation's stores are built at boot", () => {
	it("builds each of the six once, though no module reads them", async () => {
		const { factories, module } = storesModule();

		await expect(
			createApp({
				modules: [module, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).resolves.toBeDefined();

		for (const key of STORE_KEYS) expect(factories[key]).toHaveBeenCalledTimes(1);
	});

	it("refuses one whose provider yields nothing", async () => {
		const { factories, module } = storesModule({ sessionFederationIndex: () => undefined });

		await expect(
			createApp({
				modules: [module, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).rejects.toMatchObject({
			details: {
				reason: "federation-stores-incomplete",
				federationName: "google",
				missing: ["sessionFederationIndex"],
			},
		});
		expect(factories.sessionFederationIndex).toHaveBeenCalledTimes(1);
	});

	it("fails boot when a store's provider throws", async () => {
		const { module } = storesModule({
			federationTokenStore: () => {
				throw new Error("the token store cannot be built");
			},
		});

		await expect(
			createApp({
				modules: [module, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).rejects.toMatchObject({ details: { reason: "provides-factory-failed" } });
	});

	it("does not build an unread store when no federation is enabled", async () => {
		const { factories, module } = storesModule();

		await expect(
			createApp({ modules: [module], bootstrapComponents: makeBootWithNoFederations() }),
		).resolves.toBeDefined();

		for (const key of STORE_KEYS) expect(factories[key]).not.toHaveBeenCalled();
	});

	it("builds what a store's provider requires, once, though no module reads either", async () => {
		const dependency = vi.fn(() => ({ kind: "dependency" }));
		const tokenStore = vi.fn(() => ({ kind: "stub" }));
		const { factories } = storesModule();
		const withRequirement = defineModule({
			name: "test:token-store-with-a-requirement",
			requires: ["challengeStore"] as never,
			provides: { federationTokenStore: tokenStore } as never,
		});
		const dependencyModule = defineModule({
			name: "test:dependency",
			provides: { challengeStore: dependency } as never,
		});
		const { federationTokenStore: _replaced, ...rest } = factories;
		const others = defineModule({ name: "test:other-stores", provides: rest as never });

		await expect(
			createApp({
				modules: [dependencyModule, withRequirement, others, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).resolves.toBeDefined();

		expect(dependency).toHaveBeenCalledTimes(1);
		expect(tokenStore).toHaveBeenCalledTimes(1);
	});

	it("does not build a provider of a store a host map fills", async () => {
		const { factories, module } = storesModule();

		await expect(
			createApp({
				modules: [module, googleFederationModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
				overrideComponents: { sessionFederationIndex: { kind: "host" } } as never,
			}),
		).resolves.toBeDefined();

		expect(factories.sessionFederationIndex).not.toHaveBeenCalled();
		expect(factories.userSessionStore).toHaveBeenCalledTimes(1);
	});
});
