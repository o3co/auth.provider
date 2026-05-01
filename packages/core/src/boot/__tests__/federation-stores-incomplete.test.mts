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
 * Integration tests for the federation-stores-incomplete boot validator
 * (issue #101 TODO-F-1).
 *
 * Rule: when config.federations.<name>.enabled === true for any federation,
 * all 6 session/federation/refresh-family slots MUST be wired in the planned
 * component set:
 *   - userSessionStore
 *   - sessionRPRegistry
 *   - sessionFamilyIndex
 *   - sessionFederationIndex
 *   - federationTokenStore
 *   - refreshTokenFamilyRevocation
 *
 * Missing any of the first 5 causes federation routes to 503 at runtime with
 * an opaque error; missing refreshTokenFamilyRevocation causes the routes to
 * never mount at all (see packages/oauth/src/routes.mts logoutSupported /
 * federationTokenSupported gates). Both surface as opaque misconfigurations
 * to the operator; the validator catches them at boot.
 *
 * Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05; refreshTokenFamilyRevocation
 * gating added per #103 review.
 */
import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/** A bootstrap map with google federation enabled but no stores wired. */
function makeBootWithFederationEnabled() {
	return {
		config: {
			...makeValidAppConfig(),
			federations: {
				google: { enabled: true },
			},
		},
		pathResolver: (p: string) => p,
	} as never;
}

/** A bootstrap map with no federations enabled (empty federations map). */
function makeBootWithNoFederations() {
	return {
		config: makeValidAppConfig(), // federations: {}
		pathResolver: (p: string) => p,
	} as never;
}

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
				modules: [allStoresModule],
				bootstrapComponents: makeBootWithFederationEnabled(),
			}),
		).resolves.toBeDefined();
	});

	// Multi-channel coverage (multi-agent-review I1+P2 fix): the validator
	// must consult `bootstrapComponents` and `overrideComponents` in addition
	// to module `provides`. Without this, composition roots that wire stores
	// via bootstrap/override are falsely rejected.

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
				modules: [],
				bootstrapComponents: bootstrapWithStores,
			}),
		).resolves.toBeDefined();
	});

	it("does not throw when stores come via overrideComponents", async () => {
		await expect(
			createApp({
				modules: [],
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
