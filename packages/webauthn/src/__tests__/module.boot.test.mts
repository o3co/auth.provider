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
 * Bootstrap integration test for `webauthnModule` (Wave 1 Task 31 / spec §2.4.1).
 *
 * Exercises the full `createApp` planner pipeline end-to-end. Two scenarios:
 *
 * 1. Happy path — a bootstrap module provides `webauthnConfig`; boot completes
 *    and the planner materialises both the webauthn grant and the three route
 *    contributions.
 *
 * 2. Fail-fast — `webauthnConfig` slot is not provided; boot throws
 *    `BootError reason="missing-required-component"` naming `webauthnConfig`.
 *
 * Mirrors the `githubFederationModule` boot integration test pattern
 * (`packages/federation-github/src/__tests__/github-module-boot.test.mts`):
 * uses `createApp` + `makeValidCoreConfig` + a small "config-bootstrap" module
 * that satisfies the DI slot, plus a "requires-activator" module that forces
 * the planner to materialise lazy synthetic projections.
 *
 * Cross-refs: Plan T31 / spec §2.4.1
 */

import {
	createApp,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import { WEBAUTHN_GRANT_TYPE } from "../grant.mjs";
import { webauthnModule } from "../module.mjs";

// ---------------------------------------------------------------------------
// Shared boot components
// ---------------------------------------------------------------------------

const coreConfig = makeValidCoreConfig();

/** Minimal bootstrap: config + pathResolver + keyStore. */
const minBoot = {
	config: coreConfig,
	pathResolver: (p: string) => p,
} as never;

const keyStoreModule = defineModule({
	name: "test:webauthn-boot-key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
	},
});

/** Stub webauthnConfig values — not used for real ceremonies. */
const stubWebAuthnConfig: WebAuthnConfig = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
};

/** Bootstrap module: satisfies the `webauthnConfig` DI slot. */
const webauthnConfigModule = defineModule({
	name: "test:webauthn-config-bootstrap",
	provides: {
		webauthnConfig: () => stubWebAuthnConfig,
	},
});

/**
 * Activator: requires `grantHandlerResolver` (synthetic) so the boot planner
 * materialises the synthetic grant registry into handle.components.
 * Without this, the lazy projection may not be exposed.
 * Mirrors the activatorModule pattern from github-module-boot.test.mts.
 */
const activatorModule = defineModule({
	name: "test:webauthn-activator",
	requires: ["grantHandlerResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_webauthn_noop__",
				id: "test-webauthn-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

// ---------------------------------------------------------------------------
// Full module set for happy-path boot
// ---------------------------------------------------------------------------

const happyPathModules = [
	webauthnModule,
	webauthnConfigModule,
	keyStoreModule,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	defaultChallengeCeremonyModule,
	memoryWebAuthnCredentialStoreModule,
	activatorModule,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("webauthnModule boot integration (Wave 1 T31)", () => {
	it("boots successfully when webauthnConfig is provided and materialises the webauthn grant", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		// The grant registry (synthetic resolver) must contain the webauthn grant.
		const grantHandlerResolver = (handle.components as Record<string, unknown>)
			.grantHandlerResolver as { get(grantType: string): unknown } | undefined;
		expect(grantHandlerResolver).toBeDefined();
		const grantHandler = grantHandlerResolver?.get(WEBAUTHN_GRANT_TYPE);
		expect(grantHandler).toBeDefined();
		expect(typeof (grantHandler as { handle?: unknown })?.handle).toBe("function");

		await handle.dispose();
	});

	it("boots successfully and contributes all three webauthn routes", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		const routeIds = handle.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("webauthn-registration-options");
		expect(routeIds).toContain("webauthn-registration-verify");
		expect(routeIds).toContain("webauthn-authentication-options");

		await handle.dispose();
	});

	it("all three routes are mounted under /oauth/webauthn", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		const webauthnRoutes = handle.routes.filter((r) =>
			r.contribution.mountPath.startsWith("/oauth/webauthn"),
		);
		expect(webauthnRoutes.length).toBe(3);

		await handle.dispose();
	});

	it("throws BootError missing-required-component for webauthnConfig when the slot is not provided", async () => {
		const { BootError } = await import("@o3co/auth-provider-core");

		// Omit webauthnConfigModule — the slot remains unwired.
		const modulesWithoutConfig = [
			webauthnModule,
			keyStoreModule,
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			defaultChallengeCeremonyModule,
			memoryWebAuthnCredentialStoreModule,
			activatorModule,
		];

		await expect(
			createApp({
				modules: modulesWithoutConfig,
				bootstrapComponents: minBoot,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "missing-required-component",
			details: { missingKey: "webauthnConfig" },
		} satisfies Partial<InstanceType<typeof BootError>>);
	});
});
