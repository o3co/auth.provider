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
 * End-to-end boot integration test for `googleFederationModule` (Cl-M2).
 *
 * Boots the const-Module through `createApp` together with a small
 * bootstrap module that supplies `googleFederationConfig`, and asserts the
 * pairing invariant materialises both contributions in `handle.components`:
 *
 * - `federationProviders.get("google")` — the upstream OIDC protocol
 *   provider (FederationProvider).
 * - `federationRedirectPolicyResolver.get("google")` — the consumer
 *   redirect-URL policy (FederationRedirectPolicy).
 *
 * Earlier shape tests in `google-module.test.mts` only assert the const
 * Module's static surface; this test exercises the actual planner pipeline
 * (validate-manifests pairing check + applyContributions synthetic
 * projection) end-to-end.
 *
 * Per A5 §10.1 + Cl-M2.
 */
import { createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import type { FederationProvider, FederationRedirectPolicy } from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { type GoogleProviderConfig, googleFederationModule } from "../google.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

const stubGoogleConfig: GoogleProviderConfig = {
	name: "google",
	clientId: "test-client-id",
	clientSecret: "test-client-secret",
	callbackURL: "https://example.com/auth/google/callback",
	sessionDomain: "example.com",
	authCallbackUrl: "https://example.com/auth/callback",
	clientUrl: "https://example.com/",
};

// Bootstrap module: supplies the googleFederationConfig DI slot that
// googleFederationModule.requires.
const configBootstrapModule = defineModule({
	name: "test-google-config-bootstrap",
	requires: [] as const,
	provides: {
		googleFederationConfig: () => stubGoogleConfig,
	},
});

// Activator module: requires both synthetic resolvers so the boot planner
// materialises the projections into `handle.components`. Without an active
// requirer the lazy projection may not be exposed.
const activatorModule = defineModule({
	name: "test-google-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_google_noop__",
				id: "test-google-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("googleFederationModule boot integration (Cl-M2)", () => {
	it("boots end-to-end and materialises both federations.google and federationRedirectPolicies.google", async () => {
		const handle = await createApp({
			modules: [googleFederationModule, configBootstrapModule, activatorModule],
			bootstrapComponents: minBoot,
		});

		const providers = (handle.components as Record<string, unknown>).federationProviders as
			| ReadonlyMap<string, FederationProvider>
			| undefined;
		expect(providers).toBeDefined();
		const provider = providers?.get("google");
		expect(provider).toBeDefined();
		expect(provider?.name).toBe("google");

		const policyResolver = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as
			| ReadonlyMap<string, FederationRedirectPolicy>
			| undefined;
		expect(policyResolver).toBeDefined();
		const policy = policyResolver?.get("google");
		expect(policy).toBeDefined();
		expect(typeof policy?.validateRedirect).toBe("function");
		expect(typeof policy?.resolveCallbackRedirect).toBe("function");

		await handle.dispose();
	});
});
