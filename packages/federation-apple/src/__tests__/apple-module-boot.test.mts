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
 * End-to-end boot integration test for `appleFederationModule`, mirroring
 * `federation-google`'s.
 *
 * Boots the const Module through `createApp` alongside a bootstrap module
 * supplying `appleFederationConfig`, and asserts the A5 pairing invariant
 * materialises both contributions in `handle.components`:
 *
 * - `federationProviders.get("apple")` — the upstream OIDC protocol provider
 * - `federationRedirectPolicyResolver.get("apple")` — the redirect policy
 *
 * It also asserts the one thing this federation adds to that shape: the
 * provider reaches the route layer still declaring `responseMode:
 * "form_post"`, which is what mounts the POST callback for it.
 */
import { createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import type { FederationProvider, FederationRedirectPolicy } from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { type AppleProviderConfig, appleFederationModule } from "../apple.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

const stubAppleConfig: AppleProviderConfig = {
	clientId: "com.example.app.service",
	clientSecret: "test-client-secret",
	callbackURL: "https://example.com/auth/apple/callback",
	sessionDomain: "example.com",
	authCallbackUrl: "https://example.com/auth/callback",
	clientUrl: "https://example.com/",
};

const configBootstrapModule = defineModule({
	name: "test-apple-config-bootstrap",
	requires: [] as const,
	provides: {
		appleFederationConfig: () => stubAppleConfig,
	},
});

const activatorModule = defineModule({
	name: "test-apple-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_apple_noop__",
				id: "test-apple-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("appleFederationModule boot integration", () => {
	it("boots end-to-end and materialises both federations.apple and federationRedirectPolicies.apple", async () => {
		const handle = await createApp({
			modules: [appleFederationModule, configBootstrapModule, activatorModule],
			bootstrapComponents: minBoot,
		});

		const providers = (handle.components as Record<string, unknown>).federationProviders as
			| ReadonlyMap<string, FederationProvider>
			| undefined;
		expect(providers).toBeDefined();
		const provider = providers?.get("apple");
		expect(provider).toBeDefined();
		expect(provider?.name).toBe("apple");
		// The declaration the route layer reads to mount the POST callback and
		// relax the state cookie survives the planner projection.
		expect(provider?.responseMode).toBe("form_post");

		const policyResolver = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as
			| ReadonlyMap<string, FederationRedirectPolicy>
			| undefined;
		expect(policyResolver).toBeDefined();
		const policy = policyResolver?.get("apple");
		expect(policy).toBeDefined();
		expect(typeof policy?.validateRedirect).toBe("function");
		expect(typeof policy?.resolveCallbackRedirect).toBe("function");

		await handle.dispose();
	});
});
