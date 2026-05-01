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
 * End-to-end boot integration test for `githubFederationModule` (Cl-M2).
 *
 * Boots the const-Module through `createApp` together with a small
 * bootstrap module that supplies `githubFederationConfig`, and asserts the
 * pairing invariant materialises both contributions in `handle.components`:
 *
 * - `federationProviders.get("github")` — the upstream OAuth/OIDC protocol
 *   provider (FederationProvider).
 * - `federationRedirectPolicyResolver.get("github")` — the consumer
 *   redirect-URL policy (FederationRedirectPolicy).
 *
 * Earlier shape tests in `github-module.test.mts` only assert the const
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
import { type GithubProviderConfig, githubFederationModule } from "../github.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

const stubGithubConfig: GithubProviderConfig = {
	name: "github",
	clientId: "test-client-id",
	clientSecret: "test-client-secret",
	callbackURL: "https://example.com/auth/github/callback",
	sessionDomain: "example.com",
	authCallbackUrl: "https://example.com/auth/callback",
	clientUrl: "https://example.com/",
};

// Bootstrap module: supplies the githubFederationConfig DI slot that
// githubFederationModule.requires.
const configBootstrapModule = defineModule({
	name: "test-github-config-bootstrap",
	requires: [] as const,
	provides: {
		githubFederationConfig: () => stubGithubConfig,
	},
});

// Activator module: requires both synthetic resolvers so the boot planner
// materialises the projections into `handle.components`. Without an active
// requirer the lazy projection may not be exposed.
const activatorModule = defineModule({
	name: "test-github-activator",
	requires: ["federationProviders", "federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_github_noop__",
				id: "test-github-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("githubFederationModule boot integration (Cl-M2)", () => {
	it("boots end-to-end and materialises both federations.github and federationRedirectPolicies.github", async () => {
		const handle = await createApp({
			modules: [githubFederationModule, configBootstrapModule, activatorModule],
			bootstrapComponents: minBoot,
		});

		const providers = (handle.components as Record<string, unknown>).federationProviders as
			| ReadonlyMap<string, FederationProvider>
			| undefined;
		expect(providers).toBeDefined();
		const provider = providers?.get("github");
		expect(provider).toBeDefined();
		expect(provider?.name).toBe("github");

		const policyResolver = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as
			| ReadonlyMap<string, FederationRedirectPolicy>
			| undefined;
		expect(policyResolver).toBeDefined();
		const policy = policyResolver?.get("github");
		expect(policy).toBeDefined();
		expect(typeof policy?.validateRedirect).toBe("function");
		expect(typeof policy?.resolveCallbackRedirect).toBe("function");

		await handle.dispose();
	});
});
