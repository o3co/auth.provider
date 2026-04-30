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
import { describe, expect, it } from "vitest";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createBootApp, defineModule } from "../../index.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

// `federationRedirectPolicyResolver` is declared in the session package's
// ComponentMap declaration-merge. Cast requires to `never` so this core test
// can exercise the override mechanism without adding a cross-package dependency.
const activatorModule = defineModule({
	name: "test-override-activator",
	requires: ["federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_override_noop__",
				id: "test-override-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("A5 override mechanism — federationRedirectPolicies", () => {
	it("overriding federationRedirectPolicies[google] replaces the policy without replacing FederationProvider", async () => {
		// `federationRedirectPolicies` is declared in the session package's
		// ContributesMap declaration-merge. Cast contributes to `never` so this
		// core test can exercise the override mechanism without adding a
		// cross-package dependency. Per pattern established in federation-pairing.test.mts.
		const builtinGoogleModule = defineModule({
			name: "builtin-google",
			requires: [] as const,
			contributes: {
				federations: {
					google: () => ({
						name: "google",
						scope: ["openid"],
						buildAuthorizationUrl: () => new URL("https://accounts.google.com/auth"),
						exchangeCode: async () => ({
							issuer: "https://accounts.google.com",
							sub: "123",
							expiresAt: null,
						}),
					}),
				},
				federationRedirectPolicies: {
					google: () => ({
						validateRedirect: (_url: string) => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/default" }),
					}),
				},
			} as never,
		});

		// Custom override: strict redirect policy — rejects all URLs.
		// Cast overrides to `never` for the same cross-package declaration-merge
		// reason as contributes above.
		const customPolicyModule = defineModule({
			name: "custom-google-policy",
			requires: [] as const,
			overrides: {
				federationRedirectPolicies: {
					google: () => ({
						validateRedirect: (_url: string) => ({
							ok: false as const,
							status: 403,
							error: "redirect_denied",
							errorDescription: "custom strict policy rejects all",
						}),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/custom" }),
					}),
				},
			} as never,
		});

		const handle = await createBootApp({
			modules: [builtinGoogleModule, customPolicyModule, activatorModule],
			bootstrapComponents: minBoot,
		});

		const resolver = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as ReadonlyMap<
			string,
			{ validateRedirect: (url: string) => { ok: boolean; status?: number } }
		>;
		expect(resolver).toBeDefined();

		const policy = resolver.get("google");
		expect(policy).toBeDefined();
		if (policy === undefined) return; // narrowing guard; expect above already fails if absent

		// Custom policy should reject (strict policy override)
		const result = policy.validateRedirect("https://example.com/x");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(403);
		}

		// FederationProvider is still accessible via federationProviders (unchanged)
		const providers = (handle.components as Record<string, unknown>)
			.federationProviders as ReadonlyMap<string, { name: string }>;
		expect(providers).toBeDefined();
		const provider = providers?.get("google");
		expect(provider?.name).toBe("google");

		await handle.dispose();
	});
});
