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
 * Integration tests for the A5 pairing invariant (validate-manifests step 7.5)
 * and the federationRedirectPolicyResolver synthetic projection (step 0).
 *
 * `federationRedirectPolicies` is declared in the session package's
 * ContributesMap augmentation. Core tests cast `contributes` objects to
 * `never` where needed so the pairing logic (runtime) can be exercised
 * without pulling a session dependency into core.
 *
 * Per A5 §8.1, §8.2.
 */
import { describe, expect, it } from "vitest";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createBootApp, defineModule } from "../../index.mjs";
import { BootError } from "../types.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

// Activator module: a no-op route + requires federationRedirectPolicyResolver.
// Forces materialisation of the synthetic projection so the matched-pair test
// can assert the resolver is populated.
//
// `federationRedirectPolicyResolver` is added to ComponentMap via the session
// package's declaration-merge (concrete type: ReadonlyMap<string,
// FederationRedirectPolicy>). Core tests cast `requires` to `never` to avoid
// pulling a session dependency into core.
const activatorModule = defineModule({
	name: "test-federation-activator",
	requires: ["federationRedirectPolicyResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_federation_noop__",
				id: "test-federation-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

describe("A5 pairing invariant — step 7.5", () => {
	it("federation-without-policy: federations[google] without matching policy throws", async () => {
		const federationOnlyModule = defineModule({
			name: "test-google-federation-only",
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
			},
		});

		await expect(
			createBootApp({
				modules: [federationOnlyModule, activatorModule],
				bootstrapComponents: minBoot,
			}),
		).rejects.toSatisfy((err: unknown) => {
			return (
				err instanceof BootError &&
				err.reason === "federation-redirect-policy-unpaired" &&
				(err.details as { side?: string }).side === "federation-without-policy" &&
				(err.details as { name?: string }).name === "google"
			);
		});
	});

	it("policy-without-federation: federationRedirectPolicies[github] without federation throws", async () => {
		// ContributesMap declaration-merge for federationRedirectPolicies lives in
		// the session package. Cast to `never` to exercise the runtime path from
		// a core-only test without adding a cross-package dependency.
		const policyOnlyModule = defineModule({
			name: "test-github-policy-only",
			requires: [] as const,
			contributes: {
				federationRedirectPolicies: {
					github: () => ({
						validateRedirect: () => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
					}),
				},
			} as never,
		});

		await expect(
			createBootApp({
				modules: [policyOnlyModule, activatorModule],
				bootstrapComponents: minBoot,
			}),
		).rejects.toSatisfy((err: unknown) => {
			return (
				err instanceof BootError &&
				err.reason === "federation-redirect-policy-unpaired" &&
				(err.details as { side?: string }).side === "policy-without-federation" &&
				(err.details as { name?: string }).name === "github"
			);
		});
	});

	it("matched pair boots successfully and resolver is populated", async () => {
		// Both federations[google] and federationRedirectPolicies[google] provided —
		// pairing invariant satisfied. Resolver must be a ReadonlyMap with "google".
		// Cast to `never` for the same reason as the policy-only test above.
		const pairedModule = defineModule({
			name: "test-google-paired",
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
						validateRedirect: () => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
					}),
				},
			} as never,
		});

		const handle = await createBootApp({
			modules: [pairedModule, activatorModule],
			bootstrapComponents: minBoot,
		});

		const resolver = (handle.components as Record<string, unknown>)
			.federationRedirectPolicyResolver as ReadonlyMap<string, unknown>;
		expect(resolver).toBeDefined();
		expect(resolver.has("google")).toBe(true);

		await handle.dispose();
	});

	it("synthetic-key-collision: module providing federationRedirectPolicyResolver directly throws", async () => {
		// ComponentMap declaration-merge for federationRedirectPolicyResolver also
		// lives in session. Cast provides to `never` to test the runtime guard.
		const badModule = defineModule({
			name: "test-bad-provides-synthetic",
			requires: [] as const,
			provides: {
				federationRedirectPolicyResolver: () => new Map(),
			} as never,
		});

		await expect(
			createBootApp({
				modules: [badModule],
				bootstrapComponents: minBoot,
			}),
		).rejects.toSatisfy((err: unknown) => {
			return err instanceof BootError && err.reason === "synthetic-key-collision";
		});
	});
});
