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
 * A `federations` contribution that declares what it handles (#728): beside
 * the factory that builds the provider, the `type` an entry of the
 * `federations` configuration names to select it and the schema an entry of
 * that type is parsed with. Declared, not dispatched: boot registers the
 * provider under the contribution's name, as it does a bare factory's, and
 * reads neither the type nor the schema.
 */

import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { FederationProvider } from "../../federations/types.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp } from "../create-app.mjs";
import type { BootstrapMap } from "../types.mjs";
import { BootError } from "../types.mjs";

const bootWith = (extra: Record<string, unknown> = {}): BootstrapMap =>
	({
		config: { ...makeValidCoreConfig(), ...extra } as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

const providerNamed = (name: string): FederationProvider => ({
	name,
	scope: ["openid"],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/authorize`),
	exchangeCode: async () => ({ issuer: `https://${name}.example`, sub: "1", expiresAt: null }),
});

/**
 * The redirect policy every federation name is paired with at stage 1. The
 * kind is the session package's, which core does not import, hence the cast.
 */
const redirectPolicyFor = (name: string) =>
	defineModule({
		name: `policy-${name}`,
		contributes: {
			federationRedirectPolicies: {
				[name]: () => ({
					validateRedirect: () => ({ ok: true as const, value: undefined }),
					resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
				}),
			},
		} as never,
	});

const CorpEntry = z.object({ clientId: z.string() });

describe("a declared federation contribution", () => {
	it("registers the provider its factory builds under its name, the factory given the module's deps", async () => {
		const provider = providerNamed("corp");
		let config: unknown;
		const corp = defineModule({
			name: "federation-corp",
			requires: ["config"],
			contributes: {
				federations: {
					corp: {
						type: "acme",
						entrySchema: CorpEntry,
						factory: (deps) => {
							config = deps.config;
							return provider;
						},
					},
				},
			},
		});

		const handle = await createApp({
			modules: [corp, redirectPolicyFor("corp")],
			bootstrapComponents: bootWith(),
		});

		expect(handle.components.federationProviders?.get("corp")).toBe(provider);
		expect(config).toBe(handle.components.config);
		await handle.dispose();
	});

	it("is not dispatched: boot reads neither the type nor the entry schema", async () => {
		const entrySchema = z.object({ clientId: z.string() });
		const parse = vi.spyOn(entrySchema, "parse");
		const safeParse = vi.spyOn(entrySchema, "safeParse");
		const corp = defineModule({
			name: "federation-corp",
			contributes: {
				federations: {
					corp: { type: "acme", entrySchema, factory: () => providerNamed("corp") },
				},
			},
		});

		const handle = await createApp({
			modules: [corp, redirectPolicyFor("corp")],
			// An entry of another type, which the declared schema would refuse.
			bootstrapComponents: bootWith({
				federations: { corp: { enabled: false, type: "other", clientId: 42 } },
			}),
		});

		expect(handle.components.federationProviders?.get("corp")?.name).toBe("corp");
		expect(parse).not.toHaveBeenCalled();
		expect(safeParse).not.toHaveBeenCalled();
		await handle.dispose();
	});

	it("may override a bare factory's federation, and registers its own provider", async () => {
		const replacement = providerNamed("corp");
		const bare = defineModule({
			name: "federation-corp",
			contributes: { federations: { corp: () => providerNamed("corp") } },
		});
		const declared = defineModule({
			name: "federation-corp-replacement",
			overrides: {
				federations: {
					corp: { type: "acme", entrySchema: CorpEntry, factory: () => replacement },
				},
			},
		});

		const handle = await createApp({
			modules: [bare, declared, redirectPolicyFor("corp")],
			bootstrapComponents: bootWith(),
		});

		expect(handle.components.federationProviders?.get("corp")).toBe(replacement);
		await handle.dispose();
	});

	it("is one contribution of its name like a bare factory: the two under one name refuse boot", async () => {
		const bare = defineModule({
			name: "federation-corp",
			contributes: { federations: { corp: () => providerNamed("corp") } },
		});
		const declared = defineModule({
			name: "federation-corp-declared",
			contributes: {
				federations: {
					corp: { type: "acme", entrySchema: CorpEntry, factory: () => providerNamed("corp") },
				},
			},
		});

		let err: unknown;
		try {
			await createApp({
				modules: [bare, declared, redirectPolicyFor("corp")],
				bootstrapComponents: bootWith(),
			});
		} catch (caught) {
			err = caught;
		}

		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).details).toMatchObject({
			reason: "duplicate-contribute",
			kind: "federations",
			identity: "corp",
			modules: ["federation-corp", "federation-corp-declared"],
		});
	});
});
