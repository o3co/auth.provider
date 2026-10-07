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

import { describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";
import type { AuditSink } from "../audit/types.mjs";
import type { FederationProvider as ConcreteFederationProvider } from "../federations/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../grants/types.mjs";
import type { MfaFactor as ConcreteMfaFactor } from "../mfa/factor.mjs";
import type { Contributed } from "../modules/manifest/contributed.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationInstance,
	FederationProvider,
	FederationTypeContribution,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
	MfaFactorFactory,
	RateLimitBudgetFactory,
} from "../modules/manifest/contributes-map.mjs";
import { defineFederationType } from "../modules/manifest/define-federation-type.mjs";
import { defineModule } from "../modules/manifest/define-module.mjs";
import type { GrantPolicyHook } from "../policy/types.mjs";
import type { ExchangeTokenValidator as ConcreteExchangeTokenValidator } from "../token-exchange/validator.mjs";

// Every contribution kind carries its concrete type from registration to
// use. The first describe block covers the kinds whose implementations live
// in core. The second covers `FederationProvider` and
// `ExchangeTokenValidator`, whose contracts live in core so that nothing has
// to import downwards to name them: it asserts the identity, and that a
// module contributing a federation that is not one fails to compile.

describe("same-package concrete substitutions in contributes-map", () => {
	it("GrantHandler is the concrete grants/types GrantHandler", () => {
		expectTypeOf<GrantHandler>().toEqualTypeOf<ConcreteGrantHandler>();
		expect(true).toBe(true);
	});

	it("AuditHook is the canonical AuditSink interface", () => {
		expectTypeOf<AuditHook>().toEqualTypeOf<AuditSink>();
		expect(true).toBe(true);
	});

	it("MfaFactor is the second-factor contract in mfa/factor", () => {
		// `MfaFactor` is the contract a factor implements, so what a module
		// contributes and what the coordinator reads back through
		// `mfaFactorResolver` are one type.
		expectTypeOf<MfaFactor>().toEqualTypeOf<ConcreteMfaFactor>();
		expect(true).toBe(true);
	});

	it("an mfaFactors factory may answer null: the factor switched off by its configuration", () => {
		expectTypeOf<ReturnType<MfaFactorFactory<unknown>>>().toEqualTypeOf<
			Contributed<ConcreteMfaFactor | null>
		>();
		defineModule({
			name: "acme-mfa-factor-off",
			requires: [],
			contributes: { mfaFactors: { acme: () => null } },
		});
		expect(true).toBe(true);
	});

	it("GrantPolicyHookContribution is the canonical GrantPolicyHook interface", () => {
		expectTypeOf<GrantPolicyHookContribution>().toEqualTypeOf<GrantPolicyHook>();
		expect(true).toBe(true);
	});
});

describe("the two contracts core owns: FederationProvider and ExchangeTokenValidator", () => {
	// The contracts live in core, so the substitution is an identity: what a
	// module registers, what the resolver returns and what a consumer reads
	// are one type.

	it("FederationProvider is the contract, not `unknown`", () => {
		expectTypeOf<FederationProvider>().toEqualTypeOf<ConcreteFederationProvider>();
		expectTypeOf<FederationProvider>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("ExchangeTokenValidator is the contract, not `unknown`", () => {
		expectTypeOf<ExchangeTokenValidator>().toEqualTypeOf<ConcreteExchangeTokenValidator>();
		expectTypeOf<ExchangeTokenValidator>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("refuses a federation type whose factory answers a provider missing the methods, through the public entry point", () => {
		// Written against missing methods rather than a mistyped field:
		// `FederationProfile` carries a string index signature, so a wrong
		// field name can satisfy it vacuously and would pin nothing.
		defineModule({
			name: "acme-federation",
			requires: [],
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: z.object({}),
						// @ts-expect-error — no `buildAuthorizationUrl`, no `exchangeCode`
						factory: (_deps, { name }) => ({ name, scope: [] }),
						redirectPolicy: () => ({}),
					},
				},
			},
		});
		expect(true).toBe(true);
	});
});

describe("rate-limit budgets and declared federation contributions", () => {
	const provider = {
		name: "acme",
		scope: ["openid"],
		buildAuthorizationUrl: () => new URL("https://idp.example/authorize"),
		exchangeCode: async () => ({ issuer: "https://idp.example", sub: "1", expiresAt: null }),
	};

	it("a rateLimitBudgets factory claims its prefix, answering null", () => {
		expectTypeOf<ReturnType<RateLimitBudgetFactory<unknown>>>().toEqualTypeOf<Contributed<null>>();
		defineModule({
			name: "acme-claims",
			requires: ["config"],
			contributes: {
				rateLimitBudgets: {
					"acme-login": (deps) => {
						expectTypeOf(deps.config).not.toBeUnknown();
						return null;
					},
				},
			},
		});
		expect(true).toBe(true);
	});

	it("refuses a budget in place of the claim", () => {
		defineModule({
			name: "acme-budget",
			contributes: {
				rateLimitBudgets: {
					// @ts-expect-error — a claim answers null, never a budget
					"acme-login": () => ({ limit: 5, windowSeconds: 60 }),
				},
			},
		});
		expect(true).toBe(true);
	});

	const AcmeEntry = z.object({ issuer: z.string(), clientId: z.string() });
	type AcmeEntry = z.output<typeof AcmeEntry>;

	it("a federation type is contributed by type, its factory given the module's deps and the entry", () => {
		defineModule({
			name: "acme-federation-type",
			requires: ["config"],
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: AcmeEntry,
						// Inline, the entry is typed by annotating the instance.
						factory: (deps, { name, entry }: FederationInstance<AcmeEntry>) => {
							expectTypeOf(deps.config).not.toBeUnknown();
							expectTypeOf(entry.issuer).toEqualTypeOf<string>();
							return { ...provider, name };
						},
						redirectPolicy: (deps, { callbackURL }: FederationInstance<AcmeEntry>) => {
							expectTypeOf(deps.config).not.toBeUnknown();
							expectTypeOf(callbackURL).toEqualTypeOf<string>();
							return { callbackURL };
						},
					},
				},
			},
		});
		// Declared on its own, the schema and the entry are held to one type.
		const declared: FederationTypeContribution<{ readonly tag: string }, AcmeEntry> = {
			entrySchema: AcmeEntry,
			factory: (deps, { entry }) => {
				expectTypeOf(deps.tag).toEqualTypeOf<string>();
				expectTypeOf(entry).toEqualTypeOf<AcmeEntry>();
				return provider;
			},
			redirectPolicy: (deps, { name, entry }) => {
				expectTypeOf(deps.tag).toEqualTypeOf<string>();
				expectTypeOf(entry).toEqualTypeOf<AcmeEntry>();
				return { name };
			},
		};
		expect(declared.entrySchema).toBe(AcmeEntry);
	});

	it("refuses a federation type whose factory builds no provider, or whose schema is not the entry's", () => {
		defineModule({
			name: "acme-federation-type-wrong",
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: AcmeEntry,
						// @ts-expect-error — no `buildAuthorizationUrl`, no `exchangeCode`
						factory: () => ({ name: "corp", scope: [] }),
						redirectPolicy: () => ({}),
					},
				},
			},
		});
		const mismatched: FederationTypeContribution<unknown, AcmeEntry> = {
			// @ts-expect-error — this schema's output is not an AcmeEntry
			entrySchema: z.object({ issuer: z.number() }),
			factory: () => provider,
			redirectPolicy: () => ({}),
		};
		// @ts-expect-error — a declaration without its redirect policy: an entry is dispatched to both
		const unpaired: FederationTypeContribution<unknown, AcmeEntry> = {
			entrySchema: AcmeEntry,
			factory: () => provider,
		};
		expect(mismatched).toBeDefined();
		expect(unpaired).toBeDefined();
	});

	it("a module contributes no federations: a federation registers through its type, so the kind does not compile", () => {
		defineModule({
			name: "acme-federation-direct",
			contributes: {
				// @ts-expect-error — `federations` is core's; a type is declared under `federationTypes`
				federations: { corp: () => provider },
			},
		});
		expect(true).toBe(true);
	});

	it("defineFederationType ties the factory's entry to the schema: E is inferred from entrySchema, Deps given", () => {
		type AcmeDeps = { readonly tag: string };
		const declared = defineFederationType<AcmeDeps>()({
			entrySchema: AcmeEntry,
			factory: (deps, { name, entry }) => {
				expectTypeOf(deps).toEqualTypeOf<AcmeDeps>();
				expectTypeOf(entry).toEqualTypeOf<AcmeEntry>();
				return { ...provider, name: `${name}:${entry.issuer}` };
			},
			redirectPolicy: (deps, { callbackURL, entry }) => {
				expectTypeOf(deps).toEqualTypeOf<AcmeDeps>();
				expectTypeOf(entry).toEqualTypeOf<AcmeEntry>();
				return { callbackURL };
			},
		});
		expectTypeOf(declared).toEqualTypeOf<FederationTypeContribution<AcmeDeps, AcmeEntry>>();
		// The helper answers the declaration it was given, which the kind accepts.
		defineModule({
			name: "acme-federation-type-helper",
			requires: ["config"],
			contributes: {
				federationTypes: {
					acme: defineFederationType<{ readonly config: unknown }>()({
						entrySchema: AcmeEntry,
						factory: (_deps, { name }) => ({ ...provider, name }),
						redirectPolicy: () => ({}),
					}),
				},
			},
		});
		expect(declared.entrySchema).toBe(AcmeEntry);
	});

	it("defineFederationType refuses a factory whose entry is not what the schema produces", () => {
		defineFederationType<unknown>()({
			entrySchema: AcmeEntry,
			// @ts-expect-error — the schema produces no `tenant`
			factory: (_deps, { entry }) => ({ ...provider, name: entry.tenant }),
			redirectPolicy: () => ({}),
		});
		defineFederationType<unknown>()({
			entrySchema: AcmeEntry,
			factory: () => provider,
			// @ts-expect-error — the schema produces no `tenant`
			redirectPolicy: (_deps, { entry }) => ({ tenant: entry.tenant }),
		});
		defineFederationType<unknown>()({
			// @ts-expect-error — the entry is annotated as another type, so this schema does not pair with it
			entrySchema: z.object({ issuer: z.string() }),
			factory: (_deps, { entry }: FederationInstance<{ tenant: string }>) => ({
				...provider,
				name: entry.tenant,
			}),
			redirectPolicy: () => ({}),
		});
		// Inline in a module, without the helper, `E` is `unknown`: nothing ties an
		// annotated entry to the schema — the limitation the helper exists for.
		defineModule({
			name: "acme-federation-type-inline",
			contributes: {
				federationTypes: {
					acme: {
						entrySchema: z.object({ issuer: z.string() }),
						factory: (_deps, { name }: FederationInstance<{ tenant: string }>) => ({
							...provider,
							name,
						}),
						redirectPolicy: () => ({}),
					},
				},
			},
		});
		expect(true).toBe(true);
	});
});
