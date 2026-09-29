import { expect, expectTypeOf, test } from "vitest";
import type { z } from "zod";
import type { RateLimitSpec } from "../../../ratelimit/types.mjs";
import type { Contributed } from "../contributed.mjs";
import type {
	AuditHookFactory,
	ContributesMap,
	FederationFactory,
	FederationInstance,
	FederationTypeContribution,
	GrantFactory,
	RateLimitBudgetFactory,
} from "../contributes-map.mjs";
import type { ProviderDeps } from "../provider.mjs";

// Local fixture deps — does NOT augment shared ComponentMap.
type LocalDeps = { readonly _localCfg: { readonly url: string } };

test("ContributesMap has all 7 v0.5.0 base kinds plus grantMiddleware + tokenBindingMechanisms + discoveryMetadata + sessionRequirements + rateLimitBudgets + federationTypes", () => {
	// Per A2-α §4.1 baseline declares 7 kinds. A5 (Phase 7) adds
	// `federationRedirectPolicies` via `declare module` augmentation in the
	// session package. Wave 2 Phase 1 retro (Phase 2 DPoP spec §11.1) adds
	// `grantMiddleware` as the 8th kind. Cross-mechanism dispatch refactor
	// (Wave 2 Phase 3 follow-up) adds `tokenBindingMechanisms` as the 9th
	// kind so multiple binding-mechanism modules can compose into a single
	// `tokenBindingMw` with a unified `DispatchPolicy`. The OIDC discovery
	// aggregator adds `discoveryMetadata` as the 10th kind so endpoint-owning
	// modules contribute their slice of the
	// `/.well-known/openid-configuration` document, which core synthesizes.
	// The session-admission ADR's D3 adds `sessionRequirements` as the 11th:
	// the requirements every consumer of a browser session asks through
	// admission. #728 adds `rateLimitBudgets` as the 12th — the budgets each
	// module owns for its rate-limit prefixes — and `federationTypes` as the
	// 13th: the federation types a package handles, keyed by type.
	type Keys = keyof ContributesMap<LocalDeps>;
	expectTypeOf<Keys>().toEqualTypeOf<
		| "grants"
		| "federations"
		| "tokenExchangeValidators"
		| "mfaFactors"
		| "auditHooks"
		| "routes"
		| "grantPolicyHooks"
		| "grantMiddleware"
		| "tokenBindingMechanisms"
		| "discoveryMetadata"
		| "sessionRequirements"
		| "rateLimitBudgets"
		| "federationTypes"
	>();
});

test("Per-kind factories receive Deps as argument", () => {
	type GF = GrantFactory<LocalDeps>;
	expectTypeOf<GF>().parameter(0).toEqualTypeOf<LocalDeps>();
});

test("List-shaped kinds are readonly arrays", () => {
	type AuditField = NonNullable<ContributesMap<LocalDeps>["auditHooks"]>;
	expectTypeOf<AuditField>().toMatchTypeOf<readonly AuditHookFactory<LocalDeps>[]>();
});

test("Name-keyed kinds are readonly records", () => {
	type GrantsField = NonNullable<ContributesMap<LocalDeps>["grants"]>;
	expectTypeOf<GrantsField>().toMatchTypeOf<{
		readonly [name: string]: GrantFactory<LocalDeps>;
	}>();
});

// ---------------------------------------------------------------------------
// Wave 2 Token-binding Cluster — Phase 1 retro: grantMiddleware kind
// ---------------------------------------------------------------------------

test("ContributesMap includes grantMiddleware kind (Wave 2 Phase 1 retro)", () => {
	type GMDeps = ProviderDeps<"config", never>;
	type Keys = keyof ContributesMap<GMDeps>;
	type GrantMiddlewareKey = "grantMiddleware";
	const _check: GrantMiddlewareKey extends Keys ? true : false = true;
	expect(_check).toBe(true);
});

test("grantMiddleware is list-shaped (factory array)", () => {
	type GMDeps = ProviderDeps<"config", never>;
	type GMField = NonNullable<ContributesMap<GMDeps>["grantMiddleware"]>;
	// Compile-time check: GMField must be a readonly array of factories.
	const _arr: GMField = [];
	const _fn = (_deps: GMDeps) => null;
	const _withFn: GMField = [_fn];
	expect(Array.isArray(_arr)).toBe(true);
	expect(Array.isArray(_withFn)).toBe(true);
});

// ---------------------------------------------------------------------------
// #728: a module's rate-limit budgets, and what a federation contribution
// declares it handles
// ---------------------------------------------------------------------------

test("rateLimitBudgets is name-keyed by prefix, each factory answering a budget or null", () => {
	type Field = NonNullable<ContributesMap<LocalDeps>["rateLimitBudgets"]>;
	expectTypeOf<Field>().toEqualTypeOf<{
		readonly [prefix: string]: RateLimitBudgetFactory<LocalDeps>;
	}>();
	expectTypeOf<RateLimitBudgetFactory<LocalDeps>>().toEqualTypeOf<
		(deps: LocalDeps) => Contributed<RateLimitSpec | null>
	>();
});

test("a federations entry is the factory alone, name-keyed by the federation's name", () => {
	type Entry = NonNullable<ContributesMap<LocalDeps>["federations"]>[string];
	expectTypeOf<Entry>().toEqualTypeOf<FederationFactory<LocalDeps>>();
});

test("federationTypes is name-keyed by the type an entry names, each declaring its entry schema and a factory given the entry", () => {
	type Field = NonNullable<ContributesMap<LocalDeps>["federationTypes"]>;
	expectTypeOf<Field>().toEqualTypeOf<{
		readonly [type: string]: FederationTypeContribution<LocalDeps>;
	}>();
	type Entry = { readonly issuer: string };
	type Declared = FederationTypeContribution<LocalDeps, Entry>;
	expectTypeOf<Declared["entrySchema"]>().toEqualTypeOf<z.ZodType<Entry>>();
	expectTypeOf<Parameters<Declared["factory"]>>().toEqualTypeOf<
		[deps: LocalDeps, instance: FederationInstance<Entry>]
	>();
	expectTypeOf<FederationInstance<Entry>>().toEqualTypeOf<{
		readonly name: string;
		readonly entry: Entry;
	}>();
	// A declaration typed for its entry is one the record accepts.
	expectTypeOf<Declared>().toMatchTypeOf<Field[string]>();
});
