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

test("ContributesMap has exactly core's fourteen contribution kinds", () => {
	// `federationRedirectPolicies` is absent: the session package adds it
	// through `declare module` augmentation.
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
		| "admissionActions"
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
// grantMiddleware kind
// ---------------------------------------------------------------------------

test("ContributesMap includes grantMiddleware kind", () => {
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
// A module's rate-limit budgets, and what a federation contribution declares
// it handles
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
