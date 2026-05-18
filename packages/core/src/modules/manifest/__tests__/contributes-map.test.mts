import { expect, expectTypeOf, test } from "vitest";
import type { AuditHookFactory, ContributesMap, GrantFactory } from "../contributes-map.mjs";
import type { ProviderDeps } from "../provider.mjs";

// Local fixture deps — does NOT augment shared ComponentMap.
type LocalDeps = { readonly _localCfg: { readonly url: string } };

test("ContributesMap has all 7 v0.5.0 base kinds plus grantMiddleware (Wave 2 Phase 1 retro)", () => {
	// Per A2-α §4.1 baseline declares 7 kinds. A5 (Phase 7) adds
	// `federationRedirectPolicies` via `declare module` augmentation in the
	// session package. Wave 2 Phase 1 retro (Phase 2 DPoP spec §11.1) adds
	// `grantMiddleware` as the 8th kind in the core ContributesMap.
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
