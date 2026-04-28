import { expectTypeOf, test } from "vitest";
import type {
  ContributesMap,
  GrantFactory,
  AuditHookFactory,
} from "../contributes-map.mjs";

// Local fixture deps — does NOT augment shared ComponentMap.
type LocalDeps = { readonly _localCfg: { readonly url: string } };

test("ContributesMap has all 7 v0.5.0 base kinds", () => {
  // Per A2-α §4.1 baseline declares 7 kinds. A5 (Phase 7) adds an 8th
  // (federationRedirectPolicies). Phase 1 ships only the 7 baseline.
  type Keys = keyof ContributesMap<LocalDeps>;
  expectTypeOf<Keys>().toEqualTypeOf<
    | "grants"
    | "federations"
    | "tokenExchangeValidators"
    | "mfaFactors"
    | "auditHooks"
    | "routes"
    | "grantPolicyHooks"
  >();
});

test("Per-kind factories receive Deps as argument", () => {
  type GF = GrantFactory<LocalDeps>;
  expectTypeOf<GF>().parameter(0).toEqualTypeOf<LocalDeps>();
});

test("List-shaped kinds are readonly arrays", () => {
  type AuditField = NonNullable<ContributesMap<LocalDeps>["auditHooks"]>;
  expectTypeOf<AuditField>().toMatchTypeOf<
    readonly AuditHookFactory<LocalDeps>[]
  >();
});

test("Name-keyed kinds are readonly records", () => {
  type GrantsField = NonNullable<ContributesMap<LocalDeps>["grants"]>;
  expectTypeOf<GrantsField>().toMatchTypeOf<{
    readonly [name: string]: GrantFactory<LocalDeps>;
  }>();
});
