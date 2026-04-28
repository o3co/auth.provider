import { expectTypeOf, test } from "vitest";
import type { ComponentKey, ComponentMap } from "../component-map.mjs";

test("ComponentMap is declaration-mergeable (empty base accepts any consumer key)", () => {
  // Sanity: ComponentMap is an interface (declaration-mergeable). The empty
  // base has no keys, so ComponentKey is `never`. Phases 5+ will declaration-
  // merge slots which expand the union.
  expectTypeOf<ComponentKey>().toEqualTypeOf<never>();
});

test("ComponentMap does NOT contain v0.4.x legacy slots (X1/X2 amendment)", () => {
  // Per A4 spec X1 fix and A3 spec §5.5 line 391: the v0.5.0 ComponentMap
  // MUST NOT declare `userSessionStore: UserSessionStoreBase` nor
  // `refreshTokenStore: RefreshTokenStoreBase`. A4 reuses `userSessionStore`
  // for a narrower type; A3 replaces with `refreshTokenFamilyStore`.
  // This test fails if a regression accidentally adds either slot.
  type _AssertLegacyAbsent = ComponentMap extends {
    userSessionStore: infer _T extends never ? never : never;
  }
    ? "FAIL: legacy userSessionStore present"
    : "PASS";
  type _A1 = _AssertLegacyAbsent extends "PASS" ? true : false;
  expectTypeOf<_A1>().toEqualTypeOf<true>();

  type _AssertRefreshAbsent = ComponentMap extends {
    refreshTokenStore: infer _T extends never ? never : never;
  }
    ? "FAIL: legacy refreshTokenStore present"
    : "PASS";
  type _A2 = _AssertRefreshAbsent extends "PASS" ? true : false;
  expectTypeOf<_A2>().toEqualTypeOf<true>();
});
