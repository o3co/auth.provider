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
  // MUST NOT declare legacy `userSessionStore: UserSessionStoreBase` nor
  // `refreshTokenStore: RefreshTokenStoreBase`.
  //
  // The two slots have asymmetric invariants:
  //
  // - `userSessionStore`: A4 (Phase 8) reuses this slot name with a NARROW
  //   3-method type (`create` / `findById` / `delete` only — no
  //   `registerRP` / `linkFamily` / `updateClaims` / `removeFederation`).
  //   The discriminator below uses `registerRP` as the legacy-shape
  //   signature; a narrow A4 `userSessionStore` does NOT have `registerRP`,
  //   so the test still passes after Phase 8 lands. The test fires only
  //   when a regression reintroduces the legacy SHAPE.
  //
  // - `refreshTokenStore`: A3 retires this slot NAME entirely (replaced by
  //   `refreshTokenFamilyStore`). The presence-based check below fires if
  //   the legacy name reappears at all in any phase.

  type _LegacyUserSessionAbsent = ComponentMap extends {
    userSessionStore: { registerRP: (...args: never[]) => unknown };
  }
    ? "FAIL: legacy userSessionStore (with registerRP) present"
    : "PASS";
  type _A1 = _LegacyUserSessionAbsent extends "PASS" ? true : false;
  expectTypeOf<_A1>().toEqualTypeOf<true>();

  type _LegacyRefreshAbsent = "refreshTokenStore" extends keyof ComponentMap
    ? "FAIL: legacy refreshTokenStore slot name reappeared"
    : "PASS";
  type _A2 = _LegacyRefreshAbsent extends "PASS" ? true : false;
  expectTypeOf<_A2>().toEqualTypeOf<true>();
});
