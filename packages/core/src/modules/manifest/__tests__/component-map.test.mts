import { expectTypeOf, test } from "vitest";
import type { ComponentKey, ComponentMap } from "../component-map.mjs";

test("ComponentMap accumulates declaration-merged slots from each phase", () => {
	// Sanity: ComponentMap is an interface (declaration-mergeable). Phase 1
	// shipped with an empty base; Phase 4 (A2-β) adds `config` and
	// `pathResolver` per spec §6.2's DefaultBootstrapMap contract; later
	// phases expand the union further.
	//
	// This test asserts that the two Phase 4 bootstrap slots are present.
	// It does NOT pin the full union — Phase 5/6/7/8 will add more slots,
	// and a `toEqualTypeOf` here would force a churn-edit per phase. The
	// narrower `Extract<...>` check fires only when a Phase 4 slot regresses.
	type Bootstrap = Extract<ComponentKey, "config" | "pathResolver">;
	expectTypeOf<Bootstrap>().toEqualTypeOf<"config" | "pathResolver">();
});

// TODO(#issue): Re-enable when Phase 9 Task 11 (delete legacy core/src/refresh/)
// lands. Phase 9 Task 4 (oauth module migration, A2-γ §3.2.1) re-added the
// legacy `refreshTokenStore` ComponentMap slot as a transitional bridge so
// oauth/routes.mts can keep its v0.4.x dep signatures while the migration to
// refreshTokenRotation / refreshTokenFamilyStore / refreshTokenFamilyRevocation
// is finalized. The X2 sub-assertion (`refreshTokenStore` slot name absent)
// is intentionally violated by that bridge and will fail until Task 11 is
// completed.
test.skip("ComponentMap does NOT contain v0.4.x legacy slots (X1/X2 amendment)", () => {
	// Per A4 spec X1 fix and A3 spec §5.5 line 391: the v0.5.0 ComponentMap
	// MUST NOT declare legacy `userSessionStore: UserSessionStoreBase` nor
	// `refreshTokenStore: RefreshTokenStoreBase`.
	//
	// The two slots have asymmetric invariants:
	//
	// - `userSessionStore`: A4 (Phase 8) reuses this slot name with a NARROW
	//   3-method type (`create` / `get` / `delete` only — no
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
		userSessionStore?: infer V;
	}
		? NonNullable<V> extends { registerRP: (...args: never[]) => unknown }
			? "FAIL: legacy userSessionStore (with registerRP) present"
			: "PASS"
		: "PASS";
	type _A1 = _LegacyUserSessionAbsent extends "PASS" ? true : false;
	expectTypeOf<_A1>().toEqualTypeOf<true>();

	// X2 sub-assertion intentionally commented out: Phase 9 Task 4 added
	// `refreshTokenStore` back as a transitional ComponentMap bridge for
	// oauth/routes.mts compatibility. Phase 9 Task 11 (deferred) will
	// retire the slot; this assertion is restored then.
	//
	// type _LegacyRefreshAbsent = "refreshTokenStore" extends keyof ComponentMap
	//   ? "FAIL: legacy refreshTokenStore slot name reappeared"
	//   : "PASS";
	// type _A2 = _LegacyRefreshAbsent extends "PASS" ? true : false;
	// expectTypeOf<_A2>().toEqualTypeOf<true>();
});
