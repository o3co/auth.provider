import type { ComponentMap } from "@o3co/auth-provider-core";
import { expectTypeOf, test } from "vitest";

// Cross-spec invariant enforcement (X1 amendment) at the PACKAGE BOUNDARY.
//
// Per A3 spec §5.5 and A4 spec §5.6: the v0.5.0 ComponentMap MUST NOT
// declare:
//   - userSessionStore: UserSessionStoreBase   (legacy v0.4.x shape)
//   - refreshTokenStore: RefreshTokenStoreBase (legacy v0.4.x slot name)
//
// Phases 5 (A1), 6 (A3), 8 (A4) declaration-merge their replacement slots:
//   - challengeStore, replaySeenSet, challengeCeremony (A1)
//   - refreshTokenFamilyStore, refreshTokenFamilyRotation,
//     refreshTokenFamilyRevocation (A3)
//   - userSessionStore (A4 — narrowed type, NOT UserSessionStoreBase),
//     sessionRPRegistry, sessionFamilyIndex, sessionFederationIndex,
//     mutableUserSessionStore (Future Use), redisClient (A1)
//
// This test mirrors the namespace-level test in component-map.test.mts
// but imports from the package boundary `@o3co/auth-provider-core`.
// Together they catch a regression regardless of which sub-file
// accidentally re-introduces a legacy shape.

test("legacy v0.4.x slots are NOT in v0.5.0 ComponentMap (package-boundary check)", () => {
	// userSessionStore: A4 (Phase 8) reuses this slot name with a NARROW
	// 3-method type (`create` / `get` / `delete` only, no `registerRP` /
	// `linkFamily` / `updateClaims` / `removeFederation`). Discriminate on
	// `registerRP` to detect ONLY the legacy shape; the A4 narrow type
	// passes through as expected.
	//
	// The `?: infer V` form handles both required and optional slot
	// declarations — A4 declares `userSessionStore?: UserSessionStore`
	// (optional). NonNullable<V> strips undefined.
	type _LegacyUserSessionAbsent = ComponentMap extends {
		userSessionStore?: infer V;
	}
		? NonNullable<V> extends {
				registerRP: (...args: never[]) => unknown;
			}
			? "FAIL: legacy userSessionStore (with registerRP) present"
			: "PASS"
		: "PASS";
	type _A1 = _LegacyUserSessionAbsent extends "PASS" ? true : false;
	expectTypeOf<_A1>().toEqualTypeOf<true>();

	// refreshTokenStore: A3 retires the slot NAME entirely (replaced by
	// refreshTokenFamilyStore + refreshTokenFamilyRotation +
	// refreshTokenFamilyRevocation). Issue #101 (Task A8) deletes the
	// transitional bridge that was added during Phase 9; this assertion
	// is now active.
	type _LegacyRefreshAbsent = "refreshTokenStore" extends keyof ComponentMap
		? "FAIL: legacy refreshTokenStore slot name reappeared"
		: "PASS";
	type _A2 = _LegacyRefreshAbsent extends "PASS" ? true : false;
	expectTypeOf<_A2>().toEqualTypeOf<true>();
});
