import type { ComponentMap } from "@o3co/auth-provider-core";
import { expectTypeOf, test } from "vitest";

// The ComponentMap exported from `@o3co/auth-provider-core` MUST NOT declare:
//   - userSessionStore: UserSessionStoreBase   (legacy shape)
//   - refreshTokenStore: RefreshTokenStoreBase (legacy slot name)
//
// Mirrors the namespace-level test in component-map.test.mts at the package
// boundary, so a legacy shape re-introduced from any sub-file is caught.

test("the package's exported ComponentMap has no refreshTokenStore slot and no userSessionStore of the registerRP shape", () => {
	// The userSessionStore slot name is reused with a narrow type (`create` /
	// `get` / `delete` only), so discriminate on `registerRP` to detect ONLY
	// the legacy shape. `?: infer V` handles both required and optional slot
	// declarations; NonNullable<V> strips undefined.
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

	// The refreshTokenStore slot NAME is retired entirely (replaced by
	// refreshTokenFamilyStore / Rotation / Revocation).
	type _LegacyRefreshAbsent = "refreshTokenStore" extends keyof ComponentMap
		? "FAIL: legacy refreshTokenStore slot name reappeared"
		: "PASS";
	type _A2 = _LegacyRefreshAbsent extends "PASS" ? true : false;
	expectTypeOf<_A2>().toEqualTypeOf<true>();
});
