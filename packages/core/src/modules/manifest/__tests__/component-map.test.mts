import { expectTypeOf, test } from "vitest";
import type { ComponentKey, ComponentMap } from "../component-map.mjs";

test("ComponentMap accumulates declaration-merged slots from each phase", () => {
	// ComponentMap is a declaration-mergeable interface. This asserts only the
	// two bootstrap slots, `config` and `pathResolver`: modules keep adding
	// slots, and a `toEqualTypeOf` on the full union would need an edit for
	// each.
	type Bootstrap = Extract<ComponentKey, "config" | "pathResolver">;
	expectTypeOf<Bootstrap>().toEqualTypeOf<"config" | "pathResolver">();
});

test("ComponentMap has no refreshTokenStore slot and no userSessionStore of the registerRP shape", () => {
	// ComponentMap MUST NOT declare the legacy `userSessionStore:
	// UserSessionStoreBase` nor `refreshTokenStore: RefreshTokenStoreBase`.
	// The two checks differ:
	//
	// - `userSessionStore`: the slot name is reused with a NARROW 3-method type
	//   (`create` / `get` / `delete`). `registerRP` marks the legacy shape, so
	//   the check fires only if that SHAPE comes back.
	// - `refreshTokenStore`: the slot NAME is retired (replaced by
	//   `refreshTokenFamilyStore`, `refreshTokenFamilyRotation` and
	//   `refreshTokenFamilyRevocation`), so the check is on presence.

	type _LegacyUserSessionAbsent = ComponentMap extends {
		userSessionStore?: infer V;
	}
		? NonNullable<V> extends { registerRP: (...args: never[]) => unknown }
			? "FAIL: legacy userSessionStore (with registerRP) present"
			: "PASS"
		: "PASS";
	type _A1 = _LegacyUserSessionAbsent extends "PASS" ? true : false;
	expectTypeOf<_A1>().toEqualTypeOf<true>();

	type _LegacyRefreshAbsent = "refreshTokenStore" extends keyof ComponentMap
		? "FAIL: legacy refreshTokenStore slot name reappeared"
		: "PASS";
	type _A2 = _LegacyRefreshAbsent extends "PASS" ? true : false;
	expectTypeOf<_A2>().toEqualTypeOf<true>();
});
