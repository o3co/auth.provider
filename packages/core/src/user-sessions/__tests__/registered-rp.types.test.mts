/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A `SessionRPRegistry`'s copy of an RP cannot leave out how to reach it at
 * logout and still compile — for a copy built as an object literal of the
 * record type; not for one behind a cast or one that names a field with the
 * wrong value.
 *
 * A registry copies the record field by field — both bundled ones do — and a
 * field it forgets is dropped without a sound. For `RegisteredRP` that is the
 * logout cascade: `backchannelLogoutUri` / `frontchannelLogoutUri` gone, and
 * the RP is never told the session ended, so its own session outlives the
 * user's logout here; `*SessionRequired: false` gone, and `sid` is sent to an
 * RP that asked not to receive it (the default is `true`).
 *
 * Every field is a REQUIRED key, `undefined` where the client registered
 * none, so a copy that forgets one fails to compile. Asserted with
 * conditional types rather than `@ts-expect-error`; `user-sessions/__tests__`
 * is on both of core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { RegisteredRP } from "#/user-sessions/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("RegisteredRP — a registry cannot forget how to reach an RP at logout", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<RegisteredRP>>().toEqualTypeOf<never>();
	});

	it("names each logout field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<RegisteredRP, "backchannelLogoutUri">>().toEqualTypeOf<true>();
		expectTypeOf<
			IsRequiredKey<RegisteredRP, "backchannelLogoutSessionRequired">
		>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<RegisteredRP, "frontchannelLogoutUri">>().toEqualTypeOf<true>();
		expectTypeOf<
			IsRequiredKey<RegisteredRP, "frontchannelLogoutSessionRequired">
		>().toEqualTypeOf<true>();
	});

	it("still lets a client register no logout endpoint, as undefined", () => {
		expectTypeOf<RegisteredRP["backchannelLogoutUri"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<RegisteredRP["frontchannelLogoutSessionRequired"]>().toEqualTypeOf<
			boolean | undefined
		>();
	});

	it("tells an optional key from a required one — the helper's control", () => {
		type Probe = { readonly a?: string; readonly b: string | undefined };
		expectTypeOf<IsRequiredKey<Probe, "a">>().toEqualTypeOf<false>();
		expectTypeOf<IsRequiredKey<Probe, "b">>().toEqualTypeOf<true>();
	});
});
