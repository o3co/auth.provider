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
 * A session store cannot hand back a session that has lost its `amr` (#626).
 *
 * Both bundled stores copy the session field by field on the way in and on
 * the way out, and `amr` is the one field a copy could forget without an
 * error. Gone, `/authorize` can no longer see the step-up the user performed
 * — every `acr_values` request asks them to sign in again — and the id_token
 * and the refresh chain carry no `amr`.
 *
 * So `amr` is a REQUIRED key on the session and on what creates one, holding
 * `undefined` where the login path recorded nothing: a store's copy that
 * forgets it, or a login path that does not say what it knows, fails to
 * compile.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker; `user-sessions/__tests__`
 * is on BOTH of core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { CreateUserSessionInput, UserSession } from "#/user-sessions/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("UserSession — what a session store answers with", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<UserSession>>().toEqualTypeOf<never>();
	});

	it("names amr, and still lets it be absent in value", () => {
		expectTypeOf<IsRequiredKey<UserSession, "amr">>().toEqualTypeOf<true>();
		expectTypeOf<UserSession["amr"]>().toEqualTypeOf<readonly string[] | undefined>();
	});
});

describe("CreateUserSessionInput — what a login path writes", () => {
	it("has no optional key: a login path says what it knows of how the user authenticated", () => {
		expectTypeOf<OptionalKeys<CreateUserSessionInput>>().toEqualTypeOf<never>();
		expectTypeOf<IsRequiredKey<CreateUserSessionInput, "amr">>().toEqualTypeOf<true>();
	});
});

describe("the helper's control", () => {
	it("tells an optional key from a required one", () => {
		// Without this, `IsRequiredKey` answering `true` for everything would
		// pass every assertion above.
		type Probe = { readonly a?: string; readonly b: string | undefined };
		expectTypeOf<IsRequiredKey<Probe, "a">>().toEqualTypeOf<false>();
		expectTypeOf<IsRequiredKey<Probe, "b">>().toEqualTypeOf<true>();
	});
});
