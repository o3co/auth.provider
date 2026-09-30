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
 * A session store's copy of a session cannot leave `amr` or `authentication`
 * out and still compile, when the copy is an object literal of the record
 * type; not when it is behind a cast, or names the key with the wrong value.
 *
 * Both bundled stores copy the session field by field, in and out. Without
 * `amr`, `/authorize` cannot see the step-up the user performed: a request
 * whose `acr_values` needs it is answered `unmet_authentication_requirements`,
 * and the id_token and refresh chain carry no `amr`. So both keys are REQUIRED
 * on the session and on what creates one, holding `undefined` where the login
 * path recorded nothing. See ADR 2026-09-25-multi-factor-authentication, "What
 * the session records".
 *
 * `enrollmentFacts` alone is optional: a session without it — written before
 * the key, or by a store that drops it — says nothing, and its reader fails
 * closed on that; the contract suite holds a store to round-tripping it.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * proves anything only under the TypeScript checker; `user-sessions/__tests__`
 * is on BOTH of core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
	CreateUserSessionInput,
	SessionAuthentication,
	SessionEnrollmentFacts,
	UserSession,
} from "#/user-sessions/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("UserSession — what a session store answers with", () => {
	it("has no optional key but enrollmentFacts", () => {
		expectTypeOf<OptionalKeys<UserSession>>().toEqualTypeOf<"enrollmentFacts">();
		expectTypeOf<UserSession["enrollmentFacts"]>().toEqualTypeOf<
			SessionEnrollmentFacts | undefined
		>();
	});

	it("names amr, and still lets it be absent in value", () => {
		expectTypeOf<IsRequiredKey<UserSession, "amr">>().toEqualTypeOf<true>();
		expectTypeOf<UserSession["amr"]>().toEqualTypeOf<readonly string[] | undefined>();
	});

	it("names authentication, and still lets it be absent in value", () => {
		// A copy that forgot it would read every session as one written before
		// it: a federated session's untrusted upstream values split out again,
		// a verified second factor forgotten.
		expectTypeOf<IsRequiredKey<UserSession, "authentication">>().toEqualTypeOf<true>();
		expectTypeOf<UserSession["authentication"]>().toEqualTypeOf<
			SessionAuthentication | undefined
		>();
	});
});

describe("SessionAuthentication — how a session was established", () => {
	it("has no optional key: a copy names every field", () => {
		expectTypeOf<OptionalKeys<SessionAuthentication>>().toEqualTypeOf<never>();
	});
});

describe("CreateUserSessionInput — what a login path writes", () => {
	it("has no optional key but enrollmentFacts: a login path says what it knows of how the user authenticated", () => {
		expectTypeOf<OptionalKeys<CreateUserSessionInput>>().toEqualTypeOf<"enrollmentFacts">();
		expectTypeOf<IsRequiredKey<CreateUserSessionInput, "amr">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<CreateUserSessionInput, "authentication">>().toEqualTypeOf<true>();
		expectTypeOf<CreateUserSessionInput["authentication"]>().toEqualTypeOf<
			SessionAuthentication | undefined
		>();
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
