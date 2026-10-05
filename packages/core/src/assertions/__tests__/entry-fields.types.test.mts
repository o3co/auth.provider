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
 * A registry's copy of an entry cannot leave a ceiling out and still compile:
 * an entry built as an object literal of the stored type, naming its fields,
 * fails to compile when it forgets one. That is all it guarantees; it does
 * not stop a copy that writes the wrong value, one behind a cast, or a store
 * that is not TypeScript.
 *
 * Every field of `AssertionIssuerEntry` beyond `issuer`, `keys` and
 * `algorithms` restricts what an assertion from that issuer may obtain, and a
 * registry that loses a ceiling widens it (fails open): `allowedClients` gone
 * admits any presenter (an unauthenticated one too, unless the entry is an
 * ID-JAG one); `expiresAt` gone trusts the issuer for ever; `profile:
 * "id-jag"` gone falls back to plain RFC 7523, without the `jti` replay check,
 * the `typ` check and the exact-`aud` check. `clockToleranceSeconds` gone
 * applies the default, looser or stricter than what was configured. A
 * registry over a store reads its rows back field by field, and a field it
 * forgets is dropped silently.
 *
 * So a registry answers with every field as a required key, holding
 * `undefined` where the entry names no ceiling. What a caller writes (the
 * composition's entry list, `add`) is `AssertionIssuerEntryInput`, where
 * absent still means "no ceiling": an entry is configuration, and spelling
 * out every absent ceiling would make it worse to write, not safer.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * proves anything only under the TypeScript checker, so it is on both of
 * core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
	AssertionIssuerEntry,
	AssertionIssuerEntryInput,
} from "#/assertions/issuerRegistry.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("AssertionIssuerEntry — what a registry answers with", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<AssertionIssuerEntry>>().toEqualTypeOf<never>();
	});

	it("names each ceiling, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "allowedSubjects">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "allowedScopes">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "allowedAudiences">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "allowedClients">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "expiresAt">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "profile">>().toEqualTypeOf<true>();
		expectTypeOf<
			IsRequiredKey<AssertionIssuerEntry, "clockToleranceSeconds">
		>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<AssertionIssuerEntry, "maxLifetimeSeconds">>().toEqualTypeOf<true>();
	});

	it("still lets a ceiling be absent in value, as undefined", () => {
		expectTypeOf<AssertionIssuerEntry["allowedClients"]>().toEqualTypeOf<
			readonly string[] | undefined
		>();
		expectTypeOf<AssertionIssuerEntry["expiresAt"]>().toEqualTypeOf<Date | undefined>();
	});
});

describe("AssertionIssuerEntryInput — what a caller writes", () => {
	it("keeps every ceiling optional, so an entry names only what it restricts", () => {
		expectTypeOf<OptionalKeys<AssertionIssuerEntryInput>>().toEqualTypeOf<
			| "allowedSubjects"
			| "allowedScopes"
			| "allowedAudiences"
			| "allowedClients"
			| "expiresAt"
			| "profile"
			| "clockToleranceSeconds"
			| "maxLifetimeSeconds"
		>();
	});

	it("names exactly the same fields as the stored form", () => {
		// A ceiling added to the input and not to the stored form would be
		// copied by nothing — `toAssertionIssuerEntry` still compiles — and
		// dropped by the memory registry itself: the fail-open, inside core.
		expectTypeOf<keyof AssertionIssuerEntry>().toEqualTypeOf<keyof AssertionIssuerEntryInput>();
	});

	it("accepts a stored entry back as input, so list() → add() round-trips", () => {
		expectTypeOf<AssertionIssuerEntry>().toExtend<AssertionIssuerEntryInput>();
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
