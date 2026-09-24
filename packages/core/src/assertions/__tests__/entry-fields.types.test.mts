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
 * A registry's copy of an entry cannot leave a ceiling out and still compile.
 *
 * That is the guarantee, and all of it: an entry built as an object literal of
 * the stored type, naming its fields, fails to compile when it forgets one.
 * It does not stop a copy that names a field and writes the wrong value, one
 * behind a cast, or a store that is not TypeScript.
 *
 * Every field of `AssertionIssuerEntry` beyond `issuer`, `keys` and
 * `algorithms` restricts what an assertion from that issuer may obtain, and
 * for the ceilings a registry that loses one WIDENS it — fails open.
 * `clockToleranceSeconds` can go either way: gone, the default applies,
 * looser or stricter than what was configured. `allowedClients` gone admits
 * any presenter (an unauthenticated one too, unless the entry is an ID-JAG
 * one, whose presenter must authenticate); `expiresAt` gone trusts the
 * issuer for ever; `profile: "id-jag"` gone falls back to plain RFC 7523 and
 * with it the `jti` replay check, the `typ` check and the exact-`aud` check. A
 * registry over a store — which this port documents as the way to survive a
 * restart — reads its rows back field by field, and a field it forgets is
 * dropped without a sound.
 *
 * So what a registry answers with is every field as a REQUIRED key, holding
 * `undefined` where the entry names no ceiling; a read-back that forgets one
 * fails to compile. What a caller WRITES — the composition's entry list,
 * `add` — is `AssertionIssuerEntryInput`, where absent keeps meaning "no
 * ceiling", because an entry is configuration and spelling every absent
 * ceiling out would make it worse to write, not safer.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker, and is on BOTH of core's
 * typecheck lists for that reason.
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
