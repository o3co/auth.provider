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
 * A code repository's copy of a code cannot leave a field out and still
 * compile — for a copy built as an object literal of the record type; not for
 * one behind a cast or one that names a field with the wrong value.
 *
 * `/token` reads back what `/authorize` decided without deciding again, and
 * the bundled repositories copy the record field by field, so a field a copy
 * forgets is dropped silently: `nonce` gone mints an id_token the RP cannot
 * bind to its request, `acr` gone one that no longer attests the step-up the
 * user performed, `amr` gone tokens that carry no `amr`, `sid` gone makes
 * `/token` refuse the code where a session store is wired and otherwise
 * leaves the RP nothing to match a logout against, `grantedAudience` gone
 * falls back to the client as the audience.
 * So `Code` holds every field as a REQUIRED key, `undefined` where
 * `/authorize` recorded nothing. `CreateCodeInput` is tied to the same keys,
 * so a field added to the record must be named there too; only `expiresIn`
 * may be left out, meaning the repository's own default.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. The file
 * proves anything only under the TypeScript checker, so it is on both of
 * core's typecheck lists.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { CodeRepository, CreateCodeInput } from "#/repositories/CodeRepository.mjs";
import type { Code, CodeAuthentication } from "#/repositories/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("Code — what a repository answers with", () => {
	it("has no optional key but authentication, optional until every writer names it", () => {
		expectTypeOf<OptionalKeys<Code>>().toEqualTypeOf<"authentication">();
	});

	it("names each field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<Code, "code_challenge">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "code_challenge_method">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "nonce">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "sid">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "acr">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "amr">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "expiresIn">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "grantedScope">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "grantedAudience">>().toEqualTypeOf<true>();
	});

	it("still lets a field be absent in value, as undefined", () => {
		expectTypeOf<Code["nonce"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<Code["grantedAudience"]>().toEqualTypeOf<readonly string[] | undefined>();
		expectTypeOf<Code["amr"]>().toEqualTypeOf<readonly string[] | undefined>();
		expectTypeOf<Code["authentication"]>().toEqualTypeOf<CodeAuthentication | undefined>();
	});
});

describe("CreateCodeInput — what /authorize writes", () => {
	it("is what createCode takes", () => {
		expectTypeOf<Parameters<CodeRepository["createCode"]>[0]>().toEqualTypeOf<CreateCodeInput>();
	});

	it("leaves only expiresIn optional — absent means the repository's default — and authentication, until every writer names it", () => {
		expectTypeOf<OptionalKeys<CreateCodeInput>>().toEqualTypeOf<"expiresIn" | "authentication">();
	});

	it("names exactly the record's fields but the code itself", () => {
		// A field added to the record and not to the input would be written by
		// nothing — every repository copy still compiles, holding `undefined`.
		expectTypeOf<keyof CreateCodeInput>().toEqualTypeOf<Exclude<keyof Code, "code">>();
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
