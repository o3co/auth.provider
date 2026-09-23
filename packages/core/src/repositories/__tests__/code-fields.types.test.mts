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
 * A code repository cannot hand back a code that has lost a field (#626).
 *
 * `/authorize` decides everything a code carries, and `/token` reads it back
 * without deciding again — evaluate-once-at-authorize is the contract. Both
 * bundled repositories copy the record field by field, and a field a copy
 * forgets is dropped without a sound: `nonce` gone mints an id_token the RP
 * cannot bind to its request, `acr` gone mints one that no longer attests
 * the step-up the user performed, `sid` gone leaves the RP nothing to match
 * a logout against, `grantedAudience` gone falls back to the client as the
 * audience. v0.5.1 shipped exactly this bug on the Redis path (IH-2 / TS-1).
 *
 * So what a repository answers with is every field as a REQUIRED key,
 * holding `undefined` where `/authorize` recorded nothing; a copy that
 * forgets one fails to compile. What `/authorize` writes is tied to the same
 * keys, so a field added to the record is one it has to name too — all but
 * `expiresIn`, whose absence means the repository's own default.
 *
 * Asserted with conditional types rather than `@ts-expect-error`. This file
 * only proves anything under the TypeScript checker, and is on BOTH of core's
 * typecheck lists for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { CodeRepository, CreateCodeInput } from "#/repositories/CodeRepository.mjs";
import type { Code } from "#/repositories/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("Code — what a repository answers with", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<Code>>().toEqualTypeOf<never>();
	});

	it("names each field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<Code, "code_challenge">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "code_challenge_method">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "nonce">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "sid">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "acr">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "expiresIn">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "grantedScope">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<Code, "grantedAudience">>().toEqualTypeOf<true>();
	});

	it("still lets a field be absent in value, as undefined", () => {
		expectTypeOf<Code["nonce"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<Code["grantedAudience"]>().toEqualTypeOf<readonly string[] | undefined>();
	});
});

describe("CreateCodeInput — what /authorize writes", () => {
	it("is what createCode takes", () => {
		expectTypeOf<Parameters<CodeRepository["createCode"]>[0]>().toEqualTypeOf<CreateCodeInput>();
	});

	it("leaves only expiresIn optional — absent means the repository's default", () => {
		expectTypeOf<OptionalKeys<CreateCodeInput>>().toEqualTypeOf<"expiresIn">();
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
