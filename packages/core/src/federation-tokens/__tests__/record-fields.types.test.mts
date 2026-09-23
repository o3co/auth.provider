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
 * Every `FederationTokens` field is a required key.
 *
 * A `FederationTokenStore` often copies a record field by field — the bundled
 * in-memory store does. A field it forgets is dropped without a sound, and
 * every field of this record changes what happens when it is gone:
 *
 * - `tokenType` (#645): absent is read as a record written before #645 and
 *   answered as Bearer — a sender-constrained token handed on as a bearer one.
 *   Fails OPEN.
 * - `refreshToken`: absent is `410 refresh_token_absent`; the connection
 *   cannot be refreshed and the user has to sign in again.
 * - `idToken`: absent loses the `id_token_hint` logout sends the upstream.
 * - `scope` / `grantedScope` (#647): what the response reports, and the
 *   ceiling a refresh is bounded by.
 * - `expiresAt` was already required (`Date | null`), for the same reason.
 *
 * No marker in the record can catch a store that drops fields: it would drop
 * the marker too. The type can. Every field is a REQUIRED key, its value
 * `undefined` where there is nothing to record, so an object literal that
 * leaves any of them out fails to compile.
 *
 * Asserted with a conditional type rather than `@ts-expect-error`, which any
 * error on its line would satisfy. This file only proves anything under the
 * TypeScript checker; it is on BOTH of core's typecheck lists for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { FederationTokens } from "#/federation-tokens/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

/** The keys of `T` that may be left out of an object literal. */
type OptionalKeys<T> = { [K in keyof T]-?: IsRequiredKey<T, K> extends true ? never : K }[keyof T];

describe("FederationTokens — a store cannot forget a field", () => {
	it("has no optional key", () => {
		expectTypeOf<OptionalKeys<FederationTokens>>().toEqualTypeOf<never>();
	});

	it("names each field, so a failure says which one regressed", () => {
		expectTypeOf<IsRequiredKey<FederationTokens, "accessToken">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "refreshToken">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "idToken">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "expiresAt">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "tokenType">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "scope">>().toEqualTypeOf<true>();
		expectTypeOf<IsRequiredKey<FederationTokens, "grantedScope">>().toEqualTypeOf<true>();
	});

	it("still lets a field hold undefined where there is nothing to record", () => {
		expectTypeOf<FederationTokens["tokenType"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<FederationTokens["grantedScope"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<FederationTokens["refreshToken"]>().toEqualTypeOf<string | undefined>();
	});

	it("tells an optional key from a required one — the helper's control", () => {
		// Without this, `IsRequiredKey` answering `true` for everything would
		// pass every assertion above.
		type Probe = { readonly a?: string; readonly b: string | undefined };
		expectTypeOf<IsRequiredKey<Probe, "a">>().toEqualTypeOf<false>();
		expectTypeOf<IsRequiredKey<Probe, "b">>().toEqualTypeOf<true>();
		expectTypeOf<OptionalKeys<Probe>>().toEqualTypeOf<"a">();
	});
});
