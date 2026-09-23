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
 * The `FederationTokens` fields a store must not lose silently.
 *
 * A `FederationTokenStore` often copies a record field by field — the bundled
 * in-memory store does. A field it forgets is dropped without a sound, and two
 * fields mean something when they are absent:
 *
 * - `tokenType` (#645): absent is read as a record written before #645 and
 *   answered as Bearer, so losing it hands a sender-constrained token on as a
 *   bearer one — it fails OPEN.
 * - `grantedScope` (#647): absent falls back to the current scope as the
 *   ceiling — conservative, but still a silent loss of the consent record.
 *
 * No marker in the record can catch a store that drops fields: it would drop
 * the marker too. The type can. Both fields are REQUIRED keys whose value may
 * be `undefined`, so an object literal that leaves either out fails to compile
 * — which is exactly a projection that forgot it.
 *
 * Asserted with a conditional type rather than `@ts-expect-error`, which any
 * error on its line would satisfy. This file only proves anything under the
 * TypeScript checker; it is on core's typecheck allowlist for that reason.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { FederationTokens } from "#/federation-tokens/types.mjs";

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

describe("FederationTokens — the fields a store must round-trip are required keys", () => {
	it("tokenType is a required key that may be undefined (#645)", () => {
		expectTypeOf<IsRequiredKey<FederationTokens, "tokenType">>().toEqualTypeOf<true>();
		expectTypeOf<FederationTokens["tokenType"]>().toEqualTypeOf<string | undefined>();
	});

	it("grantedScope is a required key that may be undefined (#647)", () => {
		expectTypeOf<IsRequiredKey<FederationTokens, "grantedScope">>().toEqualTypeOf<true>();
		expectTypeOf<FederationTokens["grantedScope"]>().toEqualTypeOf<string | undefined>();
	});

	it("a field that carries no such meaning stays optional", () => {
		// The control: `IsRequiredKey` answers false for an optional key, so the
		// two assertions above are not true of every field by construction.
		expectTypeOf<IsRequiredKey<FederationTokens, "idToken">>().toEqualTypeOf<false>();
	});
});
