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

import { describe, expect, it } from "vitest";
import type { ExchangeTokenValidationContext, ValidatedToken } from "#/validator/types.mjs";

// CC-5 readonly compile-time assertions.
//
// These tests verify at compile time that public DTOs are `readonly`. The
// `@ts-expect-error` directives below cause `tsc --noEmit` to fail (with
// "Unused '@ts-expect-error' directive") whenever a field that should be
// readonly becomes mutable. The runtime body is a no-op — the type system
// is the assertion. Wrapped in `if (false)` so no runtime mutation runs.

describe("CC-5: validator types readonly (compile-time)", () => {
	it("ExchangeTokenValidationContext.role is readonly", () => {
		if (false as boolean) {
			const ctx = { role: "subject" } as ExchangeTokenValidationContext;
			// @ts-expect-error — readonly violation
			ctx.role = "actor";
			void ctx;
		}
		expect(true).toBe(true);
	});

	it("ValidatedToken all fields readonly (exhaustive)", () => {
		if (false as boolean) {
			const t = { sub: "u1", claims: {} } as ValidatedToken;
			// @ts-expect-error
			t.sub = "u2";
			// @ts-expect-error
			t.scope = "read";
			// @ts-expect-error
			t.aud = ["a"];
			// @ts-expect-error
			t.familyId = "f";
			// @ts-expect-error
			t.act = {};
			// @ts-expect-error
			t.claims = {};
			void t;
		}
		expect(true).toBe(true);
	});
});
