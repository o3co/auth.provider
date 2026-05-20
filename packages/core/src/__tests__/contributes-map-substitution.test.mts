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

import { describe, expect, expectTypeOf, it } from "vitest";
import type { AuditSink } from "../audit/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../grants/types.mjs";
import type { MfaProvider } from "../mfa/types.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
} from "../modules/manifest/contributes-map.mjs";
import type { GrantPolicyHook } from "../policy/types.mjs";

// AS-M1 (Phase F F9 PR6 / Phase 9 substitution): the four `unknown`
// placeholder types in `modules/manifest/contributes-map.mts` whose concrete
// implementations live in the same `core` package have been substituted
// with their concrete types. Cross-package types (`FederationProvider` from
// `session`, `ExchangeTokenValidator` from `oauth-token-exchange`) remain
// `unknown` pending Phase F resolution of the circular-import concern —
// this is intentional and pinned by the second describe block below so
// that any premature substitution of those two is caught.

describe("AS-M1: same-package concrete substitutions in contributes-map", () => {
	it("GrantHandler is the concrete grants/types GrantHandler", () => {
		expectTypeOf<GrantHandler>().toEqualTypeOf<ConcreteGrantHandler>();
		expect(true).toBe(true);
	});

	it("AuditHook is the canonical AuditSink interface", () => {
		expectTypeOf<AuditHook>().toEqualTypeOf<AuditSink>();
		expect(true).toBe(true);
	});

	it("MfaFactor is the canonical MfaProvider interface", () => {
		expectTypeOf<MfaFactor>().toEqualTypeOf<MfaProvider>();
		expect(true).toBe(true);
	});

	it("GrantPolicyHookContribution is the canonical GrantPolicyHook interface", () => {
		// Replaces the `= unknown` pin asserted in `naming-aliases.test.mts`
		// during AS-7 (PR3); that test's deliberate intent was that this
		// assertion would fail when Phase 9 substitution lands and would be
		// updated alongside the substitution work. PR6 IS that substitution.
		expectTypeOf<GrantPolicyHookContribution>().toEqualTypeOf<GrantPolicyHook>();
		expect(true).toBe(true);
	});
});

describe("AS-M1: cross-package types still deferred to Phase F", () => {
	// Substituting `FederationProvider` (session package) and
	// `ExchangeTokenValidator` (oauth-token-exchange package) requires
	// resolving a circular package-import concern. The pragmatic v0.5.1
	// resolution leaves these two as `unknown`. These pins fail-closed if
	// a future PR substitutes them without first resolving the cross-
	// package import cycle.

	it("FederationProvider is still `unknown` (Phase F deferral)", () => {
		expectTypeOf<FederationProvider>().toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("ExchangeTokenValidator is still `unknown` (Phase F deferral)", () => {
		expectTypeOf<ExchangeTokenValidator>().toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});
});
