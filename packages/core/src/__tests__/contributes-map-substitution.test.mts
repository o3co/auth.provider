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
import type { FederationProvider as ConcreteFederationProvider } from "../federations/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../grants/types.mjs";
import type { MfaFactor as ConcreteMfaFactor } from "../mfa/factor.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
	MfaFactorFactory,
} from "../modules/manifest/contributes-map.mjs";
import type { Contributed } from "../modules/manifest/contributed.mjs";
import { defineModule } from "../modules/manifest/define-module.mjs";
import type { GrantPolicyHook } from "../policy/types.mjs";
import type { ExchangeTokenValidator as ConcreteExchangeTokenValidator } from "../token-exchange/validator.mjs";

// Every contribution kind carries its concrete type from registration to
// use. Four were substituted in v0.5.1 because their implementations live in
// core; the last two — `FederationProvider` and `ExchangeTokenValidator` —
// were `unknown` because their contracts lived in `session` and in
// `oauth-token-exchange`, which core may not import. #626 P1 moves the two
// contracts into core, where nothing has to import downwards to name them,
// and the second describe block below is what says so: it asserts the
// identity the deferral used to deny, and that a module contributing a
// federation that is not one fails to compile.

describe("AS-M1: same-package concrete substitutions in contributes-map", () => {
	it("GrantHandler is the concrete grants/types GrantHandler", () => {
		expectTypeOf<GrantHandler>().toEqualTypeOf<ConcreteGrantHandler>();
		expect(true).toBe(true);
	});

	it("AuditHook is the canonical AuditSink interface", () => {
		expectTypeOf<AuditHook>().toEqualTypeOf<AuditSink>();
		expect(true).toBe(true);
	});

	it("MfaFactor is the second-factor contract in mfa/factor (D3, D7)", () => {
		// The #69 `MfaProvider` is gone; the name survives as the contract a
		// factor implements, so what a module contributes and what the
		// coordinator reads back through `mfaFactorResolver` are one type.
		expectTypeOf<MfaFactor>().toEqualTypeOf<ConcreteMfaFactor>();
		expect(true).toBe(true);
	});

	it("an mfaFactors factory may answer null: the factor switched off by its configuration (D3)", () => {
		expectTypeOf<ReturnType<MfaFactorFactory<unknown>>>().toEqualTypeOf<
			Contributed<ConcreteMfaFactor | null>
		>();
		defineModule({
			name: "acme-mfa-factor-off",
			requires: [],
			contributes: { mfaFactors: { acme: () => null } },
		});
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

describe("#626 P1: the two contracts core owns now", () => {
	// The contracts moved into core, so the substitution is an identity
	// rather than a deferral: what a module registers, what the resolver
	// returns and what a consumer reads are one type.

	it("FederationProvider is the contract, not `unknown`", () => {
		expectTypeOf<FederationProvider>().toEqualTypeOf<ConcreteFederationProvider>();
		expectTypeOf<FederationProvider>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("ExchangeTokenValidator is the contract, not `unknown`", () => {
		expectTypeOf<ExchangeTokenValidator>().toEqualTypeOf<ConcreteExchangeTokenValidator>();
		expectTypeOf<ExchangeTokenValidator>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});

	it("refuses a federation contribution that is missing the methods, through the public entry point", () => {
		// Written against missing methods rather than a mistyped field:
		// `FederationProfile` carries a string index signature, so a wrong
		// field name can satisfy it vacuously and would pin nothing.
		defineModule({
			name: "acme-federation",
			requires: [],
			contributes: {
				federations: {
					// @ts-expect-error — no `buildAuthorizationUrl`, no `exchangeCode`
					acme: () => ({ name: "acme", scope: [] }),
				},
			},
		});
		expect(true).toBe(true);
	});
});
