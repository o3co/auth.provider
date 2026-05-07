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
import type { AuditSink, AuditSinkBase } from "../audit/types.mjs";
import type {
	FederationTokenStore,
	FederationTokenStoreBase,
} from "../federation-tokens/types.mjs";
import type { MfaProvider, MfaProviderBase } from "../mfa/types.mjs";
import type { GrantPolicyHookContribution } from "../modules/manifest/contributes-map.mjs";
import type { GrantPolicyHook, GrantPolicyHookBase } from "../policy/types.mjs";
import type { RateLimiter, RateLimiterBase } from "../ratelimit/types.mjs";

// AS-7: Each non-`*Base` alias must be the same type as its `*Base`
// counterpart. The `*Base` names are deprecated as of v0.5.1 and will be
// removed at 1.0 GA; the aliases are the canonical names going forward.

describe("AS-7: deprecation aliases for *Base interfaces", () => {
	it("FederationTokenStore equals FederationTokenStoreBase", () => {
		expectTypeOf<FederationTokenStore>().toEqualTypeOf<FederationTokenStoreBase>();
		expect(true).toBe(true);
	});

	it("RateLimiter equals RateLimiterBase", () => {
		expectTypeOf<RateLimiter>().toEqualTypeOf<RateLimiterBase>();
		expect(true).toBe(true);
	});

	it("AuditSink equals AuditSinkBase", () => {
		expectTypeOf<AuditSink>().toEqualTypeOf<AuditSinkBase>();
		expect(true).toBe(true);
	});

	it("MfaProvider equals MfaProviderBase", () => {
		expectTypeOf<MfaProvider>().toEqualTypeOf<MfaProviderBase>();
		expect(true).toBe(true);
	});

	it("GrantPolicyHook (from policy) equals GrantPolicyHookBase", () => {
		expectTypeOf<GrantPolicyHook>().toEqualTypeOf<GrantPolicyHookBase>();
		expect(true).toBe(true);
	});
});

// AS-7 collision resolution: the manifest's contributes-map placeholder
// previously named `GrantPolicyHook` is renamed to
// `GrantPolicyHookContribution`. The new `GrantPolicyHook` (from policy)
// must NOT be assignable to / from `unknown` trivially — i.e. the
// `unknown` placeholder semantics belong to `GrantPolicyHookContribution`.

describe("AS-7 collision: GrantPolicyHook (policy) vs GrantPolicyHookContribution (manifest)", () => {
	it("GrantPolicyHookContribution is the renamed manifest placeholder (still `unknown`)", () => {
		// Type-only assertion: if the manifest-side rename ever regresses
		// (someone reverts the placeholder back to `GrantPolicyHook`), the
		// type-import above fails resolution and this test breaks at
		// typecheck. The `expectTypeOf<X>().toEqualTypeOf<unknown>()` pins
		// the placeholder semantics — Phase 9 substitution will replace
		// `unknown` with the concrete contribution type at which point this
		// assertion intentionally fails and must be updated alongside the
		// substitution work.
		expectTypeOf<GrantPolicyHookContribution>().toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});
});
