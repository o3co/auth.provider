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

import type { GrantPolicyHook, ProviderDeps } from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import { createTokenExchangeGrant, type TokenExchangeDependencies } from "#/grant.mjs";
import { type TokenExchangeModuleDeps, tokenExchangeModule } from "#/module.mjs";

// #626 P2 (D4): the manifest's contribution callbacks read only the slots it
// declares, and the grant factory declares the slots it reads. Compile-time
// facts: they fire under vitest's typecheck mode only, so this file is in
// both typecheck lists (vitest.config.mts and tsconfig.test.json).

const REQUIRES = ["tokenExchangeValidatorResolver", "clientRepository", "keyStore", "config"] as const;
const OPTIONAL = [
	"refreshTokenFamilyRevocation",
	"grantPolicy",
	"logger",
	"accessTokenDenylist",
	"subjectRevocation",
] as const;
type Declared = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("tokenExchangeModule's deps are the slots it declares (#626 P2)", () => {
	it("types every contribution callback as ProviderDeps of `requires` / `optional`", () => {
		expectTypeOf<TokenExchangeModuleDeps>().branded.toEqualTypeOf<Declared>();
		expect([...(tokenExchangeModule.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(tokenExchangeModule.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("refuses, at compile time, a read of a slot the module never declared", () => {
		if (false as boolean) {
			const deps = {} as TokenExchangeModuleDeps;
			// @ts-expect-error — `userSessionStore` is in neither requires nor optional
			void deps.userSessionStore;
			// @ts-expect-error — nor is `codeRepository`
			void deps.codeRepository;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as TokenExchangeModuleDeps;
			const usePolicy = (_policy: GrantPolicyHook): void => {};
			// @ts-expect-error — `grantPolicy` is optional: `GrantPolicyHook | undefined`
			usePolicy(deps.grantPolicy);
			if (deps.grantPolicy) usePolicy(deps.grantPolicy);
		}
		expect(true).toBe(true);
	});
});

describe("createTokenExchangeGrant declares the slots it reads (#626 P2)", () => {
	type GrantDeps = Parameters<typeof createTokenExchangeGrant>[0];

	it("is TokenExchangeDependencies, and carries no slot the grant does not read", () => {
		expectTypeOf<GrantDeps>().toEqualTypeOf<TokenExchangeDependencies>();
		expectTypeOf<GrantDeps>().not.toHaveProperty("userSessionStore");
		expectTypeOf<GrantDeps>().not.toHaveProperty("refreshTokenFamilyRotation");
		expectTypeOf<GrantDeps>().not.toHaveProperty("sessionRPRegistry");
		if (false as boolean) {
			const deps = {} as GrantDeps;
			// @ts-expect-error — the exchange reads no session store
			void deps.userSessionStore;
		}
		expect(true).toBe(true);
	});

	it("is satisfied by the module's deps on every slot but the validator resolver", () => {
		// `tokenExchangeValidatorResolver` is the one slot the module cannot hand
		// over as declared: core's `TokenExchangeValidatorResolver.get()` returns
		// `unknown` (F1, `ExchangeTokenValidator` pending P1) where the grant
		// needs the concrete validator. Until P1 lands the module bridges that
		// one slot; everything else is the declaration itself.
		expectTypeOf<Omit<TokenExchangeModuleDeps, "tokenExchangeValidatorResolver">>().toMatchTypeOf<
			Omit<GrantDeps, "tokenExchangeValidatorResolver">
		>();
		expectTypeOf<GrantDeps>().toHaveProperty("clientRepository");
		expectTypeOf<GrantDeps>().toHaveProperty("refreshTokenFamilyRevocation");
		expectTypeOf<GrantDeps>().toHaveProperty("grantPolicy");
		expectTypeOf<GrantDeps>().toHaveProperty("logger");
		expect(true).toBe(true);
	});
});
