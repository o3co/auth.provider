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

import type {
	ExchangeTokenValidator,
	GrantPolicyHook,
	ProviderDeps,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { createTokenExchangeGrant, TokenExchangeDependencies } from "#/grant.mjs";
import { type TokenExchangeModuleDeps, tokenExchangeModule } from "#/module.mjs";

// #626 P2 (D4): the manifest's contribution callbacks read only the slots it
// declares, and the grant factory declares the slots it reads. Compile-time
// facts: they fire under vitest's typecheck mode only, so this file is in
// both typecheck lists (vitest.config.mts and tsconfig.test.json).

const REQUIRES = [
	"tokenExchangeValidatorResolver",
	"clientRepository",
	"keyStore",
	"config",
] as const;
const OPTIONAL = [
	"refreshTokenFamilyRevocation",
	"grantPolicy",
	"logger",
	"accessTokenDenylist",
	"subjectRevocation",
	"userSessionStore",
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
			// @ts-expect-error — `sessionRPRegistry` is in neither requires nor optional
			void deps.sessionRPRegistry;
			// @ts-expect-error — nor is `codeRepository`
			void deps.codeRepository;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as TokenExchangeModuleDeps;
			const usePolicy = (_policy: GrantPolicyHook): void => {};
			// A dropped slot would satisfy this too (TS2339, not TS2345); the pin above catches that.
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
		// It reads the UserSession store (the `sid` rule) and nothing else of
		// the session stores.
		expectTypeOf<GrantDeps>().toHaveProperty("userSessionStore");
		expectTypeOf<GrantDeps>().not.toHaveProperty("refreshTokenFamilyRotation");
		expectTypeOf<GrantDeps>().not.toHaveProperty("sessionRPRegistry");
		if (false as boolean) {
			const deps = {} as GrantDeps;
			// @ts-expect-error — the exchange reads no RP registry
			void deps.sessionRPRegistry;
		}
		expect(true).toBe(true);
	});

	it("is satisfied by the module's deps on every slot, the validator resolver included", () => {
		// `tokenExchangeValidatorResolver` used to be carved out of both sides:
		// core's `TokenExchangeValidatorResolver.get()` answered `unknown` where
		// the grant needed the validator, so the module bridged that one slot and
		// this assertion could not cover it. #626 P1 moved the contract into
		// core, the bridge is gone, and the carve-out with it — every slot is the
		// declaration itself now.
		expectTypeOf<TokenExchangeModuleDeps>().toMatchTypeOf<GrantDeps>();
		// And the grant reads only keys the module declares, optional ones
		// included — assignability alone would let it read an undeclared
		// optional slot and see `undefined` forever.
		expectTypeOf<keyof GrantDeps>().toMatchTypeOf<keyof TokenExchangeModuleDeps>();
		expectTypeOf<GrantDeps>().toHaveProperty("clientRepository");
		expectTypeOf<GrantDeps>().toHaveProperty("refreshTokenFamilyRevocation");
		expectTypeOf<GrantDeps>().toHaveProperty("grantPolicy");
		expectTypeOf<GrantDeps>().toHaveProperty("logger");
		expect(true).toBe(true);
	});
});

describe("#626 P1: the validator contract is core's", () => {
	// The same hard break as session's: one type, one path.
	//
	// A runtime check cannot pin this the way session's `index.test.mts` does.
	// All three names are type-only, so `name in mod` is `false` whether or not
	// the barrel re-exports them — the assertion would pass on the break and on
	// its undoing alike. What can fail is an import, checked by `vitest`
	// typecheck mode: this file is in both `typecheck.include` and
	// `tsconfig.test.json`, so the `@ts-expect-error` below is a real gate and
	// fails the moment the name comes back.
	it("is not re-exported from this package", () => {
		if (false as boolean) {
			// @ts-expect-error — `ExchangeTokenValidator` is core's since #626 P1
			type _V = import("#/index.mjs").ExchangeTokenValidator;
			// @ts-expect-error — `ExchangeTokenValidationContext` is core's since #626 P1
			type _C = import("#/index.mjs").ExchangeTokenValidationContext;
			// @ts-expect-error — `ValidatedToken` is core's since #626 P1
			type _T = import("#/index.mjs").ValidatedToken;
		}
		expect(true).toBe(true);
	});

	it("is what the grant's own resolver slot answers with", () => {
		// The assertion the deferral denied: what `get` hands the grant is the
		// contract, not `unknown`. Before #626 P1 this was `unknown | undefined`,
		// which `toEqualTypeOf` reduces to `unknown` — so both lines below failed.
		type Resolved = ReturnType<TokenExchangeDependencies["tokenExchangeValidatorResolver"]["get"]>;
		expectTypeOf<Resolved>().toEqualTypeOf<ExchangeTokenValidator | undefined>();
		expectTypeOf<Resolved>().not.toEqualTypeOf<unknown>();
		expect(true).toBe(true);
	});
});
