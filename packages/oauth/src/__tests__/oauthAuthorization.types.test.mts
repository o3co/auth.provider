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
	AssertionVerifier,
	CodeRepository,
	GrantPolicyHook,
	OAuthTokenSettings,
	ProviderDeps,
	TokenBindingSettings,
	UserRepository,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { createAuthorizationGrant } from "#/grants/authorization.mjs";
import type { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import type { createJwtBearerGrant } from "#/grants/jwtBearer.mjs";
import type { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import type { createSessionGrant } from "#/grants/session.mjs";
import {
	type OAuthAuthorizationModuleDeps,
	oauthAuthorizationGrantsModule,
} from "#/oauthAuthorization.mjs";

// A module's contribution callbacks read only the slots it
// declares in `requires` / `optional`, and the grant factories it hands those
// deps to declare the slots they read. Both are compile-time facts, so they
// only fire under vitest's typecheck mode; a passing `vitest run` alone
// proves nothing about them. The `if (false as boolean)` blocks keep the
// negative assertions from executing.

const REQUIRES = [
	"clientRepository",
	"keyStore",
	"sessionRequirementResolver",
	"grantHandlerResolver",
	"oauthTokenSettings",
	"tokenBindingSettings",
] as const;
const OPTIONAL = [
	"codeRepository",
	"auditSink",
	"refreshTokenFamilyRotation",
	"refreshTokenFamilyRevocation",
	"subjectRevocation",
	"assertionVerifier",
	"userRepository",
	"grantPolicy",
	"userSessionStore",
	"sessionLifecycle",
	"sessionLifecycleStore",
	"logger",
] as const;
type Declared = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("oauthAuthorizationGrantsModule's deps are the slots it declares", () => {
	it("types every contribution callback as ProviderDeps of `requires` / `optional`", () => {
		// `.branded` because ProviderDeps is an intersection of two mapped types.
		expectTypeOf<OAuthAuthorizationModuleDeps>().branded.toEqualTypeOf<Declared>();
		// The runtime declaration is the same list, so the pin above cannot
		// drift from what the boot planner actually injects.
		const module = oauthAuthorizationGrantsModule;
		expect([...(module.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(module.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("refuses, at compile time, a read of a slot the module never declared", () => {
		if (false as boolean) {
			const deps = {} as OAuthAuthorizationModuleDeps;
			// @ts-expect-error — `federationGrantStore` is in neither requires nor optional
			void deps.federationGrantStore;
			// @ts-expect-error — nor is `rateLimiter`
			void deps.rateLimiter;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as OAuthAuthorizationModuleDeps;
			const usePolicy = (_policy: GrantPolicyHook): void => {};
			// A dropped slot would satisfy this too (TS2339, not TS2345); the pin above catches that.
			// @ts-expect-error — `grantPolicy` is optional: `GrantPolicyHook | undefined`
			usePolicy(deps.grantPolicy);
			// The presence check is what makes it usable.
			if (deps.grantPolicy) usePolicy(deps.grantPolicy);
		}
		expect(true).toBe(true);
	});
});

describe("the grant factories declare the slots they read", () => {
	type AuthorizationDeps = Parameters<typeof createAuthorizationGrant>[0];
	type RefreshDeps = Parameters<typeof createRefreshTokenGrant>[0];
	type JwtBearerDeps = Parameters<typeof createJwtBearerGrant>[0];
	type ClientCredentialsDeps = Parameters<typeof createClientCredentialsGrant>[0];
	type SessionDeps = Parameters<typeof createSessionGrant>[0];

	it("are satisfied by the module's typed deps where the module hands them over whole", () => {
		expectTypeOf<OAuthAuthorizationModuleDeps>().toMatchTypeOf<RefreshDeps>();
		expectTypeOf<OAuthAuthorizationModuleDeps>().toMatchTypeOf<ClientCredentialsDeps>();
		expect(true).toBe(true);
	});

	it("authorization_code requires the code repository the module lists optional", () => {
		expectTypeOf<OAuthAuthorizationModuleDeps>().not.toMatchTypeOf<AuthorizationDeps>();
		expectTypeOf<AuthorizationDeps["codeRepository"]>().toEqualTypeOf<CodeRepository>();
		expect(true).toBe(true);
	});

	it("jwt-bearer requires what the module lists optional, so the module checks before handing over", () => {
		expectTypeOf<OAuthAuthorizationModuleDeps>().not.toMatchTypeOf<JwtBearerDeps>();
		expectTypeOf<JwtBearerDeps["assertionVerifier"]>().toEqualTypeOf<AssertionVerifier>();
		expectTypeOf<JwtBearerDeps["userRepository"]>().toEqualTypeOf<UserRepository>();
		expect(true).toBe(true);
	});

	it("carry no slot the grant does not read", () => {
		// One slot per factory that its body never touches. With the old
		// `GrantDependencies` every factory admitted all of them, so a grant
		// could read a slot no module had declared for it.
		expectTypeOf<AuthorizationDeps>().not.toHaveProperty("grantPolicy");
		expectTypeOf<RefreshDeps>().not.toHaveProperty("sessionRPRegistry");
		// The authorization_code grant joins the session through the lifecycle alone.
		expectTypeOf<AuthorizationDeps>().not.toHaveProperty("sessionFamilyIndex");
		expectTypeOf<AuthorizationDeps>().not.toHaveProperty("sessionRPRegistry");
		expectTypeOf<JwtBearerDeps>().not.toHaveProperty("userSessionStore");
		expectTypeOf<ClientCredentialsDeps>().not.toHaveProperty("userSessionStore");
		expectTypeOf<SessionDeps>().not.toHaveProperty("codeRepository");
		// No grant reads the whole configuration: each reads its settings from
		// slots, and the refresh grant its unknown-family policy from the section.
		expectTypeOf<RefreshDeps>().not.toHaveProperty("config");
		expectTypeOf<AuthorizationDeps>().not.toHaveProperty("config");
		expectTypeOf<JwtBearerDeps>().not.toHaveProperty("config");
		expectTypeOf<ClientCredentialsDeps>().not.toHaveProperty("config");
		if (false as boolean) {
			const deps = {} as ClientCredentialsDeps;
			// @ts-expect-error — client_credentials reads no session store
			void deps.userSessionStore;
		}
		expect(true).toBe(true);
	});

	it("read only slots the module declares, optional ones included", () => {
		// `Pick<…, "grantPolicy">` is satisfied by a deps type WITHOUT
		// `grantPolicy` (an optional key accepts absence), so assignability
		// alone lets a grant read an optional slot its module never declared
		// and see `undefined` forever. The key sets close that gap.
		expectTypeOf<keyof AuthorizationDeps>().toMatchTypeOf<keyof OAuthAuthorizationModuleDeps>();
		// The refresh grant's one key beyond the slots is the section's policy,
		// which the module hands over itself.
		expectTypeOf<Exclude<keyof RefreshDeps, "unknownFamilyPolicy">>().toMatchTypeOf<
			keyof OAuthAuthorizationModuleDeps
		>();
		expectTypeOf<keyof JwtBearerDeps>().toMatchTypeOf<keyof OAuthAuthorizationModuleDeps>();
		expectTypeOf<keyof ClientCredentialsDeps>().toMatchTypeOf<keyof OAuthAuthorizationModuleDeps>();
		expect(true).toBe(true);
	});

	it("still carry every slot the grant does read", () => {
		expectTypeOf<AuthorizationDeps>().toHaveProperty("codeRepository");
		expectTypeOf<AuthorizationDeps>().toHaveProperty("userSessionStore");
		expectTypeOf<AuthorizationDeps>().toHaveProperty("refreshTokenFamilyRotation");
		expectTypeOf<RefreshDeps>().toHaveProperty("refreshTokenFamilyRevocation");
		expectTypeOf<RefreshDeps>().toHaveProperty("subjectRevocation");
		expectTypeOf<JwtBearerDeps>().toHaveProperty("logger");
		expectTypeOf<ClientCredentialsDeps>().toHaveProperty("grantPolicy");
		expectTypeOf<SessionDeps>().toHaveProperty("userSessionStore");
		expectTypeOf<SessionDeps>().toHaveProperty("grantPolicy");
		expectTypeOf<AuthorizationDeps["oauthTokenSettings"]>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<RefreshDeps["oauthTokenSettings"]>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<JwtBearerDeps["oauthTokenSettings"]>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<ClientCredentialsDeps["oauthTokenSettings"]>().toEqualTypeOf<OAuthTokenSettings>();
		expectTypeOf<AuthorizationDeps["tokenBindingSettings"]>().toEqualTypeOf<TokenBindingSettings>();
		expectTypeOf<RefreshDeps["tokenBindingSettings"]>().toEqualTypeOf<TokenBindingSettings>();
		// The refresh grant's unknown-family policy, as the module's section parses it.
		expectTypeOf<RefreshDeps["unknownFamilyPolicy"]>().toEqualTypeOf<
			"accept" | "reject" | undefined
		>();
		expect(true).toBe(true);
	});
});
