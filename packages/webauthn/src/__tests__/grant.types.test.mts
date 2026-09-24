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
	ChallengeCeremony,
	GrantPolicyHook,
	ProviderDeps,
	RefreshTokenFamilyRotation,
	WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { WebAuthnGrantDeps } from "#/grant.mjs";
import { webauthnModule } from "#/module.mjs";

// #626 P2 (D4), as the oauth grants apply it: a grant factory names the slots
// it reads, so a slot it reads without its module declaring it is a compile
// error rather than an `undefined` at runtime, and a slot it never reads is
// not in its signature. These assertions only fire under vitest's typecheck
// mode; a passing `vitest run` alone proves nothing about them. The
// `if (false as boolean)` block keeps the negative assertion from executing.

const REQUIRES = [
	"webauthnConfig",
	"webauthnCredentialStore",
	"challengeStore",
	"challengeCeremony",
	"config",
	"keyStore",
] as const;
const OPTIONAL = [
	"grantPolicy",
	"rateLimiter",
	"auditSink",
	"logger",
	"refreshTokenFamilyRotation",
] as const;
type ModuleDeps = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("the webauthn grant declares the slots it reads (#626 P2)", () => {
	it("pins the module's declared slots, so the key-set check below cannot drift from them", () => {
		expect([...(webauthnModule.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(webauthnModule.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("reads only slots the module declares", () => {
		// `extends GrantDependencies` admitted every shared grant slot, among
		// them four session stores, `subjectRevocation` and
		// `refreshTokenFamilyRevocation`, none of which webauthnModule declares:
		// a read of one would have compiled and seen `undefined` forever.
		// `webauthnConfig` is the module's slot, narrowed to the four fields
		// the assertion check reads.
		expectTypeOf<keyof WebAuthnGrantDeps>().toMatchTypeOf<keyof ModuleDeps>();
		expect(true).toBe(true);
	});

	it("carries no slot the grant does not read", () => {
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("userSessionStore");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionRPRegistry");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionFamilyIndex");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionFederationIndex");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("subjectRevocation");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("refreshTokenFamilyRevocation");
		// Declared by the module for its rate-limited route, not read by the grant.
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("logger");
		if (false as boolean) {
			const deps = {} as WebAuthnGrantDeps;
			// @ts-expect-error — the grant opens refresh-token families, it never revokes one
			void deps.refreshTokenFamilyRevocation;
		}
		expect(true).toBe(true);
	});

	it("still carries every slot the grant does read, typed as its ComponentMap slot", () => {
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("config");
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("keyStore");
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("webauthnConfig");
		expectTypeOf<
			WebAuthnGrantDeps["webauthnCredentialStore"]
		>().toEqualTypeOf<WebAuthnCredentialStore>();
		expectTypeOf<WebAuthnGrantDeps["challengeCeremony"]>().toEqualTypeOf<ChallengeCeremony>();
		expectTypeOf<WebAuthnGrantDeps["grantPolicy"]>().toEqualTypeOf<GrantPolicyHook | undefined>();
		expectTypeOf<WebAuthnGrantDeps["refreshTokenFamilyRotation"]>().toEqualTypeOf<
			RefreshTokenFamilyRotation | undefined
		>();
		expect(true).toBe(true);
	});
});
