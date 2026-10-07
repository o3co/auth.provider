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
	SubjectRevocation,
	TokenBindingSettings,
	UserRepository,
	WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { WebAuthnConfig } from "#/config.mjs";
import type { WebAuthnGrantDeps } from "#/grant.mjs";
import { webauthnModule } from "#/module.mjs";

// A grant factory names the slots it reads, as the oauth grants do, so a slot
// it reads without its module declaring it is a compile error rather than an
// `undefined` at runtime, and a slot it never reads is not in its signature.
// These assertions only fire under vitest's typecheck mode; a passing
// `vitest run` alone proves nothing about them. The `if (false as boolean)`
// block keeps the negative assertion from executing.

const REQUIRES = [
	"webauthnCredentialStore",
	"challengeStore",
	"challengeCeremony",
	"keyStore",
	// What the grant reads of `oauth {}`.
	"oauthTokenSettings",
	// What the grant reads of `core.tokenBinding`, which core fills.
	"tokenBindingSettings",
] as const;
const OPTIONAL = [
	"grantPolicy",
	"rateLimiter",
	"auditSink",
	"logger",
	"refreshTokenFamilyRotation",
	// The subject's revocation boundary, which the grant reads before minting.
	"subjectRevocation",
	// The user behind the credential, read under `oauth.requireEmailVerified`.
	"userRepository",
] as const;
type ModuleDeps = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("the webauthn grant declares the slots it reads", () => {
	it("pins the module's declared slots, so the key-set check below cannot drift from them", () => {
		expect([...(webauthnModule.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(webauthnModule.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("reads only slots the module declares", () => {
		// A shared grant slot the module does not declare, such as the four
		// session stores or `refreshTokenFamilyRevocation`, would compile and
		// be `undefined` forever if the grant read it.
		// `webauthnConfig` is the module's own section, which it hands over
		// in its place (the fields it reads are pinned below).
		expectTypeOf<Exclude<keyof WebAuthnGrantDeps, "webauthnConfig">>().toMatchTypeOf<
			keyof ModuleDeps
		>();
		expect(true).toBe(true);
	});

	it("carries no slot the grant does not read", () => {
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("userSessionStore");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionRPRegistry");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionFamilyIndex");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("sessionFederationIndex");
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("refreshTokenFamilyRevocation");
		// The binding rule comes from core's `tokenBindingSettings` slot, the lifetimes from
		// `oauthTokenSettings`: nothing is read from the whole configuration.
		expectTypeOf<WebAuthnGrantDeps>().not.toHaveProperty("config");
		// The module's logger is read by the grant too, for the one line a
		// policy that cannot answer writes (`grant_policy_unavailable`).
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("logger");
		if (false as boolean) {
			const deps = {} as WebAuthnGrantDeps;
			// @ts-expect-error — the grant opens refresh-token families, it never revokes one
			void deps.refreshTokenFamilyRevocation;
		}
		expect(true).toBe(true);
	});

	it("reads only fields of webauthnConfig that the config has", () => {
		// The module's `satisfies` checks slots, not the fields inside one: a
		// field added to the grant's `webauthnConfig` type that WebAuthnConfig
		// lacks would compile (an optional one is satisfied by absence) and be
		// `undefined` forever.
		expectTypeOf<keyof WebAuthnGrantDeps["webauthnConfig"]>().toMatchTypeOf<keyof WebAuthnConfig>();
		expect(true).toBe(true);
	});

	it("still carries every slot the grant does read, typed as its ComponentMap slot", () => {
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("keyStore");
		expectTypeOf<WebAuthnGrantDeps>().toHaveProperty("webauthnConfig");
		expectTypeOf<
			WebAuthnGrantDeps["webauthnCredentialStore"]
		>().toEqualTypeOf<WebAuthnCredentialStore>();
		expectTypeOf<WebAuthnGrantDeps["challengeCeremony"]>().toEqualTypeOf<ChallengeCeremony>();
		// Required: the module requires the slot, so the grant is always handed it.
		expectTypeOf<WebAuthnGrantDeps["tokenBindingSettings"]>().toEqualTypeOf<TokenBindingSettings>();
		expectTypeOf<WebAuthnGrantDeps["grantPolicy"]>().toEqualTypeOf<GrantPolicyHook | undefined>();
		expectTypeOf<WebAuthnGrantDeps["refreshTokenFamilyRotation"]>().toEqualTypeOf<
			RefreshTokenFamilyRotation | undefined
		>();
		expectTypeOf<WebAuthnGrantDeps["subjectRevocation"]>().toEqualTypeOf<
			SubjectRevocation | undefined
		>();
		expectTypeOf<WebAuthnGrantDeps["userRepository"]>().toEqualTypeOf<UserRepository | undefined>();
		expect(true).toBe(true);
	});
});
