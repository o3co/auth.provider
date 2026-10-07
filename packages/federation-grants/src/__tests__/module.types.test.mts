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

import {
	AUDIT_SINK_ABSENCE_POLICY,
	type FederationGrantStore,
	type ProviderDeps,
	type RateLimiter,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type FederationGrantsModuleDeps,
	type federationGrantsConfigSchema,
	federationGrantsModule,
} from "#/module.mjs";

// The manifest's contribution callbacks read only the slots it declares, and
// an optional slot is used only behind a presence check.
// Compile-time facts: they fire under vitest's typecheck mode only.

const REQUIRES = [
	"federationGrantBackground",
	"clientRepository",
	// The session-admission ADR's D1: every consumer of admission requires it.
	"sessionRequirementResolver",
	// The issuer the routes and the acquisition settings are built on.
	"oauthTokenSettings",
	// The federations a connection names: whether each is configured and on,
	// and its issuer and client id.
	"federationSettings",
	// The policy a client's `jwksUri` is fetched under.
	"outboundPolicy",
] as const;
const OPTIONAL = [
	"federationGrantStore",
	"rateLimiter",
	"auditSink",
	"subjectRevocation",
	"sessionLifecycleStore",
	"replaySeenSet",
	"logger",
	"federationProviders",
	"federationGrantIntentStore",
	"userRepository",
	"userSessionStore",
	// The login page connect sends a browser that is not signed in to.
	"loginEntry",
	// The CSRF policy the consent answer is held to.
	"csrfGuard",
	// Where an enabled deployment registers the drain's tail.
	"lifecycleRegistrar",
] as const;
type Declared = ProviderDeps<
	(typeof REQUIRES)[number],
	(typeof OPTIONAL)[number],
	typeof federationGrantsConfigSchema
>;

describe("federationGrantsModule's deps are the slots it declares", () => {
	it("types every contribution callback as ProviderDeps of `requires` / `optional` and its section", () => {
		expectTypeOf<FederationGrantsModuleDeps>().branded.toEqualTypeOf<Declared>();
		expect([...(federationGrantsModule.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(federationGrantsModule.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("requires core's outboundPolicy, the policy a client's jwksUri is fetched under", () => {
		expect(federationGrantsModule.requires).toContain("outboundPolicy");
	});

	it("reads no whole configuration, and leaves the audit sink's declared absence to core's policy", () => {
		expect(federationGrantsModule.requires).not.toContain("config");
		expect(federationGrantsModule.absencePolicies).toEqual({
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
		});
	});

	it("refuses, at compile time, a read of a slot the module never declared", () => {
		if (false as boolean) {
			const deps = {} as FederationGrantsModuleDeps;
			// @ts-expect-error — `keyStore` is in neither requires nor optional
			void deps.keyStore;
			// @ts-expect-error — nor is `deviceCodeStore`
			void deps.deviceCodeStore;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as FederationGrantsModuleDeps;
			const useStore = (_store: FederationGrantStore): void => {};
			// A dropped slot would satisfy this too (TS2339, not TS2345); the pin above catches that.
			// @ts-expect-error — `federationGrantStore` is `FederationGrantStore | undefined`
			useStore(deps.federationGrantStore);
			const useLimiter = (_limiter: RateLimiter): void => {};
			// @ts-expect-error — `rateLimiter` is optional too
			useLimiter(deps.rateLimiter);
			if (deps.federationGrantStore) useStore(deps.federationGrantStore);
		}
		expect(true).toBe(true);
	});
});
