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

import type { ProviderDeps, RateLimiter } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, expectTypeOf, it } from "vitest";
import { createDeviceCodeGrant } from "#/grant.mjs";
import { type DeviceGrantModuleDeps, deviceGrantModule } from "#/module.mjs";

// #626 P2 (D4): the manifest's contribution callbacks read only the slots it
// declares, and an optional slot is used only behind a presence check.
// Compile-time facts: they fire under vitest's typecheck mode only, so this
// file is in both typecheck lists (vitest.config.mts and tsconfig.test.json).

const REQUIRES = ["config", "clientRepository", "keyStore"] as const;
const OPTIONAL = [
	"deviceCodeStore",
	"rateLimiter",
	"replaySeenSet",
	"logger",
	"auditSink",
	"userSessionStore",
	"subjectRevocation",
] as const;
type Declared = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("deviceGrantModule's deps are the slots it declares (#626 P2)", () => {
	it("types every contribution callback as ProviderDeps of `requires` / `optional`", () => {
		expectTypeOf<DeviceGrantModuleDeps>().branded.toEqualTypeOf<Declared>();
		const installed = deviceGrantModule({ config: makeValidAppConfig() });
		expect([...(installed.requires ?? [])].sort()).toEqual([...REQUIRES].sort());
		expect([...(installed.optional ?? [])].sort()).toEqual([...OPTIONAL].sort());
	});

	it("refuses, at compile time, a read of a slot the module never declared", () => {
		if (false as boolean) {
			const deps = {} as DeviceGrantModuleDeps;
			// @ts-expect-error — `consentStore` is in neither requires nor optional
			void deps.consentStore;
			// @ts-expect-error — nor is `grantPolicy`
			void deps.grantPolicy;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as DeviceGrantModuleDeps;
			// The grant, the authorization endpoint and the verification
			// endpoint all take `store: DeviceCodeStore`; the slot is optional,
			// so handing it over unchecked is the error this pins.
			createDeviceCodeGrant({
				// @ts-expect-error — `deviceCodeStore` is `DeviceCodeStore | undefined`
				store: deps.deviceCodeStore,
				keyStore: deps.keyStore,
				accessTokenExpiresIn: 60,
			});
			const useLimiter = (_limiter: RateLimiter): void => {};
			// A dropped slot would satisfy this too (TS2339, not TS2345); the pin above catches that.
			// @ts-expect-error — `rateLimiter` is optional too
			useLimiter(deps.rateLimiter);
			if (deps.rateLimiter) useLimiter(deps.rateLimiter);
		}
		expect(true).toBe(true);
	});
});
