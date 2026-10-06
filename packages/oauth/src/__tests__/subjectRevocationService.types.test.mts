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

import type { ProviderDeps, SubjectRevocation } from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type SubjectRevocationServiceModuleDeps,
	subjectRevocationServiceModule,
} from "#/logout/subjectRevocationService.mjs";

// The provider reads only the slots the module declares, and an optional slot
// only behind a presence check. Compile-time facts: they fire under vitest's
// typecheck mode only.
//
// No `keyof` containment, unlike the grant modules: this provider hands its
// deps to no factory whole, but builds the options of
// `createSubjectRevocationService` field by field, and
// those keys are not slots. The typed callback is the whole of the guard.

const REQUIRES = [
	// Core's session lifecycle, which closes each of the subject's sessions.
	"sessionLifecycle",
	// The session's lifetime, which the horizon is sized from.
	"sessionCookiePolicy",
	// The token lifetimes the horizon is sized from.
	"oauthTokenSettings",
] as const;
const OPTIONAL = [
	"subjectSessionIndex",
	"subjectRevocation",
	"federationGrantStore",
	"auditSink",
	"logger",
	// Whether grants are on and may be kept; absent, grants are off.
	"federationGrantPolicy",
] as const;
type Declared = ProviderDeps<(typeof REQUIRES)[number], (typeof OPTIONAL)[number]>;

describe("subjectRevocationServiceModule's deps are the slots it declares", () => {
	it("types the provider as ProviderDeps of `requires` / `optional`", () => {
		expectTypeOf<SubjectRevocationServiceModuleDeps>().branded.toEqualTypeOf<Declared>();
		expect([...(subjectRevocationServiceModule.requires ?? [])].sort()).toEqual(
			[...REQUIRES].sort(),
		);
		expect([...(subjectRevocationServiceModule.optional ?? [])].sort()).toEqual(
			[...OPTIONAL].sort(),
		);
	});

	it("refuses, at compile time, a read of a slot the module never declared", () => {
		if (false as boolean) {
			const deps = {} as SubjectRevocationServiceModuleDeps;
			// @ts-expect-error — `keyStore` is in neither requires nor optional
			void deps.keyStore;
			// @ts-expect-error — nor is `rateLimiter`
			void deps.rateLimiter;
		}
		expect(true).toBe(true);
	});

	it("refuses, at compile time, an optional slot used as if it were present", () => {
		if (false as boolean) {
			const deps = {} as SubjectRevocationServiceModuleDeps;
			const useRevocation = (_revocation: SubjectRevocation): void => {};
			// A dropped slot would satisfy this too (TS2339, not TS2345); the pin above catches that.
			// @ts-expect-error — `subjectRevocation` is `SubjectRevocation | undefined`
			useRevocation(deps.subjectRevocation);
			if (deps.subjectRevocation) useRevocation(deps.subjectRevocation);
		}
		expect(true).toBe(true);
	});
});
