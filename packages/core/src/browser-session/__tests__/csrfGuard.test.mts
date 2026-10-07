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

/**
 * The `csrfGuard` slot, the one browser-origin / CSRF policy:
 * whether a browser's request may change state, and whether a navigation
 * may start a flow that will, decided once for every package's routes:
 * the slot's shape, its wiring between modules, and the test double. The
 * slot's contract suite is the test kit's, and runs over this double there.
 */

import type { Request, RequestHandler, Response } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { CsrfGuard, CsrfVerdict, NavigationVerdict } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestCsrfGuard, createTestSessionCookiePolicy } from "#/testing/index.mjs";

const SESSION_COOKIE = createTestSessionCookiePolicy();

describe("the csrfGuard slot", () => {
	it("is optional, and holds the one policy for whether a browser's request may change state", () => {
		expectTypeOf<ComponentMap["csrfGuard"]>().toEqualTypeOf<CsrfGuard | undefined>();
		expectTypeOf<ProviderDeps<"csrfGuard">["csrfGuard"]>().toEqualTypeOf<CsrfGuard>();
		expectTypeOf<CsrfGuard["check"]>().toEqualTypeOf<(req: Request) => CsrfVerdict>();
		expectTypeOf<CsrfGuard["checkNavigation"]>().toEqualTypeOf<
			(req: Request) => NavigationVerdict
		>();
		expectTypeOf<CsrfGuard["middleware"]>().toEqualTypeOf<RequestHandler>();
		expectTypeOf<CsrfGuard["issue"]>().toEqualTypeOf<(res: Response) => string>();
		expectTypeOf<CsrfGuard["bodyField"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<CsrfVerdict>().toEqualTypeOf<
			| { readonly outcome: "accepted" }
			| {
					readonly outcome: "refused";
					readonly reason: "foreign_origin" | "token_absent" | "token_invalid";
			  }
		>();
		expectTypeOf<NavigationVerdict>().toEqualTypeOf<
			| { readonly outcome: "accepted" }
			| {
					readonly outcome: "refused";
					readonly reason: "cross_site" | "foreign_origin" | "origin_absent";
			  }
		>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const guard = createTestCsrfGuard();
		let seen: CsrfGuard | undefined;
		const owner = defineModule({
			name: "test:csrf-guard-owner",
			provides: { csrfGuard: () => guard },
		});
		const reader = defineModule({
			name: "test:csrf-guard-reader",
			requires: ["csrfGuard"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.csrfGuard;
						return {
							id: "test-csrf-guard-reader",
							mountPath: "/__test_csrf_guard_reader__",
							handler: deps.csrfGuard.middleware,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			// The slot holds boot's snapshot of the guard (`boot/csrf-guard-slot.mts`):
			// the one value every reader gets, carrying the guard's own members and
			// core's request handler in front of its middleware.
			expect(seen).toBe(handle.components.csrfGuard);
			expect(seen?.middleware.length).toBe(3);
			expect(seen?.cookieName).toBe(guard.cookieName);
			expect(seen?.headerName).toBe(guard.headerName);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createTestCsrfGuard", () => {
	it("names its cookie from the session cookie's, as the session package does, and reads the body field csrf_token", () => {
		const guard = createTestCsrfGuard();
		expect(guard.cookieName).toBe(`${SESSION_COOKIE.name}.csrf`);
		expect(guard.headerName).toBe("x-csrf-token");
		expect(guard.bodyField).toBe("csrf_token");
		expect(
			createTestCsrfGuard({ sessionCookie: createTestSessionCookiePolicy({ name: "sid" }) })
				.cookieName,
		).toBe("sid.csrf");
	});
});
