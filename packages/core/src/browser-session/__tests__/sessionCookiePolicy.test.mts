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
 * The `sessionCookiePolicy` slot: the session cookie's attributes, which
 * other modules need to set a cookie of their own beside it or to size what
 * must outlive a session: the slot's shape, its wiring between modules, and
 * the test double. The slot's contract suite is the test kit's, and runs
 * over this double there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { SessionCookiePolicy } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestSessionCookiePolicy } from "#/testing/index.mjs";

describe("the sessionCookiePolicy slot", () => {
	it("is optional, and holds the session cookie's attributes — named for it, not for the CSRF token's cookie", () => {
		expectTypeOf<ComponentMap["sessionCookiePolicy"]>().toEqualTypeOf<
			SessionCookiePolicy | undefined
		>();
		expectTypeOf<
			ProviderDeps<"sessionCookiePolicy">["sessionCookiePolicy"]
		>().toEqualTypeOf<SessionCookiePolicy>();
		expectTypeOf<"cookiePolicy" extends keyof ComponentMap ? true : false>().toEqualTypeOf<false>();
		expectTypeOf<SessionCookiePolicy>().toEqualTypeOf<{
			readonly name: string;
			readonly secure: boolean;
			readonly sameSite: "lax" | "strict" | "none";
			readonly domain: string | undefined;
			readonly maxAgeMs: number;
		}>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const policy = createTestSessionCookiePolicy();
		let seen: SessionCookiePolicy | undefined;
		const owner = defineModule({
			name: "test:cookie-policy-owner",
			provides: { sessionCookiePolicy: () => policy },
		});
		const reader = defineModule({
			name: "test:cookie-policy-reader",
			requires: ["sessionCookiePolicy"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.sessionCookiePolicy;
						return {
							id: "test-cookie-policy-reader",
							mountPath: "/__test_cookie_policy_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
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
			expect(seen).toBe(policy);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createTestSessionCookiePolicy", () => {
	it("is the fixture configuration's session cookie unless told otherwise", () => {
		expect(createTestSessionCookiePolicy()).toStrictEqual({
			name: "__Host-auth.session",
			secure: true,
			sameSite: "lax",
			domain: undefined,
			maxAgeMs: 3_600_000,
		});
		expect(createTestSessionCookiePolicy({ sameSite: "none" }).sameSite).toBe("none");
	});
});
