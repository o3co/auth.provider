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
 * The `loginEntry` slot: the login page and the `redirect_to`
 * protocol `/authorize` and the federation-grants connect flow send a
 * browser that is not signed in by: the slot's shape, its wiring between
 * modules, and the test double. The slot's contract suite is the test kit's,
 * and runs over this double there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { LoginEntry } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestLoginEntry } from "#/testing/index.mjs";

describe("the loginEntry slot", () => {
	it("is optional, and holds the login page with the protocol that sends a browser there", () => {
		expectTypeOf<ComponentMap["loginEntry"]>().toEqualTypeOf<LoginEntry | undefined>();
		expectTypeOf<ProviderDeps<"loginEntry">["loginEntry"]>().toEqualTypeOf<LoginEntry>();
		expectTypeOf<LoginEntry["url"]>().toEqualTypeOf<string>();
		expectTypeOf<LoginEntry["urlFor"]>().toEqualTypeOf<(returnTo: string) => string>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const login = createTestLoginEntry();
		let seen: LoginEntry | undefined;
		const owner = defineModule({
			name: "test:login-entry-owner",
			provides: { loginEntry: () => login },
		});
		const reader = defineModule({
			name: "test:login-entry-reader",
			requires: ["loginEntry"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.loginEntry;
						return {
							id: "test-login-entry-reader",
							mountPath: "/__test_login_entry_reader__",
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
			expect(seen).toBe(login);
		} finally {
			await handle.dispose();
		}
	});
});

describe("createTestLoginEntry", () => {
	it("is the fixture configuration's page, /login, unless given another", () => {
		expect(createTestLoginEntry().url).toBe("/login");
		expect(createTestLoginEntry("https://idp.example/sign-in").url).toBe(
			"https://idp.example/sign-in",
		);
	});

	it("joins redirect_to with ? to a page without a query and with & to one that has one, the target encoded whole", () => {
		const target = "https://auth.test/oauth/authorize?client_id=a&state=b";
		expect(createTestLoginEntry().urlFor(target)).toBe(
			`/login?redirect_to=${encodeURIComponent(target)}`,
		);
		expect(createTestLoginEntry("/login?tenant=acme").urlFor(target)).toBe(
			`/login?tenant=acme&redirect_to=${encodeURIComponent(target)}`,
		);
		expect(createTestLoginEntry("/login?tenant=acme#x").urlFor(target)).toBe(
			`/login?tenant=acme&redirect_to=${encodeURIComponent(target)}#x`,
		);
	});

	it("refuses a page whose own query carries redirect_to", () => {
		expect(() => createTestLoginEntry("/login?redirect_to=x")).toThrow(/redirect_to/);
	});
});
