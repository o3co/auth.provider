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
 * The `loginEntry` slot (#728): the login page and the `redirect_to`
 * protocol `/authorize` and the federation-grants connect flow send a
 * browser that is not signed in by. Its contract suite and the test double:
 * the double keeps every case, and each way an entry can break the contract
 * fails the case that names it.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { LoginEntry } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createTestLoginEntry,
	type LoginEntryContractInput,
	loginEntryContract,
} from "#/testing/index.mjs";

const RULES = {
	url: "url is the login page it was built for",
	redirectTo: "urlFor adds redirect_to naming the target, once and whole",
	page: "urlFor keeps the page: its path and its own query, with nothing of the target read as either",
	fragment: "urlFor adds redirect_to to a page's query before its fragment, and keeps the fragment",
	refused: "a page whose own query already carries redirect_to is refused when the entry is built",
	frozen: "the login entry is frozen",
} as const;

/** The names of the cases the entries `build` makes fail. */
const failing = async (build: LoginEntryContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of loginEntryContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** An entry for `url` whose `urlFor` is `urlFor`, frozen as a provider hands it. */
const entry = (url: string, urlFor: (target: string) => string): LoginEntry =>
	Object.freeze({ url, urlFor });

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

describe("loginEntryContract — the double", () => {
	const cases = loginEntryContract({ build: (url) => createTestLoginEntry(url) });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.url,
			RULES.redirectTo,
			RULES.page,
			RULES.fragment,
			RULES.refused,
			RULES.frozen,
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
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

describe("loginEntryContract — each way an entry can break it", () => {
	it("a url that is not the page it was built for", async () => {
		expect(await failing((url) => entry(`${url}/`, createTestLoginEntry(url).urlFor))).toContain(
			RULES.url,
		);
	});

	it("a target appended unencoded, so its own query and fragment read as the page's", async () => {
		expect(
			await failing((url) =>
				entry(url, (target) => `${url}${url.includes("?") ? "&" : "?"}redirect_to=${target}`),
			),
		).toEqual(expect.arrayContaining([RULES.redirectTo, RULES.page]));
	});

	it("a second ? after a page that already carries a query", async () => {
		expect(
			await failing((url) =>
				entry(url, (target) => `${url}?redirect_to=${encodeURIComponent(target)}`),
			),
		).toContain(RULES.page);
	});

	it("another parameter name, or none added", async () => {
		expect(
			await failing((url) =>
				entry(
					url,
					(target) =>
						`${url}${url.includes("?") ? "&" : "?"}return_to=${encodeURIComponent(target)}`,
				),
			),
		).toContain(RULES.redirectTo);
		expect(await failing((url) => entry(url, () => url))).toContain(RULES.redirectTo);
	});

	it("redirect_to appended after the page's fragment, where the page never reads it", async () => {
		expect(
			await failing((url) =>
				entry(
					url,
					(target) =>
						`${url}${url.includes("?") ? "&" : "?"}redirect_to=${encodeURIComponent(target)}`,
				),
			),
		).toContain(RULES.fragment);
	});

	it("an entry built for a page that already carries redirect_to", async () => {
		expect(
			await failing((url) => {
				const fragmentAt = url.indexOf("#");
				const page = fragmentAt === -1 ? url : url.slice(0, fragmentAt);
				const fragment = fragmentAt === -1 ? "" : url.slice(fragmentAt);
				const joiner = page.includes("?") ? "&" : "?";
				return entry(
					url,
					(target) => `${page}${joiner}redirect_to=${encodeURIComponent(target)}${fragment}`,
				);
			}),
		).toEqual([RULES.refused]);
	});

	it("an entry a reader could change under the others", async () => {
		expect(await failing((url) => ({ ...createTestLoginEntry(url) }))).toEqual([RULES.frozen]);
	});
});
